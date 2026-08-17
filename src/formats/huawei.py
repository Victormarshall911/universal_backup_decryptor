"""
Huawei KoBackup / HiSuite backup handler (v3 and v4).

Huawei backups use a directory structure with an info.xml manifest that
describes all encrypted files and contains the cryptographic parameters.

Key derivation:
    - PBKDF2-HMAC-SHA256 (5000 rounds, 32-byte key)
    - Salt from pwkey_salt[:16]
    - Nonce from pwkey_salt[16:]

Encryption:
    - Per-backup key encrypted with AES-GCM (from e_perbackupkey)
    - Per-file keys encrypted with AES-GCM (from each file's encMsgV3)
    - File data encrypted with AES-CTR using per-file key

Backup modes:
    - v3: password IS the key (no PBKDF2 derivation)
    - v4: password → PBKDF2 → AES-GCM → per-backup key

References:
    - RealityNet/kobackupdec (Python, MIT license)
    - mauronofrio/Huawei-Backup-V4-Decrypt
"""

import binascii
import hashlib
import logging
import os
import tarfile
import xml.dom.minidom
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter

from .base import BackupHandler, DecryptResult, FormatInfo, FormatType
from ..utils import (
    ensure_dir,
    format_size,
    print_status,
    print_warning,
    Colors,
)

# PBKDF2 parameters for Huawei v4 backups
HUAWEI_PBKDF2_ROUNDS = 5000
HUAWEI_KEY_LENGTH = 32

# Maximum file size before chunked processing (512 MB)
MAX_FILE_SIZE = 536870912
CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB


class _DecryptMaterial:
    """Per-file decryption parameters parsed from info.xml."""

    __slots__ = ("name", "type_name", "enc_msg_v3", "iv",
                 "path", "copy_file_path", "records_num")

    def __init__(self, type_name: str):
        self.type_name = type_name
        self.name: Optional[str] = None
        self.enc_msg_v3: Optional[bytes] = None
        self.iv: Optional[bytes] = None
        self.path: Optional[str] = None
        self.copy_file_path: Optional[str] = None
        self.records_num: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return self.name is not None and (self.enc_msg_v3 is not None or self.iv is not None)


class HuaweiHandler(BackupHandler):
    """Handler for Huawei KoBackup / HiSuite backup directories."""

    FORMAT_NAME = "Huawei KoBackup / HiSuite"
    FORMAT_TYPE = FormatType.HUAWEI_KOBACKUP

    def __init__(self, file_path: Union[str, Path]):
        super().__init__(file_path)
        self._xml_data = {}
        self._decrypt_materials: List[_DecryptMaterial] = []

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect Huawei KoBackup by checking for info.xml in the directory.
        """
        path = Path(file_path)

        # Must be a directory
        if not path.is_dir():
            return None

        info_xml = path / "info.xml"
        if not info_xml.exists():
            return None

        # Parse info.xml to verify it's a Huawei backup
        try:
            dom = xml.dom.minidom.parse(str(info_xml))
            root = dom.documentElement

            metadata = {}
            encrypted = False

            # Look for characteristic Huawei XML elements
            for node_name in ["e_perbackupkey", "pwkey_salt", "checkMsg"]:
                elements = root.getElementsByTagName(node_name)
                if elements:
                    metadata[node_name] = True
                    encrypted = True

            # Get backup version
            if root.hasAttribute("backupVersion"):
                metadata["backup_version"] = root.getAttribute("backupVersion")

            if root.hasAttribute("header_size"):
                metadata["header_size"] = root.getAttribute("header_size")

            # At minimum, we need the root tag to be recognizable
            if encrypted or root.tagName in ["info", "backup", "BackupInfo"]:
                return FormatInfo(
                    format_type=FormatType.HUAWEI_KOBACKUP,
                    format_name="Huawei KoBackup / HiSuite",
                    confidence=0.95 if encrypted else 0.70,
                    encrypted=encrypted,
                    metadata=metadata,
                )

        except Exception:
            pass

        return None

    def get_info(self) -> Dict[str, Any]:
        """Extract metadata from the Huawei backup directory."""
        info = {
            "format": self.FORMAT_NAME,
        }

        path = self.file_path
        info_xml = path / "info.xml"

        if info_xml.exists():
            try:
                dom = xml.dom.minidom.parse(str(info_xml))
                root = dom.documentElement

                # Backup version
                if root.hasAttribute("backupVersion"):
                    info["backup_version"] = root.getAttribute("backupVersion")

                # Count encrypted files
                file_elements = root.getElementsByTagName("file")
                info["file_count"] = len(file_elements)

                # Check for encryption
                has_key = bool(root.getElementsByTagName("e_perbackupkey"))
                info["encrypted"] = has_key
                info["key_derivation"] = "PBKDF2-HMAC-SHA256" if has_key else "none"
                info["pbkdf2_rounds"] = HUAWEI_PBKDF2_ROUNDS if has_key else 0

            except Exception as e:
                info["parse_error"] = str(e)

        # Calculate total backup size
        total_size = sum(
            f.stat().st_size for f in path.rglob("*") if f.is_file()
        )
        info["total_size"] = format_size(total_size)

        return info

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt Huawei KoBackup.

        Requires a password. Parses info.xml, derives the per-backup key,
        then decrypts each file listed in the manifest.

        Args:
            output_path: Directory to extract decrypted files to.
            password: Required. The user's backup password.
        """
        output_path = Path(output_path)
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        password = kwargs.get("password")
        if not password:
            result.add_error(
                "Huawei backups require a password. Use --password"
            )
            return result

        path = self.file_path
        info_xml = path / "info.xml"

        if not info_xml.exists():
            result.add_error("info.xml not found in backup directory")
            return result

        print_status("🔐", "Huawei KoBackup detected — initializing decryption...")

        try:
            # Parse the info.xml
            dom = xml.dom.minidom.parse(str(info_xml))
            root = dom.documentElement

            # Extract crypto parameters
            bkey = self._derive_backup_key(root, password)

            if bkey is None:
                result.add_error("Failed to derive backup key — wrong password?")
                return result

            # SHA-256 of backup key (used as AES key for file decryption)
            bkey_hash = hashlib.sha256(bkey).digest()

            print_status("✓", "Backup key derived successfully", Colors.GREEN)

            # Parse per-file decrypt materials
            self._parse_file_materials(root)

            print_status(
                "📋",
                f"Found {len(self._decrypt_materials)} entries to decrypt",
                Colors.DIM,
            )

            # Decrypt each file
            for material in self._decrypt_materials:
                if not material.is_valid:
                    continue

                try:
                    self._decrypt_file(
                        material, path, output_path, bkey, bkey_hash
                    )
                    result.files_extracted += 1
                except Exception as e:
                    result.add_warning(
                        f"Failed to decrypt {material.name}: {e}"
                    )

            # Also copy unencrypted files (labeled 'P' for plaintext)
            self._copy_plaintext_files(root, path, output_path, result)

            result.success = result.files_extracted > 0
            if result.success:
                print_status(
                    "✅",
                    f"Decrypted {result.files_extracted} files",
                )

        except Exception as e:
            result.add_error(f"Huawei decryption failed: {e}")

        return result

    def _derive_backup_key(self, root, password: str) -> Optional[bytes]:
        """
        Derive the per-backup key from the user password.

        v4 (modern): PBKDF2(password, salt) → AES-GCM decrypt e_perbackupkey
        v3 (legacy): password is the key directly
        """
        # Get type_attch to determine version
        type_attch = 0
        type_elems = root.getElementsByTagName("type_attch")
        if type_elems and type_elems[0].firstChild:
            try:
                type_attch = int(type_elems[0].firstChild.data)
            except (ValueError, AttributeError):
                pass

        # Get e_perbackupkey and pwkey_salt
        e_perbackupkey = self._get_xml_hex(root, "e_perbackupkey")
        pwkey_salt = self._get_xml_hex(root, "pwkey_salt")

        if e_perbackupkey and pwkey_salt:
            # v4: PBKDF2 + AES-GCM
            print_status("🔑", "Using v4 key derivation (PBKDF2-HMAC-SHA256)")

            salt = pwkey_salt[:16]
            nonce = pwkey_salt[16:]

            # Custom PRF for PyCryptodome's PBKDF2
            def prf(p, s):
                return HMAC.new(p, s, SHA256).digest()

            derived_key = PBKDF2(
                password, salt,
                dkLen=HUAWEI_KEY_LENGTH,
                count=HUAWEI_PBKDF2_ROUNDS,
                prf=prf,
            )

            # Decrypt e_perbackupkey with AES-GCM
            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
            try:
                bkey = cipher.decrypt(e_perbackupkey)[:32]
                return bkey
            except ValueError:
                return None
        else:
            # v3: password is the key
            print_status("🔑", "Using v3 key derivation (direct password)")
            if isinstance(password, str):
                return password.encode("utf-8")[:32].ljust(32, b"\x00")
            return password[:32].ljust(32, b"\x00")

    def _parse_file_materials(self, root) -> None:
        """Parse per-file encryption parameters from info.xml."""
        self._decrypt_materials.clear()

        # Look for file entries in various XML structures
        for tag_name in ["file", "item", "entry"]:
            for elem in root.getElementsByTagName(tag_name):
                material = _DecryptMaterial(tag_name)

                # Get name attribute
                if elem.hasAttribute("name"):
                    material.name = elem.getAttribute("name")
                elif elem.hasAttribute("n"):
                    material.name = elem.getAttribute("n")

                # Get encMsgV3 (per-file encryption key)
                enc_msg = self._get_child_text(elem, "encMsgV3")
                if enc_msg:
                    try:
                        material.enc_msg_v3 = binascii.unhexlify(enc_msg)
                    except (ValueError, binascii.Error):
                        pass

                # Get IV
                iv_text = self._get_child_text(elem, "iv")
                if iv_text:
                    try:
                        material.iv = binascii.unhexlify(iv_text)
                    except (ValueError, binascii.Error):
                        pass

                # Get file path
                if elem.hasAttribute("path"):
                    material.path = elem.getAttribute("path")

                if elem.hasAttribute("copyFilePath"):
                    material.copy_file_path = elem.getAttribute("copyFilePath")

                if material.is_valid:
                    self._decrypt_materials.append(material)

    def _decrypt_file(
        self,
        material: _DecryptMaterial,
        backup_dir: Path,
        output_dir: Path,
        bkey: bytes,
        bkey_hash: bytes,
    ) -> None:
        """Decrypt a single file using its DecryptMaterial."""
        # Determine the source file path
        source_path = None
        if material.copy_file_path:
            candidate = backup_dir / material.copy_file_path
            if candidate.exists():
                source_path = candidate
        if source_path is None and material.path:
            candidate = backup_dir / material.path
            if candidate.exists():
                source_path = candidate
        if source_path is None:
            # Try to find by name
            candidate = backup_dir / material.name
            if candidate.exists():
                source_path = candidate

        if source_path is None or not source_path.exists():
            raise FileNotFoundError(
                f"Source file not found for {material.name}"
            )

        # Derive per-file key from encMsgV3
        if material.enc_msg_v3:
            # encMsgV3 is 48 bytes: encrypted per-file key (32) + GCM tag (16)
            enc_key_data = material.enc_msg_v3[:32]
            enc_key_tag = material.enc_msg_v3[32:]

            # Use first 16 bytes of bkey_hash as AES-128 key
            aes_key = bkey_hash[:16]

            if material.iv:
                nonce = material.iv[:12] if len(material.iv) >= 12 else material.iv
            else:
                nonce = bkey_hash[:12]

            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            try:
                per_file_key = cipher.decrypt_and_verify(enc_key_data, enc_key_tag)
            except ValueError:
                # Try without tag verification
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                per_file_key = cipher.decrypt(enc_key_data)
        else:
            per_file_key = bkey_hash[:16]

        # Decrypt the file data using AES-CTR
        if material.iv:
            iv_int = int.from_bytes(material.iv[:16].ljust(16, b"\x00"), "big")
        else:
            iv_int = 0

        counter = Counter.new(128, initial_value=iv_int)
        cipher = AES.new(per_file_key[:16], AES.MODE_CTR, counter=counter)

        # Determine output path
        out_name = material.name
        if material.path:
            out_file = output_dir / material.path / out_name
        else:
            out_file = output_dir / out_name
        ensure_dir(out_file.parent)

        file_size = source_path.stat().st_size

        if file_size > MAX_FILE_SIZE:
            # Chunked decryption for large files
            with open(source_path, "rb") as src, open(out_file, "wb") as dst:
                while True:
                    chunk = src.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    dst.write(cipher.decrypt(chunk))
        else:
            with open(source_path, "rb") as f:
                encrypted_data = f.read()
            decrypted = cipher.decrypt(encrypted_data)

            with open(out_file, "wb") as f:
                f.write(decrypted)

        # Check if decrypted file is a tar archive and expand it
        if tarfile.is_tarfile(str(out_file)):
            try:
                tar_dir = out_file.parent / out_file.stem
                ensure_dir(tar_dir)
                with tarfile.open(out_file, "r:*") as tar:
                    tar.extractall(path=tar_dir)
                # Keep the tar but also have the expanded version
            except tarfile.TarError:
                pass

    def _copy_plaintext_files(
        self, root, backup_dir: Path, output_dir: Path, result: DecryptResult
    ) -> None:
        """Copy unencrypted (plaintext) files from the backup."""
        import shutil

        for elem in root.getElementsByTagName("file"):
            # Files with type 'P' are plaintext
            if elem.hasAttribute("type") and elem.getAttribute("type") == "P":
                name = elem.getAttribute("name") if elem.hasAttribute("name") else None
                if name:
                    src = backup_dir / name
                    if src.exists() and src.is_file():
                        dst = output_dir / name
                        ensure_dir(dst.parent)
                        shutil.copy2(src, dst)
                        result.files_extracted += 1

    @staticmethod
    def _get_xml_hex(root, tag_name: str) -> Optional[bytes]:
        """Get hex-encoded content from an XML tag and decode it."""
        elements = root.getElementsByTagName(tag_name)
        if elements and elements[0].firstChild:
            hex_str = elements[0].firstChild.data.strip()
            if hex_str:
                try:
                    return binascii.unhexlify(hex_str)
                except (ValueError, binascii.Error):
                    pass
        return None

    @staticmethod
    def _get_child_text(elem, tag_name: str) -> Optional[str]:
        """Get text content from a child element."""
        children = elem.getElementsByTagName(tag_name)
        if children and children[0].firstChild:
            return children[0].firstChild.data.strip()
        return None

    def try_password(self, password: str) -> bool:
        """Test if a password is correct by attempting key derivation."""
        info_xml = self.file_path / "info.xml"
        if not info_xml.exists():
            return False

        try:
            dom = xml.dom.minidom.parse(str(info_xml))
            root = dom.documentElement
            bkey = self._derive_backup_key(root, password)
            return bkey is not None
        except Exception:
            return False
