"""
Seedvault backup handler (GrapheneOS / CalyxOS / LineageOS).

Seedvault is an open-source encrypted backup solution that uses a
12-word BIP39 mnemonic to derive AES-256-GCM encryption keys.

Key derivation:
    BIP39 mnemonic → 64-byte seed → HKDF-SHA256 → 32-byte AES key

File format:
    [version_byte (1B)][GCM nonce (12B)][ciphertext][GCM tag (16B)]

    Version 0x00: original format
    Version 0x02: current format (same crypto, different metadata handling)

Detection:
    - Directory containing a .sv metadata marker file
    - Individual .sbd (Seedvault Backup Data) files

References:
    - seedvault-app/seedvault (Kotlin, official)
    - WuhDaFak/seedvault_backup_parser (Python)
"""

import hashlib
import hmac as hmac_module
import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from Crypto.Cipher import AES
from mnemonic import Mnemonic

from .base import BackupHandler, DecryptResult, FormatInfo, FormatType
from ..utils import (
    ensure_dir,
    format_size,
    print_status,
    print_warning,
    Colors,
)


# ─────────────────────────────────────────────
# HKDF Implementation (RFC 5869)
# ─────────────────────────────────────────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)."""
    if not salt:
        salt = b"\x00" * 32  # hash_len for SHA-256
    return hmac_module.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand: derive output keying material."""
    hash_len = 32  # SHA-256 digest size
    n = (length + hash_len - 1) // hash_len
    t = b""
    okm = b""
    for i in range(1, n + 1):
        t = hmac_module.new(
            prk, t + info + bytes([i]), hashlib.sha256
        ).digest()
        okm += t
    return okm[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Full HKDF using SHA-256 (RFC 5869).

    Args:
        ikm: Input Keying Material.
        salt: Optional salt value (can be empty).
        info: Context/application-specific info string.
        length: Desired output key length in bytes.

    Returns:
        Derived key bytes.
    """
    prk = _hkdf_extract(salt, ikm)
    return _hkdf_expand(prk, info, length)


class SeedvaultHandler(BackupHandler):
    """Handler for Seedvault encrypted backup files."""

    FORMAT_NAME = "Seedvault Backup"
    FORMAT_TYPE = FormatType.SEEDVAULT

    # HKDF parameters used by Seedvault
    HKDF_SALT = b""  # Seedvault uses empty salt
    HKDF_INFO = b"Seed Backup"  # Application-specific info
    KEY_LENGTH = 32  # AES-256

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect Seedvault backup by directory structure or file extension.

        Seedvault backups are directories containing:
        - .sv marker file (metadata)
        - .sbd files (encrypted backup data)
        - Subdirectories per package
        """
        path = Path(file_path)

        # Case 1: Directory with .sv metadata marker
        if path.is_dir():
            sv_marker = path / ".sv"
            sv_files = list(path.rglob("*.sbd"))

            if sv_marker.exists():
                return FormatInfo(
                    format_type=FormatType.SEEDVAULT,
                    format_name="Seedvault Backup",
                    confidence=0.95,
                    encrypted=True,
                    metadata={
                        "sbd_file_count": len(sv_files),
                        "has_sv_marker": True,
                    },
                )

            # No .sv marker but has .sbd files
            if sv_files:
                return FormatInfo(
                    format_type=FormatType.SEEDVAULT,
                    format_name="Seedvault Backup (no marker)",
                    confidence=0.70,
                    encrypted=True,
                    metadata={"sbd_file_count": len(sv_files)},
                )

        # Case 2: Individual .sbd file
        if path.is_file() and path.suffix.lower() == ".sbd":
            # Check for valid version byte
            version_ok = False
            if header_bytes and len(header_bytes) >= 1:
                version_ok = header_bytes[0] in (0x00, 0x01, 0x02)

            return FormatInfo(
                format_type=FormatType.SEEDVAULT,
                format_name="Seedvault Backup Data (single file)",
                confidence=0.80 if version_ok else 0.50,
                encrypted=True,
                metadata={
                    "version": header_bytes[0] if version_ok else "unknown",
                },
            )

        return None

    def get_info(self) -> Dict[str, Any]:
        """Extract metadata from Seedvault backup."""
        info = {
            "format": self.FORMAT_NAME,
            "encrypted": True,
            "encryption": "AES-256-GCM",
            "key_derivation": "BIP39 mnemonic → HKDF-SHA256",
            "requires": "12-word BIP39 mnemonic phrase",
        }

        path = self.file_path

        if path.is_dir():
            sbd_files = list(path.rglob("*.sbd"))
            info["sbd_file_count"] = len(sbd_files)

            # Try to read .sv marker for metadata
            sv_marker = path / ".sv"
            if sv_marker.exists():
                try:
                    with open(sv_marker, "r") as f:
                        sv_data = json.load(f)
                    info["sv_metadata"] = sv_data
                except (json.JSONDecodeError, OSError):
                    info["sv_marker"] = True

            # Calculate total size
            total = sum(f.stat().st_size for f in sbd_files)
            info["total_encrypted_size"] = format_size(total)

            # List packages (subdirectories)
            packages = [
                d.name for d in path.iterdir()
                if d.is_dir() and not d.name.startswith(".")
            ]
            if packages:
                info["packages"] = sorted(packages)
                info["package_count"] = len(packages)

        elif path.is_file():
            info["file_size"] = format_size(path.stat().st_size)
            # Read version byte
            try:
                with open(path, "rb") as f:
                    version = f.read(1)
                info["version"] = version[0] if version else "unknown"
            except OSError:
                pass

        return info

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt Seedvault backup using a 12-word BIP39 mnemonic.

        Args:
            output_path: Directory to write decrypted files to.
            mnemonic: Required. 12-word BIP39 mnemonic phrase.
        """
        output_path = Path(output_path)
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        mnemonic_str = kwargs.get("mnemonic")
        if not mnemonic_str:
            result.add_error(
                "Seedvault backups require a 12-word BIP39 mnemonic. "
                "Use --mnemonic 'word1 word2 ... word12'"
            )
            return result

        # Validate mnemonic
        mnemo = Mnemonic("english")
        if not mnemo.check(mnemonic_str):
            result.add_error(
                "Invalid BIP39 mnemonic. Please check your 12 words. "
                "Each word must be from the BIP39 English word list and "
                "the checksum must be valid."
            )
            return result

        print_status("🔑", "BIP39 mnemonic validated")

        # Derive seed from mnemonic (64 bytes)
        seed = mnemo.to_seed(mnemonic_str, passphrase="")

        # Derive AES-256 key via HKDF-SHA256
        key = hkdf_sha256(
            ikm=seed,
            salt=self.HKDF_SALT,
            info=self.HKDF_INFO,
            length=self.KEY_LENGTH,
        )

        print_status("🔐", "AES-256 key derived via HKDF-SHA256")

        path = self.file_path

        if path.is_dir():
            # Decrypt all .sbd files in the directory tree
            sbd_files = sorted(path.rglob("*.sbd"))
            if not sbd_files:
                result.add_error("No .sbd files found in backup directory")
                return result

            print_status("📦", f"Found {len(sbd_files)} encrypted files")

            for sbd_file in sbd_files:
                try:
                    out_file = self._decrypt_sbd(sbd_file, path, output_path, key)
                    result.files_extracted += 1
                    result.total_size += out_file.stat().st_size
                except Exception as e:
                    result.add_warning(f"Failed: {sbd_file.name}: {e}")

        elif path.is_file():
            # Single file decryption
            try:
                out_file = self._decrypt_sbd(path, path.parent, output_path, key)
                result.files_extracted = 1
                result.total_size = out_file.stat().st_size
            except Exception as e:
                result.add_error(f"Decryption failed: {e}")
                return result

        result.success = result.files_extracted > 0
        if result.success:
            print_status(
                "✅",
                f"Decrypted {result.files_extracted} files "
                f"({format_size(result.total_size)})",
            )

        return result

    def _decrypt_sbd(
        self,
        sbd_path: Path,
        base_dir: Path,
        output_dir: Path,
        key: bytes,
    ) -> Path:
        """
        Decrypt a single .sbd file using AES-256-GCM.

        File format: [version (1B)][nonce (12B)][ciphertext...][tag (16B)]

        Returns the path to the decrypted file.
        """
        with open(sbd_path, "rb") as f:
            data = f.read()

        if len(data) < 29:  # 1 + 12 + 16 minimum
            raise ValueError(f"File too small: {len(data)} bytes")

        # Parse the encrypted file structure
        version = data[0]

        if version not in (0x00, 0x01, 0x02):
            raise ValueError(f"Unknown Seedvault version: 0x{version:02x}")

        # After version byte: 12-byte nonce, then ciphertext, last 16 bytes = tag
        nonce = data[1:13]
        ciphertext_and_tag = data[13:]

        if len(ciphertext_and_tag) < 16:
            raise ValueError("Encrypted data too short (missing GCM tag)")

        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        # Decrypt with AES-256-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            raise ValueError(
                f"GCM authentication failed (wrong mnemonic?): {e}"
            )

        # Preserve directory structure relative to base_dir
        try:
            rel_path = sbd_path.relative_to(base_dir)
        except ValueError:
            rel_path = Path(sbd_path.name)

        # Remove .sbd extension and add appropriate extension
        out_path = output_dir / rel_path.with_suffix("")
        if out_path.suffix == "":
            # Try to detect file type from decrypted content
            ext = self._detect_type(decrypted)
            out_path = out_path.with_suffix(ext)

        ensure_dir(out_path.parent)
        with open(out_path, "wb") as f:
            f.write(decrypted)

        return out_path

    @staticmethod
    def _detect_type(data: bytes) -> str:
        """Detect file type from decrypted content magic bytes."""
        if not data:
            return ".bin"

        # Common Android data file types
        if data[:6] == b"SQLite" or data[:16] == b"SQLite format 3\x00":
            return ".db"
        if data[:2] == b"PK":
            return ".zip"
        if data[:4] == b"\x1f\x8b\x08\x00":
            return ".gz"
        if data[:3] == b"\xff\xd8\xff":
            return ".jpg"
        if data[:4] == b"\x89PNG":
            return ".png"
        if data[:4] == b"RIFF":
            return ".webp"
        if data[:5] == b"<?xml":
            return ".xml"
        if data[:1] == b"{":
            return ".json"

        return ".bin"
