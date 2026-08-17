"""
Android .ab (adb backup) format handler.

Supports both unencrypted and AES-256 encrypted Android backup files.
This is the most common Android backup format, created by:
  adb backup -apk -shared -all -f backup.ab

File format:
  Line 1: "ANDROID BACKUP\n"
  Line 2: Version (1-5)
  Line 3: Compressed flag (0 or 1)
  Line 4: Encryption ("none" or "AES-256")
  [If encrypted]:
    Line 5: User password salt (hex)
    Line 6: Master key checksum salt (hex)
    Line 7: PBKDF2 rounds (integer)
    Line 8: User key IV (hex)
    Line 9: Master key blob (hex, encrypted)
  Binary data follows (DEFLATE-compressed TAR archive)

References:
  - nelenkov/android-backup-extractor (Java)
  - lclevy/ab_decrypt (Python, educational)
"""

import io
import struct
import tarfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from Crypto.Cipher import AES

from .base import BackupHandler, DecryptResult, FormatInfo, FormatType
from ..utils import (
    aes_decrypt_cbc,
    deflate_decompress,
    derive_key_pbkdf2,
    ensure_dir,
    format_size,
    java_utf8_encode,
    print_status,
    read_hex_line,
    safe_path_join,
    Colors,
    colored,
)


# Magic bytes identifying an Android backup file
AB_MAGIC = b"ANDROID BACKUP\n"


class AndroidABHandler(BackupHandler):
    """Handler for standard Android .ab backup files."""

    FORMAT_NAME = "Android ADB Backup (.ab)"
    FORMAT_TYPE = FormatType.ANDROID_AB

    def __init__(self, file_path: Union[str, Path]):
        super().__init__(file_path)
        self._header = None
        self._parse_header()

    def _parse_header(self):
        """Parse the .ab file header into a structured dict."""
        self._header = {
            "magic": None,
            "version": None,
            "compressed": None,
            "encryption": None,
            "user_salt": None,
            "checksum_salt": None,
            "pbkdf2_rounds": None,
            "user_iv": None,
            "master_key_blob": None,
            "data_offset": 0,
        }

        try:
            with open(self.file_path, "rb") as f:
                # Line 1: Magic
                magic = f.readline()
                if not magic.startswith(b"ANDROID BACKUP"):
                    return
                self._header["magic"] = magic.strip().decode("utf-8", errors="replace")

                # Line 2: Version
                version_line = f.readline().strip()
                self._header["version"] = int(version_line)

                # Line 3: Compressed
                compressed_line = f.readline().strip()
                self._header["compressed"] = int(compressed_line) == 1

                # Line 4: Encryption
                encryption_line = f.readline().strip().decode("utf-8", errors="replace")
                self._header["encryption"] = encryption_line

                if encryption_line == "AES-256":
                    # Line 5: User password salt
                    self._header["user_salt"] = f.readline().strip()
                    # Line 6: Master key checksum salt
                    self._header["checksum_salt"] = f.readline().strip()
                    # Line 7: PBKDF2 rounds
                    self._header["pbkdf2_rounds"] = int(f.readline().strip())
                    # Line 8: User key IV
                    self._header["user_iv"] = f.readline().strip()
                    # Line 9: Master key blob
                    self._header["master_key_blob"] = f.readline().strip()

                # Record where binary data starts
                self._header["data_offset"] = f.tell()

        except (OSError, ValueError, UnicodeDecodeError):
            pass

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """Detect Android .ab format by magic bytes."""
        if header_bytes.startswith(AB_MAGIC):
            # Parse minimal header for metadata
            lines = header_bytes.split(b"\n", 5)
            encrypted = False
            metadata = {}

            if len(lines) >= 4:
                try:
                    metadata["version"] = int(lines[1])
                    metadata["compressed"] = int(lines[2]) == 1
                    encryption = lines[3].decode("utf-8", errors="replace").strip()
                    metadata["encryption"] = encryption
                    encrypted = encryption == "AES-256"
                except (ValueError, UnicodeDecodeError):
                    pass

            return FormatInfo(
                format_type=FormatType.ANDROID_AB,
                format_name="Android ADB Backup (.ab)",
                confidence=1.0,
                encrypted=encrypted,
                metadata=metadata,
            )
        return None

    def get_info(self) -> Dict[str, Any]:
        """
        Extract detailed metadata from the backup without decrypting.

        Returns Android version hints, compression status, encryption details,
        and package list (if unencrypted).
        """
        info = {
            "format": self.FORMAT_NAME,
            "file_size": self.file_path.stat().st_size,
            "file_size_human": format_size(self.file_path.stat().st_size),
        }

        if self._header:
            info["version"] = self._header["version"]
            info["compressed"] = self._header["compressed"]
            info["encryption"] = self._header["encryption"]

            if self._header["encryption"] == "AES-256":
                info["pbkdf2_rounds"] = self._header["pbkdf2_rounds"]
                info["encrypted"] = True
            else:
                info["encrypted"] = False

                # For unencrypted backups, try to list packages
                packages = self._list_packages_unencrypted()
                if packages:
                    info["packages"] = packages
                    info["package_count"] = len(packages)

        return info

    def _list_packages_unencrypted(self) -> List[str]:
        """List package names from an unencrypted backup's TAR contents."""
        packages = set()
        try:
            with open(self.file_path, "rb") as f:
                f.seek(self._header["data_offset"])
                data = f.read()

                if self._header.get("compressed"):
                    data = deflate_decompress(data)

                tar_stream = io.BytesIO(data)
                with tarfile.open(fileobj=tar_stream, mode="r:") as tar:
                    for member in tar.getmembers():
                        parts = member.name.split("/")
                        if len(parts) >= 2 and parts[0] == "apps":
                            packages.add(parts[1])
        except Exception:
            pass
        return sorted(packages)

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt and extract the .ab backup.

        Args:
            output_path: Directory to extract to.
            password: Decryption password (required if encrypted).

        Returns:
            DecryptResult with extraction status.
        """
        password = kwargs.get("password")
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        if not self._header or not self._header.get("magic"):
            result.add_error("Invalid or unreadable .ab file header")
            return result

        encryption = self._header["encryption"]

        if encryption == "none":
            return self._decrypt_unencrypted(output_path, result)
        elif encryption == "AES-256":
            if not password:
                result.add_error(
                    "This backup is AES-256 encrypted. "
                    "Please provide a password with --password"
                )
                return result
            return self._decrypt_encrypted(output_path, password, result)
        else:
            result.add_error(f"Unknown encryption type: {encryption}")
            return result

    def _decrypt_unencrypted(
        self, output_path: Path, result: DecryptResult
    ) -> DecryptResult:
        """Handle unencrypted .ab file: decompress and extract TAR."""
        print_status("📦", "Unencrypted backup detected — decompressing...")

        try:
            with open(self.file_path, "rb") as f:
                f.seek(self._header["data_offset"])
                raw_data = f.read()

            if self._header["compressed"]:
                print_status("🗜️", "Decompressing DEFLATE stream...")
                data = deflate_decompress(raw_data)
            else:
                data = raw_data

            # Extract TAR archive
            files_count, total_size = self._extract_tar(data, output_path)

            result.success = True
            result.files_extracted = files_count
            result.total_size = total_size
            print_status(
                "✅",
                f"Extracted {files_count} files ({format_size(total_size)})",
            )

        except zlib.error as e:
            result.add_error(f"Decompression failed: {e}")
        except tarfile.TarError as e:
            result.add_error(f"TAR extraction failed: {e}")
        except Exception as e:
            result.add_error(f"Unexpected error: {e}")

        return result

    def _decrypt_encrypted(
        self, output_path: Path, password: str, result: DecryptResult
    ) -> DecryptResult:
        """Handle AES-256 encrypted .ab file."""
        print_status("🔐", "AES-256 encrypted backup — decrypting...")

        try:
            # Parse crypto parameters from header
            user_salt = read_hex_line(self._header["user_salt"])
            checksum_salt = read_hex_line(self._header["checksum_salt"])
            rounds = self._header["pbkdf2_rounds"]
            user_iv = read_hex_line(self._header["user_iv"])
            master_key_blob_enc = read_hex_line(self._header["master_key_blob"])

            print_status("🔑", f"PBKDF2 rounds: {rounds}", Colors.DIM)

            # Step 1: Derive user key from password
            password_bytes = java_utf8_encode(password)
            user_key = derive_key_pbkdf2(
                password_bytes, user_salt, rounds, key_length=32, hash_algo="sha1"
            )

            # Step 2: Decrypt master key blob
            master_key_blob = aes_decrypt_cbc(user_key, user_iv, master_key_blob_enc)

            # Step 3: Parse master key blob
            # Format: [IV_len(1B)][IV][key_len(1B)][key][checksum_len(1B)][checksum]
            offset = 0
            iv_len = master_key_blob[offset]
            offset += 1
            master_iv = master_key_blob[offset : offset + iv_len]
            offset += iv_len

            master_key_len = master_key_blob[offset]
            offset += 1
            master_key = master_key_blob[offset : offset + master_key_len]
            offset += master_key_len

            checksum_len = master_key_blob[offset]
            offset += 1
            stored_checksum = master_key_blob[offset : offset + checksum_len]

            # Step 4: Verify master key checksum
            # The checksum is PBKDF2(master_key, checksum_salt, rounds)
            # For version >= 2, the checksum includes a hex representation
            if self._header["version"] >= 2:
                # Version 2+ uses hex(master_key) as password for checksum PBKDF2
                hmk = master_key.hex().encode("utf-8")
            else:
                hmk = master_key

            calculated_checksum = derive_key_pbkdf2(
                hmk, checksum_salt, rounds, key_length=32, hash_algo="sha1"
            )

            if calculated_checksum != stored_checksum[:32]:
                result.add_error(
                    "Password verification failed — wrong password or corrupted file"
                )
                return result

            print_status("✓", "Password verified successfully", Colors.GREEN)

            # Step 5: Decrypt the actual backup data
            with open(self.file_path, "rb") as f:
                f.seek(self._header["data_offset"])
                encrypted_data = f.read()

            cipher = AES.new(master_key, AES.MODE_CBC, master_iv)
            decrypted_data = cipher.decrypt(encrypted_data)

            # Remove PKCS5/7 padding
            pad_len = decrypted_data[-1]
            if 1 <= pad_len <= 16:
                decrypted_data = decrypted_data[:-pad_len]

            # Step 6: Decompress if needed
            if self._header["compressed"]:
                print_status("🗜️", "Decompressing DEFLATE stream...")
                data = deflate_decompress(decrypted_data)
            else:
                data = decrypted_data

            # Step 7: Extract TAR
            files_count, total_size = self._extract_tar(data, output_path)

            result.success = True
            result.files_extracted = files_count
            result.total_size = total_size
            print_status(
                "✅",
                f"Extracted {files_count} files ({format_size(total_size)})",
            )

        except ValueError as e:
            result.add_error(f"Decryption error: {e}")
        except zlib.error as e:
            result.add_error(f"Decompression failed after decryption: {e}")
        except tarfile.TarError as e:
            result.add_error(f"TAR extraction failed: {e}")
        except Exception as e:
            result.add_error(f"Unexpected error during decryption: {e}")

        return result

    def try_password(self, password: str) -> bool:
        """
        Test a password without full decryption.

        Derives the key and verifies the master key checksum only.
        """
        if self._header["encryption"] != "AES-256":
            return False

        try:
            user_salt = read_hex_line(self._header["user_salt"])
            checksum_salt = read_hex_line(self._header["checksum_salt"])
            rounds = self._header["pbkdf2_rounds"]
            user_iv = read_hex_line(self._header["user_iv"])
            master_key_blob_enc = read_hex_line(self._header["master_key_blob"])

            password_bytes = java_utf8_encode(password)
            user_key = derive_key_pbkdf2(
                password_bytes, user_salt, rounds, key_length=32, hash_algo="sha1"
            )

            master_key_blob = aes_decrypt_cbc(user_key, user_iv, master_key_blob_enc)

            # Parse blob
            offset = 0
            iv_len = master_key_blob[offset]
            offset += 1 + iv_len
            master_key_len = master_key_blob[offset]
            offset += 1
            master_key = master_key_blob[offset : offset + master_key_len]
            offset += master_key_len
            checksum_len = master_key_blob[offset]
            offset += 1
            stored_checksum = master_key_blob[offset : offset + checksum_len]

            if self._header["version"] >= 2:
                hmk = master_key.hex().encode("utf-8")
            else:
                hmk = master_key

            calculated = derive_key_pbkdf2(
                hmk, checksum_salt, rounds, key_length=32, hash_algo="sha1"
            )

            return calculated == stored_checksum[:32]

        except Exception:
            return False

    def _extract_tar(self, data: bytes, output_path: Path) -> tuple:
        """
        Extract a TAR archive from bytes to the output directory.

        Returns (files_count, total_size).
        """
        files_count = 0
        total_size = 0

        tar_stream = io.BytesIO(data)
        try:
            with tarfile.open(fileobj=tar_stream, mode="r:") as tar:
                for member in tar.getmembers():
                    # Security: prevent path traversal in TAR
                    member_path = safe_path_join(output_path, member.name)

                    if member.isdir():
                        ensure_dir(member_path)
                    elif member.isfile():
                        ensure_dir(member_path.parent)
                        with open(member_path, "wb") as out_file:
                            file_data = tar.extractfile(member)
                            if file_data:
                                content = file_data.read()
                                out_file.write(content)
                                total_size += len(content)
                                files_count += 1
                    elif member.issym() or member.islnk():
                        # Skip symlinks for security
                        pass
        except tarfile.TarError:
            # If standard TAR parsing fails, the data may already be raw
            # Write it as-is for manual inspection
            raw_path = output_path / "raw_backup_data.bin"
            with open(raw_path, "wb") as f:
                f.write(data)
            files_count = 1
            total_size = len(data)

        return files_count, total_size
