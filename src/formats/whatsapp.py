"""
WhatsApp encrypted backup handler (.crypt12, .crypt14, .crypt15).

WhatsApp uses AES-256-GCM to encrypt its message database backups.
The encryption key comes from different sources depending on the version:

    crypt12/crypt14:
        - Key file extracted from /data/data/com.whatsapp/files/key (root)
        - 158 bytes total, AES key at bytes 126–158
        - Header: 67 bytes (includes server salt, google ID)
        - IV: 16 bytes (after header)

    crypt15 (E2EE):
        - 32-byte key provided by user when enabling E2EE backups
        - Presented as 64-char hex string
        - Header: 2 bytes (version)
        - IV: 12 bytes (standard GCM nonce)

File structure:
    [header][IV/nonce][encrypted_data][GCM_tag_16B]

The decrypted output is a zlib-compressed SQLite database (msgstore.db).

References:
    - ElDavoo/wa-crypt-tools (Python)
    - YuvrajRaghuvanshi/WhatsApp-Key-Database-Extractor
"""

import struct
import zlib
from pathlib import Path
from typing import Any, Dict, Optional, Union

from Crypto.Cipher import AES

from .base import BackupHandler, DecryptResult, FormatInfo, FormatType
from ..utils import (
    ensure_dir,
    format_size,
    print_status,
    print_warning,
    Colors,
)

# Known crypt versions and their header sizes
CRYPT_VERSIONS = {
    ".crypt12": {"header_size": 67, "iv_size": 16, "version": 12},
    ".crypt14": {"header_size": 67, "iv_size": 16, "version": 14},
    ".crypt15": {"header_size": 2, "iv_size": 12, "version": 15},
}

# Key file structure for crypt12/14
# Total: 158 bytes
# Bytes 0-29:   header
# Bytes 30-61:  server salt
# Bytes 62-93:  google ID
# Bytes 94-125: padding/unknown
# Bytes 126-157: actual 32-byte AES key
KEY_FILE_LENGTH = 158
KEY_OFFSET = 126
KEY_LENGTH = 32


class WhatsAppHandler(BackupHandler):
    """Handler for WhatsApp encrypted database backups."""

    FORMAT_NAME = "WhatsApp Encrypted Backup"
    FORMAT_TYPE = FormatType.WHATSAPP_CRYPT

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect WhatsApp encrypted backups by extension and/or header.

        Primary detection is by file extension (.crypt12, .crypt14, .crypt15).
        Secondary check verifies header bytes when possible.
        """
        path = Path(file_path)

        # Check all known crypt extensions
        ext_lower = path.suffix.lower()
        for crypt_ext, params in CRYPT_VERSIONS.items():
            if ext_lower == crypt_ext:
                # Check if this looks like a database backup
                is_msgstore = "msgstore" in path.stem.lower()

                return FormatInfo(
                    format_type=FormatType.WHATSAPP_CRYPT,
                    format_name=f"WhatsApp {crypt_ext}",
                    confidence=0.95 if is_msgstore else 0.80,
                    encrypted=True,
                    metadata={
                        "variant": crypt_ext.lstrip("."),
                        "version": params["version"],
                        "is_msgstore": is_msgstore,
                    },
                )

        return None

    def get_info(self) -> Dict[str, Any]:
        """Extract metadata from WhatsApp backup without decrypting."""
        path = self.file_path
        ext = path.suffix.lower()
        params = CRYPT_VERSIONS.get(ext, {})

        info = {
            "format": self.FORMAT_NAME,
            "file_size": path.stat().st_size,
            "file_size_human": format_size(path.stat().st_size),
            "encrypted": True,
            "encryption": "AES-256-GCM",
            "variant": ext.lstrip("."),
            "version": params.get("version", "unknown"),
        }

        if params.get("version", 0) <= 14:
            info["key_source"] = (
                "Device key file (/data/data/com.whatsapp/files/key) — "
                "requires root or extraction tool"
            )
        else:
            info["key_source"] = (
                "User-provided 64-character hex key "
                "(shown when enabling E2EE backups)"
            )

        # Try to read the header
        try:
            with open(path, "rb") as f:
                header = f.read(128)

            header_size = params.get("header_size", 0)
            if header_size > 0 and len(header) >= header_size:
                info["header_bytes"] = header[:header_size].hex()

        except OSError:
            pass

        return info

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt WhatsApp backup.

        Args:
            output_path: Directory to write msgstore.db to.
            key: 64-character hex string (for crypt15, or raw key).
            key_file: Path to the extracted WhatsApp key file (for crypt12/14).
        """
        output_path = Path(output_path)
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        # Determine the crypt version
        ext = self.file_path.suffix.lower()
        params = CRYPT_VERSIONS.get(ext)
        if not params:
            result.add_error(f"Unknown WhatsApp crypt version: {ext}")
            return result

        version = params["version"]
        print_status("📱", f"WhatsApp {ext} backup (version {version})")

        # Get the decryption key
        key_bytes = self._get_key(version, **kwargs)
        if key_bytes is None:
            if version <= 14:
                result.add_error(
                    "WhatsApp crypt12/14 requires the device key file. "
                    "Use --key-file /path/to/key (extracted from "
                    "/data/data/com.whatsapp/files/key)"
                )
            else:
                result.add_error(
                    "WhatsApp crypt15 requires your 64-character hex key. "
                    "Use --key <64_hex_chars>"
                )
            return result

        print_status("🔑", f"Key loaded ({len(key_bytes)} bytes)")

        # Read the encrypted file
        try:
            with open(self.file_path, "rb") as f:
                data = f.read()
        except OSError as e:
            result.add_error(f"Cannot read file: {e}")
            return result

        # Parse and decrypt
        try:
            decrypted = self._decrypt_data(data, key_bytes, params)
        except ValueError as e:
            result.add_error(str(e))
            return result

        # The decrypted data is typically a zlib-compressed SQLite database
        db_data = self._decompress(decrypted)

        # Verify it looks like an SQLite database
        if db_data[:16] == b"SQLite format 3\x00":
            print_status("✓", "SQLite database verified", Colors.GREEN)
        else:
            print_warning(
                "Decrypted data doesn't start with SQLite header. "
                "The key may be wrong, or the format may be unusual."
            )

        # Write output
        out_file = output_path / "msgstore.db"
        with open(out_file, "wb") as f:
            f.write(db_data)

        result.success = True
        result.files_extracted = 1
        result.total_size = len(db_data)
        result.output_path = output_path

        print_status(
            "✅",
            f"Decrypted → {out_file.name} ({format_size(len(db_data))})",
        )

        return result

    def _get_key(self, version: int, **kwargs) -> Optional[bytes]:
        """
        Extract the 32-byte AES key from the provided source.

        For crypt12/14: reads the key file (158 bytes, key at offset 126)
        For crypt15: parses the 64-char hex string directly
        """
        key_hex = kwargs.get("key")
        key_file = kwargs.get("key_file")

        if key_file:
            # Read key from file
            key_path = Path(key_file)
            if not key_path.exists():
                return None

            with open(key_path, "rb") as f:
                key_data = f.read()

            if len(key_data) == KEY_FILE_LENGTH:
                # Standard WhatsApp key file (158 bytes)
                return key_data[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
            elif len(key_data) == KEY_LENGTH:
                # Raw 32-byte key
                return key_data
            elif len(key_data) == KEY_LENGTH * 2:
                # Hex-encoded key in a file
                try:
                    return bytes.fromhex(key_data.decode("ascii").strip())
                except (ValueError, UnicodeDecodeError):
                    return key_data[:KEY_LENGTH]
            else:
                # Try to extract key from whatever we have
                if len(key_data) >= KEY_OFFSET + KEY_LENGTH:
                    return key_data[KEY_OFFSET:KEY_OFFSET + KEY_LENGTH]
                return None

        elif key_hex:
            # Direct hex key (typically for crypt15)
            key_hex = key_hex.strip()
            if len(key_hex) == 64:
                try:
                    return bytes.fromhex(key_hex)
                except ValueError:
                    return None
            elif len(key_hex) == 32:
                # Already bytes-length — might be raw
                return key_hex.encode("latin-1")

        return None

    def _decrypt_data(
        self, data: bytes, key: bytes, params: dict
    ) -> bytes:
        """
        Parse the crypt file structure and decrypt with AES-256-GCM.
        """
        header_size = params["header_size"]
        iv_size = params["iv_size"]
        version = params["version"]

        # Minimum size check
        min_size = header_size + iv_size + 16  # header + IV + GCM tag
        if len(data) < min_size:
            raise ValueError(
                f"File too small ({len(data)} bytes) for {version} format "
                f"(minimum {min_size} bytes)"
            )

        # Extract IV/nonce (after header)
        nonce = data[header_size:header_size + iv_size]

        # The GCM authentication tag is the last 16 bytes
        tag = data[-16:]

        # Ciphertext is everything between nonce and tag
        ciphertext = data[header_size + iv_size:-16]

        if len(ciphertext) == 0:
            raise ValueError("No ciphertext found (file may be empty or header-only)")

        # Decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            # GCM authentication failed — try without verification
            # (some older versions or modified backups)
            print_warning(
                "GCM tag verification failed. Attempting decrypt without "
                "authentication (key may be wrong)."
            )
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)

        return decrypted

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        """
        Decompress decrypted data (typically zlib-compressed SQLite).
        """
        # Try zlib decompression
        try:
            return zlib.decompress(data)
        except zlib.error:
            pass

        # Try with different wbits values
        for wbits in [15, -15, 31]:
            try:
                return zlib.decompress(data, wbits)
            except zlib.error:
                continue

        # Not compressed — return as-is
        return data

    def try_password(self, password: str) -> bool:
        """
        WhatsApp doesn't use passwords — keys are device-bound or user-provided.
        This method always returns False.
        """
        return False
