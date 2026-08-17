"""
MIUI Secret Album .lsa (photos) and .lsav (videos) decryptor.

Xiaomi's MIUI Gallery app encrypts Secret Album files using AES-128-ECB
with a key derived from the app's signing certificate. The default key
is well-known and works for stock MIUI installations.

Format:
    - .lsa files contain encrypted JPEG images
    - .lsav files contain encrypted MP4 videos
    - Encryption: AES-128-ECB (no IV needed)
    - Key: first 16 bytes of the hex-encoded Gallery APK certificate

Detection:
    - File extension .lsa or .lsav
    - No reliable magic bytes (encrypted data looks random)

References:
    - SpongeBombz/MIUI-Cloud-Decryptor (Python)
"""

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

# Default key from Xiaomi Gallery app signing certificate
# This is the hex representation of the first 16 bytes of the cert
DEFAULT_MIUI_KEY = bytes.fromhex("6A0978B1E485151FAE4138EE2C2524C7")


class MIUILSAHandler(BackupHandler):
    """Handler for MIUI Secret Album .lsa/.lsav encrypted files."""

    FORMAT_NAME = "MIUI Secret Album (.lsa/.lsav)"
    FORMAT_TYPE = FormatType.MIUI_LSA

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect MIUI LSA/LSAV by file extension.

        There are no reliable magic bytes — encrypted data is indistinguishable
        from random. We rely purely on the file extension.
        """
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext in [".lsa", ".lsav"]:
            file_type = "photo" if ext == ".lsa" else "video"
            return FormatInfo(
                format_type=FormatType.MIUI_LSA,
                format_name=f"MIUI Secret Album ({file_type})",
                confidence=0.90,
                encrypted=True,
                metadata={
                    "type": file_type,
                    "extension": ext,
                },
            )

        # Also detect directories containing .lsa/.lsav files
        if path.is_dir():
            lsa_files = list(path.glob("*.lsa")) + list(path.glob("*.lsav"))
            if lsa_files:
                return FormatInfo(
                    format_type=FormatType.MIUI_LSA,
                    format_name="MIUI Secret Album (directory)",
                    confidence=0.85,
                    encrypted=True,
                    metadata={
                        "file_count": len(lsa_files),
                    },
                )

        return None

    def get_info(self) -> Dict[str, Any]:
        """Extract metadata from MIUI LSA/LSAV file."""
        path = self.file_path
        info = {
            "format": self.FORMAT_NAME,
            "encrypted": True,
            "encryption": "AES-128-ECB",
            "default_key_available": True,
        }

        if path.is_file():
            info["file_size"] = path.stat().st_size
            info["file_size_human"] = format_size(path.stat().st_size)
            info["type"] = "photo" if path.suffix.lower() == ".lsa" else "video"
        elif path.is_dir():
            lsa_files = list(path.glob("*.lsa")) + list(path.glob("*.lsav"))
            info["file_count"] = len(lsa_files)
            total = sum(f.stat().st_size for f in lsa_files)
            info["total_size"] = format_size(total)

        return info

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt MIUI .lsa/.lsav files using AES-128-ECB.

        Args:
            output_path: Directory to write decrypted files to.
            key: Optional hex string for a custom decryption key.
                 Defaults to the stock Gallery app certificate key.
        """
        output_path = Path(output_path)
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        # Determine encryption key
        key_hex = kwargs.get("key")
        if key_hex:
            try:
                key = bytes.fromhex(key_hex)
                if len(key) != 16:
                    result.add_error(
                        f"Key must be 16 bytes (32 hex chars), got {len(key)} bytes"
                    )
                    return result
                print_status("🔑", "Using custom decryption key")
            except ValueError:
                result.add_error("Invalid hex key format")
                return result
        else:
            key = DEFAULT_MIUI_KEY
            print_status("🔑", "Using default MIUI Gallery certificate key")

        path = self.file_path

        if path.is_file():
            # Single file decryption
            try:
                out_file = self._decrypt_single(path, output_path, key)
                result.files_extracted = 1
                result.total_size = out_file.stat().st_size
                result.success = True
                print_status("✅", f"Decrypted → {out_file.name}")
            except Exception as e:
                result.add_error(f"Decryption failed: {e}")

        elif path.is_dir():
            # Batch decryption
            lsa_files = sorted(
                list(path.glob("*.lsa")) + list(path.glob("*.lsav"))
            )
            print_status("📦", f"Found {len(lsa_files)} encrypted files")

            for lsa_file in lsa_files:
                try:
                    out_file = self._decrypt_single(lsa_file, output_path, key)
                    result.files_extracted += 1
                    result.total_size += out_file.stat().st_size
                except Exception as e:
                    result.add_warning(f"Failed: {lsa_file.name}: {e}")

            result.success = result.files_extracted > 0
            if result.success:
                print_status(
                    "✅",
                    f"Decrypted {result.files_extracted}/{len(lsa_files)} files "
                    f"({format_size(result.total_size)})",
                )

        return result

    def _decrypt_single(self, input_file: Path, output_dir: Path, key: bytes) -> Path:
        """
        Decrypt a single .lsa/.lsav file using AES-128-ECB.

        Returns the path to the decrypted output file.
        """
        # AES-128-ECB — MIUI's choice (weak but that's what they use)
        cipher = AES.new(key, AES.MODE_ECB)

        with open(input_file, "rb") as f:
            encrypted_data = f.read()

        if len(encrypted_data) == 0:
            raise ValueError("Empty file")

        # Decrypt in 16-byte blocks
        # Pad the last block if necessary (shouldn't happen with real files)
        remainder = len(encrypted_data) % 16
        if remainder != 0:
            encrypted_data += b"\x00" * (16 - remainder)

        decrypted = cipher.decrypt(encrypted_data)

        # Remove PKCS7 padding if present
        pad_len = decrypted[-1]
        if 1 <= pad_len <= 16 and all(b == pad_len for b in decrypted[-pad_len:]):
            decrypted = decrypted[:-pad_len]

        # Determine output extension based on content
        ext = self._detect_extension(decrypted, input_file)
        out_file = output_dir / f"{input_file.stem}{ext}"

        with open(out_file, "wb") as f:
            f.write(decrypted)

        return out_file

    @staticmethod
    def _detect_extension(data: bytes, original_path: Path) -> str:
        """Detect the file type from decrypted content."""
        # Check magic bytes
        if data[:3] == b"\xff\xd8\xff":
            return ".jpg"
        if data[:4] == b"\x89PNG":
            return ".png"
        if data[:4] == b"\x00\x00\x00\x18" or data[:4] == b"\x00\x00\x00\x1c":
            return ".mp4"
        if data[4:8] == b"ftyp":
            return ".mp4"
        if data[:4] == b"RIFF":
            return ".webp"
        if data[:3] == b"GIF":
            return ".gif"

        # Fall back to original extension mapping
        orig_ext = original_path.suffix.lower()
        if orig_ext == ".lsa":
            return ".jpg"
        elif orig_ext == ".lsav":
            return ".mp4"
        return ".bin"
