"""
MIUI local backup .bak handler.

Xiaomi's local backup tool creates .bak files that prepend a proprietary
header to what is otherwise a standard Android .ab backup. This handler:
1. Detects the MIUI header (not "ANDROID BACKUP")
2. Determines the header length
3. Strips the header to reveal the inner .ab content
4. Delegates to AndroidABHandler for actual decryption

The backup directory may also contain description.xml with device metadata.

Detection:
    - .bak extension + does NOT start with "ANDROID BACKUP"
    - May also detect by the MIUI backup directory structure

References:
    - MIUI backup stored in /MIUI/backup/AllBackup/<date>/
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .base import BackupHandler, DecryptResult, FormatInfo, FormatType
from .android_ab import AndroidABHandler
from ..utils import (
    ensure_dir,
    format_size,
    print_status,
    print_warning,
    Colors,
)


class MIUIBakHandler(BackupHandler):
    """Handler for MIUI local backup .bak files."""

    FORMAT_NAME = "MIUI Local Backup (.bak)"
    FORMAT_TYPE = FormatType.MIUI_BAK

    def __init__(self, file_path: Union[str, Path]):
        super().__init__(file_path)
        self._device_metadata = {}
        self._parse_description_xml()

    def _parse_description_xml(self):
        """Parse description.xml in the same directory for device metadata."""
        desc_path = self.file_path.parent / "description.xml"
        if desc_path.exists():
            try:
                tree = ET.parse(desc_path)
                root = tree.getroot()
                # Extract common MIUI metadata fields
                for attr in ["device", "miuiVersion", "androidVersion",
                             "backupDate", "packageName", "buildVersion"]:
                    val = root.get(attr) or root.findtext(attr)
                    if val:
                        self._device_metadata[attr] = val
            except (ET.ParseError, OSError):
                pass

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect MIUI .bak files.

        MIUI .bak files have a proprietary header that is NOT "ANDROID BACKUP".
        If the file starts with "ANDROID BACKUP", it's a standard .ab file,
        not a MIUI wrapper.
        """
        path = Path(file_path)

        if path.suffix.lower() != ".bak":
            return None

        # If it starts with "ANDROID BACKUP", let the AB handler claim it
        if header_bytes.startswith(b"ANDROID BACKUP"):
            return None

        # Check if the file is large enough to contain a header + AB content
        if len(header_bytes) < 16:
            return None

        # Look for "ANDROID BACKUP" signature deeper in the file
        # MIUI prepends a variable-length header
        ab_offset = header_bytes.find(b"ANDROID BACKUP")
        metadata = {"ab_found_in_header": ab_offset >= 0}

        if ab_offset >= 0:
            metadata["header_size"] = ab_offset
            confidence = 0.90
        else:
            # The AB signature might be beyond our 512-byte header read
            # Still consider it MIUI .bak by extension
            confidence = 0.60

        return FormatInfo(
            format_type=FormatType.MIUI_BAK,
            format_name="MIUI Local Backup (.bak)",
            confidence=confidence,
            encrypted=False,  # Encryption is in the inner AB layer
            metadata=metadata,
        )

    def get_info(self) -> Dict[str, Any]:
        """Extract metadata from MIUI .bak file and description.xml."""
        info = {
            "format": self.FORMAT_NAME,
            "file_size": self.file_path.stat().st_size,
            "file_size_human": format_size(self.file_path.stat().st_size),
        }

        # Add device metadata from description.xml
        if self._device_metadata:
            info["device_metadata"] = self._device_metadata

        # Try to find the inner AB header
        ab_offset = self._find_ab_offset()
        if ab_offset is not None:
            info["miui_header_size"] = ab_offset
            info["inner_format"] = "Android AB"

            # Parse the inner AB header for additional info
            try:
                with open(self.file_path, "rb") as f:
                    f.seek(ab_offset)
                    ab_header = f.read(512)

                lines = ab_header.split(b"\n", 5)
                if len(lines) >= 4:
                    info["ab_version"] = int(lines[1])
                    info["ab_compressed"] = int(lines[2]) == 1
                    info["ab_encryption"] = lines[3].decode("utf-8", errors="replace").strip()
                    info["encrypted"] = info["ab_encryption"] == "AES-256"
            except (ValueError, IndexError):
                pass
        else:
            info["inner_format"] = "unknown"

        return info

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt MIUI .bak by stripping the header and delegating to AndroidABHandler.

        The MIUI header is variable-length. We scan for the "ANDROID BACKUP"
        magic to find where the standard AB content begins.
        """
        output_path = Path(output_path)
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        print_status("📱", "MIUI local backup detected — stripping proprietary header...")

        # Find the inner AB offset
        ab_offset = self._find_ab_offset()
        if ab_offset is None:
            result.add_error(
                "Could not find 'ANDROID BACKUP' signature inside the .bak file. "
                "The file may be corrupted or use an unsupported MIUI version."
            )
            return result

        print_status("🔍", f"Found AB content at offset {ab_offset}", Colors.DIM)

        # Extract the inner AB content to a temp file
        temp_ab_path = self.file_path.parent / f".{self.file_path.stem}_inner.ab"

        try:
            with open(self.file_path, "rb") as src:
                src.seek(ab_offset)
                with open(temp_ab_path, "wb") as dst:
                    # Stream copy for efficiency
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        dst.write(chunk)

            print_status("📦", "Delegating to Android AB handler...")

            # Delegate to AndroidABHandler
            ab_handler = AndroidABHandler(temp_ab_path)
            result = ab_handler.decrypt(output_path, **kwargs)

            # Enrich result with MIUI metadata
            if self._device_metadata:
                for key, val in self._device_metadata.items():
                    print_status("📋", f"{key}: {val}", Colors.DIM)

        except Exception as e:
            result.add_error(f"MIUI .bak processing failed: {e}")

        finally:
            # Clean up temp file
            if temp_ab_path.exists():
                temp_ab_path.unlink()

        return result

    def _find_ab_offset(self) -> Optional[int]:
        """
        Scan the file for the "ANDROID BACKUP" magic bytes.

        Returns the byte offset, or None if not found.
        Scans up to the first 1MB of the file.
        """
        magic = b"ANDROID BACKUP"
        scan_size = 1024 * 1024  # 1 MB

        try:
            with open(self.file_path, "rb") as f:
                data = f.read(scan_size)
            offset = data.find(magic)
            return offset if offset >= 0 else None
        except OSError:
            return None

    def try_password(self, password: str) -> bool:
        """
        Test a password by extracting the inner AB and testing it.
        """
        ab_offset = self._find_ab_offset()
        if ab_offset is None:
            return False

        temp_ab_path = self.file_path.parent / f".{self.file_path.stem}_test.ab"
        try:
            with open(self.file_path, "rb") as src:
                src.seek(ab_offset)
                with open(temp_ab_path, "wb") as dst:
                    dst.write(src.read(65536))  # Only need the header

            ab_handler = AndroidABHandler(temp_ab_path)
            return ab_handler.try_password(password)
        except Exception:
            return False
        finally:
            if temp_ab_path.exists():
                temp_ab_path.unlink()
