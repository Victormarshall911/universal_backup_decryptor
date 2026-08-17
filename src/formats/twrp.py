"""
TWRP / Nandroid backup handler.

Supports .win / .win000 file-level backups (tarballs) and .emmc.win
partition images. Verifies .md5 checksums when present and handles
multi-part split archives.

TWRP backups are stored in:
    /TWRP/BACKUPS/<device-serial>/<backup-name>/

Each partition produces files like:
    system.ext4.win, data.ext4.win000, data.ext4.win001, ...
    boot.emmc.win (partition image, not a tar)

Detection:
    - Directory containing .win files → confidence 0.9
    - Single .win/.win000 file → confidence 0.85
    - .emmc.win → partition image (no extraction, just copy)
"""

import hashlib
import io
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .base import BackupHandler, DecryptResult, FormatInfo, FormatType
from ..utils import (
    ensure_dir,
    format_size,
    print_status,
    print_warning,
    safe_path_join,
    Colors,
)


class TWRPHandler(BackupHandler):
    """Handler for TWRP/Nandroid backup files (.win, .win000)."""

    FORMAT_NAME = "TWRP / Nandroid Backup"
    FORMAT_TYPE = FormatType.TWRP

    @classmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect TWRP backup by directory structure or .win extension.

        TWRP backups are directories containing .win files, or individual
        .win files that are standard tar archives.
        """
        path = Path(file_path)

        # Case 1: Directory containing .win files
        if path.is_dir():
            win_files = list(path.glob("*.win")) + list(path.glob("*.win000"))
            if win_files:
                # Check for recovery.log or the TWRP path pattern
                has_recovery_log = (path / "recovery.log").exists()
                return FormatInfo(
                    format_type=FormatType.TWRP,
                    format_name="TWRP / Nandroid Backup",
                    confidence=0.95 if has_recovery_log else 0.9,
                    encrypted=False,
                    metadata={
                        "win_files": len(win_files),
                        "has_recovery_log": has_recovery_log,
                    },
                )

        # Case 2: Single .win file
        if path.is_file():
            suffixes = path.suffixes  # e.g. ['.ext4', '.win'] or ['.ext4', '.win000']
            name_lower = path.name.lower()

            if ".win" in name_lower:
                is_image = ".emmc." in name_lower
                # Try to verify it's a tar by checking for tar magic
                is_tar = False
                if header_bytes and len(header_bytes) >= 265:
                    # TAR magic at offset 257: "ustar"
                    is_tar = header_bytes[257:262] == b"ustar"

                return FormatInfo(
                    format_type=FormatType.TWRP,
                    format_name="TWRP Partition Image" if is_image else "TWRP Backup",
                    confidence=0.85,
                    encrypted=False,
                    metadata={
                        "type": "image" if is_image else "tar",
                        "is_tar": is_tar,
                        "file": path.name,
                    },
                )

        return None

    def get_info(self) -> Dict[str, Any]:
        """Extract metadata from TWRP backup without extracting."""
        info = {
            "format": self.FORMAT_NAME,
        }

        path = self.file_path

        if path.is_dir():
            win_files = sorted(
                list(path.glob("*.win")) + list(path.glob("*.win*"))
            )
            # Deduplicate
            win_files = sorted(set(win_files))
            info["partitions"] = []
            total_size = 0

            for wf in win_files:
                size = wf.stat().st_size
                total_size += size
                info["partitions"].append({
                    "name": wf.name,
                    "size": format_size(size),
                    "type": "image" if ".emmc." in wf.name else "tar",
                })

            info["total_size"] = format_size(total_size)
            info["partition_count"] = len(info["partitions"])

            # Check for recovery.log
            recovery_log = path / "recovery.log"
            if recovery_log.exists():
                info["has_recovery_log"] = True

        elif path.is_file():
            info["file_size"] = format_size(path.stat().st_size)
            info["type"] = "image" if ".emmc." in path.name else "tar"

            # For tar files, try listing contents
            if info["type"] == "tar":
                try:
                    with tarfile.open(path, "r:*") as tar:
                        members = tar.getmembers()
                        info["entries"] = len(members)
                except tarfile.TarError:
                    info["entries"] = "unknown (not a valid tar)"

        return info

    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Extract TWRP backup files.

        TWRP backups are not encrypted by default. This method extracts
        tar-based .win files and copies partition images.
        """
        output_path = Path(output_path)
        result = DecryptResult(success=False, output_path=output_path)
        ensure_dir(output_path)

        path = self.file_path

        if path.is_dir():
            # Collect all .win files, handling multi-part splits
            win_files = sorted(set(
                list(path.glob("*.win")) + list(path.glob("*.win*"))
            ))
            if not win_files:
                result.add_error("No .win files found in directory")
                return result

            for wf in win_files:
                try:
                    count, size = self._extract_win(wf, output_path)
                    result.files_extracted += count
                    result.total_size += size
                except Exception as e:
                    result.add_warning(f"Failed to extract {wf.name}: {e}")

            result.success = result.files_extracted > 0

        elif path.is_file():
            try:
                count, size = self._extract_win(path, output_path)
                result.files_extracted = count
                result.total_size = size
                result.success = True
            except Exception as e:
                result.add_error(f"Extraction failed: {e}")

        if result.success:
            print_status(
                "✅",
                f"Extracted {result.files_extracted} files "
                f"({format_size(result.total_size)})",
            )

        return result

    def _extract_win(self, win_path: Path, out_dir: Path) -> tuple:
        """
        Extract a single .win file.

        Returns (files_count, total_size).
        """
        # Verify MD5 checksum if available
        self._verify_md5(win_path)

        # Check if this is a partition image (.emmc.win)
        if ".emmc." in win_path.name:
            print_status("💾", f"Partition image: {win_path.name} (copying as-is)")
            dest = out_dir / win_path.name
            import shutil
            shutil.copy2(win_path, dest)
            return 1, win_path.stat().st_size

        # Handle multi-part archives (.win000, .win001, ...)
        if win_path.suffix in [".win000"]:
            return self._extract_multipart(win_path, out_dir)

        # Skip non-first parts (they're handled by _extract_multipart)
        if win_path.suffix and win_path.suffix.startswith(".win") and win_path.suffix != ".win":
            suffix_num = win_path.suffix.replace(".win", "")
            if suffix_num.isdigit() and int(suffix_num) > 0:
                return 0, 0

        # Standard single-file tar extraction
        print_status("📦", f"Extracting {win_path.name}...")
        files_count = 0
        total_size = 0

        try:
            with tarfile.open(win_path, "r:*") as tar:
                for member in tar.getmembers():
                    member_path = safe_path_join(out_dir, member.name)

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
        except tarfile.TarError:
            # Not a valid tar — copy as raw binary
            print_warning(f"{win_path.name} is not a tar archive, copying as raw data")
            raw_dest = out_dir / f"{win_path.stem}_raw.bin"
            import shutil
            shutil.copy2(win_path, raw_dest)
            files_count = 1
            total_size = win_path.stat().st_size

        return files_count, total_size

    def _extract_multipart(self, first_part: Path, out_dir: Path) -> tuple:
        """
        Concatenate and extract multi-part .win000, .win001, ... archives.
        """
        # Find all parts
        stem = first_part.name.rsplit(".win", 1)[0]
        parent = first_part.parent
        parts = sorted(parent.glob(f"{stem}.win*"))

        print_status(
            "📦", f"Concatenating {len(parts)} parts of {stem}..."
        )

        # Concatenate all parts into a single stream
        combined = io.BytesIO()
        for part in parts:
            with open(part, "rb") as f:
                combined.write(f.read())

        combined.seek(0)

        files_count = 0
        total_size = 0

        try:
            with tarfile.open(fileobj=combined, mode="r:*") as tar:
                for member in tar.getmembers():
                    member_path = safe_path_join(out_dir, member.name)

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
        except tarfile.TarError as e:
            print_warning(f"Multipart extraction failed: {e}")
            # Dump concatenated data for manual inspection
            raw_dest = out_dir / f"{stem}_raw.bin"
            combined.seek(0)
            with open(raw_dest, "wb") as f:
                f.write(combined.read())
            files_count = 1
            total_size = combined.tell()

        return files_count, total_size

    def _verify_md5(self, win_path: Path) -> None:
        """Verify .md5 checksum if a corresponding file exists."""
        # TWRP creates .md5 files with format: "hash  filename"
        md5_candidates = [
            win_path.with_suffix(win_path.suffix + ".md5"),
            win_path.parent / (win_path.name + ".md5"),
        ]

        for md5_path in md5_candidates:
            if md5_path.exists():
                try:
                    with open(md5_path, "r") as f:
                        content = f.read().strip()
                    expected_hash = content.split()[0].lower()

                    # Calculate actual hash
                    md5 = hashlib.md5()
                    with open(win_path, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            md5.update(chunk)
                    actual_hash = md5.hexdigest().lower()

                    if actual_hash == expected_hash:
                        print_status("✓", f"MD5 verified: {win_path.name}", Colors.GREEN)
                    else:
                        print_warning(
                            f"MD5 MISMATCH for {win_path.name}: "
                            f"expected {expected_hash}, got {actual_hash}"
                        )
                except Exception:
                    pass
                return
