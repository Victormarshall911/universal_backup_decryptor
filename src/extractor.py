"""
Post-decryption data organizer.

Takes the raw extracted output from any handler and reorganizes files
into a clean, human-readable folder structure:

    organized/
    ├── apps/
    │   └── com.example.app/
    │       ├── db/         → databases
    │       ├── sp/         → shared_prefs
    │       └── f/          → other files
    ├── media/              → photos, videos, audio
    ├── contacts/           → contact exports
    ├── sms/                → SMS/MMS exports
    ├── other/              → everything else
    └── metadata.json       → extraction report
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Set

try:
    import filetype as _filetype
except ImportError:
    _filetype = None

from .utils import ensure_dir, format_size, print_status, print_warning


class DataOrganizer:
    """
    Reorganizes raw extracted backup data into categorized folders.

    Processes the extracted files in a single pass, categorizing each file
    by its path patterns and content type.
    """

    # Package name patterns (Java/Android conventions)
    _PACKAGE_PREFIXES = (
        "com.", "org.", "net.", "io.", "me.", "de.", "fr.",
        "uk.", "jp.", "cn.", "ru.", "in.", "br.", "au.",
    )

    # Path keywords → category mapping
    _CATEGORY_KEYWORDS = {
        "contact": "contacts",
        "sms": "sms",
        "mms": "sms",
        "message": "sms",
        "telephony": "sms",
        "calllog": "sms",
    }

    # Sub-category detection for app data
    _APP_SUBCATEGORIES = {
        "database": "db",
        "databases": "db",
        ".db": "db",
        ".sqlite": "db",
        "shared_pref": "sp",
        "shared_prefs": "sp",
        ".xml": "sp",
        "files": "f",
        "cache": "f",
        "lib": "f",
    }

    def __init__(self, input_dir: str, output_dir: str):
        """
        Args:
            input_dir: Path to raw extracted backup data.
            output_dir: Path to write organized output.
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self._seen_packages: Set[str] = set()
        self.metadata: Dict[str, Any] = {
            "extracted_at": datetime.now().isoformat(),
            "source_dir": str(self.input_dir),
            "files_count": 0,
            "total_size_bytes": 0,
            "apps": [],
            "categories": {
                "media": 0,
                "contacts": 0,
                "sms": 0,
                "other": 0,
            },
        }

    def organize(self) -> Dict[str, Any]:
        """
        Run the organization process.

        Returns:
            Metadata dictionary with extraction statistics.

        Raises:
            FileNotFoundError: If input directory doesn't exist.
        """
        if not self.input_dir.exists():
            raise FileNotFoundError(
                f"Input directory not found: {self.input_dir}"
            )

        # Create output subdirectories
        for sub in ["apps", "media", "contacts", "sms", "other"]:
            ensure_dir(self.output_dir / sub)

        # Process all files
        for file_path in sorted(self.input_dir.rglob("*")):
            if file_path.is_file():
                # Skip if the file is inside our output dir (avoid loops)
                try:
                    file_path.relative_to(self.output_dir)
                    continue
                except ValueError:
                    pass

                self._process_file(file_path)

        # Deduplicate and sort app list
        self.metadata["apps"] = sorted(self._seen_packages)
        self.metadata["app_count"] = len(self._seen_packages)
        self.metadata["total_size_human"] = format_size(
            self.metadata["total_size_bytes"]
        )

        # Write metadata report
        self._write_metadata()

        return self.metadata

    def _process_file(self, file_path: Path) -> None:
        """Categorize and copy a single file."""
        rel_path = file_path.relative_to(self.input_dir)
        parts = rel_path.parts
        size = file_path.stat().st_size

        self.metadata["files_count"] += 1
        self.metadata["total_size_bytes"] += size

        # Detect content type via filetype library (if available)
        content_category = self._detect_content_type(file_path)

        # Try to identify the package name from the path
        package = self._extract_package_name(parts)

        # Determine where to put this file
        if package:
            self._file_to_app(file_path, package, parts)
        elif content_category == "media":
            self._file_to_category(file_path, "media")
        elif self._matches_category(parts):
            category = self._matches_category(parts)
            self._file_to_category(file_path, category)
        else:
            self._file_to_other(file_path, rel_path)

    def _extract_package_name(self, parts: tuple) -> str:
        """Try to extract an Android package name from path parts."""
        for part in parts:
            for prefix in self._PACKAGE_PREFIXES:
                if part.startswith(prefix) and "." in part[len(prefix):]:
                    return part
        return ""

    def _matches_category(self, parts: tuple) -> str:
        """Check if path parts match a known category keyword."""
        path_str = "/".join(parts).lower()
        for keyword, category in self._CATEGORY_KEYWORDS.items():
            if keyword in path_str:
                return category
        return ""

    def _detect_content_type(self, file_path: Path) -> str:
        """Detect if a file is media using the filetype library."""
        if _filetype is None:
            return ""

        try:
            kind = _filetype.guess(str(file_path))
            if kind:
                mime_type = kind.mime.split("/")[0]
                if mime_type in ("image", "video", "audio"):
                    return "media"
        except Exception:
            pass

        return ""

    def _file_to_app(self, src: Path, package: str, parts: tuple) -> None:
        """Copy a file to the apps/ directory, organized by package."""
        self._seen_packages.add(package)

        # Determine sub-category (db, sp, f)
        sub = "f"  # default
        path_str = "/".join(parts).lower()
        for keyword, cat in self._APP_SUBCATEGORIES.items():
            if keyword in path_str:
                sub = cat
                break

        dest_dir = self.output_dir / "apps" / package / sub
        ensure_dir(dest_dir)
        dest = dest_dir / src.name

        # Handle duplicate filenames
        dest = self._unique_path(dest)
        shutil.copy2(src, dest)

    def _file_to_category(self, src: Path, category: str) -> None:
        """Copy a file to a category directory (media, contacts, sms)."""
        self.metadata["categories"][category] += 1
        dest_dir = self.output_dir / category
        ensure_dir(dest_dir)
        dest = dest_dir / src.name
        dest = self._unique_path(dest)
        shutil.copy2(src, dest)

    def _file_to_other(self, src: Path, rel_path: Path) -> None:
        """Copy uncategorized files preserving their original structure."""
        self.metadata["categories"]["other"] += 1
        dest = self.output_dir / "other" / rel_path
        ensure_dir(dest.parent)
        dest = self._unique_path(dest)
        shutil.copy2(src, dest)

    @staticmethod
    def _unique_path(path: Path) -> Path:
        """Generate a unique path if the target already exists."""
        if not path.exists():
            return path

        stem = path.stem
        suffix = path.suffix
        parent = path.parent
        counter = 1
        while path.exists():
            path = parent / f"{stem}_{counter}{suffix}"
            counter += 1
        return path

    def _write_metadata(self) -> None:
        """Write the extraction metadata to metadata.json."""
        metadata_path = self.output_dir / "metadata.json"
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2, ensure_ascii=False)
