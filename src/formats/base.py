"""
Abstract base class and data structures for all backup format handlers.

Every format handler (Android AB, MIUI, Huawei, etc.) inherits from
BackupHandler and implements detection, info extraction, and decryption.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class FormatType(Enum):
    """Supported backup format types."""
    ANDROID_AB = auto()
    MIUI_LSA = auto()
    MIUI_BAK = auto()
    HUAWEI_KOBACKUP = auto()
    SEEDVAULT = auto()
    WHATSAPP_CRYPT = auto()
    TWRP = auto()
    UNKNOWN = auto()


@dataclass
class FormatInfo:
    """Result of format detection."""
    format_type: FormatType
    format_name: str
    confidence: float  # 0.0 to 1.0
    encrypted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.9:
            return "HIGH"
        elif self.confidence >= 0.6:
            return "MEDIUM"
        elif self.confidence >= 0.3:
            return "LOW"
        return "UNCERTAIN"


@dataclass
class DecryptResult:
    """Result of a decryption operation."""
    success: bool
    output_path: Optional[Path] = None
    files_extracted: int = 0
    total_size: int = 0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_error(self, msg: str):
        self.errors.append(msg)

    def add_warning(self, msg: str):
        self.warnings.append(msg)


class BackupHandler(ABC):
    """
    Abstract base class for all backup format handlers.

    Each handler must implement three core methods:
    - detect(): Identify if a file/path matches this format
    - get_info(): Extract metadata without decrypting
    - decrypt(): Full decryption and extraction pipeline
    """

    # Human-readable format name (override in subclasses)
    FORMAT_NAME: str = "Unknown"
    FORMAT_TYPE: FormatType = FormatType.UNKNOWN

    def __init__(self, file_path: Union[str, Path]):
        """
        Initialize handler with the backup file/directory path.

        Args:
            file_path: Path to the backup file or directory.
        """
        self.file_path = Path(file_path)

    @classmethod
    @abstractmethod
    def detect(cls, file_path: Path, header_bytes: bytes) -> Optional[FormatInfo]:
        """
        Detect if a file matches this format.

        Args:
            file_path: Path to the backup file.
            header_bytes: First 512 bytes of the file.

        Returns:
            FormatInfo if detected, None if not this format.
        """
        pass

    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """
        Extract metadata from the backup without decrypting.

        Returns:
            Dictionary of metadata key-value pairs.
        """
        pass

    @abstractmethod
    def decrypt(self, output_path: Path, **kwargs) -> DecryptResult:
        """
        Decrypt and extract the backup to the output directory.

        Args:
            output_path: Directory to extract contents to.
            **kwargs: Format-specific options (password, key_file, mnemonic, etc.)

        Returns:
            DecryptResult with status, file counts, and any errors.
        """
        pass

    def try_password(self, password: str) -> bool:
        """
        Test if a password is correct without full decryption.

        Used by the password recovery module. Default implementation
        returns False; override in handlers that support password testing.

        Args:
            password: Password to test.

        Returns:
            True if the password is correct.
        """
        return False
