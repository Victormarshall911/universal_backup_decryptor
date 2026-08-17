"""
Tests for the format auto-detection engine.

Uses synthetic file headers to verify that each handler correctly
identifies its format and rejects non-matching inputs.
"""

import pytest
from pathlib import Path

from src.detector import detect_format, detect_all
from src.formats.android_ab import AndroidABHandler
from src.formats.miui_lsa import MIUILSAHandler
from src.formats.miui_bak import MIUIBakHandler
from src.formats.whatsapp import WhatsAppHandler
from src.formats.twrp import TWRPHandler
from src.formats.base import FormatType


class TestDetectAndroidAB:
    """Tests for Android .ab format detection."""

    def test_detect_unencrypted(self, tmp_path):
        """Unencrypted .ab file should be detected with high confidence."""
        f = tmp_path / "backup.ab"
        f.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + b"\x00" * 100)

        handler_cls, info = detect_format(str(f))
        assert handler_cls == AndroidABHandler
        assert info is not None
        assert info.format_type == FormatType.ANDROID_AB
        assert info.confidence >= 0.9
        assert info.encrypted is False

    def test_detect_encrypted(self, tmp_path):
        """AES-256 encrypted .ab file should be detected as encrypted."""
        f = tmp_path / "backup.ab"
        f.write_bytes(
            b"ANDROID BACKUP\n5\n1\nAES-256\n"
            + b"aa" * 32 + b"\n"  # salt
            + b"bb" * 32 + b"\n"  # checksum salt
            + b"10000\n"          # rounds
            + b"cc" * 16 + b"\n"  # IV
            + b"dd" * 48 + b"\n"  # master key blob
            + b"\x00" * 100
        )

        handler_cls, info = detect_format(str(f))
        assert handler_cls == AndroidABHandler
        assert info.encrypted is True
        assert info.metadata.get("encryption") == "AES-256"


class TestDetectMIUI:
    """Tests for MIUI format detection."""

    def test_detect_lsa(self, tmp_path):
        """MIUI .lsa file should be detected by extension."""
        f = tmp_path / "photo.lsa"
        f.write_bytes(b"\x00" * 100)

        handler_cls, info = detect_format(str(f))
        assert handler_cls == MIUILSAHandler
        assert info.format_type == FormatType.MIUI_LSA
        assert info.encrypted is True

    def test_detect_lsav(self, tmp_path):
        """MIUI .lsav file should be detected by extension."""
        f = tmp_path / "video.lsav"
        f.write_bytes(b"\x00" * 100)

        handler_cls, info = detect_format(str(f))
        assert handler_cls == MIUILSAHandler

    def test_detect_bak_not_ab(self, tmp_path):
        """MIUI .bak that doesn't start with 'ANDROID BACKUP' should be MIUI."""
        f = tmp_path / "backup.bak"
        # Write a fake MIUI header followed by AB content deeper in
        f.write_bytes(
            b"\x00" * 64 + b"ANDROID BACKUP\n5\n1\nnone\n" + b"\x00" * 100
        )

        handler_cls, info = detect_format(str(f))
        assert handler_cls == MIUIBakHandler
        assert info.format_type == FormatType.MIUI_BAK


class TestDetectWhatsApp:
    """Tests for WhatsApp format detection."""

    def test_detect_crypt14(self, tmp_path):
        """WhatsApp .crypt14 should be detected by extension."""
        f = tmp_path / "msgstore.db.crypt14"
        f.write_bytes(b"\x00" * 100)

        handler_cls, info = detect_format(str(f))
        assert handler_cls == WhatsAppHandler
        assert info.format_type == FormatType.WHATSAPP_CRYPT
        assert info.encrypted is True
        assert info.metadata["version"] == 14

    def test_detect_crypt15(self, tmp_path):
        """WhatsApp .crypt15 should be detected by extension."""
        f = tmp_path / "msgstore.db.crypt15"
        f.write_bytes(b"\x00" * 100)

        handler_cls, info = detect_format(str(f))
        assert handler_cls == WhatsAppHandler
        assert info.metadata["version"] == 15


class TestDetectTWRP:
    """Tests for TWRP format detection."""

    def test_detect_win_directory(self, tmp_path):
        """Directory containing .win files should be detected as TWRP."""
        (tmp_path / "data.ext4.win").write_bytes(b"\x00" * 100)
        (tmp_path / "system.ext4.win").write_bytes(b"\x00" * 100)

        handler_cls, info = detect_format(str(tmp_path))
        assert handler_cls == TWRPHandler
        assert info.format_type == FormatType.TWRP
        assert info.encrypted is False

    def test_detect_single_win(self, tmp_path):
        """Single .win file should be detected as TWRP."""
        f = tmp_path / "data.ext4.win"
        f.write_bytes(b"\x00" * 100)

        handler_cls, info = detect_format(str(f))
        assert handler_cls == TWRPHandler


class TestDetectUnknown:
    """Tests for unknown format handling."""

    def test_unknown_format(self, tmp_path):
        """Random binary file should return None."""
        f = tmp_path / "random.bin"
        f.write_bytes(b"this is not a backup format at all")

        handler_cls, info = detect_format(str(f))
        assert handler_cls is None
        assert info is None

    def test_nonexistent_file(self, tmp_path):
        """Non-existent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            detect_format(str(tmp_path / "nonexistent.ab"))

    def test_empty_file(self, tmp_path):
        """Empty file should return None."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")

        handler_cls, info = detect_format(str(f))
        assert handler_cls is None
        assert info is None


class TestDetectAll:
    """Tests for detect_all (multiple matches)."""

    def test_returns_sorted_by_confidence(self, tmp_path):
        """detect_all should return results sorted by confidence."""
        f = tmp_path / "backup.ab"
        f.write_bytes(b"ANDROID BACKUP\n5\n1\nnone\n" + b"\x00" * 100)

        results = detect_all(str(f))
        assert len(results) >= 1

        # Should be sorted descending by confidence
        confidences = [info.confidence for _, info in results]
        assert confidences == sorted(confidences, reverse=True)
