"""
Tests for shared utility functions.

Covers cryptographic helpers (PBKDF2, AES), path safety,
file formatting, and terminal color helpers.
"""

import pytest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from src.utils import (
    derive_key_pbkdf2,
    aes_decrypt_cbc,
    aes_decrypt_cbc_unpad,
    aes_decrypt_gcm,
    deflate_decompress,
    java_utf8_encode,
    safe_path_join,
    format_size,
    read_hex_line,
    ensure_dir,
)


class TestKeyDerivation:
    """Tests for PBKDF2 key derivation."""

    def test_pbkdf2_sha1_produces_correct_length(self):
        """PBKDF2-SHA1 should produce key of requested length."""
        key = derive_key_pbkdf2(
            password=b"password",
            salt=b"salt",
            iterations=1000,
            key_length=32,
            hash_algo="sha1",
        )
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_pbkdf2_sha256_produces_correct_length(self):
        """PBKDF2-SHA256 should produce key of requested length."""
        key = derive_key_pbkdf2(
            password=b"password",
            salt=b"salt",
            iterations=1000,
            key_length=32,
            hash_algo="sha256",
        )
        assert len(key) == 32

    def test_pbkdf2_deterministic(self):
        """Same inputs should always produce same output."""
        key1 = derive_key_pbkdf2(b"test", b"salt123", 500, 16, "sha1")
        key2 = derive_key_pbkdf2(b"test", b"salt123", 500, 16, "sha1")
        assert key1 == key2

    def test_pbkdf2_different_passwords(self):
        """Different passwords should produce different keys."""
        key1 = derive_key_pbkdf2(b"password1", b"salt", 1000, 32, "sha1")
        key2 = derive_key_pbkdf2(b"password2", b"salt", 1000, 32, "sha1")
        assert key1 != key2

    def test_pbkdf2_16_byte_key(self):
        """Should support 16-byte (AES-128) key derivation."""
        key = derive_key_pbkdf2(b"pass", b"salt", 100, key_length=16)
        assert len(key) == 16


class TestAESDecryption:
    """Tests for AES decryption helpers."""

    def test_aes_cbc_roundtrip(self):
        """AES-CBC encrypt → decrypt should return original plaintext."""
        key = b"\x00" * 32
        iv = b"\x01" * 16
        plaintext = b"Hello, world!!!"  # 15 bytes
        padded = pad(plaintext, AES.block_size)

        # Encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)

        # Decrypt (raw, with padding)
        decrypted = aes_decrypt_cbc(key, iv, ciphertext)
        assert decrypted == padded

    def test_aes_cbc_unpad(self):
        """AES-CBC decrypt with unpadding should return original plaintext."""
        key = b"\xaa" * 32
        iv = b"\xbb" * 16
        plaintext = b"Test data 12345"

        padded = pad(plaintext, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)

        decrypted = aes_decrypt_cbc_unpad(key, iv, ciphertext)
        assert decrypted == plaintext

    def test_aes_gcm_roundtrip(self):
        """AES-GCM encrypt → decrypt should return original plaintext."""
        key = b"\x42" * 32
        nonce = b"\x43" * 12
        plaintext = b"Authenticated plaintext"

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        decrypted = aes_decrypt_gcm(key, nonce, ciphertext, tag)
        assert decrypted == plaintext

    def test_aes_gcm_wrong_key_fails(self):
        """AES-GCM with wrong key should raise ValueError."""
        key = b"\x42" * 32
        wrong_key = b"\x99" * 32
        nonce = b"\x43" * 12
        plaintext = b"secret"

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with pytest.raises(ValueError):
            aes_decrypt_gcm(wrong_key, nonce, ciphertext, tag)


class TestDeflate:
    """Tests for DEFLATE decompression."""

    def test_deflate_roundtrip(self):
        """Compress → decompress should return original data."""
        import zlib

        original = b"Hello World! " * 100  # Compressible data
        # Compress with raw deflate (no headers)
        compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
        compressed = compressor.compress(original) + compressor.flush()

        decompressed = deflate_decompress(compressed)
        assert decompressed == original


class TestJavaUTF8:
    """Tests for Java-compatible UTF-8 encoding."""

    def test_ascii_password(self):
        """ASCII passwords should encode identically to Python's UTF-8."""
        assert java_utf8_encode("password") == b"password"
        assert java_utf8_encode("test123") == b"test123"

    def test_empty_password(self):
        """Empty password should produce empty bytes."""
        assert java_utf8_encode("") == b""

    def test_unicode_password(self):
        """Unicode passwords should encode as UTF-8."""
        assert java_utf8_encode("café") == "café".encode("utf-8")


class TestPathSafety:
    """Tests for safe path joining and traversal prevention."""

    def test_safe_join_normal(self, tmp_path):
        """Normal paths should join correctly."""
        result = safe_path_join(tmp_path, "apps", "com.example", "data.db")
        assert str(result).startswith(str(tmp_path))
        assert result.name == "data.db"

    def test_safe_join_blocks_traversal(self, tmp_path):
        """Path traversal with '..' should be blocked."""
        result = safe_path_join(tmp_path, "..", "..", "etc", "passwd")
        # Should stay within tmp_path
        assert str(result).startswith(str(tmp_path))

    def test_safe_join_strips_leading_slash(self, tmp_path):
        """Leading slashes in components should be stripped."""
        result = safe_path_join(tmp_path, "/apps/data.db")
        assert str(result).startswith(str(tmp_path))

    def test_safe_join_empty_parts(self, tmp_path):
        """Empty parts should return base path."""
        result = safe_path_join(tmp_path)
        assert result == tmp_path.resolve()


class TestFormatSize:
    """Tests for human-readable size formatting."""

    def test_zero_bytes(self):
        assert format_size(0) == "0 B"

    def test_bytes(self):
        assert format_size(500) == "500 B"

    def test_kilobytes(self):
        result = format_size(1536)
        assert "KB" in result

    def test_megabytes(self):
        result = format_size(5 * 1024 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = format_size(2 * 1024 * 1024 * 1024)
        assert "GB" in result

    def test_negative(self):
        assert format_size(-1) == "unknown"


class TestHexLineParsing:
    """Tests for hex line parsing."""

    def test_parse_hex_string(self):
        result = read_hex_line("48656c6c6f")
        assert result == b"Hello"

    def test_parse_hex_bytes(self):
        result = read_hex_line(b"48656c6c6f\n")
        assert result == b"Hello"

    def test_parse_hex_with_whitespace(self):
        result = read_hex_line("  48656c6c6f  \n")
        assert result == b"Hello"


class TestEnsureDir:
    """Tests for directory creation."""

    def test_creates_nested_dirs(self, tmp_path):
        target = tmp_path / "a" / "b" / "c"
        result = ensure_dir(target)
        assert result.exists()
        assert result.is_dir()

    def test_existing_dir_ok(self, tmp_path):
        """Should not fail if directory already exists."""
        result = ensure_dir(tmp_path)
        assert result.exists()
