"""
Shared cryptographic and I/O utilities for all format handlers.

Provides PBKDF2 key derivation, AES decryption (CBC, CTR, GCM),
deflate decompression, Java-compatible UTF-8 encoding, and safe path operations.
"""

import hashlib
import os
import struct
import zlib
from pathlib import Path
from typing import Optional, Tuple, Union

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter


# ─────────────────────────────────────────────
# ANSI Color Helpers
# ─────────────────────────────────────────────

class Colors:
    """ANSI escape codes for terminal coloring."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"

    @staticmethod
    def supports_color() -> bool:
        """Check if the terminal supports ANSI colors."""
        if os.environ.get("NO_COLOR"):
            return False
        if os.environ.get("FORCE_COLOR"):
            return True
        return hasattr(os.sys.stdout, "isatty") and os.sys.stdout.isatty()


def colored(text: str, color: str) -> str:
    """Wrap text in ANSI color codes if terminal supports it."""
    if Colors.supports_color():
        return f"{color}{text}{Colors.RESET}"
    return text


def print_status(icon: str, message: str, color: str = Colors.GREEN):
    """Print a status message with colored icon."""
    print(f"  {colored(icon, color)} {message}")


def print_header(title: str):
    """Print a section header."""
    line = "─" * 50
    print(f"\n  {colored(line, Colors.DIM)}")
    print(f"  {colored('◆', Colors.CYAN)} {colored(title, Colors.BOLD)}")
    print(f"  {colored(line, Colors.DIM)}")


def print_error(message: str):
    """Print an error message with red icon."""
    print(f"  {colored('✗', Colors.RED)} {colored(message, Colors.RED)}")


def print_success(message: str):
    """Print a success message with green icon."""
    print(f"  {colored('✓', Colors.GREEN)} {colored(message, Colors.GREEN)}")


def print_warning(message: str):
    """Print a warning message with yellow icon."""
    print(f"  {colored('⚠', Colors.YELLOW)} {message}")


def print_banner():
    """Print the application banner."""
    banner = r"""
   ╔══════════════════════════════════════════════════════╗
   ║   Universal Android Backup Decryptor  v1.0.0        ║
   ║   Detect · Decrypt · Extract — Any Format            ║
   ╚══════════════════════════════════════════════════════╝
    """
    print(colored(banner, Colors.CYAN))


# ─────────────────────────────────────────────
# Key Derivation
# ─────────────────────────────────────────────

def derive_key_pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int,
    key_length: int = 32,
    hash_algo: str = "sha1",
) -> bytes:
    """
    Derive an encryption key using PBKDF2-HMAC.

    Args:
        password: The password bytes.
        salt: The salt bytes.
        iterations: Number of PBKDF2 iterations.
        key_length: Desired key length in bytes (default 32 for AES-256).
        hash_algo: Hash algorithm ('sha1' for Android AB, 'sha256' for Huawei).

    Returns:
        Derived key bytes.
    """
    if hash_algo == "sha1":
        hmac_hash = "hmac-sha1"
    elif hash_algo == "sha256":
        hmac_hash = "hmac-sha256"
    else:
        hmac_hash = f"hmac-{hash_algo}"

    # PyCryptodome's PBKDF2 expects the hmac_hash_module or we use the
    # prf parameter. For simplicity and compatibility, use hashlib-based PBKDF2.
    return hashlib.pbkdf2_hmac(
        hash_algo,
        password,
        salt,
        iterations,
        dklen=key_length,
    )


# ─────────────────────────────────────────────
# AES Decryption
# ─────────────────────────────────────────────

def aes_decrypt_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    """
    Decrypt data using AES-CBC mode.

    Args:
        key: AES key (16, 24, or 32 bytes).
        iv: Initialization vector (16 bytes).
        data: Ciphertext to decrypt.

    Returns:
        Decrypted plaintext (with PKCS7 padding still present).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


def aes_decrypt_cbc_unpad(key: bytes, iv: bytes, data: bytes) -> bytes:
    """
    Decrypt data using AES-CBC mode and remove PKCS7 padding.

    Args:
        key: AES key (16, 24, or 32 bytes).
        iv: Initialization vector (16 bytes).
        data: Ciphertext to decrypt.

    Returns:
        Decrypted plaintext with padding removed.
    """
    plaintext = aes_decrypt_cbc(key, iv, data)
    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    if 1 <= pad_len <= 16 and all(b == pad_len for b in plaintext[-pad_len:]):
        return plaintext[:-pad_len]
    return plaintext


def aes_decrypt_ctr(key: bytes, initial_value: int, data: bytes) -> bytes:
    """
    Decrypt data using AES-CTR mode.

    Args:
        key: AES key (16, 24, or 32 bytes).
        initial_value: Counter initial value (128-bit integer).
        data: Ciphertext to decrypt.

    Returns:
        Decrypted plaintext.
    """
    counter = Counter.new(128, initial_value=initial_value)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(data)


def aes_decrypt_gcm(
    key: bytes, nonce: bytes, data: bytes, tag: bytes
) -> bytes:
    """
    Decrypt and authenticate data using AES-GCM mode.

    Args:
        key: AES key (16, 24, or 32 bytes).
        nonce: GCM nonce/IV (typically 12 bytes).
        data: Ciphertext to decrypt.
        tag: Authentication tag (16 bytes).

    Returns:
        Decrypted and verified plaintext.

    Raises:
        ValueError: If authentication fails (wrong key or tampered data).
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(data, tag)


# ─────────────────────────────────────────────
# Compression
# ─────────────────────────────────────────────

def deflate_decompress(data: bytes) -> bytes:
    """
    Decompress raw DEFLATE data (no zlib/gzip headers).

    Android backups use raw deflate with SYNC_FLUSH.
    Uses wbits=-15 for raw deflate stream.

    Args:
        data: Compressed data bytes.

    Returns:
        Decompressed data bytes.
    """
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    result = decompressor.decompress(data)
    # Try to flush any remaining data
    try:
        result += decompressor.flush()
    except zlib.error:
        pass
    return result


def deflate_decompress_stream(file_obj, chunk_size: int = 65536):
    """
    Generator that decompresses raw DEFLATE data from a file object in chunks.

    Yields decompressed chunks for memory-efficient processing.

    Args:
        file_obj: File-like object to read compressed data from.
        chunk_size: Size of read chunks (default 64KB).

    Yields:
        Decompressed data chunks.
    """
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        try:
            decompressed = decompressor.decompress(chunk)
            if decompressed:
                yield decompressed
        except zlib.error:
            break
    try:
        remaining = decompressor.flush()
        if remaining:
            yield remaining
    except zlib.error:
        pass


# ─────────────────────────────────────────────
# Header / Binary Parsing
# ─────────────────────────────────────────────

def read_hex_line(line: Union[str, bytes]) -> bytes:
    """
    Parse a hex-encoded line from a backup header.

    Args:
        line: Hex string (as str or bytes), possibly with newline.

    Returns:
        Decoded bytes.
    """
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
    return bytes.fromhex(line.strip())


def java_utf8_encode(password: str) -> bytes:
    """
    Encode a password string the way Java/Android does for PBKDF2.

    Android's BackupManagerService converts the password to a byte array
    using String.getBytes("UTF-8"). For ASCII passwords this is identical
    to Python's .encode('utf-8'). For non-ASCII, Java's modified UTF-8
    may differ, but in practice backup passwords are ASCII.

    Args:
        password: The password string.

    Returns:
        UTF-8 encoded password bytes.
    """
    return password.encode("utf-8")


# ─────────────────────────────────────────────
# File I/O Helpers
# ─────────────────────────────────────────────

def safe_path_join(base: Union[str, Path], *parts: str) -> Path:
    """
    Safely join path components, preventing path traversal attacks.

    Ensures the resulting path is always within the base directory.
    Strips leading slashes and '..' components.

    Args:
        base: Base directory path.
        *parts: Path components to join.

    Returns:
        Safe resolved path within base.

    Raises:
        ValueError: If the resulting path would escape base directory.
    """
    base = Path(base).resolve()
    # Sanitize each part
    sanitized_parts = []
    for part in parts:
        # Remove leading slashes and handle '..'
        clean = part.lstrip("/").lstrip("\\")
        # Split and filter dangerous components
        components = Path(clean).parts
        safe_components = [c for c in components if c != ".." and c != "."]
        sanitized_parts.extend(safe_components)

    if not sanitized_parts:
        return base

    result = base.joinpath(*sanitized_parts).resolve()

    # Verify the result is still within base
    if not str(result).startswith(str(base)):
        raise ValueError(
            f"Path traversal detected: {'/'.join(parts)} would escape {base}"
        )

    return result


def format_size(size_bytes: int) -> str:
    """
    Format a byte count into a human-readable string.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Human-readable string (e.g., '1.5 MB', '230 KB').
    """
    if size_bytes < 0:
        return "unknown"
    if size_bytes == 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    unit_idx = 0
    while size >= 1024 and unit_idx < len(units) - 1:
        size /= 1024
        unit_idx += 1

    if unit_idx == 0:
        return f"{int(size)} B"
    return f"{size:.1f} {units[unit_idx]}"


def ensure_dir(path: Union[str, Path]) -> Path:
    """Create directory and parents if they don't exist."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def read_file_header(file_path: Union[str, Path], size: int = 512) -> bytes:
    """
    Read the first N bytes of a file.

    Args:
        file_path: Path to the file.
        size: Number of bytes to read (default 512).

    Returns:
        File header bytes (may be shorter than size for small files).
    """
    with open(file_path, "rb") as f:
        return f.read(size)
