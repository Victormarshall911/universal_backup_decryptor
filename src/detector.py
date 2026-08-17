"""
Format auto-detection engine.

Reads file headers, consults all registered handlers, and returns the
best-matching handler based on confidence scores. Handles both file-based
and directory-based backup formats.

Detection strategy:
    1. Read the first 512 bytes of the input (if it's a file)
    2. Iterate all handlers in HANDLER_REGISTRY
    3. Call each handler's detect() classmethod with the path and header
    4. Return the handler with the highest confidence score
    5. Fall back to filename/extension heuristics if no magic match
"""

from pathlib import Path
from typing import List, Optional, Tuple, Type

from .formats.base import BackupHandler, FormatInfo
from .formats import HANDLER_REGISTRY
from .utils import (
    read_file_header,
    print_status,
    print_warning,
    Colors,
    colored,
)


def detect_format(
    input_path: str,
    verbose: bool = False,
) -> Tuple[Optional[Type[BackupHandler]], Optional[FormatInfo]]:
    """
    Auto-detect the backup format by inspecting the file or directory.

    Iterates all handlers in HANDLER_REGISTRY, calling each handler's
    detect() classmethod. Returns the handler with the highest confidence.

    Args:
        input_path: Path to the backup file or directory.
        verbose: If True, print detection details for all handlers.

    Returns:
        Tuple of (handler_class, FormatInfo) if detected,
        or (None, None) if the format is unknown.
    """
    path = Path(input_path)

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {input_path}")

    # Read file header (for file-based formats)
    header_bytes = b""
    if path.is_file():
        try:
            header_bytes = read_file_header(path, size=512)
        except OSError:
            pass

    # Query all handlers
    candidates: List[Tuple[Type[BackupHandler], FormatInfo]] = []

    for handler_cls in HANDLER_REGISTRY:
        try:
            info = handler_cls.detect(path, header_bytes)
            if info is not None:
                candidates.append((handler_cls, info))
                if verbose:
                    print_status(
                        "🔍",
                        f"{handler_cls.FORMAT_NAME}: "
                        f"confidence={info.confidence:.0%} "
                        f"encrypted={info.encrypted}",
                        Colors.DIM,
                    )
        except Exception as e:
            if verbose:
                print_warning(
                    f"{handler_cls.FORMAT_NAME} detection error: {e}"
                )

    if not candidates:
        return None, None

    # Sort by confidence (highest first)
    candidates.sort(key=lambda c: c[1].confidence, reverse=True)

    best_handler, best_info = candidates[0]

    if verbose and len(candidates) > 1:
        print_status(
            "📊",
            f"Selected {best_handler.FORMAT_NAME} "
            f"(confidence: {best_info.confidence:.0%}) "
            f"over {len(candidates) - 1} other candidate(s)",
        )

    return best_handler, best_info


def detect_all(
    input_path: str,
) -> List[Tuple[Type[BackupHandler], FormatInfo]]:
    """
    Return ALL matching formats with their confidence scores.

    Useful for ambiguous files where multiple handlers claim a match.

    Args:
        input_path: Path to the backup file or directory.

    Returns:
        List of (handler_class, FormatInfo) tuples, sorted by confidence
        (highest first). Empty list if nothing matches.
    """
    path = Path(input_path)

    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {input_path}")

    header_bytes = b""
    if path.is_file():
        try:
            header_bytes = read_file_header(path, size=512)
        except OSError:
            pass

    candidates = []
    for handler_cls in HANDLER_REGISTRY:
        try:
            info = handler_cls.detect(path, header_bytes)
            if info is not None:
                candidates.append((handler_cls, info))
        except Exception:
            pass

    candidates.sort(key=lambda c: c[1].confidence, reverse=True)
    return candidates
