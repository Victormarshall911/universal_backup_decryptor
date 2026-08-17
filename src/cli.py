#!/usr/bin/env python3
"""
Main CLI entry point for the Universal Android Backup Decryptor.

Registered as the ``ubd`` console script via setup.py entry_points.

Commands:
    ubd detect  <input>           — Identify backup format
    ubd info    <input>           — Show detailed metadata
    ubd decrypt <input> [options] — Full decrypt + extract pipeline

Global options:
    --password, -p     Decryption password
    --key, -k          Hex key string
    --key-file         Path to key file (e.g. WhatsApp key)
    --mnemonic, -m     12-word BIP39 mnemonic (Seedvault)
    --output, -o       Output directory
    --format, -f       Force a specific format (skip auto-detection)
    --try-common-passwords  Attempt known default passwords
    --verbose, -v      Debug output
"""

import argparse
import sys
from pathlib import Path

from .detector import detect_format, detect_all
from .extractor import DataOrganizer
from .formats import HANDLER_REGISTRY
from .utils import (
    print_banner,
    print_header,
    print_status,
    print_error,
    print_success,
    print_warning,
    format_size,
    Colors,
    colored,
)


# Common default passwords to try when --try-common-passwords is used
COMMON_PASSWORDS = [
    "",           # empty password
    "0000",
    "1234",
    "123456",
    "password",
    "000000",
    "1111",
    "admin",
    "default",
    "backup",
]


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all commands and options."""
    parser = argparse.ArgumentParser(
        prog="ubd",
        description=(
            "Universal Android Backup Decryptor — "
            "Detect, Decrypt, and Extract any Android backup format."
        ),
        epilog="For help with a specific command: ubd <command> --help",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        help="Command to run",
    )

    # ── detect ────────────────────────────────
    detect_p = subparsers.add_parser(
        "detect",
        help="Identify the backup format without decrypting",
    )
    detect_p.add_argument("input", help="Path to backup file or directory")
    detect_p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show all candidate formats and their confidence scores",
    )

    # ── info ──────────────────────────────────
    info_p = subparsers.add_parser(
        "info",
        help="Show detailed metadata about the backup",
    )
    info_p.add_argument("input", help="Path to backup file or directory")

    # ── decrypt ───────────────────────────────
    decrypt_p = subparsers.add_parser(
        "decrypt",
        help="Decrypt and extract the backup",
    )
    decrypt_p.add_argument("input", help="Path to backup file or directory")
    decrypt_p.add_argument(
        "--output", "-o",
        help="Output directory (default: <input>_extracted)",
    )
    decrypt_p.add_argument(
        "--password", "-p",
        help="Decryption password",
    )
    decrypt_p.add_argument(
        "--key", "-k",
        help="Hex decryption key (for MIUI, WhatsApp, etc.)",
    )
    decrypt_p.add_argument(
        "--key-file",
        help="Path to key file (for WhatsApp .crypt14 key extraction)",
    )
    decrypt_p.add_argument(
        "--mnemonic", "-m",
        help="12-word BIP39 mnemonic phrase (for Seedvault)",
    )
    decrypt_p.add_argument(
        "--format", "-f",
        help="Force format (skip auto-detection). "
             "Values: ab, miui_lsa, miui_bak, huawei, seedvault, whatsapp, twrp",
    )
    decrypt_p.add_argument(
        "--try-common-passwords",
        action="store_true",
        help='Try common default passwords (empty, "0000", "1234", etc.)',
    )
    decrypt_p.add_argument(
        "--no-organize",
        action="store_true",
        help="Skip the post-extraction data organization step",
    )
    decrypt_p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed debug output",
    )

    return parser


def _resolve_format(format_name: str):
    """Resolve a --format string to a handler class."""
    # Map user-friendly names to handler classes
    name_lower = format_name.lower().replace("-", "_").replace(" ", "_")

    for handler_cls in HANDLER_REGISTRY:
        # Match against class name (without "Handler" suffix)
        cls_name = handler_cls.__name__.lower().replace("handler", "")
        if name_lower in cls_name or cls_name in name_lower:
            return handler_cls

        # Match against FORMAT_NAME
        fmt_name = handler_cls.FORMAT_NAME.lower()
        if name_lower in fmt_name:
            return handler_cls

    return None


def cmd_detect(args) -> int:
    """Handle the 'detect' command."""
    print_header("Format Detection")

    input_path = Path(args.input)

    try:
        if args.verbose:
            # Show all candidates
            candidates = detect_all(str(input_path))
            if not candidates:
                print_error("Unknown format — no handler matched.")
                return 1

            for handler_cls, info in candidates:
                conf_color = (
                    Colors.GREEN if info.confidence >= 0.8
                    else Colors.YELLOW if info.confidence >= 0.5
                    else Colors.RED
                )
                print_status(
                    "📋",
                    f"{info.format_name}  "
                    f"{colored(f'{info.confidence:.0%}', conf_color)}  "
                    f"{'🔒 encrypted' if info.encrypted else '🔓 unencrypted'}",
                )
                if info.metadata:
                    for k, v in info.metadata.items():
                        print_status("  ", f"  {k}: {v}", Colors.DIM)
        else:
            handler_cls, info = detect_format(str(input_path))
            if not handler_cls or not info:
                print_error(
                    "Unknown format. Cannot detect. "
                    "Try --verbose to see partial matches."
                )
                return 1

            print_status("📦", f"Format: {colored(info.format_name, Colors.BOLD)}")
            print_status(
                "📊",
                f"Confidence: {colored(info.confidence_label, Colors.GREEN)} "
                f"({info.confidence:.0%})",
            )
            print_status(
                "🔐" if info.encrypted else "🔓",
                f"Encrypted: {'Yes' if info.encrypted else 'No'}",
            )

            if info.metadata:
                print_status("📋", "Metadata:", Colors.DIM)
                for k, v in info.metadata.items():
                    print_status("  ", f"  {k}: {v}", Colors.DIM)

        print_success("Detection complete")
        return 0

    except FileNotFoundError as e:
        print_error(str(e))
        return 1
    except Exception as e:
        print_error(f"Detection failed: {e}")
        return 1


def cmd_info(args) -> int:
    """Handle the 'info' command."""
    print_header("Backup Metadata")

    input_path = Path(args.input)

    try:
        handler_cls, info = detect_format(str(input_path))
        if not handler_cls:
            print_error("Unknown format — cannot extract metadata.")
            return 1

        print_status("📦", f"Format: {colored(info.format_name, Colors.BOLD)}")

        # Instantiate handler and get detailed info
        handler = handler_cls(input_path)
        metadata = handler.get_info()

        print()
        for key, val in metadata.items():
            if isinstance(val, dict):
                print_status("📋", f"{key}:")
                for k2, v2 in val.items():
                    print_status("  ", f"  {k2}: {v2}", Colors.DIM)
            elif isinstance(val, list):
                print_status("📋", f"{key}: ({len(val)} items)")
                for item in val[:10]:  # Show first 10
                    print_status("  ", f"  • {item}", Colors.DIM)
                if len(val) > 10:
                    print_status("  ", f"  ... and {len(val) - 10} more", Colors.DIM)
            else:
                print_status("📋", f"{key}: {val}")

        print_success("Info retrieved")
        return 0

    except FileNotFoundError as e:
        print_error(str(e))
        return 1
    except Exception as e:
        print_error(f"Info extraction failed: {e}")
        return 1


def cmd_decrypt(args) -> int:
    """Handle the 'decrypt' command."""
    print_header("Decryption & Extraction")

    input_path = Path(args.input)

    # ── Resolve handler ──
    handler_cls = None
    if args.format:
        handler_cls = _resolve_format(args.format)
        if not handler_cls:
            print_error(
                f"Unknown format: '{args.format}'. "
                f"Available: ab, miui_lsa, miui_bak, huawei, seedvault, whatsapp, twrp"
            )
            return 1
        print_status("📦", f"Forced format: {handler_cls.FORMAT_NAME}")
    else:
        handler_cls, info = detect_format(
            str(input_path), verbose=args.verbose
        )
        if not handler_cls:
            print_error(
                "Could not auto-detect the backup format. "
                "Use --format to specify it manually."
            )
            return 1
        print_status(
            "📦",
            f"Detected: {colored(info.format_name, Colors.BOLD)} "
            f"({info.confidence:.0%} confidence)",
        )

    # ── Set output directory ──
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = Path(f"{input_path.stem}_extracted")
    print_status("📂", f"Output: {output_path}")

    # ── Build decryption kwargs ──
    decrypt_kwargs = {}
    if args.password:
        decrypt_kwargs["password"] = args.password
    if args.key:
        decrypt_kwargs["key"] = args.key
    if args.key_file:
        decrypt_kwargs["key_file"] = args.key_file
    if args.mnemonic:
        decrypt_kwargs["mnemonic"] = args.mnemonic

    # ── Try common passwords ──
    if args.try_common_passwords and not args.password:
        print_header("Trying Common Passwords")
        handler = handler_cls(input_path)

        # First, try the fast try_password() method if available
        for pw in COMMON_PASSWORDS:
            display_pw = repr(pw) if pw else "''"
            try:
                if handler.try_password(pw):
                    print_success(f"Password found: {display_pw}")
                    decrypt_kwargs["password"] = pw
                    break
            except Exception:
                pass
            print_status("✗", f"Not: {display_pw}", Colors.DIM)
        else:
            print_error(
                "No common password worked. "
                "Please provide the correct password with --password."
            )
            return 1

    # ── Decrypt ──
    print()
    handler = handler_cls(input_path)

    try:
        result = handler.decrypt(output_path, **decrypt_kwargs)
    except Exception as e:
        print_error(f"Decryption failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    if not result.success:
        print_error("Decryption failed:")
        for err in result.errors:
            print_error(f"  • {err}")
        for warn in result.warnings:
            print_warning(f"  • {warn}")
        return 1

    print_success(
        f"Decrypted {result.files_extracted} files "
        f"({format_size(result.total_size)})"
    )

    if result.warnings:
        for warn in result.warnings:
            print_warning(warn)

    # ── Organize extracted data ──
    if not args.no_organize and result.files_extracted > 0:
        print()
        print_header("Organizing Extracted Data")

        try:
            organized_dir = output_path / "organized"
            organizer = DataOrganizer(str(output_path), str(organized_dir))
            meta = organizer.organize()

            print_success(f"Data organized into {organized_dir}/")
            print_status("📊", f"Total files: {meta['files_count']}")
            print_status("📱", f"Apps detected: {meta.get('app_count', 0)}")
            print_status("🖼️", f"Media files: {meta['categories']['media']}")
            print_status("📇", f"Contacts: {meta['categories']['contacts']}")
            print_status("💬", f"SMS/MMS: {meta['categories']['sms']}")
        except Exception as e:
            print_warning(
                f"Organization failed (raw data is still available at "
                f"{output_path}): {e}"
            )

    print()
    print_success("Done! ✨")
    return 0


def main():
    """Main entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    if not args.command:
        parser.print_help()
        return 0

    # Dispatch to command handler
    commands = {
        "detect": cmd_detect,
        "info": cmd_info,
        "decrypt": cmd_decrypt,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
