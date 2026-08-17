# Universal Android Backup Decryptor

**One tool to rule them all.** Detect, decrypt, and extract data from **every** major Android backup format — no more juggling 6 different tools.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## The Problem

Millions of people have Android backups they can't open. The existing solutions are fragmented across different formats:

| Format | Existing Tool | Language |
|---|---|---|
| Android `.ab` (adb backup) | android-backup-extractor | Java |
| MIUI `.lsa`/`.lsav` | MIUI-Cloud-Decryptor | Python |
| MIUI `.bak` (local) | Various scripts | Python |
| Huawei KoBackup | kobackupdec | Python |
| Seedvault (GrapheneOS) | seedvault_backup_parser | Python |
| WhatsApp `.crypt14`/`.crypt15` | wa-crypt-tools | Python |
| TWRP/Nandroid | Manual tar extraction | CLI |

**Universal Backup Decryptor** unifies all of these into a single command.

---

## ✨ Features

- 🔍 **Auto-detection** — point it at any backup file, it figures out the format
- 🔐 **7 formats supported** (and counting):
  - `Android AB` — encrypted & unencrypted `.ab` files
  - `MIUI Secret Album` — `.lsa`/`.lsav` encrypted photos & videos
  - `MIUI Local Backup` — `.bak` files with proprietary headers
  - `Huawei KoBackup / HiSuite` — v3 & v4 encrypted backups
  - `Seedvault` — BIP39 mnemonic-based encrypted backups
  - `WhatsApp` — `.crypt12`/`.crypt14`/`.crypt15` databases
  - `TWRP` — Nandroid `.win` backup extraction
- 🔑 **Password recovery** — tries common defaults automatically
- 📁 **Organized output** — apps sorted by package, media separated, metadata exported
- ⚡ **CLI-first** — fast, scriptable, cross-platform

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/Victormarshall911/universal_backup_decryptor.git
cd universal-backup-decryptor
pip install -e .
```

### Push to PyPI
Make it installable with one command:

```bash
python -m build
twine upload dist/*
```
Then users can do `pip install universal-backup-decryptor` instead of cloning.

### Usage

```bash
# Detect what format a backup is
ubd detect my_backup.ab

# Show detailed metadata without decrypting
ubd info my_backup.ab

# Decrypt an Android .ab backup
ubd decrypt my_backup.ab --password "mysecret"

# Decrypt MIUI Secret Album photos (uses default key)
ubd decrypt photo.lsa

# Decrypt with a custom MIUI key
ubd decrypt photo.lsa --key 6A0978B1E485151FAE4138EE2C2524C7

# Decrypt a Huawei KoBackup directory
ubd decrypt /path/to/huawei_backup/ --password "mypassword"

# Decrypt a Seedvault backup with BIP39 mnemonic
ubd decrypt /path/to/seedvault/ --mnemonic "word1 word2 word3 ... word12"

# Decrypt WhatsApp crypt14 with extracted key file
ubd decrypt msgstore.db.crypt14 --key-file /path/to/key

# Decrypt WhatsApp crypt15 with hex key
ubd decrypt msgstore.db.crypt15 --key abcdef0123456789...

# Extract TWRP/Nandroid backup
ubd decrypt /path/to/twrp_backup/

# Forgot your password? Try common defaults
ubd decrypt locked_backup.ab --try-common-passwords

# Force a specific format (skip auto-detection)
ubd decrypt mystery_file --format ab --password "test"

# Verbose output for debugging
ubd decrypt backup.ab -p "pass" -v
```

---

## 📚 Supported Formats

| Format | Extension | Encryption | Key Source |
|---|---|---|---|
| Android ADB | `.ab` | AES-256-CBC | User password |
| MIUI Secret Album | `.lsa` / `.lsav` | AES-128-ECB | App certificate (default works) |
| MIUI Local | `.bak` | Varies | Password (optional) |
| Huawei KoBackup | Directory + `info.xml` | AES-GCM | User password |
| Seedvault | `.sbd` / directory | AES-256-GCM | 12-word BIP39 mnemonic |
| WhatsApp | `.crypt12`/`.crypt14`/`.crypt15` | AES-256-GCM | Key file or hex key |
| TWRP | `.win` / `.win000` | None | None required |

---

## 📖 CLI Reference

```
ubd detect <input>                  Detect format only
ubd info <input>                    Show backup metadata
ubd decrypt <input> [options]       Decrypt + extract

Options:
  --password, -p TEXT       Decryption password
  --key, -k TEXT            Hex key (MIUI/WhatsApp) 
  --key-file PATH           Key file path (WhatsApp .crypt14 key)
  --mnemonic, -m TEXT       12-word BIP39 mnemonic (Seedvault)
  --output, -o DIR          Output directory (default: <input>_extracted)
  --format, -f NAME         Force format: ab, miui_lsa, miui_bak,
                            huawei, seedvault, whatsapp, twrp
  --try-common-passwords    Try "", "0000", "1234", "password", etc.
  --no-organize             Skip post-extraction file organization
  --verbose, -v             Show debug output
```

---

## 🧠 Architecture

```
┌─────────────┐
│   ubd CLI   │    cli.py — argparse commands
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌──────────────────────────┐
│  detector   │────▶│  HANDLER_REGISTRY        │
└──────┬──────┘     │   ├─ AndroidABHandler     │
       │            │   ├─ TWRPHandler           │
       ▼            │   ├─ MIUILSAHandler        │
┌─────────────┐     │   ├─ MIUIBakHandler        │
│  handler    │────▶│   ├─ HuaweiHandler         │
│  .decrypt() │     │   ├─ SeedvaultHandler       │
└──────┬──────┘     │   └─ WhatsAppHandler        │
       │            └──────────────────────────┘
       ▼
┌─────────────┐
│ extractor   │    DataOrganizer → apps/ media/ contacts/ sms/
└──────┬──────┘
       │
       ▼
  metadata.json
```

---

## 🧪 Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## 📦 Output Structure

After decryption, your data is organized like this:

```
backup_extracted/
├── organized/
│   ├── apps/
│   │   └── com.example.app/
│   │       ├── db/          ← databases
│   │       ├── sp/          ← shared_prefs
│   │       └── f/           ← other files
│   ├── media/               ← photos, videos, audio
│   ├── contacts/            ← contact exports
│   ├── sms/                 ← SMS/MMS exports
│   ├── other/               ← uncategorized
│   └── metadata.json        ← extraction report
└── [raw extracted files]
```

---

## 🔒 Legal & Ethics

This tool is for **recovering your own data** from backups you legally own.

- ✅ Recover data from your own phone backups
- ✅ Digital forensics research (with proper authorization)
- ❌ Do **NOT** use to decrypt backups without explicit permission

The author is not responsible for misuse.

---

## 🤝 Contributing

PRs welcome! To add a new format:

1. Create a new handler in `src/formats/your_format.py`
2. Inherit from `BackupHandler` and implement `detect()`, `get_info()`, `decrypt()`
3. Add your handler to `HANDLER_REGISTRY` in `src/formats/__init__.py`
4. Add tests in `tests/`
5. Update this README

---

## 📄 License

MIT — use it freely, give credit where due.
