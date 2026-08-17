from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="universal-backup-decryptor",
    version="1.0.0",
    author="Victor",
    description="The Universal Android Backup Decryptor — detect, decrypt, and extract ANY Android backup format",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Victormarshall911/universal_backup_decryptor",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pycryptodome>=3.19.0",
        "mnemonic>=0.20",
        "filetype>=1.2.0",
        "protobuf>=4.25.0",
    ],
    entry_points={
        "console_scripts": [
            "ubd=src.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Archiving",
        "Topic :: Utilities",
    ],
    keywords="android backup decrypt ab miui huawei seedvault whatsapp twrp",
)
