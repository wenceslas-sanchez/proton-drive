"""
Cryptographic operations for Proton Drive.

This module provides:
- PGP message decryption
- Key hierarchy management (User → Address → Share → Node)
- AES-CFB block decryption (OpenPGP format)
- Secure memory handling
"""

from proton_drive.crypto.aes import decrypt_seipd_packet, parse_seipd_from_block
from proton_drive.crypto.key_manager import KeyManager
from proton_drive.crypto.pgpy_backend import PgpyBackend, PgpyPrivateKey
from proton_drive.crypto.protocol import PGPBackend, PrivateKey
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.crypto.session_key import parse_pkesk_packet

__all__ = [
    "SecureBytes",
    "KeyManager",
    "PGPBackend",
    "PrivateKey",
    "PgpyBackend",
    "PgpyPrivateKey",
    "decrypt_seipd_packet",
    "parse_seipd_from_block",
    "parse_pkesk_packet",
]
