"""
AES decryption for OpenPGP SEIPD packets.

This handles the decryption of file blocks which use OpenPGP's
Symmetrically Encrypted Integrity Protected Data (SEIPD) format.
"""

import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from proton_drive.exceptions import BlockDecryptionError, IntegrityError
from proton_drive.models.crypto import SessionKey

_TAG_LITERAL_DATA = 11
_TAG_SEIPD = 18
_MDC_PACKET_SIZE = 22  # 2-byte header + 20-byte SHA-1
_MDC_HEADER = b"\xd3\x14"
_MDC_HASH_SIZE = 20


def decrypt_seipd_packet(encrypted_data: bytes, session_key: SessionKey) -> bytes:
    """
    Decrypt a SEIPD (Symmetrically Encrypted Integrity Protected Data) packet.

    Args:
        encrypted_data: The encrypted portion of the SEIPD packet (after tag/length).
        session_key: The session key for decryption.

    Returns:
        Decrypted file content.

    Raises:
        BlockDecryptionError: If decryption fails.
        IntegrityError: If MDC verification fails.
    """
    if len(encrypted_data) < 1:
        raise BlockDecryptionError("SEIPD packet too short")

    version = encrypted_data[0]
    if version != 1:
        raise BlockDecryptionError(f"Unsupported SEIPD version: {version}")

    block_size = session_key.block_size
    if block_size == 0:
        raise BlockDecryptionError(f"Unknown block size for {session_key.algorithm}")

    ciphertext = encrypted_data[1:]
    prefix_size = block_size + 2
    min_size = prefix_size + _MDC_PACKET_SIZE
    if len(ciphertext) < min_size:
        raise BlockDecryptionError(f"Encrypted data too short: {len(ciphertext)} < {min_size}")

    plaintext = _decrypt_openpgp_cfb(ciphertext, session_key.key_data, block_size)
    _verify_mdc(plaintext)
    literal_data = plaintext[:-_MDC_PACKET_SIZE]

    return _parse_literal_data_packet(literal_data)


def _decrypt_openpgp_cfb(ciphertext: bytes, key: bytes, block_size: int) -> bytes:
    prefix_size = block_size + 2
    prefix_ciphertext = ciphertext[:prefix_size]
    rest_ciphertext = ciphertext[prefix_size:]

    # Decrypt prefix with zero IV
    iv = bytes(block_size)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    prefix_plaintext = decryptor.update(prefix_ciphertext) + decryptor.finalize()

    # Verify prefix: last 2 bytes of random data should repeat
    if prefix_plaintext[block_size - 2 : block_size] != prefix_plaintext[block_size:]:
        raise BlockDecryptionError("CFB prefix verification failed, possibly wrong key")

    # Resync IV for rest of data
    resync_iv = prefix_ciphertext[2:prefix_size]
    cipher = Cipher(algorithms.AES(key), modes.CFB(resync_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    rest_plaintext = decryptor.update(rest_ciphertext) + decryptor.finalize()

    return prefix_plaintext + rest_plaintext


def _verify_mdc(plaintext: bytes) -> None:
    if len(plaintext) < _MDC_PACKET_SIZE:
        raise IntegrityError("Data too short for MDC")

    mdc_packet = plaintext[-_MDC_PACKET_SIZE:]

    if mdc_packet[:2] != _MDC_HEADER:
        raise IntegrityError(f"Invalid MDC header: {mdc_packet[:2].hex()}")

    stored_hash = mdc_packet[2:]
    data_to_hash = plaintext[:-_MDC_HASH_SIZE]
    computed_hash = hashlib.sha1(data_to_hash).digest()

    if computed_hash != stored_hash:
        raise IntegrityError("MDC verification failed, data may be corrupted or tampered")


def _parse_literal_data_packet(data: bytes) -> bytes:
    if len(data) < 2:
        return data

    first_byte = data[0]
    packet_tag, is_new_format = _parse_packet_tag(first_byte)

    if packet_tag is None or packet_tag != _TAG_LITERAL_DATA:
        return data

    offset = 1 + _get_length_field_size(data, 1, is_new_format, first_byte)

    if offset >= len(data):
        return b""

    # Skip format byte
    offset += 1

    # Skip filename
    if offset >= len(data):
        return b""
    filename_len = data[offset]
    offset += 1 + filename_len

    # Skip date (4 bytes)
    offset += 4

    return data[offset:] if offset < len(data) else b""


def parse_seipd_from_block(block_data: bytes) -> bytes:
    """
    Parse a complete encrypted block to extract SEIPD packet data.

    Args:
        block_data: Raw encrypted block data.

    Returns:
        SEIPD packet data (everything after header).

    Raises:
        BlockDecryptionError: If parsing fails.
    """
    if len(block_data) < 2:
        raise BlockDecryptionError("Block data too short")

    first_byte = block_data[0]
    packet_tag, is_new_format = _parse_packet_tag(first_byte)

    if packet_tag is None:
        raise BlockDecryptionError(f"Invalid packet header: 0x{first_byte:02x}")

    if packet_tag != _TAG_SEIPD:
        raise BlockDecryptionError(f"Expected SEIPD packet (tag 18), got tag {packet_tag}")

    offset = 1 + _get_length_field_size(block_data, 1, is_new_format, first_byte)
    return block_data[offset:]


def _parse_packet_tag(first_byte: int) -> tuple[int | None, bool]:
    if (first_byte & 0xC0) == 0xC0:
        # New format: 11xxxxxx
        return first_byte & 0x3F, True
    if (first_byte & 0x80) == 0x80:
        # Old format: 10xxxxxx
        return (first_byte & 0x3C) >> 2, False
    return None, False


def _get_length_field_size(
    data: bytes,
    offset: int,
    is_new_format: bool,
    first_byte: int,
) -> int:
    if is_new_format:
        if offset >= len(data):
            return 0
        length_byte = data[offset]
        if length_byte < 192:
            return 1
        if length_byte < 224:
            return 2
        if length_byte == 255:
            return 5
        return 1  # Partial body
    else:
        length_type = first_byte & 0x03
        if length_type == 0:
            return 1
        if length_type == 1:
            return 2
        if length_type == 2:
            return 4
        return 0  # Indeterminate
