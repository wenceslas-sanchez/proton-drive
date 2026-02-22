import hashlib
import os

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from proton_drive.crypto.aes import (
    _parse_literal_data_packet,
    _verify_mdc,
    decrypt_seipd_packet,
    parse_seipd_from_block,
)
from proton_drive.exceptions import BlockDecryptionError, IntegrityError
from proton_drive.models.crypto import SessionKey, SymmetricAlgorithm


def _create_session_key(
    algorithm: SymmetricAlgorithm = SymmetricAlgorithm.AES_256,
) -> SessionKey:
    key_data = b"\x00" * algorithm.key_size
    return SessionKey(algorithm=algorithm, key_data=key_data)


def _build_literal_data_packet(content: bytes) -> bytes:
    """Build a minimal new-format literal data packet (tag 11)."""
    # format=binary, no filename, date=0
    body = b"b" + b"\x00" + b"\x00\x00\x00\x00" + content
    length = len(body)
    return b"\xcb" + bytes([length]) + body


def _build_seipd_packet(content: bytes, session_key: SessionKey) -> bytes:
    """
    Build a valid SEIPD v1 encrypted packet from plaintext content.

    Plaintext layout: [random prefix (block_size bytes)] + [prefix[-2:]] +
                      [literal data packet] + [\\xd3\\x14] + [sha1 hash (20 bytes)]
    Then CFB-encrypt with zero IV and prepend version byte 0x01.
    """
    block_size = session_key.block_size
    random_prefix = os.urandom(block_size)
    check_bytes = random_prefix[-2:]
    literal_packet = _build_literal_data_packet(content)
    mdc_header = b"\xd3\x14"
    data_before_hash = random_prefix + check_bytes + literal_packet + mdc_header
    mdc_hash = hashlib.sha1(data_before_hash).digest()
    plaintext = data_before_hash + mdc_hash

    iv = bytes(block_size)
    encryptor = Cipher(
        algorithms.AES(session_key.key_data), modes.CFB(iv), backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return b"\x01" + ciphertext


def test_decrypt_seipd_packet_raises_on_empty_data() -> None:
    session_key = _create_session_key()

    with pytest.raises(BlockDecryptionError, match="SEIPD packet too short"):
        decrypt_seipd_packet(b"", session_key)


def test_decrypt_seipd_packet_raises_on_unsupported_version() -> None:
    session_key = _create_session_key()
    data = b"\x02" + b"\x00" * 100  # Version 2

    with pytest.raises(BlockDecryptionError, match="Unsupported SEIPD version: 2"):
        decrypt_seipd_packet(data, session_key)


def test_decrypt_seipd_packet_raises_on_unknown_block_size() -> None:
    session_key = SessionKey(
        algorithm=SymmetricAlgorithm.PLAINTEXT,
        key_data=b"",
    )
    data = b"\x01" + b"\x00" * 100

    with pytest.raises(BlockDecryptionError, match="Unknown block size"):
        decrypt_seipd_packet(data, session_key)


def test_decrypt_seipd_packet_raises_on_short_ciphertext() -> None:
    session_key = _create_session_key()
    # Version 1 + data shorter than min_size (block_size + 2 + 22 = 40 for AES)
    data = b"\x01" + b"\x00" * 30

    with pytest.raises(BlockDecryptionError, match="Encrypted data too short"):
        decrypt_seipd_packet(data, session_key)


def test_verify_mdc_raises_on_short_data() -> None:
    with pytest.raises(IntegrityError, match="Data too short for MDC"):
        _verify_mdc(b"\x00" * 10)


def test_verify_mdc_raises_on_invalid_header() -> None:
    # 22 bytes with wrong header
    data = b"\x00" * 20 + b"\xd4\x14"  # Wrong first byte

    with pytest.raises(IntegrityError, match="Invalid MDC header"):
        _verify_mdc(data)


def test_verify_mdc_raises_on_hash_mismatch() -> None:
    # Valid header but wrong hash
    data = b"\x00" * 10 + b"\xd3\x14" + b"\x00" * 20

    with pytest.raises(IntegrityError, match="MDC verification failed"):
        _verify_mdc(data)


def test_verify_mdc_succeeds_with_valid_hash() -> None:
    content = b"test content"
    mdc_header = b"\xd3\x14"
    data_to_hash = content + mdc_header
    expected_hash = hashlib.sha1(data_to_hash).digest()
    plaintext = content + mdc_header + expected_hash

    _verify_mdc(plaintext)


def test_parse_literal_data_packet_returns_raw_on_short_data() -> None:
    result = _parse_literal_data_packet(b"\x00")

    assert result == b"\x00"


def test_parse_literal_data_packet_returns_raw_on_non_packet() -> None:
    # First byte doesn't have packet format bits
    data = b"\x00\x01\x02\x03"

    result = _parse_literal_data_packet(data)

    assert result == data


def test_parse_literal_data_packet_returns_raw_on_non_literal_tag() -> None:
    # New format, tag 10 (not 11)
    data = b"\xca" + b"\x05" + b"hello"

    result = _parse_literal_data_packet(data)

    assert result == data


def test_parse_literal_data_packet_extracts_content_new_format() -> None:
    # New format literal data packet (tag 11 = 0xCB)
    # 0xCB = 1100 1011 -> new format, tag 11
    tag = b"\xcb"
    length = b"\x10"  # 16 bytes
    format_byte = b"b"  # binary
    filename_len = b"\x04"
    filename = b"test"
    date = b"\x00\x00\x00\x00"
    content = b"hello"
    packet = tag + length + format_byte + filename_len + filename + date + content

    result = _parse_literal_data_packet(packet)

    assert result == content


def test_parse_literal_data_packet_extracts_content_old_format() -> None:
    # Old format literal data packet
    # 0xAC = 1010 1100 -> old format, tag 11, length type 0 (1 byte)
    tag = b"\xac"
    length = b"\x10"  # 16 bytes
    format_byte = b"b"
    filename_len = b"\x04"
    filename = b"test"
    date = b"\x00\x00\x00\x00"
    content = b"hello"
    packet = tag + length + format_byte + filename_len + filename + date + content

    result = _parse_literal_data_packet(packet)

    assert result == content


def test_parse_literal_data_packet_handles_empty_filename() -> None:
    tag = b"\xcb"
    length = b"\x08"
    format_byte = b"b"
    filename_len = b"\x00"
    date = b"\x00\x00\x00\x00"
    content = b"hi"
    packet = tag + length + format_byte + filename_len + date + content

    result = _parse_literal_data_packet(packet)

    assert result == content


def test_parse_seipd_from_block_raises_on_short_data() -> None:
    with pytest.raises(BlockDecryptionError, match="Block data too short"):
        parse_seipd_from_block(b"\x00")


def test_parse_seipd_from_block_raises_on_invalid_header() -> None:
    # First byte doesn't have packet format bits
    data = b"\x00\x01\x02\x03"

    with pytest.raises(BlockDecryptionError, match="Invalid packet header"):
        parse_seipd_from_block(data)


def test_parse_seipd_from_block_raises_on_wrong_tag() -> None:
    # New format, tag 11 (not 18)
    data = b"\xcb\x05hello"

    with pytest.raises(BlockDecryptionError, match="Expected SEIPD packet"):
        parse_seipd_from_block(data)


def test_parse_seipd_from_block_parses_new_format() -> None:
    # New format SEIPD packet (tag 18 = 0xD2)
    tag = b"\xd2"
    length = b"\x05"  # 5 bytes
    content = b"hello"
    block = tag + length + content

    result = parse_seipd_from_block(block)

    assert result == content


def test_parse_seipd_from_block_rejects_old_format_with_wrong_tag() -> None:
    # Old format can only represent tags 0-15. SEIPD is tag 18.
    # 0xA4 = 1010 0100 -> old format (10), tag 9 (1001), length type 0 (00)
    tag = b"\xa4"
    length = b"\x05"
    content = b"hello"
    block = tag + length + content

    with pytest.raises(BlockDecryptionError, match="Expected SEIPD packet"):
        parse_seipd_from_block(block)


def test_parse_seipd_from_block_handles_two_byte_length() -> None:
    # New format with 2-byte length (192-8383 range)
    tag = b"\xd2"
    # Length 300: first byte = ((300 - 192) >> 8) + 192 = 192
    # second byte = (300 - 192) & 0xFF = 108
    length = b"\xc0\x6c"
    content = b"x" * 300
    block = tag + length + content

    result = parse_seipd_from_block(block)

    assert result == content


def test_parse_seipd_from_block_handles_five_byte_length() -> None:
    # New format with 5-byte length (0xFF prefix)
    tag = b"\xd2"
    length = b"\xff\x00\x00\x00\x05"  # 5 bytes
    content = b"hello"
    block = tag + length + content

    result = parse_seipd_from_block(block)

    assert result == content


def test_decrypt_seipd_packet_roundtrip_aes256() -> None:
    session_key = _create_session_key(SymmetricAlgorithm.AES_256)
    content = b"Hello, Proton Drive!"

    packet = _build_seipd_packet(content, session_key)
    result = decrypt_seipd_packet(packet, session_key)

    assert result == content


def test_decrypt_seipd_packet_roundtrip_empty_content() -> None:
    session_key = _create_session_key(SymmetricAlgorithm.AES_256)
    content = b""

    packet = _build_seipd_packet(content, session_key)
    result = decrypt_seipd_packet(packet, session_key)

    assert result == content


def test_decrypt_seipd_packet_roundtrip_large_content() -> None:
    session_key = _create_session_key(SymmetricAlgorithm.AES_256)
    content = os.urandom(64 * 1024)  # 64 KB

    packet = _build_seipd_packet(content, session_key)
    result = decrypt_seipd_packet(packet, session_key)

    assert result == content


def test_decrypt_seipd_packet_wrong_key_raises_integrity_error() -> None:
    good_key = _create_session_key(SymmetricAlgorithm.AES_256)
    bad_key = SessionKey(algorithm=SymmetricAlgorithm.AES_256, key_data=b"\xff" * 32)
    content = b"secret data"

    packet = _build_seipd_packet(content, good_key)

    with pytest.raises(IntegrityError):
        decrypt_seipd_packet(packet, bad_key)


def test_decrypt_seipd_packet_tampered_ciphertext_raises_integrity_error() -> None:
    session_key = _create_session_key(SymmetricAlgorithm.AES_256)
    content = b"secret data"
    packet = bytearray(_build_seipd_packet(content, session_key))

    # Flip a bit in the middle of the ciphertext
    packet[len(packet) // 2] ^= 0xFF

    with pytest.raises(IntegrityError):
        decrypt_seipd_packet(bytes(packet), session_key)
