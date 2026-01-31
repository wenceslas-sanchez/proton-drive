"""
Session key extraction from ContentKeyPacket.

The ContentKeyPacket is a Public-Key Encrypted Session Key (PKESK) packet
that contains the symmetric key used to encrypt file blocks.
"""

from proton_drive.exceptions import SessionKeyError
from proton_drive.models.crypto import PKESKPacket, PublicKeyAlgorithm

_PKESK_TAG = 1
_MIN_PKESK_BODY_LENGTH = 10


def parse_pkesk_packet(packet_bytes: bytes) -> PKESKPacket:
    """
    Parse a PKESK (Public-Key Encrypted Session Key) packet.

    Args:
        packet_bytes: Raw packet bytes.

    Returns:
        Parsed PKESKPacket.

    Raises:
        SessionKeyError: If parsing fails.
    """
    if len(packet_bytes) < 3:
        msg = "PKESK packet too short"
        raise SessionKeyError(msg)

    packet_tag, body_offset, packet_length = _parse_packet_header(packet_bytes)
    _validate_pkesk_tag(packet_tag)

    body = packet_bytes[body_offset : body_offset + packet_length]
    return _parse_pkesk_body(body)


def _parse_packet_header(packet_bytes: bytes) -> tuple[int, int, int]:
    first_byte = packet_bytes[0]

    if _is_new_format_packet(first_byte):
        packet_tag = first_byte & 0x3F
        packet_length, length_bytes = _parse_new_format_length(packet_bytes[1:])
        return packet_tag, 1 + length_bytes, packet_length

    if _is_old_format_packet(first_byte):
        packet_tag = (first_byte & 0x3C) >> 2
        length_type = first_byte & 0x03
        packet_length, length_bytes = _parse_old_format_length(packet_bytes[1:], length_type)
        return packet_tag, 1 + length_bytes, packet_length

    msg = f"Invalid packet header: 0x{first_byte:02x}"
    raise SessionKeyError(msg)


def _is_new_format_packet(first_byte: int) -> bool:
    return (first_byte & 0xC0) == 0xC0


def _is_old_format_packet(first_byte: int) -> bool:
    return (first_byte & 0x80) == 0x80


def _validate_pkesk_tag(packet_tag: int) -> None:
    if packet_tag != _PKESK_TAG:
        msg = f"Expected PKESK packet (tag 1), got tag {packet_tag}"
        raise SessionKeyError(msg)


def _parse_new_format_length(data: bytes) -> tuple[int, int]:
    if not data:
        msg = "Missing length byte"
        raise SessionKeyError(msg)

    first_byte = data[0]

    if first_byte < 192:
        return first_byte, 1

    if first_byte < 224:
        if len(data) < 2:
            msg = "Incomplete two-byte length"
            raise SessionKeyError(msg)
        length = ((first_byte - 192) << 8) + data[1] + 192
        return length, 2

    if first_byte == 255:
        if len(data) < 5:
            msg = "Incomplete five-byte length"
            raise SessionKeyError(msg)
        length = int.from_bytes(data[1:5], "big")
        return length, 5

    msg = "Partial body length not supported"
    raise SessionKeyError(msg)


def _parse_old_format_length(data: bytes, length_type: int) -> tuple[int, int]:
    if length_type == 0:
        if len(data) < 1:
            msg = "Missing length byte"
            raise SessionKeyError(msg)
        return data[0], 1

    if length_type == 1:
        if len(data) < 2:
            msg = "Incomplete two-byte length"
            raise SessionKeyError(msg)
        return int.from_bytes(data[:2], "big"), 2

    if length_type == 2:
        if len(data) < 4:
            msg = "Incomplete four-byte length"
            raise SessionKeyError(msg)
        return int.from_bytes(data[:4], "big"), 4

    msg = "Indeterminate length not supported"
    raise SessionKeyError(msg)


def _parse_pkesk_body(body: bytes) -> PKESKPacket:
    if len(body) < _MIN_PKESK_BODY_LENGTH:
        msg = f"PKESK body too short: {len(body)} bytes"
        raise SessionKeyError(msg)

    version = body[0]
    if version == 3:
        return _parse_pkesk_v3(body)
    if version == 6:
        msg = "PKESK version 6 not yet supported"
        raise SessionKeyError(msg)

    msg = f"Unsupported PKESK version: {version}"
    raise SessionKeyError(msg)


def _parse_pkesk_v3(body: bytes) -> PKESKPacket:
    key_id = body[1:9]
    algorithm_id = body[9]
    encrypted_session_key = body[10:]

    try:
        algorithm = PublicKeyAlgorithm(algorithm_id)
    except ValueError:
        msg = f"Unknown public key algorithm: {algorithm_id}"
        raise SessionKeyError(msg) from None

    return PKESKPacket(
        version=3,
        key_id=key_id,
        algorithm=algorithm,
        encrypted_session_key=encrypted_session_key,
    )


def parse_mpi(data: bytes) -> tuple[bytes, int]:
    """
    Parse an MPI (Multi-Precision Integer) from OpenPGP format.

    MPI format: [bit_count(2 bytes)] + [data]

    Returns:
        Tuple of (mpi_bytes, total_bytes_consumed).
    """
    if len(data) < 2:
        msg = "MPI too short"
        raise SessionKeyError(msg)

    bit_count = int.from_bytes(data[:2], "big")
    byte_count = (bit_count + 7) // 8

    if len(data) < 2 + byte_count:
        msg = f"MPI data incomplete: need {byte_count}, have {len(data) - 2}"
        raise SessionKeyError(msg)

    mpi_bytes = data[2 : 2 + byte_count]
    return mpi_bytes, 2 + byte_count
