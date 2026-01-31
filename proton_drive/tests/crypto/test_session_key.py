import pytest

from proton_drive.crypto.session_key import (
    _is_new_format_packet,
    _is_old_format_packet,
    _parse_pkesk_v3,
    _validate_pkesk_tag,
    parse_mpi,
    parse_pkesk_packet,
)
from proton_drive.exceptions import SessionKeyError
from proton_drive.models.crypto import PublicKeyAlgorithm


def _build_pkesk_v3_packet(
    key_id: bytes = b"12345678",
    algorithm: int = 1,
    encrypted_sk: bytes = b"encrypted_data",
) -> bytes:
    body = bytes([3]) + key_id + bytes([algorithm]) + encrypted_sk
    header = bytes([0xC1, len(body)])  # Tag 1, new format
    return header + body


def test_parse_pkesk_packet_parses_valid_v3_packet() -> None:
    packet = _build_pkesk_v3_packet()

    result = parse_pkesk_packet(packet)

    assert result.version == 3
    assert result.key_id == b"12345678"
    assert result.algorithm == PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN
    assert result.encrypted_session_key == b"encrypted_data"


def test_parse_pkesk_packet_raises_on_too_short() -> None:
    with pytest.raises(SessionKeyError, match="too short"):
        parse_pkesk_packet(bytes(2))


def test_parse_pkesk_packet_raises_on_invalid_header() -> None:
    with pytest.raises(SessionKeyError, match="Invalid packet header"):
        parse_pkesk_packet(bytes([0x00, 0x10, 0x00]))


def test_parse_pkesk_packet_raises_on_wrong_tag() -> None:
    packet = bytes([0xC2, 0x10]) + bytes(16)  # Tag 2, not PKESK
    with pytest.raises(SessionKeyError, match="Expected PKESK packet"):
        parse_pkesk_packet(packet)


def test_is_new_format_packet_detects_correctly() -> None:
    assert _is_new_format_packet(0xC1) is True
    assert _is_new_format_packet(0x84) is False


def test_is_old_format_packet_detects_correctly() -> None:
    assert _is_old_format_packet(0x84) is True
    assert _is_old_format_packet(0x00) is False


def test_validate_pkesk_tag_passes_for_tag_1() -> None:
    _validate_pkesk_tag(1)


def test_validate_pkesk_tag_raises_for_other_tags() -> None:
    with pytest.raises(SessionKeyError, match="Expected PKESK"):
        _validate_pkesk_tag(2)


def test_parse_pkesk_v3_parses_valid_body() -> None:
    body = bytes([3]) + b"12345678" + bytes([1]) + b"encrypted"

    result = _parse_pkesk_v3(body)

    assert result.version == 3
    assert result.key_id == b"12345678"
    assert result.algorithm == PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN


def test_parse_pkesk_v3_raises_on_unknown_algorithm() -> None:
    body = bytes([3]) + b"12345678" + bytes([99]) + b"encrypted"

    with pytest.raises(SessionKeyError, match="Unknown public key algorithm"):
        _parse_pkesk_v3(body)


def test_parse_mpi_parses_valid_mpi() -> None:
    data = bytes([0x00, 0x10]) + bytes(2)  # 16 bits = 2 bytes

    mpi_bytes, consumed = parse_mpi(data)

    assert mpi_bytes == bytes(2)
    assert consumed == 4


def test_parse_mpi_raises_on_too_short() -> None:
    with pytest.raises(SessionKeyError, match="MPI too short"):
        parse_mpi(bytes(1))


def test_parse_mpi_raises_on_incomplete_data() -> None:
    data = bytes([0x00, 0x20]) + bytes(2)  # Claims 32 bits but only 2 bytes
    with pytest.raises(SessionKeyError, match="MPI data incomplete"):
        parse_mpi(data)
