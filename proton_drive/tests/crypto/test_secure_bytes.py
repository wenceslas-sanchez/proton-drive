import gc

import pytest

from proton_drive.crypto.secure_bytes import SecureBytes, _secure_zero


def test_create_from_bytes_provides_access_to_data() -> None:
    secret_data = b"secret"
    secure_bytes = SecureBytes(secret_data)

    assert bytes(secure_bytes) == b"secret"
    assert len(secure_bytes) == 6
    assert secure_bytes.decode() == "secret"
    assert list(secure_bytes) == [115, 101, 99, 114, 101, 116]
    assert not secure_bytes.is_cleared
    secure_bytes.clear()


def test_from_string_creates_secure_bytes() -> None:
    secure_bytes = SecureBytes.from_string("password")

    assert bytes(secure_bytes) == b"password"
    secure_bytes.clear()


def test_original_data_not_modified_after_clear() -> None:
    original = bytearray(b"secret")
    secure_bytes = SecureBytes(original)
    secure_bytes.clear()

    assert original == bytearray(b"secret")


def test_clear_zeros_data_and_sets_flag() -> None:
    secure_bytes = SecureBytes(b"secret")
    secure_bytes.clear()

    assert secure_bytes.is_cleared
    assert secure_bytes._data == bytearray(6)
    assert all(byte == 0 for byte in secure_bytes._data)


def test_clear_is_idempotent() -> None:
    secure_bytes = SecureBytes(b"secret")
    secure_bytes.clear()
    secure_bytes.clear()

    assert secure_bytes.is_cleared


def test_context_manager_clears_on_exit() -> None:
    secure_bytes = SecureBytes(b"secret")
    assert not secure_bytes.is_cleared
    with secure_bytes:
        pass
    assert secure_bytes.is_cleared


def test_destructor_clears_data() -> None:
    secure_bytes = SecureBytes(b"secret")
    data_reference = secure_bytes._data

    del secure_bytes
    gc.collect()

    assert all(byte == 0 for byte in data_reference)


def test_bytes_conversion_after_clear_raises_runtime_error() -> None:
    secure_bytes = SecureBytes(b"hello")
    secure_bytes.clear()

    with pytest.raises(RuntimeError, match="SecureBytes has been cleared"):
        bytes(secure_bytes)


def test_decode_after_clear_raises_runtime_error() -> None:
    secure_bytes = SecureBytes(b"hello")
    secure_bytes.clear()

    with pytest.raises(RuntimeError, match="SecureBytes has been cleared"):
        secure_bytes.decode()


def test_iteration_after_clear_raises_runtime_error() -> None:
    secure_bytes = SecureBytes(b"hello")
    secure_bytes.clear()

    with pytest.raises(RuntimeError, match="SecureBytes has been cleared"):
        list(secure_bytes)


def test_equality_with_same_secure_bytes() -> None:
    secure_bytes_1 = SecureBytes(b"secret")
    secure_bytes_2 = SecureBytes(b"secret")

    assert secure_bytes_1 == secure_bytes_2
    secure_bytes_1.clear()
    secure_bytes_2.clear()


def test_equality_with_bytes() -> None:
    secure_bytes = SecureBytes(b"secret")

    assert secure_bytes == b"secret"
    assert secure_bytes != b"other"
    secure_bytes.clear()


def test_cleared_secure_bytes_not_equal() -> None:
    secure_bytes_1 = SecureBytes(b"secret")
    secure_bytes_2 = SecureBytes(b"secret")
    secure_bytes_1.clear()

    assert secure_bytes_1 != secure_bytes_2
    secure_bytes_2.clear()


def test_bool_true_when_has_data() -> None:
    secure_bytes = SecureBytes(b"secret")
    assert bool(secure_bytes) is True
    secure_bytes.clear()


def test_bool_false_when_cleared() -> None:
    secure_bytes = SecureBytes(b"secret")
    secure_bytes.clear()
    assert bool(secure_bytes) is False


def test_repr_shows_byte_count() -> None:
    secure_bytes = SecureBytes(b"secret")
    assert repr(secure_bytes) == "SecureBytes(<6 bytes>)"
    secure_bytes.clear()


def test_repr_shows_cleared_state() -> None:
    secure_bytes = SecureBytes(b"secret")
    secure_bytes.clear()
    assert repr(secure_bytes) == "SecureBytes(<cleared>)"


def test_secure_zero_clears_bytearray() -> None:
    data = bytearray(b"sensitive")
    _secure_zero(data)
    assert all(byte == 0 for byte in data)


def test_secure_zero_handles_empty_bytearray() -> None:
    data = bytearray()
    _secure_zero(data)
    assert len(data) == 0
