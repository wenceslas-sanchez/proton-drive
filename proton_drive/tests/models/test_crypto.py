import pytest

from proton_drive.models.crypto import SessionKey, SymmetricAlgorithm


def test_symmetric_algorithm_returns_correct_key_sizes() -> None:
    assert SymmetricAlgorithm.AES_128.key_size == 16
    assert SymmetricAlgorithm.AES_192.key_size == 24
    assert SymmetricAlgorithm.AES_256.key_size == 32
    assert SymmetricAlgorithm.CAST5.key_size == 16
    assert SymmetricAlgorithm.BLOWFISH.key_size == 16
    assert SymmetricAlgorithm.TRIPLE_DES.key_size == 24
    assert SymmetricAlgorithm.TWOFISH.key_size == 32
    assert SymmetricAlgorithm.CAMELLIA_128.key_size == 16
    assert SymmetricAlgorithm.CAMELLIA_192.key_size == 24
    assert SymmetricAlgorithm.CAMELLIA_256.key_size == 32
    assert SymmetricAlgorithm.PLAINTEXT.key_size == 0


def test_symmetric_algorithm_returns_correct_block_sizes() -> None:
    assert SymmetricAlgorithm.AES_128.block_size == 16
    assert SymmetricAlgorithm.AES_192.block_size == 16
    assert SymmetricAlgorithm.AES_256.block_size == 16
    assert SymmetricAlgorithm.CAST5.block_size == 8
    assert SymmetricAlgorithm.BLOWFISH.block_size == 8
    assert SymmetricAlgorithm.TRIPLE_DES.block_size == 8
    assert SymmetricAlgorithm.TWOFISH.block_size == 16
    assert SymmetricAlgorithm.CAMELLIA_128.block_size == 16
    assert SymmetricAlgorithm.CAMELLIA_192.block_size == 16
    assert SymmetricAlgorithm.CAMELLIA_256.block_size == 16
    assert SymmetricAlgorithm.PLAINTEXT.block_size == 0


def test_session_key_raises_error_on_wrong_key_size() -> None:
    with pytest.raises(ValueError, match="Key size mismatch"):
        SessionKey(algorithm=SymmetricAlgorithm.AES_256, key_data=bytes(16))


def test_session_key_accepts_any_size_for_plaintext() -> None:
    session_key = SessionKey(algorithm=SymmetricAlgorithm.PLAINTEXT, key_data=bytes(10))
    assert len(session_key.key_data) == 10
