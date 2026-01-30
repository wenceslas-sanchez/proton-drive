import pgpy
import pytest
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)

from proton_drive.crypto.pgpy_backend import PgpyBackend, PgpyPrivateKey
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.exceptions import CryptoError, KeyDecryptionError, SessionKeyError
from proton_drive.models.crypto import SymmetricAlgorithm


def _create_test_key(passphrase: str) -> pgpy.PGPKey:
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new("Test User", comment="test", email="test@test.com")
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


def test_load_private_key_returns_pgpy_private_key() -> None:
    key = _create_test_key("pass")
    backend = PgpyBackend()

    result = backend.load_private_key(str(key))

    assert isinstance(result, PgpyPrivateKey)
    assert result.key_id
    assert result.fingerprint


def test_load_private_key_raises_crypto_error_on_invalid_key() -> None:
    backend = PgpyBackend()

    with pytest.raises(CryptoError, match="Failed to load private key"):
        backend.load_private_key("not a valid key")


def test_decrypt_message_returns_plaintext() -> None:
    passphrase = "test-passphrase"
    key = _create_test_key(passphrase)
    plaintext = b"Hello, World!"
    message = pgpy.PGPMessage.new(plaintext)
    encrypted = str(key.pubkey.encrypt(message))
    assert plaintext != encrypted

    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))
    result = backend.decrypt_message(encrypted, private_key, SecureBytes(passphrase.encode()))

    assert result == plaintext


def test_decrypt_message_raises_on_wrong_passphrase() -> None:
    key = _create_test_key("correct")
    message = pgpy.PGPMessage.new(b"secret")
    encrypted = str(key.pubkey.encrypt(message))
    assert message != encrypted

    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))

    with pytest.raises(KeyDecryptionError):
        backend.decrypt_message(encrypted, private_key, SecureBytes(b"wrong"))


def test_unlock_key_yields_unlocked_key() -> None:
    passphrase = "unlock-test"
    key = _create_test_key(passphrase)

    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))

    with backend.unlock_key(private_key, SecureBytes(passphrase.encode())) as unlocked:
        assert unlocked is private_key


def test_unlock_key_raises_on_wrong_passphrase() -> None:
    key = _create_test_key("correct")

    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))

    with pytest.raises(KeyDecryptionError, match="Failed to unlock key"):
        with backend.unlock_key(private_key, SecureBytes(b"wrong")):
            pass


def _build_session_key_payload(algo_id: int, key_data: bytes) -> bytes:
    """Build a session key payload: [algo(1)] + [key(N)] + [checksum(2)]."""
    checksum = sum(key_data) % 65536
    return bytes([algo_id]) + key_data + checksum.to_bytes(2, "big")


def test_parse_session_key_payload_returns_valid_aes256_key() -> None:
    key_data = bytes(range(32))
    payload = _build_session_key_payload(9, key_data)  # 9 = AES-256

    backend = PgpyBackend()
    result = backend._parse_session_key_payload(payload)

    assert result.algorithm == SymmetricAlgorithm.AES_256
    assert result.key_data == key_data


def test_parse_session_key_payload_returns_valid_aes128_key() -> None:
    key_data = bytes(range(16))
    payload = _build_session_key_payload(7, key_data)  # 7 = AES-128

    backend = PgpyBackend()
    result = backend._parse_session_key_payload(payload)

    assert result.algorithm == SymmetricAlgorithm.AES_128
    assert result.key_data == key_data


def test_parse_session_key_payload_raises_on_too_short() -> None:
    backend = PgpyBackend()

    with pytest.raises(SessionKeyError, match="too short"):
        backend._parse_session_key_payload(bytes([9, 0]))


def test_parse_session_key_payload_raises_on_unknown_algorithm() -> None:
    payload = bytes([99]) + bytes(16) + bytes(2)  # 99 = invalid algo

    backend = PgpyBackend()

    with pytest.raises(SessionKeyError, match="Unknown symmetric algorithm"):
        backend._parse_session_key_payload(payload)


def test_parse_session_key_payload_raises_on_checksum_mismatch() -> None:
    key_data = bytes(range(32))
    bad_checksum = bytes([0xFF, 0xFF])
    payload = bytes([9]) + key_data + bad_checksum

    backend = PgpyBackend()

    with pytest.raises(SessionKeyError, match="checksum mismatch"):
        backend._parse_session_key_payload(payload)
