from unittest.mock import Mock, patch

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
from proton_drive.models.crypto import PKESKPacket, PublicKeyAlgorithm, SymmetricAlgorithm


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


def _build_session_key_payload(algo_id: int, key_data: bytes) -> bytes:
    checksum = sum(key_data) % 65536
    return bytes([algo_id]) + key_data + checksum.to_bytes(2, "big")


def test_load_private_key_returns_pgpy_private_key() -> None:
    key = _create_test_key("pass")
    result = PgpyBackend.load_private_key(str(key))

    assert isinstance(result, PgpyPrivateKey)
    assert result.key_id
    assert result.fingerprint


def test_load_private_key_raises_crypto_error_on_invalid_key() -> None:
    with pytest.raises(CryptoError, match="Failed to load private key"):
        PgpyBackend.load_private_key("not a valid key")


def test_decrypt_message_returns_plaintext() -> None:
    passphrase = "test-passphrase"
    key = _create_test_key(passphrase)
    plaintext = b"Hello, World!"
    message = pgpy.PGPMessage.new(plaintext)
    encrypted = str(key.pubkey.encrypt(message))

    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))
    result = backend.decrypt_message(encrypted, private_key, SecureBytes(passphrase.encode()))

    assert result == plaintext


def test_decrypt_message_raises_on_wrong_passphrase() -> None:
    key = _create_test_key("correct")
    message = pgpy.PGPMessage.new(b"secret")
    encrypted = str(key.pubkey.encrypt(message))

    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))

    with pytest.raises(KeyDecryptionError):
        backend.decrypt_message(encrypted, private_key, SecureBytes(b"wrong"))


def test_extract_session_key_returns_session_key() -> None:
    passphrase = "test"
    key = _create_test_key(passphrase)
    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))

    key_data = bytes(range(32))
    payload = _build_session_key_payload(9, key_data)
    mock_pkesk = PKESKPacket(
        version=3,
        key_id=b"12345678",
        algorithm=PublicKeyAlgorithm.ECDH,
        encrypted_session_key=b"encrypted",
    )

    with (
        patch("proton_drive.crypto.pgpy_backend.parse_pkesk_packet", return_value=mock_pkesk),
        patch.object(PgpyBackend, "_decrypt_session_key", return_value=payload),
    ):
        result = backend.extract_session_key(
            b"dummy_packet", private_key, SecureBytes(passphrase.encode())
        )

    assert result.algorithm == SymmetricAlgorithm.AES_256
    assert result.key_data == key_data


def test_extract_session_key_raises_session_key_error_on_failure() -> None:
    passphrase = "test"
    key = _create_test_key(passphrase)
    backend = PgpyBackend()
    private_key = backend.load_private_key(str(key))

    with patch(
        "proton_drive.crypto.pgpy_backend.parse_pkesk_packet",
        side_effect=ValueError("parse error"),
    ):
        with pytest.raises(SessionKeyError, match="Failed to extract session key"):
            backend.extract_session_key(
                b"bad_packet", private_key, SecureBytes(passphrase.encode())
            )


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


def test_normalize_decrypted_content_returns_bytes_unchanged() -> None:
    assert PgpyBackend._normalize_decrypted_content(b"hello") == b"hello"


def test_normalize_decrypted_content_encodes_string() -> None:
    assert PgpyBackend._normalize_decrypted_content("hello") == b"hello"


def test_find_encryption_key_returns_private_subkey() -> None:
    mock_subkey = Mock(is_public=False)
    mock_key = Mock()
    mock_key.subkeys = {"sub1": mock_subkey}

    result = PgpyBackend._find_encryption_key(mock_key)

    assert result is mock_subkey


def test_find_encryption_key_returns_primary_when_no_private_subkey() -> None:
    mock_key = Mock()
    mock_key.subkeys = {}

    result = PgpyBackend._find_encryption_key(mock_key)

    assert result is mock_key


def test_validate_payload_length_passes_for_valid_length() -> None:
    PgpyBackend._validate_payload_length(bytes(3))


def test_validate_payload_length_raises_for_short_payload() -> None:
    with pytest.raises(SessionKeyError, match="too short"):
        PgpyBackend._validate_payload_length(bytes(2))


def test_parse_algorithm_returns_valid_algorithm() -> None:
    assert PgpyBackend._parse_algorithm(9) == SymmetricAlgorithm.AES_256


def test_parse_algorithm_raises_for_unknown_id() -> None:
    with pytest.raises(SessionKeyError, match="Unknown symmetric algorithm"):
        PgpyBackend._parse_algorithm(99)


def test_determine_key_size_returns_algorithm_key_size() -> None:
    result = PgpyBackend._determine_key_size(SymmetricAlgorithm.AES_256, payload_length=100)
    assert result == 32


def test_determine_key_size_infers_from_payload_length() -> None:
    result = PgpyBackend._determine_key_size(SymmetricAlgorithm.PLAINTEXT, payload_length=19)
    assert result == 16


def test_determine_key_size_raises_for_invalid_inferred_size() -> None:
    with pytest.raises(SessionKeyError, match="Cannot determine key size"):
        PgpyBackend._determine_key_size(SymmetricAlgorithm.PLAINTEXT, payload_length=10)


def test_verify_checksum_passes_for_valid_checksum() -> None:
    key_data = bytes([1, 2, 3])
    checksum = (6).to_bytes(2, "big")
    PgpyBackend._verify_checksum(key_data, checksum)


def test_verify_checksum_raises_for_invalid_checksum() -> None:
    with pytest.raises(SessionKeyError, match="checksum mismatch"):
        PgpyBackend._verify_checksum(bytes([1, 2, 3]), bytes([0xFF, 0xFF]))


def test_parse_session_key_payload_returns_valid_aes256_key() -> None:
    key_data = bytes(range(32))
    payload = _build_session_key_payload(9, key_data)

    result = PgpyBackend()._parse_session_key_payload(payload)

    assert result.algorithm == SymmetricAlgorithm.AES_256
    assert result.key_data == key_data


def test_parse_session_key_payload_returns_valid_aes128_key() -> None:
    key_data = bytes(range(16))
    payload = _build_session_key_payload(7, key_data)

    result = PgpyBackend()._parse_session_key_payload(payload)

    assert result.algorithm == SymmetricAlgorithm.AES_128
    assert result.key_data == key_data
