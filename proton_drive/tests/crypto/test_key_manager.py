import base64
from unittest.mock import Mock

import pytest

from proton_drive.crypto.key_manager import KeyCache, KeyManager
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.exceptions import KeyDecryptionError, KeyUnlockError
from proton_drive.models.auth import AddressKey, KeySalt, UserKey


def test_key_cache_put_and_get() -> None:
    """Test basic key cache operations."""
    cache = KeyCache(max_size=10)

    mock_key = Mock()
    passphrase = SecureBytes(b"test_passphrase")

    cache.put("link_123", mock_key, passphrase)

    result = cache.get("link_123")
    assert result is not None
    key, retrieved_passphrase = result
    assert key is mock_key
    assert retrieved_passphrase is passphrase


def test_key_cache_clear_securely_wipes_passphrases() -> None:
    """Test clear() securely wipes all passphrases."""
    cache = KeyCache(max_size=10)

    mock_key = Mock()
    passphrase = Mock(spec=SecureBytes)
    passphrase.clear = Mock()

    cache.put("link_1", mock_key, passphrase)
    cache.clear()

    passphrase.clear.assert_called_once()
    assert len(cache) == 0


def _create_mock_backend() -> Mock:
    backend = Mock()
    backend.load_private_key.return_value = Mock()
    backend.unlock_key.return_value.__enter__ = Mock()
    backend.unlock_key.return_value.__exit__ = Mock(return_value=False)
    backend.decrypt_message.return_value = b"decrypted_passphrase"
    return backend


def _create_user_key(key_id: str = "user_key_123") -> UserKey:
    return UserKey(key_id=key_id, armored_key="-----BEGIN PGP PRIVATE KEY-----")


def _create_address_key(
    key_id: str = "addr_key_456",
    address_id: str = "addr_123",
    token: str | None = "encrypted_token",
) -> AddressKey:
    return AddressKey(
        key_id=key_id,
        address_id=address_id,
        armored_key="-----BEGIN PGP PRIVATE KEY-----",
        token=token,
    )


def _create_key_salt(key_id: str = "user_key_123") -> KeySalt:
    salt = base64.b64encode(b"0123456789abcdef").decode()
    return KeySalt(key_id=key_id, salt=salt)


def test_unlock_user_key_returns_passphrase() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()

    result = manager.unlock_user_key(user_key, SecureBytes.from_string("password123"), key_salt)

    assert result.decode() == "AbdTFsE7Z2WQjHtnC6/AIn.FdpyDXHS"


def test_unlock_user_key_raises_key_unlock_error_on_failure() -> None:
    backend = _create_mock_backend()
    backend.load_private_key.side_effect = ValueError("parse error")
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()

    with pytest.raises(KeyUnlockError, match="Failed to unlock user key"):
        manager.unlock_user_key(user_key, SecureBytes.from_string("password123"), key_salt)


def test_unlock_user_key_reraises_key_decryption_error() -> None:
    backend = _create_mock_backend()
    backend.unlock_key.return_value.__enter__.side_effect = KeyDecryptionError("bad passphrase")
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()

    with pytest.raises(KeyDecryptionError):
        manager.unlock_user_key(user_key, SecureBytes.from_string("password123"), key_salt)


def test_unlock_address_key_with_token_decrypts_passphrase() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key(token="encrypted_token")

    manager.unlock_address_key(address_key, user_key.key_id)

    backend.decrypt_message.assert_called()


def test_unlock_address_key_without_token_uses_user_passphrase() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    user_passphrase = manager.unlock_user_key(
        user_key, SecureBytes.from_string("password"), key_salt
    )
    address_key = _create_address_key(token=None)
    backend.decrypt_message.reset_mock()

    result = manager.unlock_address_key(address_key, user_key.key_id)

    backend.decrypt_message.assert_not_called()
    assert result is user_passphrase


def test_unlock_address_key_returns_cached_if_already_unlocked() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key()
    first_result = manager.unlock_address_key(address_key, user_key.key_id)
    backend.load_private_key.reset_mock()

    second_result = manager.unlock_address_key(address_key, user_key.key_id)

    assert second_result is first_result
    backend.load_private_key.assert_not_called()


def test_unlock_address_key_raises_if_user_key_not_unlocked() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    address_key = _create_address_key()

    with pytest.raises(KeyDecryptionError, match="User key not unlocked"):
        manager.unlock_address_key(address_key, "nonexistent_key")


def test_unlock_address_key_raises_on_decryption_failure() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    backend.decrypt_message.side_effect = ValueError("decrypt failed")
    address_key = _create_address_key()

    with pytest.raises(KeyDecryptionError, match="Failed to unlock address key"):
        manager.unlock_address_key(address_key, user_key.key_id)


def test_unlock_share_key_returns_key_and_passphrase() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key()
    manager.unlock_address_key(address_key, user_key.key_id)

    share_key, passphrase = manager.unlock_share_key(
        "share_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        address_key.key_id,
    )

    assert share_key is not None
    assert passphrase.decode() == "decrypted_passphrase"


def test_unlock_share_key_raises_if_address_key_not_unlocked() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)

    with pytest.raises(KeyDecryptionError, match="Address key not unlocked"):
        manager.unlock_share_key(
            "share_123",
            "-----BEGIN PGP PRIVATE KEY-----",
            "encrypted_passphrase",
            "nonexistent_key",
        )


def test_unlock_share_key_raises_on_decryption_failure() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key()
    manager.unlock_address_key(address_key, user_key.key_id)
    backend.decrypt_message.side_effect = ValueError("decrypt failed")

    with pytest.raises(KeyDecryptionError, match="Failed to unlock share key"):
        manager.unlock_share_key(
            "share_123",
            "-----BEGIN PGP PRIVATE KEY-----",
            "encrypted_passphrase",
            address_key.key_id,
        )


def test_unlock_node_key_returns_parent_key_if_no_node_key() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"parent_pass")

    node_key, passphrase = manager.unlock_node_key(
        "link_123", None, "encrypted_passphrase", parent_key, parent_passphrase
    )

    assert node_key is parent_key
    assert passphrase is parent_passphrase


def test_unlock_node_key_decrypts_passphrase_when_provided() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"parent_pass")

    manager.unlock_node_key(
        "link_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        parent_key,
        parent_passphrase,
    )

    backend.decrypt_message.assert_called_once()


def test_unlock_node_key_uses_parent_passphrase_if_no_encrypted_passphrase() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"parent_pass")

    node_key, passphrase = manager.unlock_node_key(
        "link_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        None,
        parent_key,
        parent_passphrase,
    )

    backend.decrypt_message.assert_not_called()
    assert passphrase is parent_passphrase


def test_unlock_node_key_raises_on_decryption_failure() -> None:
    backend = _create_mock_backend()
    backend.decrypt_message.side_effect = ValueError("decrypt failed")
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"parent_pass")

    with pytest.raises(KeyDecryptionError, match="Failed to unlock node key"):
        manager.unlock_node_key(
            "link_123",
            "-----BEGIN PGP PRIVATE KEY-----",
            "encrypted_passphrase",
            parent_key,
            parent_passphrase,
        )


def test_decrypt_name_returns_decrypted_string() -> None:
    backend = _create_mock_backend()
    backend.decrypt_message.return_value = b"my_file.txt"
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"pass")

    result = manager.decrypt_name("encrypted_name", parent_key, parent_passphrase)

    assert result == "my_file.txt"


def test_decrypt_name_returns_empty_string_for_empty_input() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"pass")

    result = manager.decrypt_name("", parent_key, parent_passphrase)

    assert result == ""
    backend.decrypt_message.assert_not_called()


def test_decrypt_name_returns_placeholder_on_failure() -> None:
    backend = _create_mock_backend()
    backend.decrypt_message.side_effect = ValueError("decrypt error")
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"pass")

    result = manager.decrypt_name("encrypted_name", parent_key, parent_passphrase)

    assert result.startswith("[encrypted:")


def test_get_loaded_key_returns_key_if_exists() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)

    result = manager.get_loaded_key(user_key.key_id)

    assert result is not None


def test_get_loaded_key_returns_none_if_not_exists() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)

    result = manager.get_loaded_key("nonexistent")

    assert result is None


def test_get_passphrase_returns_passphrase_if_exists() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)

    result = manager.get_passphrase(user_key.key_id)

    assert result.decode() == "XRXXrqgKlfCAdDBrwFcbhmFeQL8lq2m"


def test_get_passphrase_returns_none_if_not_exists() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)

    result = manager.get_passphrase("nonexistent")

    assert result is None


def test_clear_removes_all_keys_and_passphrases() -> None:
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)

    manager.clear()

    assert manager.get_loaded_key(user_key.key_id) is None
    assert manager.get_passphrase(user_key.key_id) is None


def test_derive_key_passphrase_returns_secure_bytes() -> None:
    key_salt = _create_key_salt()

    result = KeyManager._derive_key_passphrase(SecureBytes.from_string("password123"), key_salt)

    assert result.decode() == "AbdTFsE7Z2WQjHtnC6/AIn.FdpyDXHS"


def test_derive_key_passphrase_returns_31_bytes() -> None:
    key_salt = _create_key_salt()

    result = KeyManager._derive_key_passphrase(SecureBytes.from_string("password123"), key_salt)

    assert len(result) == 31


def test_derive_key_passphrase_is_deterministic() -> None:
    key_salt = _create_key_salt()

    result1 = KeyManager._derive_key_passphrase(SecureBytes.from_string("password123"), key_salt)
    result2 = KeyManager._derive_key_passphrase(SecureBytes.from_string("password123"), key_salt)

    assert result1 == result2


def test_derive_key_passphrase_differs_for_different_passwords() -> None:
    key_salt = _create_key_salt()

    result1 = KeyManager._derive_key_passphrase(SecureBytes.from_string("password1"), key_salt)
    result2 = KeyManager._derive_key_passphrase(SecureBytes.from_string("password2"), key_salt)

    assert result1 != result2


def test_derive_key_passphrase_differs_for_different_salts() -> None:
    salt1 = KeySalt(key_id="k1", salt=base64.b64encode(b"salt1___________").decode())
    salt2 = KeySalt(key_id="k2", salt=base64.b64encode(b"salt2___________").decode())

    result1 = KeyManager._derive_key_passphrase(SecureBytes.from_string("password"), salt1)
    result2 = KeyManager._derive_key_passphrase(SecureBytes.from_string("password"), salt2)

    assert result1 != result2


def test_unlock_share_key_caches_result() -> None:
    """Test that unlock_share_key caches the result for subsequent calls."""
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key()
    manager.unlock_address_key(address_key, user_key.key_id)

    # First call
    share_key1, passphrase1 = manager.unlock_share_key(
        "share_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        address_key.key_id,
    )

    # Reset mock to verify cache hit
    backend.decrypt_message.reset_mock()
    backend.load_private_key.reset_mock()

    # Second call with same share_id should hit cache
    share_key2, passphrase2 = manager.unlock_share_key(
        "share_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        address_key.key_id,
    )

    # Should return cached values without calling backend
    assert share_key1 is share_key2
    assert passphrase1 is passphrase2
    backend.decrypt_message.assert_not_called()
    backend.load_private_key.assert_not_called()


def test_unlock_node_key_caches_result() -> None:
    """Test that unlock_node_key caches the result for subsequent calls."""
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    parent_key = Mock()
    parent_passphrase = SecureBytes(b"parent_pass")

    # First call
    node_key1, passphrase1 = manager.unlock_node_key(
        "link_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        parent_key,
        parent_passphrase,
    )

    # Reset mock to verify cache hit
    backend.decrypt_message.reset_mock()
    backend.load_private_key.reset_mock()

    # Second call with same link_id should hit cache
    node_key2, passphrase2 = manager.unlock_node_key(
        "link_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        parent_key,
        parent_passphrase,
    )

    # Should return cached values without calling backend
    assert node_key1 is node_key2
    assert passphrase1 is passphrase2
    backend.decrypt_message.assert_not_called()
    backend.load_private_key.assert_not_called()


def test_get_cached_key_returns_cached_share_key() -> None:
    """Test get_cached_key returns share keys."""
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key()
    manager.unlock_address_key(address_key, user_key.key_id)

    share_key, passphrase = manager.unlock_share_key(
        "share_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        address_key.key_id,
    )

    cached = manager.get_cached_key("share_123")
    assert cached is not None
    cached_key, cached_passphrase = cached
    assert cached_key is share_key
    assert cached_passphrase is passphrase


def test_get_cached_key_returns_none_if_not_cached() -> None:
    """Test get_cached_key returns None for non-existent keys."""
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)

    result = manager.get_cached_key("nonexistent")
    assert result is None


def test_clear_clears_cached_keys() -> None:
    """Test that clear() also clears the internal key cache."""
    backend = _create_mock_backend()
    manager = KeyManager(pgp_backend=backend)
    user_key = _create_user_key()
    key_salt = _create_key_salt()
    manager.unlock_user_key(user_key, SecureBytes.from_string("password"), key_salt)
    address_key = _create_address_key()
    manager.unlock_address_key(address_key, user_key.key_id)

    # Cache a share key
    manager.unlock_share_key(
        "share_123",
        "-----BEGIN PGP PRIVATE KEY-----",
        "encrypted_passphrase",
        address_key.key_id,
    )

    manager.clear()

    # All caches should be cleared
    assert manager.get_loaded_key(user_key.key_id) is None
    assert manager.get_passphrase(user_key.key_id) is None
    assert manager.get_cached_key("share_123") is None
