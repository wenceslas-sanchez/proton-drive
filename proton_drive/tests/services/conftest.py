import base64
from unittest.mock import Mock

import pytest

from proton_drive.crypto.key_manager import KeyManager


@pytest.fixture
def mock_key_manager() -> Mock:
    mock_key = Mock()
    mock_passphrase = Mock()
    manager = Mock(spec=KeyManager)
    manager.unlock_user_key = Mock()
    manager.clear = Mock()
    manager.get_cached_key.return_value = (mock_key, mock_passphrase)
    manager.unlock_node_key.return_value = (mock_key, mock_passphrase)
    manager.decrypt_name.side_effect = lambda encrypted_name, *_: encrypted_name
    return manager


@pytest.fixture
def mock_gpg() -> Mock:
    gpg = Mock()
    verified = Mock()
    verified.valid = True
    verified.fingerprint = "test_fingerprint"
    verified.data = base64.b64encode(b"test_modulus")
    gpg.decrypt.return_value = verified
    return gpg
