import base64
from unittest.mock import Mock

import pytest

from proton_drive.crypto.key_manager import KeyManager


@pytest.fixture
def mock_key_manager() -> Mock:
    manager = Mock(spec=KeyManager)
    manager.unlock_user_key = Mock()
    manager.clear = Mock()
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
