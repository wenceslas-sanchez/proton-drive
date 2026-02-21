import base64
from collections.abc import Callable
from unittest.mock import Mock

import pytest

from proton_drive.crypto.key_manager import KeyManager
from proton_drive.models.drive import Link, LinkState, NodeType, Share, Volume
from proton_drive.tests.services.constants import (
    ADDRESS_ID,
    ADDRESS_KEY_ID,
    ARMORED_KEY,
    FILE_LINK_ID,
    ROOT_LINK_ID,
    SHARE_ID,
    VOLUME_ID,
)


@pytest.fixture
def make_volume() -> Callable[[], Volume]:
    def _make() -> Volume:
        return Volume(volume_id=VOLUME_ID, share_id=SHARE_ID, state=1)

    return _make


@pytest.fixture
def make_share() -> Callable[[], Share]:
    def _make() -> Share:
        return Share(
            share_id=SHARE_ID,
            volume_id=VOLUME_ID,
            link_id=ROOT_LINK_ID,
            address_id=ADDRESS_ID,
            address_key_id=ADDRESS_KEY_ID,
            armored_key=ARMORED_KEY,
            encrypted_passphrase="enc_passphrase",
            state=1,
        )

    return _make


@pytest.fixture
def make_link() -> Callable[..., Link]:
    def _make(
        link_id: str = FILE_LINK_ID,
        name: str = "encrypted_name",
        node_type: NodeType = NodeType.FILE,
        parent_link_id: str | None = ROOT_LINK_ID,
        state: LinkState = LinkState.ACTIVE,
        with_key: bool = True,
        content_key_packet: str | None = None,
        active_revision_id: str | None = None,
    ) -> Link:
        return Link(
            link_id=link_id,
            parent_link_id=parent_link_id,
            share_id=SHARE_ID,
            node_type=node_type,
            encrypted_name=name,
            armored_node_key=ARMORED_KEY if with_key else None,
            encrypted_node_passphrase="enc_pass" if with_key else None,
            state=state,
            created_at=None,
            modified_at=None,
            content_key_packet=content_key_packet,
            active_revision_id=active_revision_id,
        )

    return _make


@pytest.fixture
def mock_http() -> Mock:
    return Mock()


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
