from unittest.mock import AsyncMock, Mock, patch

import pytest

from proton_drive.models.auth import AddressKey, UserKey
from proton_drive.models.drive import Link, LinkState, NodeType, Share, Volume
from proton_drive.services.tree_service import TreeService

SHARE_ID = "share_abc"
VOLUME_ID = "vol_abc"
ADDRESS_ID = "addr_abc"
ADDRESS_KEY_ID = "addrkey_abc"
ROOT_LINK_ID = "link_root"
FOLDER_LINK_ID = "link_folder"
FILE_LINK_ID = "link_file"
ARMORED_KEY = "-----BEGIN PGP MESSAGE-----\ntest\n-----END PGP MESSAGE-----"


def make_volume() -> Volume:
    return Volume(volume_id=VOLUME_ID, share_id=SHARE_ID, state=1)


def make_share() -> Share:
    return Share(
        share_id=SHARE_ID,
        volume_id=VOLUME_ID,
        link_id=ROOT_LINK_ID,
        address_id=ADDRESS_ID,
        address_key_id=ADDRESS_KEY_ID,
        armored_key=ARMORED_KEY,
        encrypted_passphrase="enc_passphrase",
    )


def make_link(
    link_id: str,
    name: str = "encrypted_name",
    node_type: NodeType = NodeType.FILE,
    state: LinkState = LinkState.ACTIVE,
    with_key: bool = True,
) -> Link:
    return Link(
        link_id=link_id,
        parent_link_id=ROOT_LINK_ID,
        share_id=SHARE_ID,
        node_type=node_type,
        encrypted_name=name,
        armored_node_key=ARMORED_KEY if with_key else None,
        encrypted_node_passphrase="enc_pass" if with_key else None,
    )


def make_address_key() -> AddressKey:
    return AddressKey(key_id=ADDRESS_KEY_ID, address_id=ADDRESS_ID, armored_key=ARMORED_KEY)


def make_user_key() -> UserKey:
    return UserKey(key_id="userkey_abc", armored_key=ARMORED_KEY, is_primary=True)


@pytest.fixture
def mock_http() -> Mock:
    return Mock()


@pytest.fixture
def tree_service(mock_http: Mock, mock_key_manager: Mock) -> TreeService:
    return TreeService(mock_http, mock_key_manager)


@pytest.mark.asyncio
async def test_initialize_share_returns_cached_share_if_already_initialized(
    tree_service: TreeService,
) -> None:
    existing_share = make_share()
    tree_service._share = existing_share

    result = await tree_service.initialize_share()
    assert result is existing_share


@pytest.mark.asyncio
async def test_initialize_share_fetches_default_share_when_none_provided(
    tree_service: TreeService,
    mock_key_manager: Mock,
) -> None:
    share = make_share()
    with (
        patch(
            "proton_drive.services.tree_service.get_volumes", new_callable=AsyncMock
        ) as mock_volumes,
        patch("proton_drive.services.tree_service.get_share", new_callable=AsyncMock) as mock_share,
        patch(
            "proton_drive.services.tree_service.get_address_keys", new_callable=AsyncMock
        ) as mock_addr_keys,
        patch(
            "proton_drive.services.tree_service.get_user_keys", new_callable=AsyncMock
        ) as mock_user_keys,
    ):
        mock_volumes.return_value = [make_volume()]
        mock_share.return_value = share
        mock_addr_keys.return_value = [make_address_key()]
        mock_user_keys.return_value = [make_user_key()]
        result = await tree_service.initialize_share()

    assert result is share
    assert tree_service._share is share
    mock_key_manager.unlock_address_key.assert_called_once()
    mock_key_manager.unlock_share_key.assert_called_once()


@pytest.mark.asyncio
async def test_initialize_share_raises_when_no_volumes(tree_service: TreeService) -> None:
    with patch(
        "proton_drive.services.tree_service.get_volumes", new_callable=AsyncMock
    ) as mock_volumes:
        mock_volumes.return_value = []
        with pytest.raises(ValueError, match="No volumes found"):
            await tree_service.initialize_share()


@pytest.mark.asyncio
async def test_build_tree_returns_root_with_children(
    tree_service: TreeService,
    mock_key_manager: Mock,
) -> None:
    tree_service._share = make_share()
    root_link = make_link(ROOT_LINK_ID, node_type=NodeType.FOLDER)
    file_link = make_link(FILE_LINK_ID, name="document.pdf")
    with (
        patch.object(tree_service, "initialize_share", new_callable=AsyncMock),
        patch(
            "proton_drive.services.tree_service.get_link", new_callable=AsyncMock
        ) as mock_get_link,
        patch(
            "proton_drive.services.tree_service.list_folder_children", new_callable=AsyncMock
        ) as mock_list,
    ):
        mock_get_link.return_value = root_link
        mock_list.return_value = [file_link]
        root = await tree_service.build_tree()

    assert root.link_id == ROOT_LINK_ID
    assert len(root.children) == 1
    assert root.children[0].link_id == FILE_LINK_ID
    assert root.children[0].name == "document.pdf"


@pytest.mark.asyncio
async def test_list_directory_returns_root_children_for_slash(
    tree_service: TreeService,
    mock_key_manager: Mock,
) -> None:
    tree_service._share = make_share()
    root_link = make_link(ROOT_LINK_ID, node_type=NodeType.FOLDER)
    file_link = make_link(FILE_LINK_ID, name="notes.txt")
    with (
        patch.object(tree_service, "initialize_share", new_callable=AsyncMock),
        patch(
            "proton_drive.services.tree_service.get_link", new_callable=AsyncMock
        ) as mock_get_link,
        patch(
            "proton_drive.services.tree_service.list_folder_children", new_callable=AsyncMock
        ) as mock_list,
    ):
        mock_get_link.return_value = root_link
        mock_list.return_value = [file_link]
        nodes = await tree_service.list_directory("/")

    assert len(nodes) == 1
    assert nodes[0].link_id == FILE_LINK_ID
    assert nodes[0].name == "notes.txt"


@pytest.mark.asyncio
async def test_list_directory_returns_empty_when_path_not_found(
    tree_service: TreeService,
) -> None:
    tree_service._share = make_share()
    root_link = make_link(ROOT_LINK_ID, node_type=NodeType.FOLDER)
    with (
        patch.object(tree_service, "initialize_share", new_callable=AsyncMock),
        patch(
            "proton_drive.services.tree_service.get_link", new_callable=AsyncMock
        ) as mock_get_link,
        patch(
            "proton_drive.services.tree_service.list_folder_children", new_callable=AsyncMock
        ) as mock_list,
    ):
        mock_get_link.return_value = root_link
        mock_list.return_value = []
        nodes = await tree_service.list_directory("/nonexistent")

    assert nodes == []


@pytest.mark.asyncio
async def test_list_directory_traverses_nested_path(
    tree_service: TreeService,
    mock_key_manager: Mock,
) -> None:
    tree_service._share = make_share()
    root_link = make_link(ROOT_LINK_ID, node_type=NodeType.FOLDER)
    music_link = make_link(FOLDER_LINK_ID, name="Music", node_type=NodeType.FOLDER)
    video_link = make_link(FOLDER_LINK_ID, name="Video", node_type=NodeType.FOLDER)
    file_link = make_link(FILE_LINK_ID, name="song.mp3")
    with (
        patch.object(tree_service, "initialize_share", new_callable=AsyncMock),
        patch(
            "proton_drive.services.tree_service.get_link", new_callable=AsyncMock
        ) as mock_get_link,
        patch(
            "proton_drive.services.tree_service.list_folder_children", new_callable=AsyncMock
        ) as mock_list,
    ):
        mock_get_link.return_value = root_link
        mock_list.side_effect = [
            [music_link, video_link],  # listing root → finds "Music"
            [file_link],  # listing Music → returns "song.mp3"
        ]
        nodes = await tree_service.list_directory("/Music")

    assert len(nodes) == 1
    assert nodes[0].name == "song.mp3"


@pytest.mark.asyncio
async def test_get_node_by_path_returns_none_for_empty_path(tree_service: TreeService) -> None:
    result = await tree_service.get_node_by_path("/")
    assert result is None


@pytest.mark.asyncio
async def test_get_node_by_path_returns_node_at_path(
    tree_service: TreeService,
    mock_key_manager: Mock,
) -> None:
    tree_service._share = make_share()
    root_link = make_link(ROOT_LINK_ID, node_type=NodeType.FOLDER)
    file_link = make_link(FILE_LINK_ID, name="report.pdf")
    with (
        patch.object(tree_service, "initialize_share", new_callable=AsyncMock),
        patch(
            "proton_drive.services.tree_service.get_link", new_callable=AsyncMock
        ) as mock_get_link,
        patch(
            "proton_drive.services.tree_service.list_folder_children", new_callable=AsyncMock
        ) as mock_list,
    ):
        mock_get_link.return_value = root_link
        mock_list.return_value = [file_link]
        node = await tree_service.get_node_by_path("/report.pdf")

    assert node is not None
    assert node.link_id == FILE_LINK_ID
    assert node.name == "report.pdf"


@pytest.mark.asyncio
async def test_get_node_by_path_returns_none_when_not_found(
    tree_service: TreeService,
) -> None:
    tree_service._share = make_share()
    root_link = make_link(ROOT_LINK_ID, node_type=NodeType.FOLDER)
    with (
        patch.object(tree_service, "initialize_share", new_callable=AsyncMock),
        patch(
            "proton_drive.services.tree_service.get_link", new_callable=AsyncMock
        ) as mock_get_link,
        patch(
            "proton_drive.services.tree_service.list_folder_children", new_callable=AsyncMock
        ) as mock_list,
    ):
        mock_get_link.return_value = root_link
        mock_list.return_value = []
        node = await tree_service.get_node_by_path("/missing.txt")

    assert node is None


def test_cleanup_clears_share(tree_service: TreeService) -> None:
    tree_service._share = make_share()
    tree_service.cleanup()
    assert tree_service._share is None
