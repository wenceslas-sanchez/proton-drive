from unittest.mock import AsyncMock, Mock

import pytest

from proton_drive.api.endpoints.drive import (
    download_block,
    get_file_revisions,
    get_link,
    get_revision_blocks,
    get_share,
    get_volumes,
    list_folder_children,
)
from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.models.drive import NodeType
from proton_drive.tests.api.endpoints.conftest import make_success_response


@pytest.mark.asyncio
async def test_get_volumes_returns_volumes(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Volumes": [
                    {
                        "VolumeID": "vol-1",
                        "Share": {"ShareID": "share-1"},
                        "State": 1,
                    },
                ],
            }
        )
    )

    volumes = await get_volumes(mock_http)

    assert len(volumes) == 1
    assert volumes[0].volume_id == "vol-1"
    assert volumes[0].share_id == "share-1"


@pytest.mark.asyncio
async def test_get_share_returns_share(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "ShareID": "share-1",
                "LinkID": "link-1",
                "VolumeID": "vol-1",
                "Key": "share-key",
                "Passphrase": "share-passphrase",
                "AddressID": "addr-1",
                "AddressKeyID": "addr-key-1",
                "State": 1,
            }
        )
    )

    share = await get_share(mock_http, "share-1")

    assert share.share_id == "share-1"
    assert share.link_id == "link-1"
    assert share.armored_key == "share-key"
    assert share.encrypted_passphrase == "share-passphrase"


@pytest.mark.asyncio
async def test_get_link_returns_link(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Link": {
                    "LinkID": "link-1",
                    "ParentLinkID": "parent-1",
                    "Type": 2,
                    "Name": "encrypted-name",
                    "NodeKey": "node-key",
                    "NodePassphrase": "node-passphrase",
                    "Size": 1024,
                    "MIMEType": "text/plain",
                    "State": 1,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "FileProperties": {
                        "ContentKeyPacket": "content-key",
                        "ActiveRevision": {"ID": "rev-1"},
                    },
                },
            }
        )
    )

    link = await get_link(mock_http, "share-1", "link-1")

    assert link.link_id == "link-1"
    assert link.parent_link_id == "parent-1"
    assert link.node_type == NodeType.FILE
    assert link.encrypted_name == "encrypted-name"
    assert link.size == 1024
    assert link.content_key_packet == "content-key"
    assert link.active_revision_id == "rev-1"


@pytest.mark.asyncio
async def test_get_link_handles_folder_without_file_properties(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Link": {
                    "LinkID": "folder-1",
                    "Type": 1,
                    "Name": "folder-name",
                    "NodeKey": "node-key",
                    "NodePassphrase": "node-passphrase",
                    "State": 1,
                    "FileProperties": None,
                },
            }
        )
    )

    link = await get_link(mock_http, "share-1", "folder-1")

    assert link.link_id == "folder-1"
    assert link.node_type == NodeType.FOLDER
    assert link.content_key_packet is None
    assert link.active_revision_id is None


@pytest.mark.asyncio
async def test_list_folder_children_returns_links(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Links": [
                    {
                        "LinkID": "file-1",
                        "Type": 2,
                        "Name": "file-name",
                        "NodeKey": "key",
                        "NodePassphrase": "pass",
                        "State": 1,
                        "CreateTime": 1700000000,
                        "ModifyTime": 1700000001,
                        "FileProperties": {"ContentKeyPacket": "ck"},
                    },
                    {
                        "LinkID": "folder-1",
                        "Type": 1,
                        "Name": "folder-name",
                        "NodeKey": "key",
                        "NodePassphrase": "pass",
                        "State": 1,
                        "CreateTime": 1700000000,
                        "ModifyTime": 1700000001,
                        "FileProperties": None,
                    },
                ],
            }
        )
    )

    children = await list_folder_children(mock_http, "share-1", "parent-1")

    assert len(children) == 2
    assert children[0].node_type == NodeType.FILE
    assert children[1].node_type == NodeType.FOLDER


@pytest.mark.asyncio
async def test_list_folder_children_paginates(mock_http: Mock) -> None:
    first_response = make_success_response(
        {
            "Links": [
                {
                    "LinkID": f"link-{i}",
                    "Type": 2,
                    "State": 1,
                    "Name": f"file-{i}",
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "FileProperties": None,
                }
                for i in range(150)
            ],
        }
    )
    second_response = make_success_response(
        {
            "Links": [
                {
                    "LinkID": "link-150",
                    "Type": 2,
                    "State": 1,
                    "Name": "file-150",
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "FileProperties": None,
                }
            ],
        }
    )

    mock_http.request = AsyncMock(side_effect=[first_response, second_response])

    children = await list_folder_children(mock_http, "share-1", "parent-1")

    assert len(children) == 151
    assert mock_http.request.call_count == 2


@pytest.mark.asyncio
async def test_get_file_revisions_returns_revisions(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Revisions": [
                    {"ID": "rev-1", "Size": 1024, "State": 1, "CreateTime": 1700000000},
                    {"ID": "rev-2", "Size": 2048, "State": 0, "CreateTime": 1700000001},
                ],
            }
        )
    )

    revisions = await get_file_revisions(mock_http, "share-1", "file-1")

    assert len(revisions) == 2
    assert revisions[0].revision_id == "rev-1"
    assert revisions[0].size == 1024
    assert revisions[0].state == 1


@pytest.mark.asyncio
async def test_get_revision_blocks_returns_blocks(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Blocks": [
                    {
                        "Index": 1,
                        "URL": "https://storage/block1",
                        "EncSignature": "sig1",
                        "Hash": "hash1",
                        "Size": 1024,
                    },
                    {
                        "Index": 2,
                        "URL": "https://storage/block2",
                        "EncSignature": "sig2",
                        "Hash": "hash2",
                        "Size": 2048,
                    },
                ],
            }
        )
    )

    blocks = await get_revision_blocks(mock_http, "share-1", "file-1", "rev-1")

    assert len(blocks) == 2
    assert blocks[0].index == 1
    assert blocks[0].url == "https://storage/block1"
    assert blocks[0].encrypted_hash == "hash1"


@pytest.mark.asyncio
async def test_download_block_returns_bytes(mock_http: Mock) -> None:
    mock_http.request_raw = AsyncMock(return_value=b"encrypted content")

    result = await download_block(mock_http, "https://storage/block1")

    mock_http.request_raw.assert_called_once_with("GET", "https://storage/block1")
    assert result == b"encrypted content"


@pytest.mark.asyncio
async def test_link_parses_timestamps(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Link": {
                    "LinkID": "link-1",
                    "Type": 1,
                    "State": 1,
                    "Name": "folder-1",
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "FileProperties": None,
                },
            }
        )
    )

    link = await get_link(mock_http, "share-1", "link-1")

    assert link.created_at is not None
    assert link.modified_at is not None
    assert link.created_at.year >= 2023


@pytest.mark.asyncio
async def test_link_handles_missing_timestamps(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Link": {
                    "LinkID": "link-1",
                    "Type": 1,
                    "State": 1,
                    "Name": "folder-1",
                    "FileProperties": None,
                },
            }
        )
    )

    link = await get_link(mock_http, "share-1", "link-1")

    assert link.created_at is None
    assert link.modified_at is None


@pytest.mark.asyncio
async def test_get_volumes_with_real_response(replay_http: AsyncHttpClient) -> None:
    volumes = await get_volumes(replay_http)

    assert len(volumes) >= 1
    assert volumes[0].volume_id is not None
    assert volumes[0].share_id is not None


@pytest.mark.asyncio
async def test_get_share_with_real_response(replay_http: AsyncHttpClient) -> None:
    volumes = await get_volumes(replay_http)
    share = await get_share(replay_http, volumes[0].share_id)

    assert share.share_id == volumes[0].share_id
    assert share.link_id is not None
    assert share.armored_key is not None


@pytest.mark.asyncio
async def test_list_folder_children_with_real_response(replay_http: AsyncHttpClient) -> None:
    volumes = await get_volumes(replay_http)
    share = await get_share(replay_http, volumes[0].share_id)
    children = await list_folder_children(replay_http, share.share_id, share.link_id)

    assert len(children) >= 1
    node_types = {c.node_type for c in children}
    assert NodeType.FOLDER in node_types or NodeType.FILE in node_types


@pytest.mark.asyncio
async def test_get_link_with_real_response(replay_http: AsyncHttpClient) -> None:
    volumes = await get_volumes(replay_http)
    share = await get_share(replay_http, volumes[0].share_id)
    children = await list_folder_children(replay_http, share.share_id, share.link_id)

    link = await get_link(replay_http, share.share_id, children[0].link_id)

    assert link.link_id == children[0].link_id
    assert link.armored_node_key is not None


@pytest.mark.asyncio
async def test_get_file_revisions_with_real_response(replay_http: AsyncHttpClient) -> None:
    volumes = await get_volumes(replay_http)
    share = await get_share(replay_http, volumes[0].share_id)
    children = await list_folder_children(replay_http, share.share_id, share.link_id)

    folder = next((c for c in children if c.node_type == NodeType.FOLDER), None)
    assert folder is not None

    folder_children = await list_folder_children(replay_http, share.share_id, folder.link_id)
    file = next((c for c in folder_children if c.node_type == NodeType.FILE), None)
    assert file is not None

    revisions = await get_file_revisions(replay_http, share.share_id, file.link_id)

    assert len(revisions) >= 1
    assert revisions[0].revision_id is not None


@pytest.mark.asyncio
async def test_get_revision_blocks_with_real_response(replay_http: AsyncHttpClient) -> None:
    volumes = await get_volumes(replay_http)
    share = await get_share(replay_http, volumes[0].share_id)
    children = await list_folder_children(replay_http, share.share_id, share.link_id)

    folder = next((c for c in children if c.node_type == NodeType.FOLDER), None)
    assert folder is not None

    folder_children = await list_folder_children(replay_http, share.share_id, folder.link_id)

    for file in folder_children:
        if file.node_type != NodeType.FILE:
            continue

        revisions = await get_file_revisions(replay_http, share.share_id, file.link_id)
        active = next((r for r in revisions if r.state == 1), None)
        if not active:
            continue

        blocks = await get_revision_blocks(
            replay_http, share.share_id, file.link_id, active.revision_id
        )
        if blocks:
            assert blocks[0].url is not None
            assert blocks[0].index >= 1
            return

    pytest.fail("No file with blocks found")
