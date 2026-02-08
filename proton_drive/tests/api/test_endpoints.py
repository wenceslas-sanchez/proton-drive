from pathlib import Path
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio

from proton_drive.api.endpoints import ProtonAPIEndpoints
from proton_drive.api.http_client import AsyncHttpClient, ProtonAPICode
from proton_drive.config import ProtonDriveConfig
from proton_drive.models.drive import NodeType
from proton_drive.tests.utils.recording_transport import ReplayTransport

FIXTURES_DIR = Path(__file__).parent / "data"


@pytest.fixture
def mock_http() -> Mock:
    return Mock()


@pytest.fixture
def api(mock_http: Mock) -> ProtonAPIEndpoints:
    return ProtonAPIEndpoints(mock_http)


def make_success_response(data: dict[str, Any]) -> dict[str, Any]:
    return {"Code": ProtonAPICode.SUCCESS, **data}


@pytest.mark.asyncio
async def test_get_auth_info_calls_correct_endpoint(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Modulus": "test-modulus",
                "ServerEphemeral": "test-ephemeral",
                "Salt": "test-salt",
                "Version": 4,
                "SRPSession": "test-session",
            }
        )
    )

    result = await api.get_auth_info("user@example.com")

    mock_http.request.assert_called_once_with(
        "POST",
        "/auth/v4/info",
        json={"Username": "user@example.com"},
        authenticated=False,
    )
    assert result["Modulus"] == "test-modulus"


@pytest.mark.asyncio
async def test_authenticate_calls_correct_endpoint(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "UID": "test-uid",
                "AccessToken": "test-token",
            }
        )
    )

    await api.authenticate(
        username="user@example.com",
        client_ephemeral="ephemeral",
        client_proof="proof",
        srp_session="session",
    )

    mock_http.request.assert_called_once()
    call_args = mock_http.request.call_args
    assert call_args[0] == ("POST", "/auth/v4")
    assert call_args[1]["authenticated"] is False
    assert call_args[1]["json"]["Username"] == "user@example.com"


@pytest.mark.asyncio
async def test_provide_2fa_calls_correct_endpoint(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Scopes": ["full", "drive"],
            }
        )
    )

    result = await api.provide_2fa("123456")

    mock_http.request.assert_called_once_with(
        "POST",
        "/auth/v4/2fa",
        json={"TwoFactorCode": "123456"},
    )
    assert result["Scopes"] == ["full", "drive"]


@pytest.mark.asyncio
async def test_logout_calls_correct_endpoint(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(return_value=make_success_response({}))

    await api.logout()

    mock_http.request.assert_called_once_with("DELETE", "/auth")


@pytest.mark.asyncio
async def test_get_user_keys_returns_user_keys(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "User": {
                    "Keys": [
                        {
                            "ID": "key-1",
                            "PrivateKey": "armored-key-1",
                            "Primary": 1,
                        },
                        {
                            "ID": "key-2",
                            "PrivateKey": "armored-key-2",
                            "Primary": 0,
                        },
                    ],
                },
            }
        )
    )

    keys = await api.get_user_keys()

    assert len(keys) == 2
    assert keys[0].key_id == "key-1"
    assert keys[0].armored_key == "armored-key-1"
    assert keys[0].is_primary is True
    assert keys[1].is_primary is False


@pytest.mark.asyncio
async def test_get_key_salts_returns_salts(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "KeySalts": [
                    {"ID": "key-1", "KeySalt": "salt-1"},
                    {"ID": "key-2", "KeySalt": "salt-2"},
                ],
            }
        )
    )

    salts = await api.get_key_salts()

    assert len(salts) == 2
    assert salts[0].key_id == "key-1"
    assert salts[0].salt == "salt-1"


@pytest.mark.asyncio
async def test_get_volumes_returns_volumes(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
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

    volumes = await api.get_volumes()

    assert len(volumes) == 1
    assert volumes[0].volume_id == "vol-1"
    assert volumes[0].share_id == "share-1"


@pytest.mark.asyncio
async def test_get_share_returns_share(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
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
            }
        )
    )

    share = await api.get_share("share-1")

    assert share.share_id == "share-1"
    assert share.link_id == "link-1"
    assert share.armored_key == "share-key"
    assert share.encrypted_passphrase == "share-passphrase"


@pytest.mark.asyncio
async def test_get_link_returns_link(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
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

    link = await api.get_link("share-1", "link-1")

    assert link.link_id == "link-1"
    assert link.parent_link_id == "parent-1"
    assert link.node_type == NodeType.FILE
    assert link.encrypted_name == "encrypted-name"
    assert link.size == 1024
    assert link.content_key_packet == "content-key"
    assert link.active_revision_id == "rev-1"


@pytest.mark.asyncio
async def test_get_link_handles_folder_without_file_properties(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
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

    link = await api.get_link("share-1", "folder-1")

    assert link.link_id == "folder-1"
    assert link.node_type == NodeType.FOLDER
    assert link.content_key_packet is None
    assert link.active_revision_id is None


@pytest.mark.asyncio
async def test_list_folder_children_returns_links(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
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
                        "FileProperties": {"ContentKeyPacket": "ck"},
                    },
                    {
                        "LinkID": "folder-1",
                        "Type": 1,
                        "Name": "folder-name",
                        "NodeKey": "key",
                        "NodePassphrase": "pass",
                        "State": 1,
                        "FileProperties": None,
                    },
                ],
            }
        )
    )

    children = await api.list_folder_children("share-1", "parent-1")

    assert len(children) == 2
    assert children[0].node_type == NodeType.FILE
    assert children[1].node_type == NodeType.FOLDER


@pytest.mark.asyncio
async def test_list_folder_children_paginates(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    first_response = make_success_response(
        {
            "Links": [
                {"LinkID": f"link-{i}", "Type": 2, "State": 1, "FileProperties": None}
                for i in range(150)
            ],
        }
    )
    second_response = make_success_response(
        {
            "Links": [{"LinkID": "link-150", "Type": 2, "State": 1, "FileProperties": None}],
        }
    )

    mock_http.request = AsyncMock(side_effect=[first_response, second_response])

    children = await api.list_folder_children("share-1", "parent-1")

    assert len(children) == 151
    assert mock_http.request.call_count == 2


@pytest.mark.asyncio
async def test_get_file_revisions_returns_revisions(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
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

    revisions = await api.get_file_revisions("share-1", "file-1")

    assert len(revisions) == 2
    assert revisions[0].revision_id == "rev-1"
    assert revisions[0].size == 1024
    assert revisions[0].state == 1


@pytest.mark.asyncio
async def test_get_revision_blocks_returns_blocks(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Blocks": [
                    {
                        "Index": 1,
                        "URL": "https://storage/block1",
                        "EncSignature": "sig1",
                        "Hash": "hash1",
                    },
                    {
                        "Index": 2,
                        "URL": "https://storage/block2",
                        "EncSignature": "sig2",
                        "Hash": "hash2",
                    },
                ],
            }
        )
    )

    blocks = await api.get_revision_blocks("share-1", "file-1", "rev-1")

    assert len(blocks) == 2
    assert blocks[0].index == 1
    assert blocks[0].url == "https://storage/block1"
    assert blocks[0].encrypted_hash == "hash1"


@pytest.mark.asyncio
async def test_download_block_returns_bytes(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request_raw = AsyncMock(return_value=b"encrypted content")

    result = await api.download_block("https://storage/block1")

    mock_http.request_raw.assert_called_once_with("GET", "https://storage/block1")
    assert result == b"encrypted content"


@pytest.mark.asyncio
async def test_get_addresses_returns_raw_dicts(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Addresses": [
                    {
                        "ID": "addr-1",
                        "Keys": [
                            {"ID": "key-1", "PrivateKey": "armored-key", "Primary": 1},
                        ],
                    },
                ],
            }
        )
    )

    addresses = await api.get_addresses()

    assert len(addresses) == 1
    assert addresses[0]["ID"] == "addr-1"
    assert len(addresses[0]["Keys"]) == 1
    assert addresses[0]["Keys"][0]["ID"] == "key-1"


@pytest.mark.asyncio
async def test_link_parses_timestamps(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Link": {
                    "LinkID": "link-1",
                    "Type": 1,
                    "State": 1,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "FileProperties": None,
                },
            }
        )
    )

    link = await api.get_link("share-1", "link-1")

    assert link.created_at is not None
    assert link.modified_at is not None
    assert link.created_at.year >= 2023


@pytest.mark.asyncio
async def test_link_handles_missing_timestamps(
    api: ProtonAPIEndpoints,
    mock_http: Mock,
) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Link": {
                    "LinkID": "link-1",
                    "Type": 1,
                    "State": 1,
                    "FileProperties": None,
                },
            }
        )
    )

    link = await api.get_link("share-1", "link-1")

    assert link.created_at is None
    assert link.modified_at is None


@pytest_asyncio.fixture
async def replay_api() -> AsyncIterator[ProtonAPIEndpoints]:
    config = ProtonDriveConfig()
    transport = ReplayTransport(FIXTURES_DIR)
    client = AsyncHttpClient(config, transport=transport)
    await client._ensure_client()
    await client.set_session(uid="fake", access_token="fake", refresh_token="fake")

    yield ProtonAPIEndpoints(client)

    await client._close()


@pytest.mark.asyncio
async def test_get_volumes_with_real_response(replay_api: ProtonAPIEndpoints) -> None:
    volumes = await replay_api.get_volumes()

    assert len(volumes) >= 1
    assert volumes[0].volume_id is not None
    assert volumes[0].share_id is not None


@pytest.mark.asyncio
async def test_get_share_with_real_response(replay_api: ProtonAPIEndpoints) -> None:
    volumes = await replay_api.get_volumes()
    share = await replay_api.get_share(volumes[0].share_id)

    assert share.share_id == volumes[0].share_id
    assert share.link_id is not None
    assert share.armored_key is not None


@pytest.mark.asyncio
async def test_list_folder_children_with_real_response(replay_api: ProtonAPIEndpoints) -> None:
    volumes = await replay_api.get_volumes()
    share = await replay_api.get_share(volumes[0].share_id)
    children = await replay_api.list_folder_children(share.share_id, share.link_id)

    assert len(children) >= 1
    node_types = {c.node_type for c in children}
    assert NodeType.FOLDER in node_types or NodeType.FILE in node_types


@pytest.mark.asyncio
async def test_get_link_with_real_response(replay_api: ProtonAPIEndpoints) -> None:
    volumes = await replay_api.get_volumes()
    share = await replay_api.get_share(volumes[0].share_id)
    children = await replay_api.list_folder_children(share.share_id, share.link_id)

    link = await replay_api.get_link(share.share_id, children[0].link_id)

    assert link.link_id == children[0].link_id
    assert link.armored_node_key is not None


@pytest.mark.asyncio
async def test_get_file_revisions_with_real_response(replay_api: ProtonAPIEndpoints) -> None:
    volumes = await replay_api.get_volumes()
    share = await replay_api.get_share(volumes[0].share_id)
    children = await replay_api.list_folder_children(share.share_id, share.link_id)

    folder = next((c for c in children if c.node_type == NodeType.FOLDER), None)
    assert folder is not None

    folder_children = await replay_api.list_folder_children(share.share_id, folder.link_id)
    file = next((c for c in folder_children if c.node_type == NodeType.FILE), None)
    assert file is not None

    revisions = await replay_api.get_file_revisions(share.share_id, file.link_id)

    assert len(revisions) >= 1
    assert revisions[0].revision_id is not None


@pytest.mark.asyncio
async def test_get_revision_blocks_with_real_response(replay_api: ProtonAPIEndpoints) -> None:
    volumes = await replay_api.get_volumes()
    share = await replay_api.get_share(volumes[0].share_id)
    children = await replay_api.list_folder_children(share.share_id, share.link_id)

    folder = next((c for c in children if c.node_type == NodeType.FOLDER), None)
    assert folder is not None

    folder_children = await replay_api.list_folder_children(share.share_id, folder.link_id)

    for file in folder_children:
        if file.node_type != NodeType.FILE:
            continue

        revisions = await replay_api.get_file_revisions(share.share_id, file.link_id)
        active = next((r for r in revisions if r.state == 1), None)
        if not active:
            continue

        blocks = await replay_api.get_revision_blocks(
            share.share_id, file.link_id, active.revision_id
        )
        if blocks:
            assert blocks[0].url is not None
            assert blocks[0].index >= 1
            return

    pytest.fail("No file with blocks found")
