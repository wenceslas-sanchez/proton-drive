import base64
import hashlib
from collections.abc import Callable
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from proton_drive.exceptions import (
    BlockDecryptionError,
    IntegrityError,
    NotAFileError,
    PathNotFoundError,
)
from proton_drive.models.drive import FileBlock, FileRevision, Link, NodeType, RevisionState, Share
from proton_drive.services.file_service import FileService
from proton_drive.services.tree_service import TreeService
from proton_drive.tests.services.constants import (
    FILE_LINK_ID,
    FOLDER_LINK_ID,
    SHARE_ID,
)

REVISION_ID = "rev_abc"
CONTENT_KEY_PACKET = base64.b64encode(b"fake_key_packet").decode()


def make_block(index: int = 1, content: bytes = b"encrypted_data") -> tuple[FileBlock, bytes]:
    block = FileBlock(
        index=index,
        url=f"https://storage/block{index}",
        encrypted_hash=base64.b64encode(hashlib.sha256(content).digest()).decode("ascii"),
        size=len(content),
    )
    return block, content


@pytest.fixture
def mock_tree_service(make_share: Callable[[], Share]) -> Mock:
    service = Mock(spec=TreeService)
    service.share = make_share()
    return service


@pytest.fixture
def mock_pgp() -> Mock:
    pgp = Mock()
    pgp.unlock_key.return_value = MagicMock(
        __enter__=Mock(return_value=None), __exit__=Mock(return_value=False)
    )
    pgp.extract_session_key.return_value = Mock()
    return pgp


@pytest.fixture
def file_service(
    mock_http: Mock, mock_key_manager: Mock, mock_tree_service: Mock, mock_pgp: Mock
) -> FileService:
    return FileService(
        http=mock_http,
        key_manager=mock_key_manager,
        tree_service=mock_tree_service,
        pgp_backend=mock_pgp,
    )


@pytest.mark.asyncio
async def test_download_file_raises_when_share_not_initialized(
    file_service: FileService, mock_tree_service: Mock
) -> None:
    mock_tree_service.share = None
    with pytest.raises(ValueError, match="Share not initialized"):
        async for _ in file_service.download_file("/file.txt"):
            pass


@pytest.mark.asyncio
async def test_download_file_raises_when_path_not_found(
    file_service: FileService, mock_tree_service: Mock
) -> None:
    mock_tree_service.get_node_by_path = AsyncMock(return_value=None)
    with pytest.raises(PathNotFoundError):
        async for _ in file_service.download_file("/missing.txt"):
            pass


@pytest.mark.asyncio
async def test_download_file_raises_when_path_is_folder(
    file_service: FileService, mock_tree_service: Mock
) -> None:
    folder_node = Mock()
    folder_node.node_type = NodeType.FOLDER
    mock_tree_service.get_node_by_path = AsyncMock(return_value=folder_node)
    with pytest.raises(NotAFileError):
        async for _ in file_service.download_file("/folder"):
            pass


@pytest.mark.asyncio
async def test_download_file_yields_chunks_for_valid_path(
    file_service: FileService,
    mock_tree_service: Mock,
    mock_key_manager: Mock,
    mock_pgp: Mock,
    make_link: Callable[..., Link],
) -> None:
    file_node = Mock()
    file_node.node_type = NodeType.FILE
    file_node.link_id = FILE_LINK_ID
    mock_tree_service.get_node_by_path = AsyncMock(return_value=file_node)

    link = make_link(
        node_type=NodeType.FILE,
        content_key_packet=CONTENT_KEY_PACKET,
        active_revision_id=REVISION_ID,
    )
    block, encrypted = make_block()
    decrypted = b"decrypted_content"

    with (
        patch(
            "proton_drive.services.file_service.get_link", new_callable=AsyncMock, return_value=link
        ),
        patch(
            "proton_drive.services.file_service.get_revision_blocks",
            new_callable=AsyncMock,
            return_value=[block],
        ),
        patch(
            "proton_drive.services.file_service.download_block",
            new_callable=AsyncMock,
            return_value=encrypted,
        ),
        patch("proton_drive.services.file_service.parse_seipd_from_block", return_value=b"seipd"),
        patch("proton_drive.services.file_service.decrypt_seipd_packet", return_value=decrypted),
    ):
        chunks = []
        async for chunk in file_service.download_file("/file.txt"):
            chunks.append(chunk)

    assert chunks == [decrypted]


@pytest.mark.asyncio
async def test_download_to_file_writes_chunks_to_disk(
    file_service: FileService,
    mock_tree_service: Mock,
    mock_key_manager: Mock,
    mock_pgp: Mock,
    make_link: Callable[..., Link],
    tmp_path: Path,
) -> None:
    file_node = Mock()
    file_node.node_type = NodeType.FILE
    file_node.link_id = FILE_LINK_ID
    mock_tree_service.get_node_by_path = AsyncMock(return_value=file_node)

    link = make_link(
        node_type=NodeType.FILE,
        content_key_packet=CONTENT_KEY_PACKET,
        active_revision_id=REVISION_ID,
    )
    block, encrypted = make_block()
    decrypted = b"file content"
    destination = tmp_path / "output.txt"

    with (
        patch(
            "proton_drive.services.file_service.get_link", new_callable=AsyncMock, return_value=link
        ),
        patch(
            "proton_drive.services.file_service.get_revision_blocks",
            new_callable=AsyncMock,
            return_value=[block],
        ),
        patch(
            "proton_drive.services.file_service.download_block",
            new_callable=AsyncMock,
            return_value=encrypted,
        ),
        patch("proton_drive.services.file_service.parse_seipd_from_block", return_value=b"seipd"),
        patch("proton_drive.services.file_service.decrypt_seipd_packet", return_value=decrypted),
    ):
        await file_service.download_to_file("/file.txt", destination)

    assert destination.exists()
    assert destination.read_bytes() == decrypted


@pytest.mark.asyncio
async def test_download_by_link_id_raises_when_link_is_folder(
    file_service: FileService,
    make_link: Callable[..., Link],
) -> None:
    folder_link = make_link(link_id=FOLDER_LINK_ID, node_type=NodeType.FOLDER)
    with patch(
        "proton_drive.services.file_service.get_link",
        new_callable=AsyncMock,
        return_value=folder_link,
    ):
        with pytest.raises(NotAFileError):
            async for _ in file_service.download_by_link_id(SHARE_ID, folder_link.link_id):
                pass


@pytest.mark.asyncio
async def test_download_by_link_id_yields_decrypted_chunks(
    file_service: FileService,
    mock_key_manager: Mock,
    mock_pgp: Mock,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(
        node_type=NodeType.FILE,
        content_key_packet=CONTENT_KEY_PACKET,
        active_revision_id=REVISION_ID,
    )
    block, encrypted = make_block()
    decrypted = b"hello_world"

    with (
        patch(
            "proton_drive.services.file_service.get_link", new_callable=AsyncMock, return_value=link
        ),
        patch(
            "proton_drive.services.file_service.get_revision_blocks",
            new_callable=AsyncMock,
            return_value=[block],
        ),
        patch(
            "proton_drive.services.file_service.download_block",
            new_callable=AsyncMock,
            return_value=encrypted,
        ),
        patch("proton_drive.services.file_service.parse_seipd_from_block", return_value=b"seipd"),
        patch("proton_drive.services.file_service.decrypt_seipd_packet", return_value=decrypted),
    ):
        chunks = []
        async for chunk in file_service.download_by_link_id(SHARE_ID, FILE_LINK_ID):
            chunks.append(chunk)

    assert chunks == [decrypted]


@pytest.mark.asyncio
async def test_get_active_revision_id_returns_link_revision_when_set(
    file_service: FileService,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE, active_revision_id=REVISION_ID)

    result = await file_service._get_active_revision_id(SHARE_ID, link)

    assert result == REVISION_ID


@pytest.mark.asyncio
async def test_get_active_revision_id_fetches_active_revision_when_not_set(
    file_service: FileService,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE, active_revision_id=None)
    active_rev = FileRevision(revision_id="rev_active", size=100, state=RevisionState.ACTIVE)
    obsolete_rev = FileRevision(revision_id="rev_old", size=100, state=RevisionState.OBSOLETE)

    with patch(
        "proton_drive.services.file_service.get_file_revisions",
        new_callable=AsyncMock,
        return_value=[obsolete_rev, active_rev],
    ):
        result = await file_service._get_active_revision_id(SHARE_ID, link)

    assert result == "rev_active"


@pytest.mark.asyncio
async def test_get_active_revision_id_raises_when_no_revisions(
    file_service: FileService,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE, active_revision_id=None)
    with patch(
        "proton_drive.services.file_service.get_file_revisions",
        new_callable=AsyncMock,
        return_value=[],
    ):
        with pytest.raises(ValueError, match="No revisions found"):
            await file_service._get_active_revision_id(SHARE_ID, link)


@pytest.mark.asyncio
async def test_get_node_key_returns_cached_key(
    file_service: FileService,
    mock_key_manager: Mock,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE)
    cached_key = Mock()
    cached_passphrase = Mock()
    mock_key_manager.get_cached_key.return_value = (cached_key, cached_passphrase)

    key, passphrase = await file_service._get_node_key(SHARE_ID, link)

    assert key is cached_key
    assert passphrase is cached_passphrase
    mock_key_manager.unlock_node_key.assert_not_called()


@pytest.mark.asyncio
async def test_get_node_key_raises_when_max_depth_exceeded(
    file_service: FileService,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE)
    with pytest.raises(RuntimeError, match="maximum depth"):
        await file_service._get_node_key(SHARE_ID, link, _depth=51)


@pytest.mark.asyncio
async def test_get_node_key_raises_when_share_key_not_available(
    file_service: FileService,
    mock_key_manager: Mock,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(link_id=FILE_LINK_ID, parent_link_id=None, node_type=NodeType.FILE)
    mock_key_manager.get_cached_key.return_value = None
    with pytest.raises(ValueError, match="Share key not available"):
        await file_service._get_node_key(SHARE_ID, link)


def test_verify_block_hash_passes_with_correct_hash() -> None:
    content = b"some_encrypted_data"
    block, _ = make_block(content=content)
    FileService._verify_block_hash(block, content)


def test_verify_block_hash_raises_integrity_error_on_mismatch() -> None:
    block = FileBlock(index=1, url="https://storage/block1", encrypted_hash="wrong_hash==", size=0)
    with pytest.raises(IntegrityError):
        FileService._verify_block_hash(block, b"some_data")


def test_decrypt_block_raises_on_parse_failure() -> None:
    block = FileBlock(index=1, url="https://storage/block1", encrypted_hash="hash", size=0)
    session_key = Mock()

    with patch(
        "proton_drive.services.file_service.parse_seipd_from_block",
        side_effect=ValueError("bad format"),
    ):
        with pytest.raises(BlockDecryptionError, match="Failed to parse block 1"):
            FileService._decrypt_block(block, b"bad_data", session_key)


def test_decrypt_block_raises_on_decryption_failure() -> None:
    block = FileBlock(index=1, url="https://storage/block1", encrypted_hash="hash", size=0)
    session_key = Mock()

    with (
        patch("proton_drive.services.file_service.parse_seipd_from_block", return_value=b"seipd"),
        patch(
            "proton_drive.services.file_service.decrypt_seipd_packet",
            side_effect=ValueError("decryption failed"),
        ),
    ):
        with pytest.raises(BlockDecryptionError, match="Failed to decrypt block 1"):
            FileService._decrypt_block(block, b"data", session_key)


def test_decrypt_block_returns_plaintext() -> None:
    block = FileBlock(index=1, url="https://storage/block1", encrypted_hash="hash", size=0)
    session_key = Mock()

    with (
        patch("proton_drive.services.file_service.parse_seipd_from_block", return_value=b"seipd"),
        patch("proton_drive.services.file_service.decrypt_seipd_packet", return_value=b"plaintext"),
    ):
        result = FileService._decrypt_block(block, b"data", session_key)

    assert result == b"plaintext"


def test_get_session_key_raises_when_no_content_key_packet(
    file_service: FileService,
    mock_key_manager: Mock,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE, content_key_packet=None)
    node_key = Mock()
    node_passphrase = Mock()

    with pytest.raises(ValueError, match="No ContentKeyPacket"):
        file_service._get_session_key(link, node_key, node_passphrase)


def test_get_session_key_unlocks_key_and_extracts_session_key(
    file_service: FileService,
    mock_pgp: Mock,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(node_type=NodeType.FILE, content_key_packet=CONTENT_KEY_PACKET)
    node_key = Mock()
    node_passphrase = Mock()
    expected_session_key = Mock()
    mock_pgp.extract_session_key.return_value = expected_session_key

    result = file_service._get_session_key(link, node_key, node_passphrase)

    mock_pgp.unlock_key.assert_called_once_with(node_key, node_passphrase)
    mock_pgp.extract_session_key.assert_called_once()
    assert result is expected_session_key


@pytest.mark.asyncio
async def test_stream_file_yields_blocks_in_order(
    file_service: FileService,
    mock_key_manager: Mock,
    mock_pgp: Mock,
    make_link: Callable[..., Link],
) -> None:
    link = make_link(
        node_type=NodeType.FILE,
        content_key_packet=CONTENT_KEY_PACKET,
        active_revision_id=REVISION_ID,
    )
    block1, enc1 = make_block(index=1, content=b"block_1_data")
    block2, enc2 = make_block(index=2, content=b"block_2_data")

    with (
        patch(
            "proton_drive.services.file_service.get_revision_blocks",
            new_callable=AsyncMock,
            return_value=[block2, block1],
        ),
        patch(
            "proton_drive.services.file_service.download_block",
            new_callable=AsyncMock,
            side_effect=[enc1, enc2],
        ),
        patch("proton_drive.services.file_service.parse_seipd_from_block", side_effect=lambda d: d),
        patch(
            "proton_drive.services.file_service.decrypt_seipd_packet", side_effect=lambda d, _: d
        ),
    ):
        chunks = []
        async for chunk in file_service._stream_file(SHARE_ID, link):
            chunks.append(chunk)

    assert chunks == [enc1, enc2]
