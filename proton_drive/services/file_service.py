"""
File download service for Proton Drive.

Handles streaming file downloads with decryption.
"""

import base64
import hashlib
from collections.abc import AsyncGenerator
from pathlib import Path

import structlog

from proton_drive.api.endpoints.drive import (
    download_block,
    get_file_revisions,
    get_link,
    get_revision_blocks,
)
from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.crypto.aes import decrypt_seipd_packet, parse_seipd_from_block
from proton_drive.crypto.key_manager import KeyManager
from proton_drive.crypto.pgpy_backend import PgpyBackend
from proton_drive.crypto.protocol import PGPBackend, PrivateKey
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.exceptions import (
    BlockDecryptionError,
    IntegrityError,
    NotAFileError,
    PathNotFoundError,
)
from proton_drive.models.crypto import SessionKey
from proton_drive.models.drive import FileBlock, Link, NodeType, RevisionState
from proton_drive.services.tree_service import TreeService

logger = structlog.get_logger(__name__)
# Maximum depth for parent key traversal to prevent infinite loops on circular parent chains.
_MAX_DEPTH = 50


class FileService:
    """
    Service for downloading and decrypting files.

    Supports streaming downloads for large files.
    """

    def __init__(
        self,
        http: AsyncHttpClient,
        key_manager: KeyManager,
        tree_service: TreeService,
        pgp_backend: PGPBackend | None = None,
    ) -> None:
        """
        Args:
            http: Async HTTP client.
            key_manager: Key manager for decryption and caching.
            tree_service: Tree service for path resolution.
            pgp_backend: PGP backend for session key extraction.
        """
        self._http = http
        self._key_manager = key_manager
        self._tree_service = tree_service
        self._pgp = pgp_backend or PgpyBackend()

    async def download_file(self, path: str) -> AsyncGenerator[bytes, None]:
        """
        Download and decrypt a file as a stream.

        Args:
            path: File path in the drive.

        Yields:
            Decrypted file content in chunks.

        Raises:
            PathNotFoundError: If the path doesn't exist.
            NotAFileError: If the path is a folder.
            ValueError: If share is not initialized.
        """
        if self._tree_service.share is None:
            msg = "Share not initialized"
            raise ValueError(msg)

        node = await self._tree_service.get_node_by_path(path)
        if node is None:
            msg = f"Path not found: {path}"
            raise PathNotFoundError(msg, path=path)
        if node.node_type != NodeType.FILE:
            msg = f"Path is not a file: {path}"
            raise NotAFileError(msg, path=path)

        async for chunk in self.download_by_link_id(
            self._tree_service.share.share_id, node.link_id
        ):
            yield chunk

    async def download_by_link_id(self, share_id: str, link_id: str) -> AsyncGenerator[bytes, None]:
        """
        Download and decrypt a file by link ID.

        Args:
            share_id: Share ID.
            link_id: File link ID.

        Yields:
            Decrypted file content in chunks.
        """
        logger.debug("Downloading file", link_id=link_id)
        link = await get_link(self._http, share_id, link_id)
        if link.node_type != NodeType.FILE:
            msg = f"Link is not a file: {link_id}"
            raise NotAFileError(msg, path=link_id)
        async for chunk in self._stream_file(share_id, link):
            yield chunk

    async def _stream_file(self, share_id: str, link: Link) -> AsyncGenerator[bytes, None]:
        node_key, node_passphrase = await self._get_node_key(share_id, link)
        session_key = self._get_session_key(link, node_key, node_passphrase)
        revision_id = await self._get_active_revision_id(share_id, link)
        blocks = sorted(
            await get_revision_blocks(self._http, share_id, link.link_id, revision_id),
            key=lambda b: b.index,
        )
        for block in blocks:
            yield await self._download_and_decrypt_block(block, session_key)

    async def download_to_file(self, path: str, destination: Path) -> None:
        """
        Download a file and save to disk.

        Args:
            path: File path in the drive.
            destination: Local file path to save to.
        """
        destination.parent.mkdir(parents=True, exist_ok=True)

        with destination.open("wb") as f:
            async for chunk in self.download_file(path):
                f.write(chunk)

        logger.info("File saved", path=path, destination=str(destination))

    async def _get_active_revision_id(self, share_id: str, link: Link) -> str:
        if link.active_revision_id is not None:
            return link.active_revision_id
        revisions = await get_file_revisions(self._http, share_id, link.link_id)
        if len(revisions) == 0:
            msg = f"No revisions found for file: {link.link_id}"
            raise ValueError(msg)
        active = next((r for r in revisions if r.state == RevisionState.ACTIVE), revisions[0])
        return active.revision_id

    async def _get_node_key(
        self, share_id: str, link: Link, _depth: int = 0
    ) -> tuple[PrivateKey, SecureBytes]:
        if _depth > _MAX_DEPTH:
            msg = f"Key traversal exceeded maximum depth for link: {link.link_id}"
            raise RuntimeError(msg)

        if (cached := self._key_manager.get_cached_key(link.link_id)) is not None:
            return cached

        parent_key, parent_passphrase = await self._get_parent_key(share_id, link, _depth)
        return self._key_manager.unlock_node_key(
            link.link_id,
            link.armored_node_key,
            link.encrypted_node_passphrase,
            parent_key,
            parent_passphrase,
        )

    async def _get_parent_key(
        self, share_id: str, link: Link, _depth: int
    ) -> tuple[PrivateKey, SecureBytes]:
        if link.parent_link_id is not None:
            if (parent_cached := self._key_manager.get_cached_key(link.parent_link_id)) is not None:
                return parent_cached
            logger.warning("Node key not cached, traversing parent chain", link_id=link.link_id)
            parent_link = await get_link(self._http, share_id, link.parent_link_id)
            return await self._get_node_key(share_id, parent_link, _depth + 1)

        if (share_key_data := self._key_manager.get_cached_key(share_id)) is None:
            msg = "Share key not available"
            raise ValueError(msg)
        return share_key_data

    def _get_session_key(
        self,
        link: Link,
        node_key: PrivateKey,
        node_passphrase: SecureBytes,
    ) -> SessionKey:
        if link.content_key_packet is None:
            msg = f"No ContentKeyPacket for file: {link.link_id}"
            raise ValueError(msg)

        with self._pgp.unlock_key(node_key, node_passphrase):
            return self._pgp.extract_session_key(
                base64.b64decode(link.content_key_packet), node_key, node_passphrase
            )

    async def _download_and_decrypt_block(self, block: FileBlock, session_key: SessionKey) -> bytes:
        logger.debug("Downloading block", index=block.index)
        encrypted = await download_block(self._http, block.url)
        self._verify_block_hash(block, encrypted)
        return self._decrypt_block(block, encrypted, session_key)

    @staticmethod
    def _verify_block_hash(block: FileBlock, encrypted: bytes) -> None:
        computed_hash = base64.b64encode(hashlib.sha256(encrypted).digest()).decode("ascii")
        if computed_hash == block.encrypted_hash:
            return
        msg = f"Block {block.index} hash mismatch: expected {block.encrypted_hash}, got {computed_hash}"
        raise IntegrityError(msg)

    @staticmethod
    def _decrypt_block(block: FileBlock, encrypted: bytes, session_key: SessionKey) -> bytes:
        try:
            seipd_data = parse_seipd_from_block(encrypted)
        except Exception as e:
            msg = f"Failed to parse block {block.index}: {e}"
            raise BlockDecryptionError(msg, block_index=block.index) from e
        try:
            return decrypt_seipd_packet(seipd_data, session_key)
        except Exception as e:
            msg = f"Failed to decrypt block {block.index}: {e}"
            raise BlockDecryptionError(msg, block_index=block.index) from e
