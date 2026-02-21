"""
Tree traversal service for Proton Drive.

Handles building the decrypted folder tree structure.
"""

import asyncio

import structlog

from proton_drive.api.endpoints.drive import (
    get_link,
    get_share,
    get_volumes,
    list_folder_children,
)
from proton_drive.api.endpoints.user import get_address_keys, get_user_keys
from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.crypto.key_manager import KeyManager
from proton_drive.crypto.protocol import PrivateKey
from proton_drive.crypto.secure_bytes import SecureBytes
from proton_drive.models.auth import AddressKey, UserKey
from proton_drive.models.drive import DriveNode, Link, LinkState, NodeType, Share

logger = structlog.get_logger(__name__)
DEFAULT_NODE_NAME = "[undefined]"


def _split_path(path: str) -> list[str]:
    return [p for p in path.strip("/").split("/") if p]


class TreeService:
    """
    Service for building and traversing the drive tree.

    Handles decryption of folder/file names and caching of keys.
    """

    def __init__(
        self,
        http: AsyncHttpClient,
        key_manager: KeyManager,
    ) -> None:
        """
        Initialize tree service.

        Args:
            http: Async HTTP client.
            key_manager: Key manager for decryption.
        """
        self._http = http
        self._key_manager = key_manager
        self._share: Share | None = None

    @property
    def share(self) -> Share | None:
        """The currently initialized share, or None if not yet initialized."""
        return self._share

    async def initialize_share(self, share: Share | None = None) -> Share:
        """
        Initialize the share and unlock its key.

        Args:
            share: Share to initialize, or None for default.

        Returns:
            The initialized share.

        Raises:
            ValueError: If address key or user keys not found.
        """
        if share is None:
            if self._share is not None:
                return self._share
            share = await self._get_default_share()

        self._share = share

        address_key, primary_user_key = await asyncio.gather(
            self._get_address_key(share),
            self._get_primary_user_key(),
        )

        self._key_manager.unlock_address_key(address_key, primary_user_key.key_id)
        self._key_manager.unlock_share_key(
            share.share_id,
            share.armored_key,
            share.encrypted_passphrase,
            address_key.key_id,
        )

        logger.debug("Share initialized", share_id=share.share_id)
        return share

    async def build_tree(self) -> DriveNode:
        """
        Build complete folder tree.

        Returns:
            Root DriveNode with children populated.

        Raises:
            ValueError: If no volumes found.
            RuntimeError: If share key is unavailable.
        """
        await self.initialize_share()

        share_key, share_passphrase = self._get_share_key()
        root_link, root_key, root_passphrase = await self._get_root_node(
            share_key, share_passphrase
        )

        children = await self._build_subtree(
            self._share.share_id, root_link.link_id, root_key, root_passphrase
        )

        return DriveNode(
            link_id=root_link.link_id,
            parent_link_id=None,
            name="",
            node_type=NodeType.FOLDER,
            created_at=root_link.created_at,
            modified_at=root_link.modified_at,
            children=tuple(children),
        )

    async def list_directory(self, path: str = "/") -> list[DriveNode]:
        """
        List contents of a directory.

        Args:
            path: POSIX-style path.

        Returns:
            List of child nodes.

        Raises:
            ValueError: If no volumes found or keys are missing.
            RuntimeError: If share key is unavailable.
        """
        result = await self._navigate_to_folder(path)
        if result is None:
            return []

        folder_link_id, folder_key, folder_passphrase = result
        children = await list_folder_children(self._http, self._share.share_id, folder_link_id)
        return [
            self._link_to_node(
                child,
                self._key_manager.decrypt_name(child.encrypted_name, folder_key, folder_passphrase)
                or DEFAULT_NODE_NAME,
                (),
            )
            for child in children
            if child.state == LinkState.ACTIVE
        ]

    async def get_node_by_path(self, path: str) -> DriveNode | None:
        """
        Get a node by its path without building the full tree.

        Args:
            path: POSIX-style path.

        Returns:
            DriveNode or None if not found.

        Raises:
            ValueError: If no volumes found or keys are missing.
            RuntimeError: If share key is unavailable.
        """
        parts = _split_path(path)
        if not parts:
            return None

        siblings = await self.list_directory("/".join(parts[:-1]))
        return next((node for node in siblings if node.name == parts[-1]), None)

    def cleanup(self) -> None:
        """
        Clean up sensitive data from memory.

        Securely wipes all cached keys including the share key.
        Should be called when the service is no longer needed.
        """
        self._share = None

    async def _get_default_share(self) -> Share:
        volumes = await get_volumes(self._http)
        if not volumes:
            msg = "No volumes found"
            raise ValueError(msg)
        return await get_share(self._http, volumes[0].share_id)

    async def _get_address_key(self, share: Share) -> AddressKey:
        address_keys = await get_address_keys(self._http, share.address_id)
        address_key = next(
            (k for k in address_keys if k.key_id == share.address_key_id),
            address_keys[0] if address_keys else None,
        )
        if address_key is None:
            msg = f"Address key not found: {share.address_key_id}"
            raise ValueError(msg)
        return address_key

    async def _get_primary_user_key(self) -> UserKey:
        user_keys = await get_user_keys(self._http)
        if not user_keys:
            msg = "No user keys found"
            raise ValueError(msg)
        return next((k for k in user_keys if k.is_primary), user_keys[0])

    def _get_share_key(self) -> tuple[PrivateKey, SecureBytes]:
        if (share_key_data := self._key_manager.get_cached_key(self._share.share_id)) is not None:
            return share_key_data
        msg = "Share key not available. Call initialize_share() first."
        raise RuntimeError(msg)

    async def _get_root_node(
        self, share_key: PrivateKey, share_passphrase: SecureBytes
    ) -> tuple[Link, PrivateKey, SecureBytes]:
        root_link = await get_link(self._http, self._share.share_id, self._share.link_id)
        root_key, root_passphrase = self._key_manager.unlock_node_key(
            root_link.link_id,
            root_link.armored_node_key,
            root_link.encrypted_node_passphrase,
            share_key,
            share_passphrase,
        )
        return root_link, root_key, root_passphrase

    async def _build_subtree(
        self,
        share_id: str,
        parent_link_id: str,
        parent_key: PrivateKey,
        parent_passphrase: SecureBytes,
    ) -> list[DriveNode]:
        try:
            children = await list_folder_children(self._http, share_id, parent_link_id)
        except Exception as e:
            logger.warning("Failed to list folder", link_id=parent_link_id, exc_info=e)
            return []

        tasks = [
            self._process_link(link, share_id, parent_link_id, parent_key, parent_passphrase)
            for link in children
        ]
        results = await asyncio.gather(*tasks)
        return [node for node in results if node is not None]

    async def _process_link(
        self,
        link: Link,
        share_id: str,
        parent_link_id: str,
        parent_key: PrivateKey,
        parent_passphrase: SecureBytes,
    ) -> DriveNode | None:
        if link.state != LinkState.ACTIVE:
            return None

        name = (
            self._key_manager.decrypt_name(link.encrypted_name, parent_key, parent_passphrase)
            or DEFAULT_NODE_NAME
        )

        children_nodes = (
            await self._get_folder_children(link, share_id, parent_key, parent_passphrase)
            if link.node_type == NodeType.FOLDER
            else ()
        )

        return self._link_to_node(link, name, children_nodes, parent_link_id=parent_link_id)

    async def _get_folder_children(
        self,
        link: Link,
        share_id: str,
        parent_key: PrivateKey,
        parent_passphrase: SecureBytes,
    ) -> tuple[DriveNode, ...]:
        try:
            folder_key, folder_passphrase = await self._unlock_link(
                link, share_id, parent_key, parent_passphrase
            )
            return tuple(
                await self._build_subtree(share_id, link.link_id, folder_key, folder_passphrase)
            )
        except Exception as e:
            logger.warning("Failed to process folder", link_id=link.link_id, exc_info=e)
            return ()

    async def _navigate_to_folder(self, path: str) -> tuple[str, PrivateKey, SecureBytes] | None:
        await self.initialize_share()
        share_key, share_passphrase = self._get_share_key()
        _, current_key, current_passphrase = await self._get_root_node(share_key, share_passphrase)
        current_link_id = self._share.link_id

        for part in _split_path(path):
            children = await list_folder_children(self._http, self._share.share_id, current_link_id)
            matched = next(
                (
                    child
                    for child in children
                    if child.state == LinkState.ACTIVE
                    and child.node_type == NodeType.FOLDER
                    and self._key_manager.decrypt_name(
                        child.encrypted_name, current_key, current_passphrase
                    )
                    == part
                ),
                None,
            )
            if matched is None:
                return None

            current_key, current_passphrase = await self._unlock_link(
                matched, self._share.share_id, current_key, current_passphrase
            )
            current_link_id = matched.link_id

        return current_link_id, current_key, current_passphrase

    async def _unlock_link(
        self,
        link: Link,
        share_id: str,
        parent_key: PrivateKey,
        parent_passphrase: SecureBytes,
    ) -> tuple[PrivateKey, SecureBytes]:
        if link.armored_node_key is None or link.encrypted_node_passphrase is None:
            link = await get_link(self._http, share_id, link.link_id)
        return self._key_manager.unlock_node_key(
            link.link_id,
            link.armored_node_key,
            link.encrypted_node_passphrase,
            parent_key,
            parent_passphrase,
        )

    @staticmethod
    def _link_to_node(
        link: Link,
        name: str,
        children: tuple[DriveNode, ...],
        parent_link_id: str | None = None,
    ) -> DriveNode:
        return DriveNode(
            link_id=link.link_id,
            parent_link_id=parent_link_id if parent_link_id is not None else link.parent_link_id,
            name=name,
            node_type=link.node_type,
            size=link.size,
            mime_type=link.mime_type,
            created_at=link.created_at,
            modified_at=link.modified_at,
            children=children,
        )
