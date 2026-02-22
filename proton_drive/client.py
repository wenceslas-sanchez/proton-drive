"""
Proton Drive client facade.

This is the main entry point for users of the library. It provides a clean,
high-level API that hides the complexity of the underlying services.
"""

import asyncio
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Self

import httpx
import structlog

from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.config import ProtonDriveConfig
from proton_drive.crypto.key_manager import KeyManager
from proton_drive.crypto.pgpy_backend import PgpyBackend
from proton_drive.crypto.protocol import PGPBackend
from proton_drive.exceptions import AuthenticationError, TwoFactorRequiredError
from proton_drive.models.auth import SessionInfo
from proton_drive.models.drive import DriveNode
from proton_drive.services.auth_service import AuthService
from proton_drive.services.file_service import FileService
from proton_drive.services.tree_service import _MAX_DEPTH as _TREE_MAX_DEPTH
from proton_drive.services.tree_service import TreeService

logger = structlog.get_logger(__name__)


class ProtonDriveClient:
    """
    Async client for Proton Drive.

    This is the main entry point for interacting with Proton Drive.
    It provides a clean, high-level API for authentication, file listing,
    and file downloads.

    Example:
        ```python
        async with ProtonDriveClient() as client:
            await client.authenticate("user@proton.me", "password")

            if client.requires_2fa:
                await client.provide_2fa("123456")

            # List files
            root = await client.build_tree()
            print(root.format_tree())

            # Download a file
            async for chunk in client.download_file("/docs/report.pdf"):
                f.write(chunk)
        ```

    Args:
        config: Client configuration. Uses defaults if not provided.
        transport: Optional httpx transport for testing (mock transport).
    """

    def __init__(
        self,
        config: ProtonDriveConfig | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """
        Initialize the Proton Drive client.

        Args:
            config: Client configuration. Uses defaults if not provided.
            transport: Optional httpx transport for testing.
        """
        self._config = config or ProtonDriveConfig()
        self._transport = transport

        self._http: AsyncHttpClient | None = None
        self._pgp: PGPBackend | None = None
        self._key_manager: KeyManager | None = None
        self._auth_service: AuthService | None = None
        self._tree_service: TreeService | None = None
        self._file_service: FileService | None = None

        self._initialized = False
        self._init_lock = asyncio.Lock()

    async def __aenter__(self) -> Self:
        """Enter async context."""
        await self._ensure_initialized()
        return self

    async def __aexit__(
        self, exc_type: type | None, exc_val: BaseException | None, exc_tb: object
    ) -> None:
        """Exit async context."""
        await self.close()

    async def _ensure_initialized(self) -> None:
        """Ensure all components are initialized."""
        async with self._init_lock:
            if self._initialized:
                return

            # Create HTTP client
            self._http = AsyncHttpClient(self._config, transport=self._transport)
            await self._http.__aenter__()

            # Create crypto components
            self._pgp = PgpyBackend()
            self._key_manager = KeyManager(self._pgp, cache_size=self._config.key_cache_max_size)

            # Create services
            self._auth_service = AuthService(self._http, self._key_manager)
            self._tree_service = TreeService(self._http, self._key_manager)
            self._file_service = FileService(
                self._http,
                self._key_manager,
                self._tree_service,
                self._pgp,
            )

            self._initialized = True
            logger.debug("Client initialized")

    async def close(self) -> None:
        """Close the client and release resources."""
        async with self._init_lock:
            if self._auth_service:
                self._auth_service.cleanup()
                self._auth_service = None

            if self._http:
                await self._http.__aexit__(None, None, None)
                self._http = None

            self._key_manager = None
            self._pgp = None
            self._tree_service = None
            self._file_service = None
            self._initialized = False
            logger.debug("Client closed")

    async def authenticate(self, username: str, password: str) -> SessionInfo:
        """
        Authenticate with Proton.

        After calling this method, check `requires_2fa` to see if a 2FA code
        is needed before accessing drive features.

        Args:
            username: Proton email/username.
            password: Account password.

        Returns:
            SessionInfo with current scopes.

        Raises:
            InvalidCredentialsError: If credentials are invalid.
            AuthenticationError: If authentication fails.

        Example:
            ```python
            await client.authenticate("user@proton.me", "password")
            if client.requires_2fa:
                await client.provide_2fa(input("2FA code: "))
            ```
        """
        await self._ensure_initialized()
        if self._auth_service is None:
            raise RuntimeError("Client not initialized")
        return await self._auth_service.authenticate(username, password)

    async def provide_2fa(self, code: str) -> SessionInfo:
        """
        Provide 2FA code to complete authentication.

        Args:
            code: 6-digit 2FA code from authenticator app.

        Returns:
            SessionInfo with updated scopes.

        Raises:
            TwoFactorInvalidError: If the code is invalid.
            AuthenticationError: If not in 2FA state.
        """
        await self._ensure_initialized()
        if self._auth_service is None:
            raise RuntimeError("Client not initialized")
        return await self._auth_service.provide_2fa(code)

    async def logout(self) -> None:
        """Logout and clear session."""
        if self._auth_service:
            await self._auth_service.logout()

    @property
    def is_authenticated(self) -> bool:
        """Check if authenticated."""
        return self._auth_service is not None and self._auth_service.is_authenticated

    @property
    def requires_2fa(self) -> bool:
        """Check if 2FA is required to access drive."""
        return self._auth_service is not None and self._auth_service.requires_2fa

    @property
    def has_drive_access(self) -> bool:
        """Check if we have full drive access."""
        return self._auth_service is not None and self._auth_service.has_drive_access

    async def build_tree(self, max_depth: int = _TREE_MAX_DEPTH) -> DriveNode:
        """
        Build the complete folder tree with decrypted names.

        Args:
            max_depth: Maximum folder depth to traverse.

        Returns:
            Root DriveNode with children populated.

        Raises:
            AuthenticationError: If not authenticated with drive access.

        Example:
            ```python
            root = await client.build_tree()
            print(root.format_tree())
            ```
        """
        self._require_drive_access()
        if self._tree_service is None:
            raise RuntimeError("Client not initialized")
        return await self._tree_service.build_tree(max_depth)

    async def list_directory(self, path: str = "/") -> list[DriveNode]:
        """
        List contents of a directory.

        Args:
            path: Directory path (e.g., "/Documents").

        Returns:
            List of child nodes (files and folders).

        Raises:
            PathNotFoundError: If the path doesn't exist.
            NotAFolderError: If the path is a file.
        """
        self._require_drive_access()
        if self._tree_service is None:
            raise RuntimeError("Client not initialized")
        return await self._tree_service.list_directory(path)

    async def get_node(self, path: str) -> DriveNode | None:
        """
        Get a node by path.

        Args:
            path: File or folder path.

        Returns:
            DriveNode or None if not found.
        """
        self._require_drive_access()
        if self._tree_service is None:
            raise RuntimeError("Client not initialized")
        return await self._tree_service.get_node_by_path(path)

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
            CryptoError: If decryption fails.

        Example:
            ```python
            with open("local_file.pdf", "wb") as f:
                async for chunk in client.download_file("/docs/report.pdf"):
                    f.write(chunk)
            ```
        """
        self._require_drive_access()
        if self._file_service is None:
            raise RuntimeError("Client not initialized")
        async for chunk in self._file_service.download_file(path):
            yield chunk

    async def download_to_file(self, path: str, destination: Path | str) -> None:
        """
        Download a file and save to disk.

        Args:
            path: File path in the drive.
            destination: Local file path to save to.

        Raises:
            PathNotFoundError: If the path doesn't exist.
            NotAFileError: If the path is a folder.
        """
        self._require_drive_access()
        if self._file_service is None:
            raise RuntimeError("Client not initialized")
        await self._file_service.download_to_file(path, Path(destination))

    def _require_drive_access(self) -> None:
        if not self.is_authenticated:
            msg = "Not authenticated. Call authenticate() first."
            raise AuthenticationError(msg)

        if self.requires_2fa:
            raise TwoFactorRequiredError()

        if not self.has_drive_access:
            msg = "No drive access. Check account permissions."
            raise AuthenticationError(msg)
