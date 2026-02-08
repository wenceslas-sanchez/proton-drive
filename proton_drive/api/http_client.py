"""
Async HTTP client for Proton API.

Provides a clean interface for making API requests with automatic
token refresh, error handling, and retry logic.
"""

import asyncio
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

import httpx
import structlog

from proton_drive.config import ProtonDriveConfig
from proton_drive.exceptions import (
    APIError,
    NotFoundError,
    RateLimitError,
    SessionExpiredError,
)
from proton_drive.utils import WaitGroup

logger = structlog.get_logger(__name__)

SENSITIVE_KEYS = frozenset(
    {
        "AccessToken",
        "RefreshToken",
        "UID",
        "SRPSession",
        "Salt",
        "Modulus",
        "ServerEphemeral",
        "ServerProof",
        "PrivateKey",
        "Passphrase",
        "NodePassphrase",
        "NodeKey",
        "Key",
        "KeySalt",
        "KeyPacket",
        "ContentKeyPacket",
        "NodeHashKey",
        "RecoverySecret",
        "RootLinkRecoveryPassphrase",
        "Password",
    }
)


def sanitize_for_log(data: dict[str, Any]) -> dict[str, Any]:
    """
    Remove sensitive fields from a dict before logging.

    Recursively sanitizes nested dictionaries and lists.

    Args:
        data: Dictionary that may contain sensitive values.

    Returns:
        Copy with sensitive values replaced by "***".
    """
    result = {}
    for key, value in data.items():
        if key in SENSITIVE_KEYS:
            result[key] = "***"
        elif isinstance(value, dict):
            result[key] = sanitize_for_log(value)
        elif isinstance(value, list):
            result[key] = [
                sanitize_for_log(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class Session:
    """Immutable session data for atomic updates."""

    uid: str
    access_token: str
    refresh_token: str


class ProtonAPICode(IntEnum):
    """Proton API response codes."""

    SUCCESS = 1000
    INVALID_TOKEN = 401
    NOT_FOUND = 2501
    RATE_LIMITED = 85131


class AsyncHttpClient:
    """Async HTTP client for Proton API."""

    def __init__(
        self,
        config: ProtonDriveConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """
        Args:
            config: Client configuration.
            transport: Optional transport for testing (mock transport).
        """
        self._config = config
        self._transport = transport

        self._session: Session | None = None
        self._client: httpx.AsyncClient | None = None

        self._client_lock = asyncio.Lock()
        self._refresh_lock = asyncio.Lock()
        self._wait_group = WaitGroup()

    async def __aenter__(self) -> "AsyncHttpClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self._close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        async with self._client_lock:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    base_url=self._config.api_url,
                    timeout=self._config.timeout,
                    transport=self._transport,
                    headers={
                        "x-pm-apiversion": "3",
                        "Accept": "application/vnd.protonmail.v1+json",
                        "x-pm-appversion": self._config.app_version,
                        "User-Agent": self._config.user_agent,
                    },
                )
            self._wait_group.add()
        return self._client

    async def _close(self) -> None:
        """Close the HTTP client if no other context managers hold a reference."""
        async with self._client_lock:
            if self._client is None:
                logger.debug("Client not open.")
                return
            self._wait_group.done()
            if self._wait_group != 0:
                logger.debug("Skipping close, requests in progress", count=self._wait_group)
                return
            if self._client is not None:
                await self._client.aclose()
                self._client = None
                self._wait_group = WaitGroup()

    async def set_session(self, uid: str, access_token: str, refresh_token: str) -> None:
        """
        Set session tokens after authentication.

        Note:
            Internal use only. Called by AuthService after successful
            authentication. External callers should use AuthService.authenticate().

        Acquires ``_refresh_lock`` so this cannot race with
        ``_refresh_access_token`` writing ``self._session``.

        Args:
            uid: User ID.
            access_token: Bearer access token.
            refresh_token: Token for refreshing access.
        """
        async with self._refresh_lock:
            self._session = Session(uid=uid, access_token=access_token, refresh_token=refresh_token)

    async def clear_session(self) -> None:
        """
        Clear session tokens.

        Note:
            Internal use only. Called by AuthService.logout().
        """
        async with self._refresh_lock:
            if self._wait_group != 0:
                logger.debug("Skipping clear session, requests in progress", count=self._wait_group)
                return
            self._session = None
            self._client = None
            self._wait_group = WaitGroup()

    @property
    def is_authenticated(self) -> bool:
        """Check if we have session tokens."""
        return self._session is not None

    async def request(
        self,
        method: str,
        endpoint: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        authenticated: bool = True,
        auto_refresh: bool = True,
    ) -> dict[str, Any]:
        """
        Make an API request.

        Args:
            method: HTTP method (GET, POST, etc.).
            endpoint: API endpoint (e.g., "/drive/volumes").
            json: JSON body for POST/PUT requests.
            params: Query parameters.
            authenticated: Whether to include auth headers.
            auto_refresh: Whether to auto-refresh on 401.

        Returns:
            Response JSON data.

        Raises:
            APIError: If the API returns an error.
            httpx.HTTPError: If the request fails due to network issues.
            SessionExpiredError: If token refresh fails.
        """
        session = self._session  # Capture atomically for consistent reads
        headers = {}
        if authenticated and session is not None:
            headers["Authorization"] = f"Bearer {session.access_token}"
            headers["x-pm-uid"] = session.uid

        if self._client is None:
            msg = "HTTP client not initialized. Use 'async with' first."
            raise RuntimeError(msg)
        response = await self._client.request(
            method=method,
            url=endpoint,
            json=json,
            params=params,
            headers=headers,
        )

        try:
            data = response.json()
        except Exception as e:
            raise APIError(
                "Invalid JSON response from API",
                code=response.status_code,
                endpoint=endpoint,
            ) from e

        code = data.get("Code", 0)

        if code == ProtonAPICode.INVALID_TOKEN and auto_refresh and (session is not None):
            logger.debug("Token expired, attempting refresh")
            await self._refresh_access_token(stale_session=session)
            return await self.request(
                method,
                endpoint,
                json=json,
                params=params,
                authenticated=authenticated,
                auto_refresh=False,
            )

        if code != ProtonAPICode.SUCCESS:
            self._raise_api_error(code, data, endpoint)

        return data

    async def request_raw(
        self,
        method: str,
        url: str,
        *,
        timeout: float | None = None,
    ) -> bytes:
        """
        Make a raw HTTP request (for downloading blocks).

        Security:
            This method accepts arbitrary URLs. To prevent SSRF attacks,
            only pass URLs obtained from trusted Proton API responses
            (e.g., Block.URL from /drive/.../blocks endpoints).
            NEVER pass user-supplied input directly to this method.

        Args:
            method: HTTP method.
            url: Full URL from Proton API response.
            timeout: Optional custom timeout.

        Returns:
            Raw response bytes.

        Raises:
            httpx.HTTPError: If the request fails.
        """
        response = await self._client.request(
            method=method,
            url=url,
            timeout=timeout or self._config.block_download_timeout,
        )
        response.raise_for_status()
        return response.content

    async def stream_raw(
        self,
        method: str,
        url: str,
        *,
        timeout: float | None = None,
        chunk_size: int = 64 * 1024,
    ):
        """
        Stream a raw HTTP response (for large downloads).

        Security:
            This method accepts arbitrary URLs. To prevent SSRF attacks,
            only pass URLs obtained from trusted Proton API responses
            (e.g., Block.URL from /drive/.../blocks endpoints).
            NEVER pass user-supplied input directly to this method.

        Args:
            method: HTTP method.
            url: Full URL from Proton API response.
            timeout: Optional custom timeout.
            chunk_size: Size of chunks to yield.

        Yields:
            Response content in chunks.

        Raises:
            httpx.HTTPError: If the request fails.
        """
        async with self._client.stream(
            method=method,
            url=url,
            timeout=timeout or self._config.block_download_timeout,
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes(chunk_size):
                yield chunk

    async def _refresh_access_token(self, stale_session: Session) -> None:
        async with self._refresh_lock:
            if self._session is not stale_session:
                logger.debug("Token already refreshed by another coroutine")
                return

            if self._session is None:
                msg = "No session available"
                raise SessionExpiredError(msg)

            try:
                response = await self.request(
                    "POST",
                    "/auth/refresh",
                    json={
                        "ResponseType": "token",
                        "GrantType": "refresh_token",
                        "RefreshToken": self._session.refresh_token,
                        "RedirectURI": self._config.redirect_uri,
                    },
                    authenticated=True,
                    auto_refresh=False,
                )

                self._session = Session(
                    uid=self._session.uid,
                    access_token=response["AccessToken"],
                    refresh_token=response["RefreshToken"],
                )
                logger.debug("Token refreshed successfully")

            except APIError as e:
                msg = f"Token refresh failed: {e.message}"
                raise SessionExpiredError(msg) from e

    @staticmethod
    def _raise_api_error(code: int, data: dict[str, Any], endpoint: str) -> None:
        error_msg = data.get("Error", "Unknown error")

        if code == ProtonAPICode.NOT_FOUND:
            raise NotFoundError(error_msg, endpoint=endpoint)
        if code == ProtonAPICode.RATE_LIMITED:
            retry_after = data.get("RetryAfter")
            raise RateLimitError(error_msg, retry_after=retry_after)

        msg = f"{error_msg} (code={code})"
        raise APIError(msg, code=code, endpoint=endpoint)
