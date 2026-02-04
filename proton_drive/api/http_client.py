"""
Async HTTP client for Proton API.

Provides a clean interface for making API requests with automatic
token refresh, error handling, and retry logic.
"""

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

    Args:
        data: Dictionary that may contain sensitive values.

    Returns:
        Copy with sensitive values replaced by "***".
    """
    return {k: "***" if k in SENSITIVE_KEYS else v for k, v in data.items()}


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

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._uid: str | None = None

        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AsyncHttpClient":
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
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
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def set_session(self, uid: str, access_token: str, refresh_token: str) -> None:
        """
        Set session tokens after authentication.

        Args:
            uid: User ID.
            access_token: Bearer access token.
            refresh_token: Token for refreshing access.
        """
        self._uid = uid
        self._access_token = access_token
        self._refresh_token = refresh_token

    def clear_session(self) -> None:
        """Clear session tokens."""
        self._uid = None
        self._access_token = None
        self._refresh_token = None

    @property
    def is_authenticated(self) -> bool:
        """Check if we have session tokens."""
        return self._access_token is not None

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
        client = await self._ensure_client()

        headers = {}
        if authenticated and (self._access_token is not None):
            headers["Authorization"] = f"Bearer {self._access_token}"
            if self._uid is not None:
                headers["x-pm-uid"] = self._uid

        response = await client.request(
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

        if (
            code == ProtonAPICode.INVALID_TOKEN
            and auto_refresh
            and (self._refresh_token is not None)
        ):
            logger.debug("Token expired, attempting refresh")
            await self._refresh_access_token()
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

        Args:
            method: HTTP method.
            url: Full URL (not just endpoint).
            timeout: Optional custom timeout.

        Returns:
            Raw response bytes.

        Raises:
            httpx.HTTPError: If the request fails.
        """
        client = await self._ensure_client()
        response = await client.request(
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

        Args:
            method: HTTP method.
            url: Full URL.
            timeout: Optional custom timeout.
            chunk_size: Size of chunks to yield.

        Yields:
            Response content in chunks.

        Raises:
            httpx.HTTPError: If the request fails.
        """
        client = await self._ensure_client()

        async with client.stream(
            method=method,
            url=url,
            timeout=timeout or self._config.block_download_timeout,
        ) as response:
            response.raise_for_status()
            async for chunk in response.aiter_bytes(chunk_size):
                yield chunk

    async def _refresh_access_token(self) -> None:
        if self._refresh_token is None:
            msg = "No refresh token available"
            raise SessionExpiredError(msg)

        try:
            response = await self.request(
                "POST",
                "/auth/refresh",
                json={
                    "ResponseType": "token",
                    "GrantType": "refresh_token",
                    "RefreshToken": self._refresh_token,
                    "RedirectURI": self._config.redirect_uri,
                },
                authenticated=True,
                auto_refresh=False,
            )

            self._access_token = response["AccessToken"]
            self._refresh_token = response["RefreshToken"]
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
