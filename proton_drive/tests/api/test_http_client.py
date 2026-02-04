"""Tests for AsyncHttpClient."""

import json
from typing import Any

import httpx
import pytest

from proton_drive.api.http_client import AsyncHttpClient, ProtonAPICode
from proton_drive.config import ProtonDriveConfig
from proton_drive.exceptions import (
    APIError,
    NotFoundError,
    RateLimitError,
    SessionExpiredError,
)


class MockTransport(httpx.AsyncBaseTransport):
    """Mock transport for testing."""

    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self._responses = responses or []
        self._call_index = 0
        self.requests: list[httpx.Request] = []

    def add_response(
        self,
        status_code: int = httpx.codes.OK,
        json_data: dict[str, Any] | None = None,
        content: bytes | None = None,
    ) -> None:
        """Add a response to the queue."""
        self._responses.append(
            {
                "status_code": status_code,
                "json_data": json_data,
                "content": content,
            }
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Return next queued response."""
        self.requests.append(request)
        if self._call_index >= len(self._responses):
            return httpx.Response(
                httpx.codes.INTERNAL_SERVER_ERROR,
                content=b'{"Code": 500, "Error": "No mock response"}',
            )

        resp_data = self._responses[self._call_index]
        self._call_index += 1

        content = resp_data.get("content")
        if content is None and resp_data.get("json_data"):
            content = json.dumps(resp_data["json_data"]).encode()

        return httpx.Response(
            status_code=resp_data["status_code"],
            content=content or b"",
        )


@pytest.fixture
def config() -> ProtonDriveConfig:
    """Create test config."""
    return ProtonDriveConfig()


@pytest.fixture
def mock_transport() -> MockTransport:
    """Create mock transport."""
    return MockTransport()


# Session management tests


def test_is_authenticated_returns_false_initially(config: ProtonDriveConfig) -> None:
    """Test that client is not authenticated by default."""
    client = AsyncHttpClient(config)
    assert client.is_authenticated is False


def test_set_session_sets_tokens(config: ProtonDriveConfig) -> None:
    """Test that set_session stores tokens."""
    client = AsyncHttpClient(config)
    client.set_session(
        uid="test-uid",
        access_token="test-access",
        refresh_token="test-refresh",
    )

    assert client.is_authenticated is True
    assert client._uid == "test-uid"
    assert client._access_token == "test-access"
    assert client._refresh_token == "test-refresh"


def test_clear_session_removes_tokens(config: ProtonDriveConfig) -> None:
    """Test that clear_session removes all tokens."""
    client = AsyncHttpClient(config)
    client.set_session(
        uid="test-uid",
        access_token="test-access",
        refresh_token="test-refresh",
    )
    client.clear_session()

    assert client.is_authenticated is False
    assert client._uid is None
    assert client._access_token is None
    assert client._refresh_token is None


# Request headers tests


@pytest.mark.asyncio
async def test_request_includes_auth_headers_when_authenticated(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that authenticated requests include auth headers."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        client.set_session(
            uid="test-uid",
            access_token="test-token",
            refresh_token="refresh",
        )
        await client.request("GET", "/test")

    request = mock_transport.requests[0]
    assert request.headers.get("authorization") == "Bearer test-token"
    assert request.headers.get("x-pm-uid") == "test-uid"


@pytest.mark.asyncio
async def test_request_excludes_auth_headers_when_not_authenticated(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that unauthenticated requests don't include auth headers."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        await client.request("GET", "/test", authenticated=False)

    request = mock_transport.requests[0]
    assert "authorization" not in request.headers
    assert "x-pm-uid" not in request.headers


@pytest.mark.asyncio
async def test_request_includes_default_headers(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that requests include default Proton headers."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        await client.request("GET", "/test", authenticated=False)

    request = mock_transport.requests[0]
    assert request.headers.get("x-pm-apiversion") == "3"
    assert "x-pm-appversion" in request.headers
    assert "user-agent" in request.headers


# Request/response handling tests


@pytest.mark.asyncio
async def test_request_returns_json_data(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that successful request returns JSON data."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS, "Data": "test"})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        result = await client.request("GET", "/test", authenticated=False)

    assert result == {"Code": ProtonAPICode.SUCCESS, "Data": "test"}


@pytest.mark.asyncio
async def test_request_sends_json_body(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that request sends JSON body correctly."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        await client.request(
            "POST",
            "/test",
            json={"key": "value"},
            authenticated=False,
        )

    request = mock_transport.requests[0]
    assert json.loads(request.content) == {"key": "value"}


@pytest.mark.asyncio
async def test_request_sends_query_params(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that request sends query params correctly."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        await client.request(
            "GET",
            "/test",
            params={"page": 1, "limit": 10},
            authenticated=False,
        )

    request = mock_transport.requests[0]
    assert "page=1" in str(request.url)
    assert "limit=10" in str(request.url)


# Error handling tests


@pytest.mark.asyncio
async def test_request_raises_api_error_on_failure(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that failed API response raises APIError."""
    mock_transport.add_response(json_data={"Code": 9999, "Error": "Test error"})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        with pytest.raises(APIError) as exc_info:
            await client.request("GET", "/test", authenticated=False)

    assert "Test error" in str(exc_info.value)
    assert exc_info.value.code == 9999


@pytest.mark.asyncio
async def test_request_raises_not_found_error_on_2501(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that code 2501 raises NotFoundError."""
    mock_transport.add_response(json_data={"Code": 2501, "Error": "Not found"})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        with pytest.raises(NotFoundError):
            await client.request("GET", "/test", authenticated=False)


@pytest.mark.asyncio
async def test_request_raises_rate_limit_error_on_85131(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that code 85131 raises RateLimitError."""
    mock_transport.add_response(
        json_data={
            "Code": 85131,
            "Error": "Rate limited",
            "RetryAfter": 60,
        }
    )

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        with pytest.raises(RateLimitError) as exc_info:
            await client.request("GET", "/test", authenticated=False)

    assert exc_info.value.retry_after == 60


@pytest.mark.asyncio
async def test_request_raises_api_error_on_invalid_json(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that invalid JSON response raises APIError."""
    mock_transport.add_response(status_code=httpx.codes.OK, content=b"not json")

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        with pytest.raises(APIError) as exc_info:
            await client.request("GET", "/test", authenticated=False)

    assert "Invalid JSON" in str(exc_info.value)


# Token refresh tests


@pytest.mark.asyncio
async def test_request_refreshes_token_on_401(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that 401 triggers token refresh and retry."""
    # First request returns 401
    mock_transport.add_response(json_data={"Code": ProtonAPICode.INVALID_TOKEN})
    # Refresh request succeeds
    mock_transport.add_response(
        json_data={
            "Code": ProtonAPICode.SUCCESS,
            "AccessToken": "new-token",
            "RefreshToken": "new-refresh",
        }
    )
    # Retry request succeeds
    mock_transport.add_response(json_data={"Code": ProtonAPICode.SUCCESS, "Data": "success"})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        client.set_session(
            uid="test-uid",
            access_token="old-token",
            refresh_token="old-refresh",
        )
        result = await client.request("GET", "/test")

    assert result["Data"] == "success"
    assert client._access_token == "new-token"
    assert client._refresh_token == "new-refresh"


@pytest.mark.asyncio
async def test_request_raises_session_expired_on_refresh_failure(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that failed refresh raises SessionExpiredError."""
    # First request returns 401
    mock_transport.add_response(json_data={"Code": ProtonAPICode.INVALID_TOKEN})
    # Refresh request fails
    mock_transport.add_response(json_data={"Code": 9999, "Error": "Refresh failed"})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        client.set_session(
            uid="test-uid",
            access_token="old-token",
            refresh_token="old-refresh",
        )
        with pytest.raises(SessionExpiredError):
            await client.request("GET", "/test")


@pytest.mark.asyncio
async def test_request_does_not_refresh_when_disabled(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that auto_refresh=False prevents token refresh."""
    mock_transport.add_response(json_data={"Code": ProtonAPICode.INVALID_TOKEN})

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        client.set_session(
            uid="test-uid",
            access_token="token",
            refresh_token="refresh",
        )
        # With auto_refresh=False, should not retry
        with pytest.raises(APIError):
            await client.request("GET", "/test", auto_refresh=False)

    # Only one request should have been made
    assert len(mock_transport.requests) == 1


# Raw request tests


@pytest.mark.asyncio
async def test_request_raw_returns_bytes(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that request_raw returns raw bytes."""
    mock_transport.add_response(status_code=httpx.codes.OK, content=b"raw content")

    async with AsyncHttpClient(config, transport=mock_transport) as client:
        result = await client.request_raw("GET", "https://example.com/file")

    assert result == b"raw content"


@pytest.mark.asyncio
async def test_stream_raw_yields_chunks(config: ProtonDriveConfig) -> None:
    """Test that stream_raw yields content chunks."""

    class StreamingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(httpx.codes.OK, content=b"chunk1chunk2chunk3")

    async with AsyncHttpClient(config, transport=StreamingTransport()) as client:
        chunks = []
        async for chunk in client.stream_raw("GET", "https://example.com/file"):
            chunks.append(chunk)

    assert b"".join(chunks) == b"chunk1chunk2chunk3"


# Context manager tests


@pytest.mark.asyncio
async def test_client_closes_on_exit(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that client closes properly on context exit."""
    async with AsyncHttpClient(config, transport=mock_transport) as client:
        assert client._client is not None

    assert client._client is None


@pytest.mark.asyncio
async def test_close_is_idempotent(
    config: ProtonDriveConfig,
    mock_transport: MockTransport,
) -> None:
    """Test that close can be called multiple times."""
    client = AsyncHttpClient(config, transport=mock_transport)
    await client._ensure_client()
    await client.close()
    await client.close()  # Should not raise

    assert client._client is None
