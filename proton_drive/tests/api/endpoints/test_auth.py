from unittest.mock import AsyncMock, Mock

import pytest

from proton_drive.api.endpoints.auth import authenticate, get_auth_info, logout, provide_2fa
from proton_drive.tests.api.endpoints.conftest import make_success_response


@pytest.mark.asyncio
async def test_get_auth_info_calls_correct_endpoint(mock_http: Mock) -> None:
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

    result = await get_auth_info(mock_http, "user@example.com")

    mock_http.request.assert_called_once_with(
        "POST",
        "/auth/v4/info",
        json={"Username": "user@example.com"},
        authenticated=False,
    )
    assert result["Modulus"] == "test-modulus"


@pytest.mark.asyncio
async def test_authenticate_calls_correct_endpoint(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "UID": "test-uid",
                "AccessToken": "test-token",
            }
        )
    )

    await authenticate(
        mock_http,
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
async def test_provide_2fa_calls_correct_endpoint(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Scopes": ["full", "drive"],
            }
        )
    )

    result = await provide_2fa(mock_http, "123456")

    mock_http.request.assert_called_once_with(
        "POST",
        "/auth/v4/2fa",
        json={"TwoFactorCode": "123456"},
    )
    assert result["Scopes"] == ["full", "drive"]


@pytest.mark.asyncio
async def test_logout_calls_correct_endpoint(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(return_value=make_success_response({}))

    await logout(mock_http)

    mock_http.request.assert_called_once_with("DELETE", "/auth")
