"""Authentication-related API endpoints."""

from typing import Any

import structlog

from proton_drive.api.http_client import AsyncHttpClient

logger = structlog.get_logger(__name__)


async def get_auth_info(http: AsyncHttpClient, username: str) -> dict[str, Any]:
    """
    Get authentication info for SRP.

    Args:
        http: Configured async HTTP client.
        username: Proton username/email.

    Returns:
        Auth info including Modulus, ServerEphemeral, Salt, Version, SRPSession.
    """
    return await http.request(
        "POST",
        "/auth/v4/info",
        json={"Username": username},
        authenticated=False,
    )


async def authenticate(
    http: AsyncHttpClient,
    username: str,
    client_ephemeral: str,
    client_proof: str,
    srp_session: str,
) -> dict[str, Any]:
    """
    Complete SRP authentication.

    Args:
        http: Configured async HTTP client.
        username: Proton username.
        client_ephemeral: Base64-encoded client ephemeral.
        client_proof: Base64-encoded client proof.
        srp_session: SRP session from auth info.

    Returns:
        Auth response with UID, AccessToken, RefreshToken, Scope, ServerProof.
    """
    return await http.request(
        "POST",
        "/auth/v4",
        json={
            "Username": username,
            "ClientEphemeral": client_ephemeral,
            "ClientProof": client_proof,
            "SRPSession": srp_session,
        },
        authenticated=False,
    )


async def provide_2fa(http: AsyncHttpClient, code: str) -> dict[str, Any]:
    """
    Provide 2FA code.

    Args:
        http: Configured async HTTP client.
        code: 6-digit 2FA code.

    Returns:
        Response with updated Scopes.
    """
    return await http.request(
        "POST",
        "/auth/v4/2fa",
        json={"TwoFactorCode": code},
    )


async def logout(http: AsyncHttpClient) -> None:
    """Logout and invalidate tokens."""
    try:
        await http.request("DELETE", "/auth")
    except Exception as e:
        logger.warning("Logout request failed", error=str(e))
