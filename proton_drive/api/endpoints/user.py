"""User and key-related API endpoints."""

from typing import Any

from proton_drive.api.http_client import AsyncHttpClient
from proton_drive.models.auth import AddressKey, KeySalt, UserKey


async def get_user(http: AsyncHttpClient) -> dict[str, Any]:
    """Get user info including keys."""
    response = await http.request("GET", "/core/v4/users")
    return response.get("User", {})


async def get_user_keys(http: AsyncHttpClient) -> list[UserKey]:
    """Get user's PGP keys."""
    user = await get_user(http)
    keys = user.get("Keys", [])

    return [
        UserKey(
            key_id=k["ID"],
            armored_key=k["PrivateKey"],
            is_primary=k.get("Primary") == 1,
            fingerprint=k.get("Fingerprint"),
        )
        for k in keys
    ]


async def get_key_salts(http: AsyncHttpClient) -> list[KeySalt]:
    """Get key salts for all keys."""
    response = await http.request("GET", "/core/v4/keys/salts")
    salts = response.get("KeySalts", [])

    return [
        KeySalt(key_id=s["ID"], salt=s["KeySalt"]) for s in salts if s.get("KeySalt") is not None
    ]


async def get_addresses(http: AsyncHttpClient) -> list[dict[str, Any]]:
    """Get user addresses."""
    response = await http.request("GET", "/core/v4/addresses")
    return response.get("Addresses", [])


async def get_address_keys(http: AsyncHttpClient, address_id: str) -> list[AddressKey]:
    """Get keys for a specific address."""
    addresses = await get_addresses(http)

    for addr in addresses:
        if addr.get("ID") != address_id:
            continue
        keys = addr.get("Keys", [])
        return [
            AddressKey(
                key_id=k["ID"],
                address_id=address_id,
                armored_key=k["PrivateKey"],
                token=k.get("Token"),
                is_primary=k.get("Primary") == 1,
            )
            for k in keys
        ]

    return []
