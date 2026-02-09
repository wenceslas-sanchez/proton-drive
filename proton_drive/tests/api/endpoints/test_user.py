from unittest.mock import AsyncMock, Mock

import pytest

from proton_drive.api.endpoints.user import get_addresses, get_key_salts, get_user_keys
from proton_drive.tests.api.endpoints.conftest import make_success_response


@pytest.mark.asyncio
async def test_get_user_keys_returns_user_keys(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "User": {
                    "Keys": [
                        {
                            "ID": "key-1",
                            "PrivateKey": "armored-key-1",
                            "Primary": 1,
                        },
                        {
                            "ID": "key-2",
                            "PrivateKey": "armored-key-2",
                            "Primary": 0,
                        },
                    ],
                },
            }
        )
    )

    keys = await get_user_keys(mock_http)

    assert len(keys) == 2
    assert keys[0].key_id == "key-1"
    assert keys[0].armored_key == "armored-key-1"
    assert keys[0].is_primary is True
    assert keys[1].is_primary is False


@pytest.mark.asyncio
async def test_get_key_salts_returns_salts(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "KeySalts": [
                    {"ID": "key-1", "KeySalt": "salt-1"},
                    {"ID": "key-2", "KeySalt": "salt-2"},
                ],
            }
        )
    )

    salts = await get_key_salts(mock_http)

    assert len(salts) == 2
    assert salts[0].key_id == "key-1"
    assert salts[0].salt == "salt-1"


@pytest.mark.asyncio
async def test_get_addresses_returns_raw_dicts(mock_http: Mock) -> None:
    mock_http.request = AsyncMock(
        return_value=make_success_response(
            {
                "Addresses": [
                    {
                        "ID": "addr-1",
                        "Keys": [
                            {"ID": "key-1", "PrivateKey": "armored-key", "Primary": 1},
                        ],
                    },
                ],
            }
        )
    )

    addresses = await get_addresses(mock_http)

    assert len(addresses) == 1
    assert addresses[0]["ID"] == "addr-1"
    assert len(addresses[0]["Keys"]) == 1
    assert addresses[0]["Keys"][0]["ID"] == "key-1"
