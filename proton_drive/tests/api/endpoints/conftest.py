from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import pytest_asyncio

from proton_drive.api.http_client import AsyncHttpClient, ProtonAPICode
from proton_drive.config import ProtonDriveConfig
from proton_drive.tests.utils.recording_transport import ReplayTransport

FIXTURES_DIR = Path(__file__).parent / "data"


@pytest.fixture
def mock_http() -> Mock:
    return Mock()


def make_success_response(data: dict[str, Any]) -> dict[str, Any]:
    return {"Code": ProtonAPICode.SUCCESS, **data}


@pytest_asyncio.fixture
async def replay_http() -> AsyncIterator[AsyncHttpClient]:
    config = ProtonDriveConfig()
    transport = ReplayTransport(FIXTURES_DIR)
    client = AsyncHttpClient(config, transport=transport)
    await client._ensure_client()
    await client.set_session(uid="fake", access_token="fake", refresh_token="fake")

    yield client

    await client._close()
