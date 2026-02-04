"""
HTTP transport for recording and replaying API responses.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx


def _request_key(request: httpx.Request) -> str:
    """Generate a unique key for a request based on method, URL, and body."""
    body = request.content.decode() if request.content else ""
    raw = f"{request.method}|{request.url}|{body}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class RecordingTransport(httpx.AsyncBaseTransport):
    """Records HTTP requests/responses to JSON files."""

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._inner = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self._inner.handle_async_request(request)
        await response.aread()

        key = _request_key(request)
        data = {
            "request": {
                "method": request.method,
                "url": str(request.url),
                "content": request.content.decode() if request.content else None,
            },
            "response": {
                "status_code": response.status_code,
                "content": response.content.decode("utf-8", errors="replace"),
            },
        }

        (self._output_dir / f"{key}.json").write_text(json.dumps(data, indent=2))
        return response

    async def aclose(self) -> None:
        await self._inner.aclose()


class ReplayTransport(httpx.AsyncBaseTransport):
    """Replays recorded HTTP responses from JSON files."""

    def __init__(self, fixtures_dir: Path) -> None:
        self._fixtures: dict[str, dict[str, Any]] = {}
        for f in fixtures_dir.iterdir():
            if not f.suffix == ".json":
                continue
            data = json.loads(f.read_text())
            key = f.stem  # filename without extension is the key
            self._fixtures[key] = data

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = _request_key(request)

        if key not in self._fixtures:
            msg = f"No recorded response for: {request.method} {request.url}"
            raise ValueError(msg)

        resp = self._fixtures[key]["response"]
        return httpx.Response(
            status_code=resp["status_code"],
            content=resp["content"].encode(),
        )

    async def aclose(self) -> None:
        pass
