"""Shared test fixtures. All tests run offline via ``httpx.MockTransport``."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from magic_auth_client import MagicAuthClient, MagicAuthConfig


class Recorder:
    """Callable transport handler that records requests and delegates the response."""

    def __init__(self, responder: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self._responder = responder

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._responder(request)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


@pytest.fixture
def recorder() -> type[Recorder]:
    """Return the ``Recorder`` class; tests call ``recorder(responder)``."""
    return Recorder


@pytest.fixture
def test_config() -> MagicAuthConfig:
    return MagicAuthConfig(
        base_url="http://auth.test",
        project_hash="PROJ",
        user_group_hash="GROUP",
        user_agent="test-agent/1.0",
    )


@pytest.fixture
async def make_client(test_config):
    """Factory: ``make_client(handler, *, config=None) -> MagicAuthClient`` wired to a
    MockTransport. Injected clients are closed at teardown (exercises the borrowed-client
    path, which the client itself must not close)."""
    clients: list[httpx.AsyncClient] = []

    def _factory(handler, *, config: MagicAuthConfig | None = None) -> MagicAuthClient:
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(transport=transport)
        clients.append(http_client)
        return MagicAuthClient(config or test_config, http_client=http_client)

    yield _factory

    for client in clients:
        await client.aclose()
