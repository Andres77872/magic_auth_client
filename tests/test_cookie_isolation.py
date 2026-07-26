"""Provider response cookies never become process-wide backend credentials."""

from __future__ import annotations

import httpx
import pytest

from magic_auth_client import MagicAuthClient, MagicAuthConfig, RejectingCookieJar


async def test_borrowed_client_rejects_and_never_replays_provider_cookies():
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"success": True, "access_token": "access"},
            headers=[
                ("set-cookie", "session_token=provider-access; Path=/"),
                ("set-cookie", "refresh_token=provider-refresh; Path=/auth"),
            ],
        )

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    auth = MagicAuthClient(
        MagicAuthConfig(base_url="https://auth.test", project_hash="project"),
        http_client=http_client,
    )
    try:
        assert isinstance(http_client.cookies.jar, RejectingCookieJar)

        await auth.login("alice", "password")
        await auth.refresh("request-scoped-refresh")

        assert len(http_client.cookies) == 0
        assert "cookie" not in requests[1].headers
        assert b"request-scoped-refresh" in requests[1].content
    finally:
        await http_client.aclose()


@pytest.mark.parametrize(
    ("source", "header_name"),
    [
        ("jar", None),
        ("header", "Cookie"),
        ("header", "Authorization"),
        ("header", "X-API-Key"),
    ],
)
async def test_borrowed_client_rejects_preconfigured_cookie_state(
    source,
    header_name,
):
    if source == "jar":
        http_client = httpx.AsyncClient(cookies={"session_token": "shared-secret"})
    else:
        assert header_name is not None
        http_client = httpx.AsyncClient(headers={header_name: "shared-secret"})

    try:
        with pytest.raises(ValueError, match="credential|cookies"):
            MagicAuthClient(http_client=http_client)
    finally:
        await http_client.aclose()
