"""Google OAuth agnostic-leg tests: start returns Google's URL (no redirect follow),
callback returns a LoginResponse, and provider errors propagate."""

from __future__ import annotations

import json

import httpx
import pytest

from magic_auth_client import AuthApiError, LoginResponse


async def test_start_google_oauth_posts_json_and_returns_location(make_client, recorder):
    google_url = "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=s&code_challenge=c"
    rec = recorder(lambda r: httpx.Response(303, headers={"location": google_url}))
    client = make_client(rec)

    location = await client.start_google_oauth(
        "pit-token",
        redirect_uri="http://localhost:5000/auth/google/callback/return",
        return_origin="http://localhost:3000",
        remember_me=True,
    )

    assert location == google_url
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "http://auth.test/auth/google/start"
    assert req.headers["user-agent"] == "test-agent/1.0"
    body = json.loads(req.content.decode())
    assert body == {
        "provider_init_token": "pit-token",
        "redirect_uri": "http://localhost:5000/auth/google/callback/return",
        "return_origin": "http://localhost:3000",
        "remember_me": True,
    }


async def test_start_google_oauth_raises_on_provider_error(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(401, json={"success": False, "message": "denied", "error_code": "OAUTH_PROVIDER_INIT_INVALID"})
    )
    client = make_client(rec)

    with pytest.raises(AuthApiError):
        await client.start_google_oauth("pit", redirect_uri="http://x", return_origin="http://y")


async def test_complete_google_oauth_gets_callback_and_returns_login_response(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "access_token": "acc",
                "refresh_token": "ref",
                "user": {"user_hash": "u1", "username": "alice"},
                "accessible_projects": [{"project_hash": "P1", "project_name": "One"}],
            },
        )
    )
    client = make_client(rec)

    resp = await client.complete_google_oauth("code-123", "state-abc")

    assert isinstance(resp, LoginResponse)
    assert resp.access_token == "acc"
    assert resp.refresh_token == "ref"
    req = rec.last
    assert req.method == "GET"
    assert req.url.path == "/auth/google/callback"
    assert dict(req.url.params) == {"code": "code-123", "state": "state-abc"}
