"""Provider-agnostic OAuth tests: the inverted handshake (init → start → callback).

The project-scoped API key travels only as ``X-API-Key`` on init/providers, project
and group are never sent, start returns the authorization URL without following the
redirect, and the callback forwards ``iss``/``error`` when present.
"""

from __future__ import annotations

import json

import httpx
import pytest

from magic_auth_client import (
    AuthApiError,
    LoginResponse,
    MagicAuthConfig,
    OAuthInitResponse,
    OAuthProvidersResponse,
)
from magic_auth_client.constants import ERROR_CODE_NAMES


API_KEY = "proj-api-key-secret-sentinel"


@pytest.fixture
def keyed_config() -> MagicAuthConfig:
    return MagicAuthConfig(
        base_url="http://auth.test",
        user_agent="test-agent/1.0",
        project_api_key=API_KEY,
    )


# init ------------------------------------------------------------------------
async def test_oauth_init_posts_json_with_api_key_and_returns_init_token(
    make_client, recorder, keyed_config
):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "init_token": "init-tok",
                "expires_in": 300,
                "connection": "google",
                "provider_type": "google",
            },
        )
    )
    client = make_client(rec, config=keyed_config)

    resp = await client.oauth_init(
        "google",
        return_origin="http://localhost:3000",
        remember_me=True,
    )

    assert isinstance(resp, OAuthInitResponse)
    assert resp.init_token == "init-tok"
    assert resp.expires_in == 300
    assert resp.connection == "google"
    assert resp.provider_type == "google"
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "http://auth.test/auth/oauth/init"
    assert req.headers["x-api-key"] == API_KEY
    assert req.headers["user-agent"] == "test-agent/1.0"
    assert "authorization" not in req.headers
    assert json.loads(req.content.decode()) == {
        "connection": "google",
        "purpose": "login",
        "return_origin": "http://localhost:3000",
        "remember_me": True,
    }


async def test_oauth_init_never_sends_project_or_group_scope(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "init_token": "t"}))
    config = MagicAuthConfig(
        base_url="http://auth.test",
        user_agent="test-agent/1.0",
        project_hash="PROJ-SENTINEL",
        user_group_hash="GROUP-SENTINEL",
        project_api_key=API_KEY,
    )
    client = make_client(rec, config=config)

    await client.oauth_init("microsoft", return_origin="http://localhost:3000")

    body = rec.last.content.decode()
    assert "PROJ-SENTINEL" not in body
    assert "GROUP-SENTINEL" not in body
    assert set(json.loads(body)) == {
        "connection",
        "purpose",
        "return_origin",
        "remember_me",
    }


async def test_oauth_init_accepts_a_per_call_api_key_override(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "init_token": "t"}))
    client = make_client(rec)  # config without a project API key

    await client.oauth_init(
        "google",
        return_origin="http://localhost:3000",
        project_api_key="other-key",
    )

    assert rec.last.headers["x-api-key"] == "other-key"


async def test_oauth_init_without_an_api_key_fails_before_any_request(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    with pytest.raises(ValueError) as excinfo:
        await client.oauth_init("google", return_origin="http://localhost:3000")

    assert rec.requests == []
    assert API_KEY not in str(excinfo.value)


async def test_oauth_init_raises_on_provider_error(make_client, recorder, keyed_config):
    rec = recorder(
        lambda r: httpx.Response(
            403,
            json={
                "success": False,
                "status": "error",
                "error": {"code": "EXT_8011", "category": "external", "message": "disabled"},
            },
        )
    )
    client = make_client(rec, config=keyed_config)

    with pytest.raises(AuthApiError) as excinfo:
        await client.oauth_init("google", return_origin="http://localhost:3000")

    assert excinfo.value.error_code == "EXT_8011"
    assert excinfo.value.error_name == "OAUTH_PROVIDER_DISABLED"


# providers -------------------------------------------------------------------
async def test_list_oauth_providers_gets_with_api_key(make_client, recorder, keyed_config):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "providers": [
                    {"connection": "google", "provider_type": "google", "display_name": "Google"}
                ],
            },
        )
    )
    client = make_client(rec, config=keyed_config)

    resp = await client.list_oauth_providers()

    assert isinstance(resp, OAuthProvidersResponse)
    assert [p.connection for p in resp.providers] == ["google"]
    assert resp.providers[0].display_name == "Google"
    req = rec.last
    assert req.method == "GET"
    assert str(req.url) == "http://auth.test/auth/oauth/providers"
    assert req.headers["x-api-key"] == API_KEY


# start -----------------------------------------------------------------------
async def test_oauth_start_posts_init_token_and_returns_location(make_client, recorder):
    authorize_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=s"
    rec = recorder(lambda r: httpx.Response(303, headers={"location": authorize_url}))
    client = make_client(rec)

    location = await client.oauth_start(
        "init-tok",
        "http://localhost:5000/auth/oauth/microsoft/callback/return",
    )

    assert location == authorize_url
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "http://auth.test/auth/oauth/start"
    assert req.headers["user-agent"] == "test-agent/1.0"
    assert json.loads(req.content.decode()) == {
        "init_token": "init-tok",
        "redirect_uri": "http://localhost:5000/auth/oauth/microsoft/callback/return",
    }


@pytest.mark.parametrize("remember_me", [True, False])
async def test_oauth_start_sends_remember_me_when_given(make_client, recorder, remember_me):
    """A real JSON boolean is what overrides the value bound at init — False included."""
    rec = recorder(lambda r: httpx.Response(303, headers={"location": "https://idp.test/auth"}))
    client = make_client(rec)

    await client.oauth_start(
        "init-tok", "http://localhost:5000/return", remember_me=remember_me
    )

    body = json.loads(rec.last.content.decode())
    assert body == {
        "init_token": "init-tok",
        "redirect_uri": "http://localhost:5000/return",
        "remember_me": remember_me,
    }
    assert type(body["remember_me"]) is bool


async def test_oauth_start_omits_remember_me_when_none(make_client, recorder):
    """Omitting the key is what leaves the init-time preference in place."""
    rec = recorder(lambda r: httpx.Response(303, headers={"location": "https://idp.test/auth"}))
    client = make_client(rec)

    await client.oauth_start("init-tok", "http://localhost:5000/return", remember_me=None)

    assert "remember_me" not in json.loads(rec.last.content.decode())


async def test_oauth_start_raises_on_provider_error(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            401,
            json={
                "success": False,
                "status": "error",
                "error": {"code": "EXT_8012", "category": "external", "message": "denied"},
            },
        )
    )
    client = make_client(rec)

    with pytest.raises(AuthApiError) as excinfo:
        await client.oauth_start("init-tok", "http://localhost:5000/return")

    assert excinfo.value.error_code == "EXT_8012"


# callback --------------------------------------------------------------------
async def test_oauth_callback_returns_login_response_without_optional_params(
    make_client, recorder
):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "access_token": "acc",
                "refresh_token": "ref",
                "user": {"user_hash": "u1", "username": "alice"},
            },
        )
    )
    client = make_client(rec)

    resp = await client.oauth_callback("code-123", "state-abc")

    assert isinstance(resp, LoginResponse)
    assert resp.access_token == "acc"
    req = rec.last
    assert req.method == "GET"
    assert req.url.path == "/auth/oauth/callback"
    assert dict(req.url.params) == {"code": "code-123", "state": "state-abc"}


async def test_oauth_callback_forwards_iss_and_error_when_present(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    await client.oauth_callback(
        "code-123",
        "state-abc",
        iss="https://accounts.google.com",
        error="access_denied",
    )

    assert dict(rec.last.url.params) == {
        "code": "code-123",
        "state": "state-abc",
        "iss": "https://accounts.google.com",
        "error": "access_denied",
    }


@pytest.mark.parametrize(
    ("status_code", "code", "name"),
    [
        (400, "EXT_8031", "OAUTH_USER_CANCELLED"),
        (409, "EXT_8032", "OAUTH_ACCOUNT_LINK_REQUIRED"),
    ],
)
async def test_oauth_callback_surfaces_the_new_neutral_codes(
    make_client, recorder, status_code, code, name
):
    rec = recorder(
        lambda r: httpx.Response(
            status_code,
            json={
                "success": False,
                "status": "error",
                "error": {"code": code, "category": "external", "message": "neutral"},
            },
        )
    )
    client = make_client(rec)

    with pytest.raises(AuthApiError) as excinfo:
        await client.oauth_callback("code-123", "state-abc")

    assert excinfo.value.status_code == status_code
    assert excinfo.value.error_code == code
    assert excinfo.value.error_name == name
    assert ERROR_CODE_NAMES[code] == name


# configuration ---------------------------------------------------------------
def test_project_api_key_is_excluded_from_repr(keyed_config):
    assert API_KEY not in repr(keyed_config)
    assert keyed_config.project_api_key == API_KEY


def test_oauth_endpoints_resolve_from_base_url(keyed_config):
    assert keyed_config.oauth_init_endpoint == "http://auth.test/auth/oauth/init"
    assert keyed_config.oauth_start_endpoint == "http://auth.test/auth/oauth/start"
    assert keyed_config.oauth_callback_endpoint == "http://auth.test/auth/oauth/callback"
    assert keyed_config.oauth_providers_endpoint == "http://auth.test/auth/oauth/providers"


def test_from_env_reads_the_project_api_key():
    config = MagicAuthConfig.from_env(
        {"AUTH_API_URL": "http://auth.test", "AUTH_PROJECT_API_KEY": API_KEY}
    )
    assert config.project_api_key == API_KEY
    assert API_KEY not in repr(config)


def test_google_named_methods_are_unchanged():
    """The deprecated Google wrappers must keep their own endpoints and signatures."""
    from inspect import signature

    from magic_auth_client import MagicAuthClient

    assert "provider_init_token" in signature(MagicAuthClient.start_google_oauth).parameters
    config = MagicAuthConfig(base_url="http://auth.test")
    assert config.google_oauth_start_endpoint == "http://auth.test/auth/google/start"
    assert config.google_oauth_callback_endpoint == "http://auth.test/auth/google/callback"
