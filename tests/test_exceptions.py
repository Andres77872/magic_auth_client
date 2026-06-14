"""Error-mapping tests for both wire shapes and transport failures."""

from __future__ import annotations

import httpx
import pytest

from magic_auth_client import (
    AuthApiError,
    AuthBadRequestError,
    AuthConflictError,
    AuthForbiddenError,
    AuthServerError,
    AuthTransportError,
    AuthUnauthorizedError,
    AuthValidationError,
)


def envelope(code: str, *, message: str = "boom", category: str | None = None) -> dict:
    err: dict = {"code": code, "message": message}
    if category:
        err["category"] = category
    return {"status": "error", "error": err}


async def test_invalid_credentials_maps_to_unauthorized(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            401, json=envelope("AUTH_1001", message="bad creds", category="authentication")
        )
    )
    client = make_client(rec)
    with pytest.raises(AuthUnauthorizedError) as ei:
        await client.login("a", "b", project_hash="P")
    exc = ei.value
    assert exc.status_code == 401
    assert exc.error_code == "AUTH_1001"
    assert exc.error_name == "INVALID_CREDENTIALS"
    assert exc.category == "authentication"
    assert exc.message == "bad creds"


async def test_refresh_mismatch_friendly_name(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(401, json=envelope("AUTH_1016")))
    client = make_client(rec)
    with pytest.raises(AuthUnauthorizedError) as ei:
        await client.refresh("ref")
    assert ei.value.error_name == "REFRESH_TOKEN_MISMATCH"


async def test_conflict_username_exists(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(409, json=envelope("CONF_5001", message="taken")))
    client = make_client(rec)
    with pytest.raises(AuthConflictError) as ei:
        await client.register("a", "b", user_group_hash="G")
    assert ei.value.error_name == "USERNAME_EXISTS"


async def test_forbidden_project_access(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(403, json=envelope("AUTHZ_2003")))
    client = make_client(rec)
    with pytest.raises(AuthForbiddenError) as ei:
        await client.login("a", "b", project_hash="P")
    assert ei.value.error_name == "PROJECT_ACCESS_DENIED"


async def test_ambiguous_credentials_detail_string(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(400, json={"detail": "ambiguous_credentials"}))
    client = make_client(rec)
    with pytest.raises(AuthBadRequestError) as ei:
        await client.validate_api_key("sk_x.y")
    assert ei.value.error_code == "ambiguous_credentials"
    assert ei.value.message == "ambiguous_credentials"
    assert ei.value.error_name is None


async def test_fastapi_validation_detail_list(make_client, recorder):
    detail = [{"loc": ["header", "user-agent"], "msg": "field required", "type": "missing"}]
    rec = recorder(lambda r: httpx.Response(422, json={"detail": detail}))
    client = make_client(rec)
    with pytest.raises(AuthValidationError) as ei:
        await client.login("a", "b", project_hash="P")
    assert ei.value.message == "validation_error"
    assert ei.value.details == {"errors": detail}


async def test_server_error_unparseable_body(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(500, text="boom"))
    client = make_client(rec)
    with pytest.raises(AuthServerError) as ei:
        await client.login("a", "b", project_hash="P")
    assert ei.value.status_code == 500
    assert ei.value.error_code is None


async def test_bare_message_body_is_surfaced(make_client, recorder):
    """A bare ``{"message": ...}`` (no envelope, no ``detail``) becomes the message."""
    rec = recorder(lambda r: httpx.Response(409, json={"message": "Already exists"}))
    client = make_client(rec)
    with pytest.raises(AuthConflictError) as ei:
        await client.register("a", "b", user_group_hash="G")
    assert ei.value.message == "Already exists"
    assert ei.value.error_code is None
    assert ei.value.error_name is None


async def test_plain_text_body_is_surfaced(make_client, recorder):
    """A non-JSON error body falls back to the raw response text, not the reason phrase."""
    rec = recorder(lambda r: httpx.Response(422, text="plain provider text"))
    client = make_client(rec)
    with pytest.raises(AuthValidationError) as ei:
        await client.login("a", "b", project_hash="P")
    assert ei.value.message == "plain provider text"


async def test_change_password_wrong_current_maps_to_unauthorized(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(401, json=envelope("AUTH_1001", message="Invalid credentials"))
    )
    client = make_client(rec)
    with pytest.raises(AuthUnauthorizedError) as ei:
        await client.change_password("tok", "wrong", "NewPassw0rd!")
    assert ei.value.error_name == "INVALID_CREDENTIALS"


async def test_reset_password_weak_maps_to_validation(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(422, json=envelope("VAL_3007", message="Password too weak", category="validation"))
    )
    client = make_client(rec)
    with pytest.raises(AuthValidationError) as ei:
        await client.reset_password("lid.secret", "123")
    assert ei.value.error_name == "WEAK_PASSWORD"


async def test_change_password_rate_limited_carries_retry_after(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            429,
            json={
                "status": "error",
                "error": {
                    "code": "INT_7005",
                    "category": "internal",
                    "message": "Too many attempts",
                    "details": {"retry_after_seconds": 42},
                },
            },
        )
    )
    client = make_client(rec)
    with pytest.raises(AuthApiError) as ei:
        await client.change_password("tok", "Old1!", "New2!")
    exc = ei.value
    assert exc.status_code == 429
    assert exc.error_name == "RATE_LIMIT_EXCEEDED"
    assert exc.details == {"retry_after_seconds": 42}


async def test_transport_error(make_client, recorder):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    rec = recorder(handler)
    client = make_client(rec)
    with pytest.raises(AuthTransportError) as ei:
        await client.validate(token="t")
    assert isinstance(ei.value.cause, httpx.ConnectError)
