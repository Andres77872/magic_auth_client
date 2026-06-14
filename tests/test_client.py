"""Per-method happy-path tests: URL, HTTP method, credential placement, User-Agent."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from magic_auth_client import (
    ChangePasswordResponse,
    CheckAvailabilityResponse,
    EmailListResponse,
    LoginResponse,
    LogoutResponse,
    MagicAuthConfig,
    RegisterResponse,
    RemoveEmailResponse,
    SetPrimaryEmailResponse,
    SwitchProjectResponse,
    UserProfileResponse,
    ValidateApiKeyResponse,
    ValidateSessionResponse,
)


def form(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode())


async def test_login_sends_form_and_user_agent(make_client, recorder):
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
    resp = await client.login("alice", "pw", project_hash="P1")

    assert isinstance(resp, LoginResponse)
    assert resp.access_token == "acc"
    assert resp.accessible_projects[0].project_hash == "P1"
    req = rec.last
    assert req.method == "POST"
    assert str(req.url) == "http://auth.test/auth/login"
    assert req.headers["user-agent"] == "test-agent/1.0"
    assert req.headers["accept"] == "application/json"
    body = form(req)
    assert body["username"] == ["alice"]
    assert body["password"] == ["pw"]
    assert body["project_hash"] == ["P1"]


async def test_login_falls_back_to_config_project_hash(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)
    await client.login("alice", "pw")  # config.project_hash == "PROJ"
    assert form(rec.last)["project_hash"] == ["PROJ"]


async def test_login_requires_project_hash(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec, config=MagicAuthConfig(base_url="http://auth.test", user_agent="t"))
    with pytest.raises(ValueError):
        await client.login("alice", "pw")
    assert rec.requests == []  # nothing sent


async def test_platform_login_has_no_project_hash(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "access_token": "a"}))
    client = make_client(rec)
    resp = await client.platform_login("root", "pw")
    assert isinstance(resp, LoginResponse)
    assert str(rec.last.url) == "http://auth.test/auth/platform/login"
    assert "project_hash" not in form(rec.last)


async def test_register_uses_config_group_and_omits_none(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200, json={"success": True, "user": {"user_hash": "u", "username": "bob"}}
        )
    )
    client = make_client(rec)
    resp = await client.register("bob", "pw", email="b@x.io")
    assert isinstance(resp, RegisterResponse)
    body = form(rec.last)
    assert body["user_group_hash"] == ["GROUP"]
    assert body["email"] == ["b@x.io"]


async def test_register_omits_none_email(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)
    await client.register("bob", "pw", user_group_hash="G")
    assert "email" not in form(rec.last)


async def test_validate_uses_bearer_header(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={"success": True, "valid": True, "user": {"user_hash": "u", "username": "a"}},
        )
    )
    client = make_client(rec)
    resp = await client.validate(token="tok")
    assert isinstance(resp, ValidateSessionResponse)
    assert resp.valid is True
    req = rec.last
    assert req.method == "GET"
    assert req.headers["authorization"] == "Bearer tok"


async def test_validate_uses_cookie(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "valid": True}))
    client = make_client(rec)
    await client.validate(session_token="cook")
    req = rec.last
    assert "authorization" not in req.headers
    assert req.headers["cookie"] == "session_token=cook"


async def test_validate_valid_false_does_not_raise(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(200, json={"success": True, "valid": False, "message": "nope"})
    )
    client = make_client(rec)
    resp = await client.validate(token="tok")
    assert resp.valid is False
    assert resp.message == "nope"


async def test_validate_requires_a_credential(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "valid": True}))
    client = make_client(rec)
    with pytest.raises(ValueError):
        await client.validate()
    assert rec.requests == []


async def test_validate_api_key_never_sends_authorization(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "valid": True,
                "api_key": {"key_id": "k", "public_id": "p"},
                "permissions": ["read"],
            },
        )
    )
    client = make_client(rec)
    resp = await client.validate_api_key("sk_abc.def")
    assert isinstance(resp, ValidateApiKeyResponse)
    assert resp.permissions == ["read"]
    req = rec.last
    assert req.method == "POST"
    assert req.headers["x-api-key"] == "sk_abc.def"
    assert "authorization" not in req.headers


async def test_logout_sends_bearer(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "message": "bye"}))
    client = make_client(rec)
    resp = await client.logout(token="tok")
    assert isinstance(resp, LogoutResponse)
    assert rec.last.headers["authorization"] == "Bearer tok"


async def test_refresh_uses_form_not_bearer(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "access_token": "new"}))
    client = make_client(rec)
    resp = await client.refresh("reftok")
    assert resp.access_token == "new"
    req = rec.last
    assert "authorization" not in req.headers
    assert form(req)["refresh_token"] == ["reftok"]


async def test_refresh_use_cookie(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)
    await client.refresh("reftok", use_cookie=True)
    req = rec.last
    assert req.headers["cookie"] == "refresh_token=reftok"
    assert not req.content  # no form body


async def test_switch_project_sends_bearer_and_form(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={"success": True, "project": {"project_hash": "P2", "project_name": "Two"}},
        )
    )
    client = make_client(rec)
    resp = await client.switch_project("acc", "P2", refresh_token="ref")
    assert isinstance(resp, SwitchProjectResponse)
    assert resp.project.project_hash == "P2"
    req = rec.last
    assert req.headers["authorization"] == "Bearer acc"
    body = form(req)
    assert body["project_hash"] == ["P2"]
    assert body["refresh_token"] == ["ref"]


async def test_check_availability(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200, json={"success": True, "username_available": True, "email_available": False}
        )
    )
    client = make_client(rec)
    resp = await client.check_availability(username="x", email="y@z.io")
    assert isinstance(resp, CheckAvailabilityResponse)
    assert resp.username_available is True
    assert resp.email_available is False


async def test_get_profile(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={"success": True, "user_hash": "u", "username": "a", "groups": [], "projects": []},
        )
    )
    client = make_client(rec)
    resp = await client.get_profile("tok")
    assert isinstance(resp, UserProfileResponse)
    assert str(rec.last.url) == "http://auth.test/users/profile"
    assert rec.last.method == "GET"
    assert rec.last.headers["authorization"] == "Bearer tok"


# Password & email workflows ---------------------------------------------------
def _accepted(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(202, json={"success": True, "message": "If the request can be processed, it has been accepted."})


async def test_forgot_password_form_no_auth(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.forgot_password("alice@example.com")
    assert rec.last.method == "POST"
    assert str(rec.last.url) == "http://auth.test/auth/password/forgot"
    assert form(rec.last)["email_or_username"] == ["alice@example.com"]
    assert "authorization" not in rec.last.headers
    assert "x-public-base-url" not in rec.last.headers


async def test_forgot_password_forwards_public_base_url(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.forgot_password(
        "alice@example.com", public_base_url="http://192.168.1.13:5173"
    )
    assert rec.last.headers["x-public-base-url"] == "http://192.168.1.13:5173"


async def test_reset_password_form_no_auth(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.reset_password("lid.secret", "NewPassw0rd!")
    assert str(rec.last.url) == "http://auth.test/auth/password/reset"
    body = form(rec.last)
    assert body["token"] == ["lid.secret"]
    assert body["new_password"] == ["NewPassw0rd!"]
    assert "authorization" not in rec.last.headers


async def test_change_password_sends_bearer_and_form(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "message": "Password changed successfully"}))
    client = make_client(rec)
    resp = await client.change_password("tok", "Old1!", "New2!")
    assert isinstance(resp, ChangePasswordResponse)
    assert str(rec.last.url) == "http://auth.test/auth/password/change"
    assert rec.last.headers["authorization"] == "Bearer tok"
    body = form(rec.last)
    assert body["current_password"] == ["Old1!"]
    assert body["new_password"] == ["New2!"]


async def test_verify_email_form_no_auth(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.verify_email("lid.secret")
    assert str(rec.last.url) == "http://auth.test/auth/email/verify"
    assert form(rec.last)["token"] == ["lid.secret"]
    assert "authorization" not in rec.last.headers


async def test_list_emails_get_bearer(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={"success": True, "emails": [{"id": "E1", "email_masked": "a***@x.io", "status": "activated", "is_primary": True}]},
        )
    )
    client = make_client(rec)
    resp = await client.list_emails("tok")
    assert isinstance(resp, EmailListResponse)
    assert resp.emails[0].id == "E1"
    assert resp.emails[0].is_primary is True
    assert rec.last.method == "GET"
    assert str(rec.last.url) == "http://auth.test/users/me/emails"
    assert rec.last.headers["authorization"] == "Bearer tok"


async def test_add_email_post_bearer(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.add_email("tok", "new@example.com")
    assert str(rec.last.url) == "http://auth.test/users/me/emails"
    assert rec.last.method == "POST"
    assert form(rec.last)["email"] == ["new@example.com"]
    assert rec.last.headers["authorization"] == "Bearer tok"
    assert "x-public-base-url" not in rec.last.headers


async def test_add_email_forwards_public_base_url(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.add_email(
        "tok", "new@example.com", public_base_url="http://192.168.1.13:5173"
    )
    assert rec.last.headers["authorization"] == "Bearer tok"
    assert rec.last.headers["x-public-base-url"] == "http://192.168.1.13:5173"


async def test_resend_email_activation(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.resend_email_activation("tok", "E1")
    assert str(rec.last.url) == "http://auth.test/users/me/emails/E1/resend"
    assert rec.last.method == "POST"
    assert rec.last.headers["authorization"] == "Bearer tok"
    assert "x-public-base-url" not in rec.last.headers


async def test_resend_email_activation_forwards_public_base_url(make_client, recorder):
    rec = recorder(_accepted)
    client = make_client(rec)
    await client.resend_email_activation(
        "tok", "E1", public_base_url="http://192.168.1.13:5173"
    )
    assert rec.last.headers["authorization"] == "Bearer tok"
    assert rec.last.headers["x-public-base-url"] == "http://192.168.1.13:5173"


async def test_remove_email_delete(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(200, json={"success": True, "email_id": "E1", "new_primary_email_id": "E2"})
    )
    client = make_client(rec)
    resp = await client.remove_email("tok", "E1")
    assert isinstance(resp, RemoveEmailResponse)
    assert resp.new_primary_email_id == "E2"
    assert rec.last.method == "DELETE"
    assert str(rec.last.url) == "http://auth.test/users/me/emails/E1"
    assert rec.last.headers["authorization"] == "Bearer tok"


async def test_set_primary_email(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "email_id": "E1", "status": "primary_changed"}))
    client = make_client(rec)
    resp = await client.set_primary_email("tok", "E1")
    assert isinstance(resp, SetPrimaryEmailResponse)
    assert str(rec.last.url) == "http://auth.test/users/me/emails/E1/primary"
    assert rec.last.method == "POST"
    assert rec.last.headers["authorization"] == "Bearer tok"
