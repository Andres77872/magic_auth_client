"""Internal transactional-email surface (root Bearer) and the public liveness probe."""

from __future__ import annotations

import json

import httpx
import pytest

from magic_auth_client import (
    AuthForbiddenError,
    AuthNotFoundError,
    AuthTransportError,
    EmailIdentityResponse,
    EmailMessageStatusResponse,
    PingResponse,
    TemplateEmailResponse,
)


def body(request: httpx.Request) -> dict:
    return json.loads(request.content.decode())


async def test_resolve_email_identity_matched(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "matched": True,
                "email": "a@example.test",
                "email_masked": "a***@example.test",
                "user_hash": "usr-1",
                "username": "alice",
                "user_type": "consumer",
            },
        )
    )
    client = make_client(rec)
    resp = await client.resolve_email_identity("A@Example.test", bearer_token="root-token")

    assert isinstance(resp, EmailIdentityResponse)
    assert resp.matched is True
    assert resp.user_hash == "usr-1"

    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/internal/email/resolve-identity"
    assert req.headers["authorization"] == "Bearer root-token"
    assert body(req) == {"email": "A@Example.test"}


async def test_resolve_email_identity_unmatched_round_trips_provider_keys(make_client, recorder):
    wire = {"matched": False, "email": "a@example.test", "email_masked": "a***@example.test"}
    rec = recorder(lambda r: httpx.Response(200, json=wire))
    client = make_client(rec)

    resp = await client.resolve_email_identity("a@example.test", bearer_token="root-token")

    assert resp.matched is False
    assert resp.user_hash is None
    # The body has no success/message envelope, and none is invented on the way out.
    assert resp.model_dump(mode="json", exclude_unset=True) == wire


async def test_resolve_email_identity_rejects_non_root(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            403,
            json={
                "status": "error",
                "error": {"code": "AUTHZ_2001", "category": "authorization", "message": "denied"},
            },
        )
    )
    client = make_client(rec)

    with pytest.raises(AuthForbiddenError) as exc_info:
        await client.resolve_email_identity("a@example.test", bearer_token="consumer-token")

    assert exc_info.value.error_name == "ACCESS_DENIED"


async def test_send_template_email_sends_json(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            202,
            json={
                "accepted": True,
                "email_message_id": "msg-1",
                "lifecycle_status": "template_email_enqueued",
                "template_code": "email_credit_grant_notification",
            },
        )
    )
    client = make_client(rec)
    resp = await client.send_template_email(
        "a@example.test",
        "email_credit_grant_notification",
        bearer_token="root-token",
        variables={"credits": "100"},
        provider_idempotency_key="grant-7",
        priority=4,
    )

    assert isinstance(resp, TemplateEmailResponse)
    assert resp.accepted is True
    assert resp.email_message_id == "msg-1"
    assert rec.last.url.path == "/internal/email/send-template"
    assert body(rec.last) == {
        "recipient_email": "a@example.test",
        "template_code": "email_credit_grant_notification",
        "variables": {"credits": "100"},
        "provider_idempotency_key": "grant-7",
        "priority": 4,
    }


async def test_send_template_email_omits_unset_optionals(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(202, json={"accepted": True}))
    client = make_client(rec)

    await client.send_template_email("a@example.test", "welcome", bearer_token="root-token")

    assert body(rec.last) == {"recipient_email": "a@example.test", "template_code": "welcome"}


async def test_get_email_message_status_keeps_null_fields(make_client, recorder):
    wire = {
        "email_message_id": "msg-1",
        "purpose": "delivery_operation",
        "template_code": "email_credit_grant_notification",
        "recipient_masked": "a***@example.test",
        "provider": "resend",
        "provider_message_id": None,
        "status": "queued",
        "attempt_count": 0,
        "max_attempts": 5,
        "sent_at": None,
        "terminal_at": None,
        "last_error_code": None,
        "created_at": "2026-01-01T12:00:00",
        "updated_at": "2026-01-01T12:00:00",
    }
    rec = recorder(lambda r: httpx.Response(200, json=wire))
    client = make_client(rec)
    resp = await client.get_email_message_status("msg-1", bearer_token="root-token")

    assert isinstance(resp, EmailMessageStatusResponse)
    assert resp.status == "queued"
    assert resp.created_at.year == 2026
    assert rec.last.url.path == "/internal/email/message-status"
    assert body(rec.last) == {"email_message_id": "msg-1"}
    # Nulls the provider sent survive a dump, so a consumer's strict DTO still sees them.
    assert resp.model_dump(mode="json", exclude_unset=True) == wire


async def test_get_email_message_status_unknown_id(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(404, json={"detail": "email_message_id not found"}))
    client = make_client(rec)

    with pytest.raises(AuthNotFoundError):
        await client.get_email_message_status("nope", bearer_token="root-token")


# System -----------------------------------------------------------------------
async def test_ping_is_an_unauthenticated_get(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={"success": True, "message": "running", "timestamp": "2026-01-01T00:00:00Z"},
        )
    )
    client = make_client(rec)
    resp = await client.ping()

    assert isinstance(resp, PingResponse)
    assert resp.success is True
    assert resp.timestamp == "2026-01-01T00:00:00Z"
    assert rec.last.method == "GET"
    assert rec.last.url.path == "/system/ping"
    assert "authorization" not in rec.last.headers
    assert rec.last.headers["user-agent"] == "test-agent/1.0"


async def test_ping_raises_when_provider_is_down(make_client):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = make_client(handler)

    with pytest.raises(AuthTransportError):
        await client.ping()
