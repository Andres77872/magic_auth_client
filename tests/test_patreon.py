"""Patreon entitlement surface: user link routes (Bearer) and the S2S entitlement reads."""

from __future__ import annotations

import json

import httpx
import pytest

from magic_auth_client import (
    AuthRateLimitError,
    AuthUnauthorizedError,
    PatreonEntitlementResponse,
    PatreonLinkRequestResponse,
    PatreonLinkStatusResponse,
    PatreonResyncResponse,
    PatreonUnlinkResponse,
)


def body(request: httpx.Request) -> dict:
    return json.loads(request.content.decode())


# User link routes -------------------------------------------------------------
async def test_request_patreon_link_sends_bearer_and_json(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            202, json={"success": True, "accepted": True, "message": "ok", "link_status": None}
        )
    )
    client = make_client(rec)
    resp = await client.request_patreon_link(
        "user-token", patreon_email_hint="patron@example.test", explicit_user_intent=True
    )

    assert isinstance(resp, PatreonLinkRequestResponse)
    assert resp.accepted is True
    assert resp.http_status == 202

    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/auth/patreon/link/request"
    assert req.headers["authorization"] == "Bearer user-token"
    assert req.headers["content-type"] == "application/json"
    assert body(req) == {
        "patreon_email_hint": "patron@example.test",
        "explicit_user_intent": True,
        "confirm_email_match": False,
    }


async def test_confirm_patreon_link_maps_proof_token_to_token_field(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "link_status": "linked",
                "entitlement": {"status": "active", "plan_code": "pro", "link_status": "linked"},
            },
        )
    )
    client = make_client(rec)
    resp = await client.confirm_patreon_link(
        "user-token", proof_token="lookup.secret", explicit_user_intent=True
    )

    assert isinstance(resp, PatreonLinkStatusResponse)
    assert resp.http_status == 200
    assert resp.link_status == "linked"
    assert resp.entitlement.plan_code == "pro"
    assert rec.last.url.path == "/auth/patreon/link/confirm"
    # The user's Bearer travels in the header; the emailed proof is the body ``token``.
    assert rec.last.headers["authorization"] == "Bearer user-token"
    assert body(rec.last) == {"token": "lookup.secret", "explicit_user_intent": True}


async def test_confirm_patreon_link_neutral_posture_exposes_202(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(202, json={"success": True, "link_status": "none"}))
    client = make_client(rec)

    resp = await client.confirm_patreon_link("user-token", lookup_id="lk", secret="sec")

    assert resp.http_status == 202
    assert resp.entitlement is None
    assert body(rec.last) == {"lookup_id": "lk", "secret": "sec", "explicit_user_intent": False}


async def test_confirm_patreon_link_rate_limited_keeps_provider_body(make_client, recorder):
    payload = {"success": False, "message": "Too many requests.", "retry_after_seconds": 30}
    rec = recorder(lambda r: httpx.Response(429, json=payload, headers={"Retry-After": "30"}))
    client = make_client(rec)

    with pytest.raises(AuthRateLimitError) as exc_info:
        await client.confirm_patreon_link("user-token", proof_token="p")

    # ``raw`` is the untouched provider body, so a BFF can mirror it to the browser.
    assert exc_info.value.raw == payload
    assert exc_info.value.retry_after_seconds == 30


async def test_get_patreon_link_status_is_a_bodyless_get(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "link_status": "linked"}))
    client = make_client(rec)

    resp = await client.get_patreon_link_status("user-token")

    assert resp.link_status == "linked"
    assert rec.last.method == "GET"
    assert rec.last.url.path == "/auth/patreon/link/status"
    assert rec.last.content == b""


async def test_unlink_patreon_without_flags_sends_no_body(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True, "link_status": "unlinked"}))
    client = make_client(rec)

    resp = await client.unlink_patreon("user-token")

    assert isinstance(resp, PatreonUnlinkResponse)
    assert resp.link_status == "unlinked"
    assert rec.last.method == "DELETE"
    assert rec.last.url.path == "/auth/patreon/link"
    assert rec.last.content == b""


async def test_unlink_patreon_sends_only_set_flags(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    await client.unlink_patreon("user-token", confirm_unlink=True)

    assert body(rec.last) == {"confirm_unlink": True}


async def test_unlink_patreon_requires_recent_reauth(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            401,
            json={
                "status": "error",
                "error": {"code": "AUTH_1003", "category": "authentication", "message": "reauth"},
            },
        )
    )
    client = make_client(rec)

    with pytest.raises(AuthUnauthorizedError) as exc_info:
        await client.unlink_patreon("user-token")

    assert exc_info.value.error_name == "SESSION_INVALID"


# S2S entitlement reads --------------------------------------------------------
async def test_get_patreon_entitlement_request_and_parse(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "user_hash": "usr-1",
                "contract_version": 1,
                "entitlement": {
                    "external_source": "patreon",
                    "status": "active",
                    "plan_code": "pro",
                    "tier_code": "gold",
                    "link_status": "linked",
                    "next_renewal_at": "2026-03-01T00:00:00Z",
                },
            },
        )
    )
    client = make_client(rec)
    resp = await client.get_patreon_entitlement("usr-1", bearer_token="patreon-s2s")

    assert isinstance(resp, PatreonEntitlementResponse)
    assert resp.entitlement.status == "active"
    assert resp.entitlement.next_renewal_at.month == 3

    req = rec.last
    assert req.method == "GET"
    assert req.url.path == "/internal/users/usr-1/entitlements"
    # The entitlement is user-scoped: no project selector is sent.
    assert req.url.query == b""
    assert req.headers["authorization"] == "Bearer patreon-s2s"


async def test_get_patreon_entitlement_free_user(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200, json={"success": True, "user_hash": "usr-1", "entitlement": {"status": "free"}}
        )
    )
    client = make_client(rec)

    resp = await client.get_patreon_entitlement("usr-1", bearer_token="patreon-s2s")

    assert resp.entitlement.status == "free"
    assert resp.entitlement.plan_code == "free"
    assert resp.entitlement.link_status == "none"


async def test_request_patreon_resync(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(202, json={"success": True, "accepted": True, "status": "queued"})
    )
    client = make_client(rec)
    resp = await client.request_patreon_resync(
        "usr-1", bearer_token="patreon-s2s", force=True, reason="support"
    )

    assert isinstance(resp, PatreonResyncResponse)
    assert resp.status == "queued"
    assert rec.last.url.path == "/internal/users/usr-1/entitlements/patreon/resync"
    assert body(rec.last) == {"force": True, "reason": "support"}
