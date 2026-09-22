"""Internal billing (S2S) surface: URL, method, JSON body, credential, status, parsing."""

from __future__ import annotations

import json

import httpx
import pytest

from magic_auth_client import (
    AuthConflictError,
    AuthNotFoundError,
    BillingCheckoutResponse,
    BillingPortalResponse,
    BillingPurchaseResponse,
    BillingResyncResponse,
    BillingStatusResponse,
)


def body(request: httpx.Request) -> dict:
    return json.loads(request.content.decode())


async def test_get_billing_catalog_forwards_item_type(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    await client.get_billing_catalog(
        project_hash="P1", bearer_token="s2s", item_type="credit_package"
    )

    assert dict(rec.last.url.params) == {"provider": "stripe", "item_type": "credit_package"}


async def test_get_billing_catalog_omits_unset_item_type(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    await client.get_billing_catalog(project_hash="P1", bearer_token="s2s")

    assert dict(rec.last.url.params) == {"provider": "stripe"}


async def test_get_billing_status_request_and_parse(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "message": "Billing status returned.",
                "contract_version": 2,
                "user_hash": "usr-1",
                "project_hash": "P1",
                "provider": "stripe",
                "billing": {
                    "provider": "stripe",
                    "status": "active",
                    "plan_code": "plus",
                    "tier_code": "plus",
                    "link_status": "linked",
                    "current_period_end": "2026-02-01T00:00:00Z",
                    "cancel_at_period_end": False,
                    "subscription_ref": "bsub_1",
                },
                "purchases": [
                    {
                        "purchase_ref": "bpur_1",
                        "status": "paid",
                        "credit_product_code": "payg_100",
                        "quantity": 1,
                    }
                ],
            },
        )
    )
    client = make_client(rec)
    resp = await client.get_billing_status("usr-1", project_hash="P1", bearer_token="s2s")

    assert isinstance(resp, BillingStatusResponse)
    assert resp.http_status == 200
    assert resp.billing.status == "active"
    assert resp.billing.plan_code == "plus"
    assert resp.billing.current_period_end.year == 2026
    assert resp.purchases[0].purchase_ref == "bpur_1"
    assert resp.purchases[0].status == "paid"

    req = rec.last
    assert req.method == "GET"
    assert req.url.path == "/internal/users/usr-1/billing"
    assert dict(req.url.params) == {"project_hash": "P1", "provider": "stripe"}
    assert req.headers["authorization"] == "Bearer s2s"
    assert req.headers["user-agent"] == "test-agent/1.0"


async def test_billing_user_hash_is_path_quoted(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    await client.get_billing_status("usr/../x", project_hash="P1", bearer_token="s2s")

    assert rec.last.url.raw_path.startswith(b"/internal/users/usr%2F..%2Fx/billing")


async def test_get_billing_purchase_request_and_parse(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200,
            json={
                "success": True,
                "user_hash": "usr-1",
                "project_hash": "P1",
                "purchase": {"purchase_ref": "bpur_1", "status": "refunded"},
            },
        )
    )
    client = make_client(rec)
    resp = await client.get_billing_purchase(
        "usr-1", "bpur_1", project_hash="P1", bearer_token="s2s"
    )

    assert isinstance(resp, BillingPurchaseResponse)
    assert resp.purchase.status == "refunded"
    assert rec.last.url.path == "/internal/users/usr-1/billing/purchases/bpur_1"
    assert dict(rec.last.url.params) == {"project_hash": "P1", "provider": "stripe"}


async def test_get_billing_purchase_unknown_ref_raises_not_found(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(404, json={"success": False, "message": "Not found."}))
    client = make_client(rec)

    with pytest.raises(AuthNotFoundError) as exc_info:
        await client.get_billing_purchase("usr-1", "nope", project_hash="P1", bearer_token="s2s")

    assert exc_info.value.raw == {"success": False, "message": "Not found."}


async def test_create_billing_checkout_sends_json_and_idempotency_key(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            202,
            json={
                "success": True,
                "checkout_ref": "bco_1",
                "subscription_ref": "bsub_1",
                "purchase_ref": None,
                "url": "https://checkout.test/s/1",
            },
        )
    )
    client = make_client(rec)
    resp = await client.create_billing_checkout(
        "usr-1",
        bearer_token="s2s",
        project_hash="P1",
        intent_type="subscription",
        price_ref={"ref_type": "lookup_key", "value": "plus_monthly"},
        success_url="https://app.test/ok",
        cancel_url="https://app.test/cancel",
        plan_code="plus",
        client_intent_ref="intent-1",
        idempotency_key="idem-1",
    )

    assert isinstance(resp, BillingCheckoutResponse)
    assert resp.http_status == 202
    assert resp.url == "https://checkout.test/s/1"
    assert resp.checkout_ref == "bco_1"

    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/internal/users/usr-1/billing/checkout"
    assert req.headers["content-type"] == "application/json"
    assert req.headers["authorization"] == "Bearer s2s"
    assert req.headers["idempotency-key"] == "idem-1"
    # Unset optionals are omitted rather than sent as null.
    assert body(req) == {
        "project_hash": "P1",
        "provider": "stripe",
        "intent_type": "subscription",
        "price_ref": {"ref_type": "lookup_key", "value": "plus_monthly"},
        "quantity": 1,
        "plan_code": "plus",
        "success_url": "https://app.test/ok",
        "cancel_url": "https://app.test/cancel",
        "client_intent_ref": "intent-1",
    }


async def test_create_billing_checkout_replay_exposes_200(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            200, json={"success": True, "checkout_ref": "bco_1", "url": "https://checkout.test/s/1"}
        )
    )
    client = make_client(rec)
    resp = await client.create_billing_checkout(
        "usr-1",
        bearer_token="s2s",
        project_hash="P1",
        intent_type="credit_purchase",
        price_ref={"ref_type": "lookup_key", "value": "payg_100"},
        success_url="https://app.test/ok",
        cancel_url="https://app.test/cancel",
        credit_product_code="payg_100",
        idempotency_key="idem-1",
    )

    assert resp.http_status == 200
    assert body(rec.last)["credit_product_code"] == "payg_100"


async def test_create_billing_checkout_idempotency_conflict(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            409,
            json={
                "status": "error",
                "error": {"code": "EXT_8208", "category": "external", "message": "conflict"},
            },
        )
    )
    client = make_client(rec)

    with pytest.raises(AuthConflictError) as exc_info:
        await client.create_billing_checkout(
            "usr-1",
            bearer_token="s2s",
            project_hash="P1",
            intent_type="subscription",
            price_ref={"ref_type": "lookup_key", "value": "plus_monthly"},
            success_url="https://app.test/ok",
            cancel_url="https://app.test/cancel",
            idempotency_key="idem-1",
        )

    assert exc_info.value.error_name == "BILLING_IDEMPOTENCY_CONFLICT"


async def test_create_billing_portal(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            202, json={"success": True, "portal_ref": "bpo_1", "url": "https://portal.test/p/1"}
        )
    )
    client = make_client(rec)
    resp = await client.create_billing_portal(
        "usr-1", bearer_token="s2s", project_hash="P1", return_url="https://app.test/billing"
    )

    assert isinstance(resp, BillingPortalResponse)
    assert resp.http_status == 202
    assert resp.url == "https://portal.test/p/1"

    req = rec.last
    assert req.method == "POST"
    assert req.url.path == "/internal/users/usr-1/billing/portal"
    assert "idempotency-key" not in req.headers
    assert body(req) == {
        "project_hash": "P1",
        "provider": "stripe",
        "return_url": "https://app.test/billing",
    }


async def test_request_billing_resync_reports_declined_in_body(make_client, recorder):
    rec = recorder(
        lambda r: httpx.Response(
            202,
            json={"success": True, "accepted": False, "status": "disabled", "user_hash": "usr-1"},
        )
    )
    client = make_client(rec)
    resp = await client.request_billing_resync(
        "usr-1", bearer_token="s2s", project_hash="P1", reason="support_ticket"
    )

    assert isinstance(resp, BillingResyncResponse)
    assert resp.accepted is False
    assert resp.status == "disabled"
    assert rec.last.url.path == "/internal/users/usr-1/billing/resync"
    assert body(rec.last) == {"project_hash": "P1", "reason": "support_ticket"}


async def test_billing_forwards_request_context(make_client, recorder):
    rec = recorder(lambda r: httpx.Response(200, json={"success": True}))
    client = make_client(rec)

    await client.get_billing_status(
        "usr-1",
        project_hash="P1",
        bearer_token="s2s",
        user_agent="browser/1.0",
        client_ip="203.0.113.9",
    )

    assert rec.last.headers["user-agent"] == "browser/1.0"
    assert rec.last.headers["x-forwarded-for"] == "203.0.113.9"
