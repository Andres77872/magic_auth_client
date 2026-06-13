"""Tests for delegated (service-to-service) auth resolution."""

from __future__ import annotations

import httpx
import pytest

from magic_auth_client import DelegatedSession, DelegationError, MagicAuthConfig


def deleg_config(**overrides) -> MagicAuthConfig:
    base = dict(
        base_url="http://auth.test",
        project_hash="TARGET",
        user_agent="test-agent/1.0",
        delegation_enabled=True,
        delegation_trusted_clients={"SRC": frozenset({"pub1"})},
    )
    base.update(overrides)
    return MagicAuthConfig(**base)


def api_key_ok(*, public_id="pub1", project="TARGET", valid=True, key_id="k1") -> dict:
    return {
        "success": True,
        "valid": valid,
        "user": {"user_hash": "delegator", "username": "svc"},
        "project": {"project_hash": project, "project_name": "T"} if project else None,
        "api_key": {"key_id": key_id, "public_id": public_id},
    }


def session_ok(*, project="SRC", valid=True) -> dict:
    return {
        "success": True,
        "valid": valid,
        "user": {"user_hash": "subject", "username": "alice", "user_type": "consumer", "email": "a@x.io"},
        "project": {"project_hash": project, "project_name": "S"} if project else None,
        "user_groups": ["g1"],
    }


def dual_handler(api_key_resp: dict, session_resp: dict):
    def _handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/auth/validate-api-key"):
            return httpx.Response(200, json=api_key_resp)
        if path.endswith("/auth/validate"):
            return httpx.Response(200, json=session_resp)
        return httpx.Response(404, json={"detail": f"unexpected {path}"})

    return _handler


async def test_delegation_happy_path(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok()))
    client = make_client(rec, config=deleg_config())
    result = await client.validate_delegated_session(
        delegation_api_key="sk_pub1.secret", session_token="subjtok"
    )
    assert isinstance(result, DelegatedSession)
    # subject identity
    assert result.user_hash == "subject"
    assert result.user_type == "consumer"
    assert result.username == "alice"
    assert result.email == "a@x.io"
    assert result.user_groups == ["g1"]
    assert result.source_project_hash == "SRC"
    # delegation metadata
    assert result.target_project_hash == "TARGET"
    assert result.delegator_user_hash == "delegator"
    assert result.delegator_project_hash == "TARGET"
    assert result.key_public_id == "pub1"
    assert result.key_id == "k1"
    # raw sub-results preserved
    assert result.session.valid is True
    assert result.api_key.valid is True

    # two requests: api-key validated first (no Authorization), then session (no X-API-Key)
    assert len(rec.requests) == 2
    first, second = rec.requests
    assert first.url.path.endswith("/auth/validate-api-key")
    assert first.method == "POST"
    assert first.headers["x-api-key"] == "sk_pub1.secret"
    assert "authorization" not in first.headers
    assert second.url.path.endswith("/auth/validate")
    assert second.method == "GET"
    assert second.headers["authorization"] == "Bearer subjtok"
    assert "x-api-key" not in second.headers


async def test_delegation_disabled(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok()))
    client = make_client(rec, config=deleg_config(delegation_enabled=False))
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegated_auth_disabled"
    assert ei.value.status_code == 403
    assert rec.requests == []


async def test_delegation_missing_subject(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok()))
    client = make_client(rec, config=deleg_config())
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="")
    assert ei.value.reason == "delegated_missing_subject"
    assert ei.value.status_code == 401
    assert rec.requests == []


async def test_delegation_trusted_clients_empty(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok()))
    client = make_client(rec, config=deleg_config(delegation_trusted_clients={}))
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegated_trusted_clients_empty"
    assert ei.value.status_code == 403
    assert rec.requests == []


async def test_delegation_key_invalid(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(valid=False), session_ok()))
    client = make_client(rec, config=deleg_config())
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegation_key_invalid"
    assert ei.value.status_code == 401
    assert len(rec.requests) == 1  # session never validated


async def test_delegation_key_wrong_project(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(project="OTHER"), session_ok()))
    client = make_client(rec, config=deleg_config())
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegation_key_wrong_project"
    assert ei.value.status_code == 403
    assert len(rec.requests) == 1


async def test_delegation_key_not_registered(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(public_id="unknown"), session_ok()))
    client = make_client(rec, config=deleg_config())
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegation_key_not_registered"
    assert len(rec.requests) == 1


async def test_delegation_source_project_not_allowed(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok(project="UNKNOWN_SRC")))
    client = make_client(rec, config=deleg_config())
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegated_source_project_not_allowed"
    assert len(rec.requests) == 2


async def test_delegation_subject_invalid(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok(valid=False)))
    client = make_client(rec, config=deleg_config())
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegated_subject_invalid"
    assert ei.value.status_code == 401
    assert len(rec.requests) == 2


async def test_delegation_key_not_trusted_for_source(make_client, recorder):
    # pub1 is globally registered (via OTHER) but SRC only trusts pubX.
    trusted = {"SRC": frozenset({"pubX"}), "OTHER": frozenset({"pub1"})}
    rec = recorder(dual_handler(api_key_ok(public_id="pub1"), session_ok(project="SRC")))
    client = make_client(rec, config=deleg_config(delegation_trusted_clients=trusted))
    with pytest.raises(DelegationError) as ei:
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert ei.value.reason == "delegation_key_not_trusted_for_source_project"
    assert len(rec.requests) == 2


async def test_delegation_per_call_overrides_and_list_trust(make_client, recorder):
    # Config has delegation disabled and no trust; per-call args override everything,
    # and trusted_clients accepts a plain list (normalized internally).
    rec = recorder(dual_handler(api_key_ok(project="PX"), session_ok(project="SX")))
    client = make_client(rec, config=MagicAuthConfig(base_url="http://auth.test", user_agent="t"))
    result = await client.validate_delegated_session(
        delegation_api_key="k",
        session_token="t",
        enabled=True,
        target_project_hash="PX",
        trusted_clients={"SX": ["pub1"]},
    )
    assert result.target_project_hash == "PX"
    assert result.source_project_hash == "SX"


async def test_delegation_target_required(make_client, recorder):
    rec = recorder(dual_handler(api_key_ok(), session_ok()))
    client = make_client(rec, config=deleg_config(project_hash=None))
    with pytest.raises(ValueError):
        await client.validate_delegated_session(delegation_api_key="k", session_token="t")
    assert rec.requests == []
