"""Tests for response models: forward-compatibility, defaults, and helpers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from magic_auth_client import ActionResponse, LoginResponse, ValidateSessionResponse
from magic_auth_client.models import TokenPair, _BaseResponse


def test_extra_fields_ignored():
    resp = LoginResponse.model_validate(
        {
            "success": True,
            "access_token": "a",
            "brand_new_server_field": {"nested": 1},
            "user": {"user_hash": "u", "username": "n", "surprise": "x"},
        }
    )
    assert resp.access_token == "a"
    assert resp.user is not None and resp.user.user_hash == "u"
    assert not hasattr(resp, "brand_new_server_field")
    assert not hasattr(resp.user, "surprise")


def test_token_pair_defaults():
    tp = TokenPair()
    assert tp.token_type == "Bearer"
    assert tp.access_token is None
    assert tp.refresh_token is None
    assert tp.remember_me is False


def test_action_response_is_public_and_private_name_is_compatibility_alias():
    response = ActionResponse(success=True, message="accepted")
    assert response.message == "accepted"
    assert _BaseResponse is ActionResponse


def test_login_response_collection_defaults():
    resp = LoginResponse.model_validate({"success": True})
    assert resp.accessible_projects == []
    assert resp.user_groups == []
    assert resp.user is None


def test_validate_session_minimal():
    resp = ValidateSessionResponse.model_validate({"valid": True})
    assert resp.valid is True
    assert resp.auth_method == "session"
    assert resp.user_groups == []


def test_is_expired():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    assert TokenPair(expires_at=past).is_expired() is True
    assert TokenPair(expires_at=future).is_expired() is False
    assert TokenPair().is_expired() is None
