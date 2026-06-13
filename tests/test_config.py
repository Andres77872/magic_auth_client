"""Tests for MagicAuthConfig and from_env() drop-in compatibility."""

from __future__ import annotations

import pytest

from magic_auth_client import MagicAuthConfig, parse_trusted_clients
from magic_auth_client.constants import DEFAULT_BASE_URL, DEFAULT_TIMEOUT_SECONDS


def test_from_env_reads_all_names():
    env = {
        "AUTH_SERVICE_BASE_URL": "https://auth.example.com/",
        "AUTH_LOGIN_URL": "https://login.example.com/x",
        "AUTH_VALIDATE_URL": "https://validate.example.com/v",
        "PROJECT_HASH": "PH",
        "USER_GROUP_HASH": "UGH",
        "AUTH_FORWARD_USER_AGENT": "svc/2.0",
        "AUTH_FORWARD_TIMEOUT_SECONDS": "5.5",
    }
    cfg = MagicAuthConfig.from_env(env)
    assert cfg.base_url == "https://auth.example.com"  # trailing slash stripped
    assert cfg.project_hash == "PH"
    assert cfg.user_group_hash == "UGH"
    assert cfg.user_agent == "svc/2.0"
    assert cfg.timeout_seconds == 5.5


def test_per_endpoint_override_beats_base_url():
    cfg = MagicAuthConfig.from_env(
        {"AUTH_SERVICE_BASE_URL": "https://auth.example.com", "AUTH_LOGIN_URL": "https://login.example.com/x"}
    )
    assert cfg.login_endpoint == "https://login.example.com/x"  # override used verbatim
    assert cfg.validate_endpoint == "https://auth.example.com/auth/validate"  # derived


def test_from_env_defaults():
    cfg = MagicAuthConfig.from_env({})
    assert cfg.base_url == DEFAULT_BASE_URL
    assert cfg.project_hash is None
    assert cfg.user_group_hash is None
    assert cfg.timeout_seconds == DEFAULT_TIMEOUT_SECONDS
    assert cfg.login_endpoint == f"{DEFAULT_BASE_URL}/auth/login"
    assert cfg.platform_login_endpoint == f"{DEFAULT_BASE_URL}/auth/platform/login"


def test_endpoints_without_override_use_base_url():
    cfg = MagicAuthConfig(base_url="http://x")
    assert cfg.switch_project_endpoint == "http://x/auth/switch-project"
    assert cfg.check_availability_endpoint == "http://x/auth/check-availability"
    assert cfg.validate_api_key_endpoint == "http://x/auth/validate-api-key"
    assert cfg.profile_endpoint == "http://x/users/profile"


# Delegation config ------------------------------------------------------------
def test_from_env_reads_delegation():
    cfg = MagicAuthConfig.from_env(
        {
            "DELEGATED_AUTH_ENABLED": "true",
            "DELEGATED_AUTH_TRUSTED_CLIENTS": "src1:k1,src1:k2,src2:k3",
        }
    )
    assert cfg.delegation_enabled is True
    assert cfg.delegation_trusted_clients == {
        "src1": frozenset({"k1", "k2"}),
        "src2": frozenset({"k3"}),
    }


def test_from_env_delegation_defaults():
    cfg = MagicAuthConfig.from_env({})
    assert cfg.delegation_enabled is False
    assert cfg.delegation_trusted_clients == {}


# Env-var alias compatibility (magic-worlds-api conventions) -------------------
def test_from_env_fallback_aliases():
    cfg = MagicAuthConfig.from_env(
        {
            "AUTH_API_URL": "https://mw.example.com/",
            "AUTH_PROVIDER_USER_AGENT": "magic-worlds-api/1.0",
            "AUTH_API_TIMEOUT": "2.5",
        }
    )
    assert cfg.base_url == "https://mw.example.com"
    assert cfg.user_agent == "magic-worlds-api/1.0"
    assert cfg.timeout_seconds == 2.5


def test_canonical_env_wins_over_alias():
    cfg = MagicAuthConfig.from_env(
        {
            "AUTH_SERVICE_BASE_URL": "https://canonical",
            "AUTH_API_URL": "https://alias",
            "AUTH_FORWARD_USER_AGENT": "canon/1",
            "AUTH_PROVIDER_USER_AGENT": "alias/1",
            "AUTH_FORWARD_TIMEOUT_SECONDS": "7",
            "AUTH_API_TIMEOUT": "2",
        }
    )
    assert cfg.base_url == "https://canonical"
    assert cfg.user_agent == "canon/1"
    assert cfg.timeout_seconds == 7.0


# parse_trusted_clients --------------------------------------------------------
def test_parse_trusted_clients_valid_and_dedupe():
    result = parse_trusted_clients("src1:k1,src1:k2,src1:k1,src2:k3")
    assert result == {"src1": frozenset({"k1", "k2"}), "src2": frozenset({"k3"})}


def test_parse_trusted_clients_blank():
    assert parse_trusted_clients("") == {}
    assert parse_trusted_clients(None) == {}
    assert parse_trusted_clients("   ") == {}


@pytest.mark.parametrize("spec", ["no-colon-here", "src:", ":key"])
def test_parse_trusted_clients_malformed(spec):
    with pytest.raises(ValueError):
        parse_trusted_clients(spec)
