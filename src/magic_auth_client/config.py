"""Client configuration.

``MagicAuthConfig`` is an immutable dataclass. ``from_env()`` reads the same
``AUTH_*`` environment variable names used by the existing consumer
(``api.magic_llm/src/util/const.py``) so the client is a drop-in for that wiring.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import quote

from . import constants

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def _parse_bool(value: str | None, *, default: bool, name: str) -> bool:
    """Parse a security-sensitive boolean without treating typos as ``False``."""
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    raise ValueError(f"{name} must be one of: 1/0, true/false, yes/no, on/off")


def parse_trusted_clients(spec: str | None) -> dict[str, frozenset[str]]:
    """Parse a ``DELEGATED_AUTH_TRUSTED_CLIENTS`` spec into a trust map.

    Mirrors ``api.magic_llm``'s ``_env_delegated_auth_trusted_clients``: a CSV of
    ``<source-project-hash>:<delegation-key-public-id>`` entries (one ``source:key``
    pair per comma item — repeat the source for multiple keys, e.g.
    ``"src:k1,src:k2,other:k3"``). Keys are de-duplicated per source.

    Returns ``{source_project_hash: frozenset(key_public_ids)}``. An empty/blank spec
    yields ``{}``. Raises ``ValueError`` if an entry lacks a ``:`` or has a blank side.
    """
    if not spec or not spec.strip():
        return {}

    clients: dict[str, list[str]] = {}
    for raw_entry in spec.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        source_project_hash, separator, key_public_id = entry.partition(":")
        source_project_hash = source_project_hash.strip()
        key_public_id = key_public_id.strip()
        if separator != ":" or not source_project_hash or not key_public_id:
            raise ValueError(
                "trusted-clients entries must use "
                "'<source-project-hash>:<delegation-key-public-id>'"
            )
        clients.setdefault(source_project_hash, []).append(key_public_id)

    return {
        source: frozenset(dict.fromkeys(keys))
        for source, keys in clients.items()
    }


@dataclass(frozen=True, slots=True)
class MagicAuthConfig:
    """Connection settings for the auth provider.

    Per-endpoint ``*_url`` overrides, when set, are used verbatim; otherwise the
    endpoint resolves to ``base_url`` + the documented path. ``project_hash`` and
    ``user_group_hash`` are optional defaults for :meth:`MagicAuthClient.login` /
    ``register`` and are intentionally left ``None`` so the library stays
    project-agnostic — the consumer supplies them via env.
    """

    base_url: str = constants.DEFAULT_BASE_URL
    login_url: str | None = None
    register_url: str | None = None
    logout_url: str | None = None
    refresh_url: str | None = None
    validate_url: str | None = None
    api_key_validate_url: str | None = None
    profile_url: str | None = None
    google_oauth_start_url: str | None = None
    google_oauth_callback_url: str | None = None
    project_hash: str | None = None
    user_group_hash: str | None = None
    # Project-scoped API key for the provider-agnostic OAuth surface. It is sent as
    # ``X-API-Key`` on ``/auth/oauth/init`` and ``/auth/oauth/providers`` only, is never
    # logged by this library, and is excluded from ``repr()`` so it cannot leak through
    # a traceback, a debugger frame or a structured log that renders the config.
    project_api_key: str | None = field(default=None, repr=False)
    user_agent: str = constants.DEFAULT_USER_AGENT
    timeout_seconds: float = constants.DEFAULT_TIMEOUT_SECONDS
    verify_tls: bool = True
    # Delegated / service-to-service auth policy. The target project for delegation is
    # `project_hash` (mirrors api.magic_llm's EXPECTED_PROJECT_HASH == PROJECT_HASH).
    delegation_enabled: bool = False
    delegation_trusted_clients: dict[str, frozenset[str]] = field(default_factory=dict)

    # URL resolution -----------------------------------------------------------
    def _resolve(self, override: str | None, path: str) -> str:
        if override:
            return override
        return f"{self.base_url.rstrip('/')}{path}"

    @property
    def login_endpoint(self) -> str:
        return self._resolve(self.login_url, constants.PATH_LOGIN)

    @property
    def platform_login_endpoint(self) -> str:
        # No env override exists for this endpoint; always resolved from base_url.
        return self._resolve(None, constants.PATH_PLATFORM_LOGIN)

    @property
    def register_endpoint(self) -> str:
        return self._resolve(self.register_url, constants.PATH_REGISTER)

    @property
    def validate_endpoint(self) -> str:
        return self._resolve(self.validate_url, constants.PATH_VALIDATE)

    @property
    def validate_api_key_endpoint(self) -> str:
        return self._resolve(self.api_key_validate_url, constants.PATH_VALIDATE_API_KEY)

    @property
    def logout_endpoint(self) -> str:
        return self._resolve(self.logout_url, constants.PATH_LOGOUT)

    @property
    def refresh_endpoint(self) -> str:
        return self._resolve(self.refresh_url, constants.PATH_REFRESH)

    @property
    def switch_project_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_SWITCH_PROJECT)

    @property
    def check_availability_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_CHECK_AVAILABILITY)

    @property
    def profile_endpoint(self) -> str:
        return self._resolve(self.profile_url, constants.PATH_PROFILE)

    @property
    def google_oauth_start_endpoint(self) -> str:
        return self._resolve(self.google_oauth_start_url, constants.PATH_GOOGLE_OAUTH_START)

    @property
    def google_oauth_callback_endpoint(self) -> str:
        return self._resolve(self.google_oauth_callback_url, constants.PATH_GOOGLE_OAUTH_CALLBACK)

    # Provider-agnostic OAuth (no env override; always resolved from base_url) -----
    @property
    def oauth_init_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_OAUTH_INIT)

    @property
    def oauth_start_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_OAUTH_START)

    @property
    def oauth_callback_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_OAUTH_CALLBACK)

    @property
    def oauth_providers_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_OAUTH_PROVIDERS)

    # Password & email endpoints (no env override; always resolved from base_url) --
    @property
    def password_forgot_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PASSWORD_FORGOT)

    @property
    def password_reset_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PASSWORD_RESET)

    @property
    def password_change_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PASSWORD_CHANGE)

    @property
    def email_verify_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_EMAIL_VERIFY)

    @property
    def user_emails_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_USER_EMAILS)

    def user_email_endpoint(self, email_id: str) -> str:
        return f"{self.user_emails_endpoint}/{quote(email_id, safe='')}"

    def user_email_resend_endpoint(self, email_id: str) -> str:
        return f"{self.user_email_endpoint(email_id)}/resend"

    def user_email_primary_endpoint(self, email_id: str) -> str:
        return f"{self.user_email_endpoint(email_id)}/primary"

    def billing_catalog_endpoint(self, project_hash: str) -> str:
        path = constants.PATH_BILLING_CATALOG.format(
            project_hash=quote(project_hash, safe="")
        )
        return self._resolve(None, path)

    # Internal S2S endpoints (no env override; always resolved from base_url) ------
    def _user_scoped_endpoint(self, template: str, user_hash: str, **segments: str) -> str:
        quoted = {name: quote(value, safe="") for name, value in segments.items()}
        return self._resolve(
            None, template.format(user_hash=quote(user_hash, safe=""), **quoted)
        )

    def billing_status_endpoint(self, user_hash: str) -> str:
        return self._user_scoped_endpoint(constants.PATH_BILLING_STATUS, user_hash)

    def billing_checkout_endpoint(self, user_hash: str) -> str:
        return self._user_scoped_endpoint(constants.PATH_BILLING_CHECKOUT, user_hash)

    def billing_portal_endpoint(self, user_hash: str) -> str:
        return self._user_scoped_endpoint(constants.PATH_BILLING_PORTAL, user_hash)

    def billing_purchase_endpoint(self, user_hash: str, purchase_ref: str) -> str:
        return self._user_scoped_endpoint(
            constants.PATH_BILLING_PURCHASE, user_hash, purchase_ref=purchase_ref
        )

    def billing_resync_endpoint(self, user_hash: str) -> str:
        return self._user_scoped_endpoint(constants.PATH_BILLING_RESYNC, user_hash)

    def patreon_entitlement_endpoint(self, user_hash: str) -> str:
        return self._user_scoped_endpoint(constants.PATH_PATREON_ENTITLEMENT, user_hash)

    def patreon_entitlement_resync_endpoint(self, user_hash: str) -> str:
        return self._user_scoped_endpoint(
            constants.PATH_PATREON_ENTITLEMENT_RESYNC, user_hash
        )

    @property
    def internal_email_resolve_identity_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_INTERNAL_EMAIL_RESOLVE_IDENTITY)

    @property
    def internal_email_send_template_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_INTERNAL_EMAIL_SEND_TEMPLATE)

    @property
    def internal_email_message_status_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_INTERNAL_EMAIL_MESSAGE_STATUS)

    # Patreon entitlement link (current user's Bearer) ---------------------------
    @property
    def patreon_link_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PATREON_LINK)

    @property
    def patreon_link_request_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PATREON_LINK_REQUEST)

    @property
    def patreon_link_confirm_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PATREON_LINK_CONFIRM)

    @property
    def patreon_link_status_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PATREON_LINK_STATUS)

    @property
    def ping_endpoint(self) -> str:
        return self._resolve(None, constants.PATH_PING)

    # Construction -------------------------------------------------------------
    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "MagicAuthConfig":
        """Build a config from environment variables.

        Primary names mirror ``api.magic_llm/src/util/const.py``. Fallback aliases let
        the same call serve ``magic-worlds-api``'s conventions too (the canonical name
        wins when both are set):

        * ``base_url``: ``AUTH_SERVICE_BASE_URL`` else ``AUTH_API_URL``
        * ``user_agent``: ``AUTH_FORWARD_USER_AGENT`` else ``AUTH_PROVIDER_USER_AGENT``
        * ``timeout_seconds``: ``AUTH_FORWARD_TIMEOUT_SECONDS`` else ``AUTH_API_TIMEOUT``
        * ``verify_tls``: ``AUTH_VERIFY_TLS`` (defaults to true)
        * ``project_api_key``: ``AUTH_PROJECT_API_KEY`` (only needed for the
          provider-agnostic ``/auth/oauth/init`` and ``/auth/oauth/providers`` calls)
        """
        e = env if env is not None else os.environ
        base_raw = e.get("AUTH_SERVICE_BASE_URL") or e.get("AUTH_API_URL") or constants.DEFAULT_BASE_URL
        user_agent = (
            e.get("AUTH_FORWARD_USER_AGENT")
            or e.get("AUTH_PROVIDER_USER_AGENT")
            or constants.DEFAULT_USER_AGENT
        )
        timeout_raw = (
            e.get("AUTH_FORWARD_TIMEOUT_SECONDS")
            or e.get("AUTH_API_TIMEOUT")
            or str(constants.DEFAULT_TIMEOUT_SECONDS)
        )
        delegation_enabled = (e.get("DELEGATED_AUTH_ENABLED") or "").strip().lower() in _TRUTHY
        return cls(
            base_url=base_raw.rstrip("/"),
            login_url=e.get("AUTH_LOGIN_URL"),
            register_url=e.get("AUTH_REGISTER_URL"),
            logout_url=e.get("AUTH_LOGOUT_URL"),
            refresh_url=e.get("AUTH_REFRESH_URL"),
            validate_url=e.get("AUTH_VALIDATE_URL"),
            api_key_validate_url=e.get("AUTH_API_KEY_VALIDATE_URL"),
            profile_url=e.get("AUTH_PROFILE_URL"),
            google_oauth_start_url=e.get("AUTH_GOOGLE_START_URL"),
            google_oauth_callback_url=e.get("AUTH_GOOGLE_CALLBACK_URL"),
            project_hash=e.get("PROJECT_HASH"),
            user_group_hash=e.get("USER_GROUP_HASH"),
            project_api_key=e.get("AUTH_PROJECT_API_KEY"),
            user_agent=user_agent,
            timeout_seconds=float(timeout_raw),
            verify_tls=_parse_bool(
                e.get("AUTH_VERIFY_TLS"),
                default=True,
                name="AUTH_VERIFY_TLS",
            ),
            delegation_enabled=delegation_enabled,
            delegation_trusted_clients=parse_trusted_clients(e.get("DELEGATED_AUTH_TRUSTED_CLIENTS")),
        )
