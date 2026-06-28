"""Async client for the magic auth provider.

Every request carries a ``User-Agent`` (the provider returns 422 without one) and
form-encodes POST bodies. The client treats tokens as opaque and validates them via
the provider; it does not verify JWT signatures locally.
"""

from __future__ import annotations

from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from collections.abc import Iterable, Mapping

from . import constants
from .config import MagicAuthConfig
from .exceptions import AuthTransportError, DelegationError, parse_error_response
from .models import (
    BillingCatalogResponse,
    ChangePasswordResponse,
    CheckAvailabilityResponse,
    DelegatedSession,
    EmailListResponse,
    LoginResponse,
    LogoutResponse,
    RegisterResponse,
    RemoveEmailResponse,
    SetPrimaryEmailResponse,
    SwitchProjectResponse,
    UserProfileResponse,
    ValidateApiKeyResponse,
    ValidateSessionResponse,
    _BaseResponse,
)

_M = TypeVar("_M", bound=BaseModel)


def _ua_override(user_agent: str | None) -> dict[str, str] | None:
    """Build a one-off ``User-Agent`` header override, or ``None`` to use the config
    default. Used by the auth-forwarding methods so a reverse-proxy consumer can relay
    the original caller's User-Agent to the provider."""
    return {constants.HEADER_USER_AGENT: user_agent} if user_agent else None


def _link_overrides(
    user_agent: str | None, public_base_url: str | None
) -> dict[str, str] | None:
    """Combine the optional ``User-Agent`` and ``X-Public-Base-Url`` overrides into a
    single header dict (or ``None`` when neither is set). A reverse-proxy/BFF consumer
    relays the end-user's browser origin via ``public_base_url`` so the provider builds
    user-facing links from where the user actually is, not its own bind address."""
    headers: dict[str, str] = {}
    if user_agent:
        headers[constants.HEADER_USER_AGENT] = user_agent
    if public_base_url:
        headers[constants.HEADER_PUBLIC_BASE_URL] = public_base_url
    return headers or None


class MagicAuthClient:
    """Async client wrapping the auth provider's auth-consumer endpoints.

    The client either owns an internal ``httpx.AsyncClient`` (created when
    ``http_client`` is omitted and closed by :meth:`aclose`) or borrows one passed in
    by the caller (never closed here) so a service can share a pooled client::

        async with MagicAuthClient(MagicAuthConfig.from_env()) as auth:
            login = await auth.login("alice", "pw", project_hash="ABC...")
    """

    def __init__(
        self,
        config: MagicAuthConfig | None = None,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._config = config if config is not None else MagicAuthConfig.from_env()
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                verify=self._config.verify_tls,
            )
            self._owns_client = True

    @property
    def config(self) -> MagicAuthConfig:
        return self._config

    # Lifecycle ----------------------------------------------------------------
    async def __aenter__(self) -> "MagicAuthClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying client, but only if this instance owns it."""
        if self._owns_client:
            await self._client.aclose()

    # Internal request helper --------------------------------------------------
    async def _request(
        self,
        method: str,
        url: str,
        *,
        model: type[_M],
        data: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> _M:
        req_headers: dict[str, str] = {
            constants.HEADER_USER_AGENT: self._config.user_agent,
            constants.HEADER_ACCEPT: "application/json",
        }
        if headers:
            req_headers.update(headers)
        # Send credentials as an explicit Cookie header rather than the per-request
        # cookies= kwarg: these are per-call credentials that must not persist on a
        # shared/borrowed client (and httpx deprecates per-request cookies).
        if cookies:
            req_headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies.items())

        form = None
        if data is not None:
            form = {key: value for key, value in data.items() if value is not None}

        try:
            response = await self._client.request(
                method,
                url,
                data=form,
                params=params,
                headers=req_headers,
            )
        except httpx.HTTPError as exc:
            raise AuthTransportError(cause=exc) from exc

        if response.status_code >= 400:
            raise parse_error_response(response)

        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthTransportError(
                "Invalid JSON response from auth service", cause=exc
            ) from exc

        return model.model_validate(payload)

    # Authentication flows -----------------------------------------------------
    async def login(
        self,
        username: str,
        password: str,
        *,
        project_hash: str | None = None,
        user_agent: str | None = None,
    ) -> LoginResponse:
        """Project-scoped login. ``project_hash`` is required by the provider for all
        users; falls back to ``config.project_hash`` when omitted. ``user_agent``
        overrides the configured User-Agent for this call (e.g. to relay a caller's)."""
        resolved = project_hash or self._config.project_hash
        if not resolved:
            raise ValueError(
                "project_hash is required for login: pass it or set config.project_hash"
            )
        return await self._request(
            "POST",
            self._config.login_endpoint,
            model=LoginResponse,
            data={"username": username, "password": password, "project_hash": resolved},
            headers=_ua_override(user_agent),
        )

    async def platform_login(self, username: str, password: str) -> LoginResponse:
        """Login for root/admin users without project scope (dashboard access)."""
        return await self._request(
            "POST",
            self._config.platform_login_endpoint,
            model=LoginResponse,
            data={"username": username, "password": password},
        )

    async def register(
        self,
        username: str,
        password: str,
        *,
        email: str | None = None,
        user_group_hash: str | None = None,
        user_agent: str | None = None,
    ) -> RegisterResponse:
        """Register a new user. ``user_group_hash`` is required by the provider;
        falls back to ``config.user_group_hash`` when omitted. ``user_agent`` overrides
        the configured User-Agent for this call."""
        resolved = user_group_hash or self._config.user_group_hash
        if not resolved:
            raise ValueError(
                "user_group_hash is required for register: pass it or set config.user_group_hash"
            )
        return await self._request(
            "POST",
            self._config.register_endpoint,
            model=RegisterResponse,
            data={
                "username": username,
                "password": password,
                "email": email,
                "user_group_hash": resolved,
            },
            headers=_ua_override(user_agent),
        )

    async def validate(
        self, *, token: str | None = None, session_token: str | None = None
    ) -> ValidateSessionResponse:
        """Validate an access token. Provide ``token`` (Bearer header) or
        ``session_token`` (cookie).

        Note: the provider may return HTTP 200 with ``valid=False``; this method does
        not raise in that case — inspect ``.valid`` on the result.
        """
        if not token and not session_token:
            raise ValueError("validate requires token or session_token")
        headers: dict[str, str] = {}
        cookies: dict[str, str] | None = None
        if token:
            headers[constants.HEADER_AUTHORIZATION] = f"Bearer {token}"
        else:
            cookies = {constants.COOKIE_SESSION: session_token}  # type: ignore[dict-item]
        return await self._request(
            "GET",
            self._config.validate_endpoint,
            model=ValidateSessionResponse,
            headers=headers,
            cookies=cookies,
        )

    async def validate_api_key(self, api_key: str) -> ValidateApiKeyResponse:
        """Validate an API key via the ``X-API-Key`` header.

        Never sends ``Authorization`` (the provider rejects requests carrying both
        with 400 ``ambiguous_credentials``). Like :meth:`validate`, a 200 with
        ``valid=False`` is returned rather than raised.
        """
        return await self._request(
            "POST",
            self._config.validate_api_key_endpoint,
            model=ValidateApiKeyResponse,
            headers={constants.HEADER_API_KEY: api_key},
        )

    async def get_billing_catalog(
        self,
        *,
        project_hash: str,
        bearer_token: str,
        provider: str = "stripe",
    ) -> BillingCatalogResponse:
        """List a project's centralized billing catalog (subscriptions + credit packs).

        This is a server-to-server read on the internal billing surface; ``bearer_token``
        is the billing S2S bearer (not a user session token). The catalog carries no
        secrets — only display info, opaque ``features``, and the price ``lookup_key``.
        """
        url = f"{self._config.base_url.rstrip('/')}/internal/projects/{project_hash}/billing/catalog"
        return await self._request(
            "GET",
            url,
            model=BillingCatalogResponse,
            params={"provider": provider},
            headers={constants.HEADER_AUTHORIZATION: f"Bearer {bearer_token}"},
        )

    async def logout(
        self,
        *,
        token: str | None = None,
        session_token: str | None = None,
        user_agent: str | None = None,
    ) -> LogoutResponse:
        """Invalidate the session and revoke its refresh family. ``user_agent``
        overrides the configured User-Agent for this call."""
        if not token and not session_token:
            raise ValueError("logout requires token or session_token")
        headers: dict[str, str] = {}
        cookies: dict[str, str] | None = None
        if token:
            headers[constants.HEADER_AUTHORIZATION] = f"Bearer {token}"
        else:
            cookies = {constants.COOKIE_SESSION: session_token}  # type: ignore[dict-item]
        if user_agent:
            headers[constants.HEADER_USER_AGENT] = user_agent
        return await self._request(
            "POST",
            self._config.logout_endpoint,
            model=LogoutResponse,
            headers=headers,
            cookies=cookies,
        )

    async def refresh(
        self, refresh_token: str, *, use_cookie: bool = False, user_agent: str | None = None
    ) -> LoginResponse:
        """Rotate the refresh family and issue a new token pair.

        The refresh token is sent as a form field (default) or via the
        ``refresh_token`` cookie (``use_cookie=True``) — never as a Bearer header.
        ``user_agent`` overrides the configured User-Agent for this call.
        """
        if use_cookie:
            return await self._request(
                "POST",
                self._config.refresh_endpoint,
                model=LoginResponse,
                cookies={constants.COOKIE_REFRESH: refresh_token},
                headers=_ua_override(user_agent),
            )
        return await self._request(
            "POST",
            self._config.refresh_endpoint,
            model=LoginResponse,
            data={"refresh_token": refresh_token},
            headers=_ua_override(user_agent),
        )

    async def switch_project(
        self, access_token: str, project_hash: str, *, refresh_token: str | None = None
    ) -> SwitchProjectResponse:
        """Switch the session to another accessible project, rotating tokens.

        Sends the access token as a Bearer header *and* ``project_hash`` (plus an
        optional ``refresh_token``) in the form body.
        """
        return await self._request(
            "POST",
            self._config.switch_project_endpoint,
            model=SwitchProjectResponse,
            data={"project_hash": project_hash, "refresh_token": refresh_token},
            headers={constants.HEADER_AUTHORIZATION: f"Bearer {access_token}"},
        )

    async def check_availability(
        self, *, username: str | None = None, email: str | None = None
    ) -> CheckAvailabilityResponse:
        """Check whether a username and/or email is available."""
        if not username and not email:
            raise ValueError("check_availability requires username or email")
        return await self._request(
            "POST",
            self._config.check_availability_endpoint,
            model=CheckAvailabilityResponse,
            data={"username": username, "email": email},
        )

    async def get_profile(self, token: str) -> UserProfileResponse:
        """Fetch the current user's full profile (groups, projects, metadata)."""
        return await self._request(
            "GET",
            self._config.profile_endpoint,
            model=UserProfileResponse,
            headers={constants.HEADER_AUTHORIZATION: f"Bearer {token}"},
        )

    # Google OAuth (agnostic legs) ---------------------------------------------
    async def start_google_oauth(
        self,
        provider_init_token: str,
        *,
        redirect_uri: str,
        return_origin: str,
        remember_me: bool = False,
        user_agent: str | None = None,
    ) -> str:
        """Begin the Google OAuth flow and return Google's authorization URL.

        POSTs the opaque ``provider_init_token`` (minted by the calling project's
        BFF, which keeps the strict project/group scope server-side) to the
        provider's ``/auth/google/start``. The provider redeems it server-to-server,
        creates PKCE/nonce state, and replies with a 303 to Google. This method does
        NOT follow that redirect — it returns the ``Location`` (Google authorization
        URL) for the BFF to hand to the browser as a top-level navigation. The
        provider is agnostic about the project: ``redirect_uri`` (where Google sends
        the user back — typically the BFF callback) and ``return_origin`` (the SPA
        origin) are supplied by the BFF and validated against the provider allowlists.

        Raises :class:`AuthApiError` if the provider rejects the request (provider
        disabled, invalid/replayed provider-init, redirect/origin not allowed).
        """
        req_headers = {
            constants.HEADER_USER_AGENT: user_agent or self._config.user_agent,
            constants.HEADER_ACCEPT: "application/json",
        }
        body = {
            "provider_init_token": provider_init_token,
            "redirect_uri": redirect_uri,
            "return_origin": return_origin,
            "remember_me": remember_me,
        }
        try:
            response = await self._client.request(
                "POST",
                self._config.google_oauth_start_endpoint,
                json=body,
                headers=req_headers,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise AuthTransportError(cause=exc) from exc

        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                raise AuthTransportError(
                    "Google OAuth start returned a redirect without a Location header"
                )
            return location
        if response.status_code >= 400:
            raise parse_error_response(response)
        raise AuthTransportError(
            f"Google OAuth start expected a redirect, got HTTP {response.status_code}"
        )

    async def complete_google_oauth(
        self,
        code: str,
        state: str,
        *,
        user_agent: str | None = None,
    ) -> LoginResponse:
        """Complete the Google OAuth callback and return the issued session.

        GETs the provider's ``/auth/google/callback`` with the ``code`` and ``state``
        Google returned. The provider consumes the one-time state, exchanges the code,
        verifies the ID token, and resolves/provisions the user into the group the BFF
        bound via provider-init, returning a :class:`LoginResponse` — the same shape as
        password login, including the refresh token. Intended to be called
        server-to-server by the BFF (no browser cookies are required; CSRF rests on the
        single-use ``state`` + PKCE + nonce).

        Raises :class:`AuthApiError` on any OAuth failure (invalid/replayed state,
        code-exchange failure, ID-token rejected, provisioning denied).
        """
        return await self._request(
            "GET",
            self._config.google_oauth_callback_endpoint,
            model=LoginResponse,
            params={"code": code, "state": state},
            headers=_ua_override(user_agent),
        )

    # Password workflows -------------------------------------------------------
    async def forgot_password(
        self,
        email_or_username: str,
        *,
        user_agent: str | None = None,
        public_base_url: str | None = None,
    ) -> _BaseResponse:
        """Request a password-reset email by email or username.

        Unauthenticated. The provider responds with a generic accepted body
        regardless of whether the identifier resolves to an account (it never
        discloses account existence). ``user_agent`` overrides the configured
        User-Agent for this call. ``public_base_url`` relays the end-user's
        browser origin so the emailed reset link points there (the provider
        validates it against its allowlist).
        """
        return await self._request(
            "POST",
            self._config.password_forgot_endpoint,
            model=_BaseResponse,
            data={"email_or_username": email_or_username},
            headers=_link_overrides(user_agent, public_base_url),
        )

    async def reset_password(
        self, token: str, new_password: str, *, user_agent: str | None = None
    ) -> _BaseResponse:
        """Consume a password-reset link token and set a new password.

        Unauthenticated; ``token`` is the ``lookup_id.secret`` value from the
        emailed link. The provider validates the password policy *before* the
        token, so a weak password raises a real 4xx (``WEAK_PASSWORD``); an
        invalid/expired token returns a generic accepted body. No session is
        created (all of the user's sessions are revoked on success).
        """
        return await self._request(
            "POST",
            self._config.password_reset_endpoint,
            model=_BaseResponse,
            data={"token": token, "new_password": new_password},
            headers=_ua_override(user_agent),
        )

    async def change_password(
        self,
        token: str,
        current_password: str,
        new_password: str,
        *,
        user_agent: str | None = None,
    ) -> ChangePasswordResponse:
        """Change the authenticated user's password (Bearer ``token``).

        Requires the current password for re-authentication. Wrong current
        password raises ``AuthUnauthorizedError`` (``INVALID_CREDENTIALS``); a
        weak new password raises ``WEAK_PASSWORD``. The provider revokes the
        user's *other* sessions but preserves this one, and issues no new token.
        ``user_agent`` overrides the configured User-Agent for this call.
        """
        headers = {constants.HEADER_AUTHORIZATION: f"Bearer {token}"}
        if user_agent:
            headers[constants.HEADER_USER_AGENT] = user_agent
        return await self._request(
            "POST",
            self._config.password_change_endpoint,
            model=ChangePasswordResponse,
            data={"current_password": current_password, "new_password": new_password},
            headers=headers,
        )

    # Email workflows ----------------------------------------------------------
    async def verify_email(
        self, token: str, *, user_agent: str | None = None
    ) -> _BaseResponse:
        """Consume an email-activation link token.

        Unauthenticated; ``token`` is the ``lookup_id.secret`` value from the
        emailed link. Returns a generic accepted body regardless of outcome. On
        success the provider activates the address and revokes the user's
        sessions. ``user_agent`` overrides the configured User-Agent.
        """
        return await self._request(
            "POST",
            self._config.email_verify_endpoint,
            model=_BaseResponse,
            data={"token": token},
            headers=_ua_override(user_agent),
        )

    async def list_emails(self, token: str) -> EmailListResponse:
        """List the authenticated user's email addresses (Bearer ``token``)."""
        return await self._request(
            "GET",
            self._config.user_emails_endpoint,
            model=EmailListResponse,
            headers={constants.HEADER_AUTHORIZATION: f"Bearer {token}"},
        )

    async def add_email(
        self,
        token: str,
        email: str,
        *,
        user_agent: str | None = None,
        public_base_url: str | None = None,
    ) -> _BaseResponse:
        """Add an email and enqueue an activation link (Bearer ``token``).

        Returns a generic accepted body on success; an invalid address raises a
        4xx. ``user_agent`` overrides the configured User-Agent for this call.
        ``public_base_url`` relays the end-user's browser origin so the emailed
        activation link points there (the provider validates it against its
        allowlist).
        """
        headers = {constants.HEADER_AUTHORIZATION: f"Bearer {token}"}
        headers.update(_link_overrides(user_agent, public_base_url) or {})
        return await self._request(
            "POST",
            self._config.user_emails_endpoint,
            model=_BaseResponse,
            data={"email": email},
            headers=headers,
        )

    async def resend_email_activation(
        self,
        token: str,
        email_id: str,
        *,
        user_agent: str | None = None,
        public_base_url: str | None = None,
    ) -> _BaseResponse:
        """Resend the activation link for a pending email (Bearer ``token``).

        Cooldown- and rate-limited by the provider; returns a generic accepted
        body. ``user_agent`` overrides the configured User-Agent for this call.
        ``public_base_url`` relays the end-user's browser origin so the emailed
        activation link points there (the provider validates it against its
        allowlist).
        """
        headers = {constants.HEADER_AUTHORIZATION: f"Bearer {token}"}
        headers.update(_link_overrides(user_agent, public_base_url) or {})
        return await self._request(
            "POST",
            self._config.user_email_resend_endpoint(email_id),
            model=_BaseResponse,
            headers=headers,
        )

    async def remove_email(self, token: str, email_id: str) -> RemoveEmailResponse:
        """Remove one of the user's email addresses (Bearer ``token``).

        If the removed address was primary, the provider promotes the next
        activated address and returns its id in ``new_primary_email_id``.
        """
        return await self._request(
            "DELETE",
            self._config.user_email_endpoint(email_id),
            model=RemoveEmailResponse,
            headers={constants.HEADER_AUTHORIZATION: f"Bearer {token}"},
        )

    async def set_primary_email(
        self, token: str, email_id: str
    ) -> SetPrimaryEmailResponse:
        """Mark an activated email as the user's primary address (Bearer ``token``)."""
        return await self._request(
            "POST",
            self._config.user_email_primary_endpoint(email_id),
            model=SetPrimaryEmailResponse,
            headers={constants.HEADER_AUTHORIZATION: f"Bearer {token}"},
        )

    # Delegated / service-to-service auth --------------------------------------
    async def validate_delegated_session(
        self,
        *,
        delegation_api_key: str,
        session_token: str,
        target_project_hash: str | None = None,
        trusted_clients: Mapping[str, Iterable[str]] | None = None,
        enabled: bool | None = None,
    ) -> DelegatedSession:
        """Resolve a delegated (service-to-service) session.

        Composes two provider calls — ``validate_api_key`` for the delegation key, then
        ``validate`` for the subject's session — and applies the trust-policy checks
        used by api.magic_llm. The resulting identity is the *subject* user.

        ``enabled``/``trusted_clients``/``target_project_hash`` fall back to
        ``config.delegation_enabled`` / ``config.delegation_trusted_clients`` /
        ``config.project_hash``. Raises :class:`DelegationError` (with a ``reason`` and
        suggested ``status_code``) when any check fails; propagates the underlying
        :class:`AuthApiError` if the provider returns a non-2xx response.
        """
        is_enabled = self._config.delegation_enabled if enabled is None else enabled
        if not is_enabled:
            raise DelegationError("delegated_auth_disabled", status_code=403, message="Delegated auth is not enabled")

        if not session_token:
            raise DelegationError("delegated_missing_subject", status_code=401, message="Authentication required")

        raw_trusted = self._config.delegation_trusted_clients if trusted_clients is None else trusted_clients
        # Normalize to {source: set(keys)}, dropping blank sources/keys (mirrors
        # api.magic_llm's _configured_trusted_clients).
        trusted: dict[str, set[str]] = {}
        for source, keys in dict(raw_trusted).items():
            norm_source = str(source).strip()
            norm_keys = {str(k).strip() for k in keys if str(k).strip()}
            if norm_source and norm_keys:
                trusted[norm_source] = norm_keys
        if not trusted:
            raise DelegationError(
                "delegated_trusted_clients_empty", status_code=403,
                message="Delegated auth trusted clients are not configured",
            )

        target = target_project_hash or self._config.project_hash
        if not target:
            raise ValueError(
                "delegation target project unknown: pass target_project_hash or set config.project_hash"
            )

        # 1) Validate the delegation API key (short-circuits before touching the session).
        api_key_resp = await self.validate_api_key(delegation_api_key)
        if not api_key_resp.valid:
            raise DelegationError("delegation_key_invalid", status_code=401, message="Invalid delegation API key")

        delegator_project_hash = api_key_resp.project.project_hash if api_key_resp.project else None
        if delegator_project_hash != target:
            raise DelegationError(
                "delegation_key_wrong_project", status_code=403,
                message="Delegation API key is not authorized for this project",
            )

        key_public_id = api_key_resp.api_key.public_id if api_key_resp.api_key else None
        all_trusted_keys = {key for keys in trusted.values() for key in keys}
        if not key_public_id or key_public_id not in all_trusted_keys:
            raise DelegationError(
                "delegation_key_not_registered", status_code=403,
                message="Delegation API key is not registered",
            )

        # 2) Validate the subject's session.
        session_resp = await self.validate(token=session_token)
        if not session_resp.valid:
            raise DelegationError("delegated_subject_invalid", status_code=401, message="Invalid subject session")

        subject_project_hash = session_resp.project.project_hash if session_resp.project else None
        if not subject_project_hash or subject_project_hash not in trusted:
            raise DelegationError(
                "delegated_source_project_not_allowed", status_code=403,
                message="Delegated source project is not allowed",
            )

        if key_public_id not in trusted[subject_project_hash]:
            raise DelegationError(
                "delegation_key_not_trusted_for_source_project", status_code=403,
                message="Delegation API key is not trusted for this source project",
            )

        user = session_resp.user
        delegator = api_key_resp.user
        return DelegatedSession(
            user_hash=user.user_hash if user else "",
            user_type=user.user_type if user else None,
            username=user.username if user else None,
            email=user.email if user else None,
            user_groups=list(session_resp.user_groups),
            project_hash=subject_project_hash,
            source_project_hash=subject_project_hash,
            target_project_hash=target,
            delegator_user_hash=delegator.user_hash if delegator else None,
            delegator_project_hash=delegator_project_hash,
            key_id=api_key_resp.api_key.key_id if api_key_resp.api_key else None,
            key_public_id=key_public_id,
            session=session_resp,
            api_key=api_key_resp,
        )
