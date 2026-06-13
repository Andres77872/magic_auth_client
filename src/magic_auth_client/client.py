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
    CheckAvailabilityResponse,
    DelegatedSession,
    LoginResponse,
    LogoutResponse,
    RegisterResponse,
    SwitchProjectResponse,
    UserProfileResponse,
    ValidateApiKeyResponse,
    ValidateSessionResponse,
)

_M = TypeVar("_M", bound=BaseModel)


def _ua_override(user_agent: str | None) -> dict[str, str] | None:
    """Build a one-off ``User-Agent`` header override, or ``None`` to use the config
    default. Used by the auth-forwarding methods so a reverse-proxy consumer can relay
    the original caller's User-Agent to the provider."""
    return {constants.HEADER_USER_AGENT: user_agent} if user_agent else None


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
