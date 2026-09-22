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
from .cookies import RejectingCookieJar, isolate_provider_cookies
from .exceptions import AuthTransportError, DelegationError, parse_error_response
from .models import (
    ActionResponse,
    BillingCatalogResponse,
    BillingCheckoutResponse,
    BillingPortalResponse,
    BillingPurchaseResponse,
    BillingResyncResponse,
    BillingStatusResponse,
    ChangePasswordResponse,
    CheckAvailabilityResponse,
    DelegatedSession,
    EmailIdentityResponse,
    EmailListResponse,
    EmailMessageStatusResponse,
    LoginResponse,
    LogoutResponse,
    OAuthInitResponse,
    OAuthProvidersResponse,
    PatreonEntitlementResponse,
    PatreonLinkRequestResponse,
    PatreonLinkStatusResponse,
    PatreonResyncResponse,
    PatreonUnlinkResponse,
    PingResponse,
    RegisterResponse,
    RemoveEmailResponse,
    SetPrimaryEmailResponse,
    SwitchProjectResponse,
    TemplateEmailResponse,
    UserProfileResponse,
    ValidateApiKeyResponse,
    ValidateSessionResponse,
    _HttpStatusMixin,
)

_M = TypeVar("_M", bound=BaseModel)


def _request_headers(
    *,
    bearer_token: str | None = None,
    api_key: str | None = None,
    user_agent: str | None = None,
    client_ip: str | None = None,
    public_base_url: str | None = None,
    idempotency_key: str | None = None,
) -> dict[str, str] | None:
    """Build optional credential and trusted request-context headers."""
    if bearer_token and api_key:
        raise ValueError("bearer_token and api_key are mutually exclusive")

    headers: dict[str, str] = {}
    if bearer_token:
        headers[constants.HEADER_AUTHORIZATION] = f"Bearer {bearer_token}"
    if api_key:
        headers[constants.HEADER_API_KEY] = api_key
    if user_agent:
        headers[constants.HEADER_USER_AGENT] = user_agent
    if client_ip:
        headers[constants.HEADER_FORWARDED_FOR] = client_ip
    if public_base_url:
        headers[constants.HEADER_PUBLIC_BASE_URL] = public_base_url
    if idempotency_key:
        headers[constants.HEADER_IDEMPOTENCY_KEY] = idempotency_key
    return headers or None


def _session_credential(
    operation: str,
    *,
    token: str | None,
    session_token: str | None,
) -> tuple[str | None, dict[str, str] | None]:
    """Require exactly one access-token transport and return request parts."""
    if bool(token) == bool(session_token):
        raise ValueError(
            f"{operation} requires exactly one of token or session_token"
        )
    if token:
        return token, None
    return None, {constants.COOKIE_SESSION: str(session_token)}


class MagicAuthClient:
    """Async client wrapping the auth provider's auth-consumer endpoints.

    The client either owns an internal ``httpx.AsyncClient`` (created when
    ``http_client`` is omitted and closed by :meth:`aclose`) or borrows one passed in
    by the caller (never closed here) so a service can use a dedicated pooled client::

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
            isolate_provider_cookies(http_client)
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                verify=self._config.verify_tls,
                cookies=RejectingCookieJar(),
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
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> _M:
        """Send one provider request and parse the 2xx body into ``model``.

        ``data`` is form-encoded (the provider's auth endpoints); ``json`` is sent as a
        JSON body (the internal S2S and Patreon endpoints, whose request models reject
        form bodies). ``None`` values are dropped from both and from ``params``.
        """
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
            req_headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in cookies.items()
            )

        form = None
        if data is not None:
            form = {key: value for key, value in data.items() if value is not None}
        query = None
        if params is not None:
            # ``or None``: an empty mapping would make httpx strip the URL's own query.
            query = {key: value for key, value in params.items() if value is not None} or None
        # ``json`` is passed only when used, so form/GET calls keep the exact call
        # shape consumers' transport doubles were written against.
        extra: dict[str, Any] = {}
        if json is not None:
            extra["json"] = {key: value for key, value in json.items() if value is not None}

        try:
            response = await self._client.request(
                method,
                url,
                data=form,
                params=query,
                headers=req_headers,
                **extra,
            )
        except httpx.HTTPError as exc:
            raise AuthTransportError(cause=exc) from exc

        if not response.is_success:
            raise parse_error_response(response)

        try:
            payload = response.json()
        except ValueError as exc:
            raise AuthTransportError(
                "Invalid JSON response from auth service", cause=exc
            ) from exc

        # Preserve the established client contract: syntactically valid JSON
        # with the wrong endpoint schema raises Pydantic's ValidationError.
        # Existing consumers use that distinction to fail closed without
        # treating a malformed 200 as provider unavailability.
        parsed = model.model_validate(payload)
        if isinstance(parsed, _HttpStatusMixin):
            parsed._http_status = response.status_code
        return parsed

    # Authentication flows -----------------------------------------------------
    async def login(
        self,
        username: str,
        password: str,
        *,
        project_hash: str | None = None,
        remember_me: bool = False,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> LoginResponse:
        """Project-scoped login. ``project_hash`` is required by the provider for all
        users; falls back to ``config.project_hash`` when omitted. ``remember_me``
        selects the provider's longer-lived refresh policy. ``user_agent`` overrides
        the configured User-Agent for this call (e.g. to relay a caller's)."""
        resolved = project_hash or self._config.project_hash
        if not resolved:
            raise ValueError(
                "project_hash is required for login: pass it or set config.project_hash"
            )
        data: dict[str, Any] = {
            "username": username,
            "password": password,
            "project_hash": resolved,
        }
        if remember_me:
            data["remember_me"] = True
        return await self._request(
            "POST",
            self._config.login_endpoint,
            model=LoginResponse,
            data=data,
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def platform_login(
        self,
        username: str,
        password: str,
        *,
        remember_me: bool = False,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> LoginResponse:
        """Login for root/admin users without project scope (dashboard access)."""
        data: dict[str, Any] = {"username": username, "password": password}
        if remember_me:
            data["remember_me"] = True
        return await self._request(
            "POST",
            self._config.platform_login_endpoint,
            model=LoginResponse,
            data=data,
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def register(
        self,
        username: str,
        password: str,
        *,
        email: str | None = None,
        user_group_hash: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
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
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def validate(
        self,
        *,
        token: str | None = None,
        session_token: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> ValidateSessionResponse:
        """Validate an access token. Provide ``token`` (Bearer header) or
        ``session_token`` (cookie).

        Note: the provider may return HTTP 200 with ``valid=False``; this method does
        not raise in that case — inspect ``.valid`` on the result.
        """
        bearer_token, cookies = _session_credential(
            "validate",
            token=token,
            session_token=session_token,
        )
        return await self._request(
            "GET",
            self._config.validate_endpoint,
            model=ValidateSessionResponse,
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
            cookies=cookies,
        )

    async def validate_api_key(
        self,
        api_key: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> ValidateApiKeyResponse:
        """Validate an API key via the ``X-API-Key`` header.

        Never sends ``Authorization`` (the provider rejects requests carrying both
        with 400 ``ambiguous_credentials``). Like :meth:`validate`, a 200 with
        ``valid=False`` is returned rather than raised.
        """
        return await self._request(
            "POST",
            self._config.validate_api_key_endpoint,
            model=ValidateApiKeyResponse,
            headers=_request_headers(
                api_key=api_key,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def get_billing_catalog(
        self,
        *,
        project_hash: str,
        bearer_token: str,
        provider: str = "stripe",
        item_type: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> BillingCatalogResponse:
        """List a project's centralized billing catalog (subscriptions + credit packs).

        This is a server-to-server read on the internal billing surface; ``bearer_token``
        is the billing S2S bearer (not a user session token). The catalog carries no
        secrets — only display info, opaque ``features``, and the price ``lookup_key``.
        ``item_type`` narrows the listing to ``subscription_plan`` or ``credit_package``.
        """
        return await self._request(
            "GET",
            self._config.billing_catalog_endpoint(project_hash),
            model=BillingCatalogResponse,
            params={"provider": provider, "item_type": item_type},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def get_billing_status(
        self,
        user_hash: str,
        *,
        project_hash: str,
        bearer_token: str,
        provider: str = "stripe",
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> BillingStatusResponse:
        """Read a user's safe billing facts (subscription state + one-time purchases).

        Server-to-server: ``bearer_token`` is the billing S2S bearer. The provider
        resolves ``project_hash`` to its billing group; a user with no billing history
        comes back as ``status="free"`` rather than an error.
        """
        return await self._request(
            "GET",
            self._config.billing_status_endpoint(user_hash),
            model=BillingStatusResponse,
            params={"project_hash": project_hash, "provider": provider},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def get_billing_purchase(
        self,
        user_hash: str,
        purchase_ref: str,
        *,
        project_hash: str,
        bearer_token: str,
        provider: str = "stripe",
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> BillingPurchaseResponse:
        """Read one purchase's safe facts by its opaque ``purchase_ref`` (S2S bearer).

        An unknown reference raises :class:`AuthNotFoundError`.
        """
        return await self._request(
            "GET",
            self._config.billing_purchase_endpoint(user_hash, purchase_ref),
            model=BillingPurchaseResponse,
            params={"project_hash": project_hash, "provider": provider},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def create_billing_checkout(
        self,
        user_hash: str,
        *,
        bearer_token: str,
        project_hash: str,
        intent_type: str,
        price_ref: Mapping[str, str],
        success_url: str,
        cancel_url: str,
        quantity: int = 1,
        plan_code: str | None = None,
        tier_code: str | None = None,
        tier_name: str | None = None,
        credit_product_code: str | None = None,
        client_intent_ref: str | None = None,
        provider: str = "stripe",
        idempotency_key: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> BillingCheckoutResponse:
        """Create a hosted Checkout session for a subscription or a credit purchase.

        Server-to-server (billing S2S bearer). ``intent_type`` is ``"subscription"`` or
        ``"credit_purchase"``; ``price_ref`` is ``{"ref_type": "lookup_key" | "price_id",
        "value": ...}`` — use the catalog item's ``provider_price_lookup_key``.
        ``idempotency_key`` is forwarded as ``Idempotency-Key``; replaying the same key
        and body returns the original session with ``http_status == 200`` instead of
        202, while the same key with a different body raises :class:`AuthConflictError`.
        """
        return await self._request(
            "POST",
            self._config.billing_checkout_endpoint(user_hash),
            model=BillingCheckoutResponse,
            json={
                "project_hash": project_hash,
                "provider": provider,
                "intent_type": intent_type,
                "price_ref": dict(price_ref),
                "quantity": quantity,
                "plan_code": plan_code,
                "tier_code": tier_code,
                "tier_name": tier_name,
                "credit_product_code": credit_product_code,
                "success_url": success_url,
                "cancel_url": cancel_url,
                "client_intent_ref": client_intent_ref,
            },
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
                idempotency_key=idempotency_key,
            ),
        )

    async def create_billing_portal(
        self,
        user_hash: str,
        *,
        bearer_token: str,
        project_hash: str,
        return_url: str,
        provider: str = "stripe",
        idempotency_key: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> BillingPortalResponse:
        """Create a hosted, restricted customer-portal session (billing S2S bearer).

        ``return_url`` is validated against the provider's allowlist. A user with no
        billing customer raises an :class:`AuthApiError`.
        """
        return await self._request(
            "POST",
            self._config.billing_portal_endpoint(user_hash),
            model=BillingPortalResponse,
            json={
                "project_hash": project_hash,
                "provider": provider,
                "return_url": return_url,
            },
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
                idempotency_key=idempotency_key,
            ),
        )

    async def request_billing_resync(
        self,
        user_hash: str,
        *,
        bearer_token: str,
        project_hash: str,
        reason: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> BillingResyncResponse:
        """Ask the provider to re-read a user's billing state (billing S2S bearer).

        Always answers 202: inspect ``accepted``/``status`` — the provider reports
        ``disabled``, ``rate_limited`` or ``degraded`` in the body rather than failing.
        """
        return await self._request(
            "POST",
            self._config.billing_resync_endpoint(user_hash),
            model=BillingResyncResponse,
            json={"project_hash": project_hash, "reason": reason},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    # Patreon entitlements (server-to-server) ----------------------------------
    async def get_patreon_entitlement(
        self,
        user_hash: str,
        *,
        bearer_token: str,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> PatreonEntitlementResponse:
        """Read a user's normalized Patreon entitlement (Patreon S2S bearer).

        The entitlement is scoped to the user, not to a project. A user with no Patreon
        link comes back as a ``status="free"`` entitlement rather than an error.
        """
        return await self._request(
            "GET",
            self._config.patreon_entitlement_endpoint(user_hash),
            model=PatreonEntitlementResponse,
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def request_patreon_resync(
        self,
        user_hash: str,
        *,
        bearer_token: str,
        force: bool = False,
        reason: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> PatreonResyncResponse:
        """Ask the provider to re-read a user's Patreon membership (Patreon S2S bearer).

        Always answers 202: inspect ``accepted``/``status`` for ``disabled``,
        ``rate_limited`` or ``degraded`` outcomes.
        """
        return await self._request(
            "POST",
            self._config.patreon_entitlement_resync_endpoint(user_hash),
            model=PatreonResyncResponse,
            json={"force": force, "reason": reason},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def logout(
        self,
        *,
        token: str | None = None,
        session_token: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> LogoutResponse:
        """Invalidate the session and revoke its refresh family. ``user_agent``
        overrides the configured User-Agent for this call."""
        bearer_token, cookies = _session_credential(
            "logout",
            token=token,
            session_token=session_token,
        )
        return await self._request(
            "POST",
            self._config.logout_endpoint,
            model=LogoutResponse,
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
            cookies=cookies,
        )

    async def refresh(
        self,
        refresh_token: str,
        *,
        use_cookie: bool = False,
        user_agent: str | None = None,
        client_ip: str | None = None,
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
                headers=_request_headers(
                    user_agent=user_agent,
                    client_ip=client_ip,
                ),
            )
        return await self._request(
            "POST",
            self._config.refresh_endpoint,
            model=LoginResponse,
            data={"refresh_token": refresh_token},
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def switch_project(
        self,
        access_token: str,
        project_hash: str,
        *,
        refresh_token: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
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
            headers=_request_headers(
                bearer_token=access_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def check_availability(
        self,
        *,
        username: str | None = None,
        email: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> CheckAvailabilityResponse:
        """Check whether a username and/or email is available."""
        if not username and not email:
            raise ValueError("check_availability requires username or email")
        return await self._request(
            "POST",
            self._config.check_availability_endpoint,
            model=CheckAvailabilityResponse,
            data={"username": username, "email": email},
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def get_profile(
        self,
        token: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> UserProfileResponse:
        """Fetch the current user's full profile (groups, projects, metadata)."""
        return await self._request(
            "GET",
            self._config.profile_endpoint,
            model=UserProfileResponse,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
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
        client_ip: str | None = None,
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
        req_headers: dict[str, str] = {
            constants.HEADER_USER_AGENT: user_agent or self._config.user_agent,
            constants.HEADER_ACCEPT: "application/json",
        }
        if client_ip:
            req_headers[constants.HEADER_FORWARDED_FOR] = client_ip
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
        client_ip: str | None = None,
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
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    # Provider-agnostic OAuth (any connection key) ------------------------------
    def _require_project_api_key(self, operation: str, override: str | None) -> str:
        """Resolve the project-scoped API key without ever putting it in a message."""
        api_key = override if override is not None else self._config.project_api_key
        if not api_key:
            raise ValueError(
                f"{operation} requires a project-scoped API key "
                "(config.project_api_key or the project_api_key argument)"
            )
        return api_key

    async def oauth_init(
        self,
        connection: str,
        *,
        return_origin: str,
        remember_me: bool = False,
        purpose: str = "login",
        project_api_key: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> OAuthInitResponse:
        """Mint a single-use init token for ``connection`` (inverted handshake).

        POSTs to ``/auth/oauth/init`` authenticated with the project-scoped API key
        (``X-API-Key``). The provider derives the project from that credential and the
        provisioning group from the binding, so a caller MUST NOT send ``project_hash``
        or ``user_group_hash`` — the provider rejects bodies that carry them. The
        returned ``init_token`` is handed straight to :meth:`oauth_start`; it is the
        replacement for the consumer-minted provider-init token, and no callback into
        the consumer takes place.

        Raises :class:`AuthApiError` if the credential is rejected, the binding is
        missing/disabled, or ``return_origin`` is not on the binding's allow-list.
        """
        api_key = self._require_project_api_key("oauth_init", project_api_key)
        return await self._request(
            "POST",
            self._config.oauth_init_endpoint,
            model=OAuthInitResponse,
            json={
                "connection": connection,
                "purpose": purpose,
                "return_origin": return_origin,
                "remember_me": remember_me,
            },
            headers=_request_headers(
                api_key=api_key,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def list_oauth_providers(
        self,
        *,
        project_api_key: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> OAuthProvidersResponse:
        """Enabled sign-in providers for the calling project, so a login page renders
        its buttons from data instead of a compiled-in provider list.

        GETs ``/auth/oauth/providers`` with the project-scoped API key. Enabling a
        provider becomes an administrative action in the provider with no front-end
        release.
        """
        api_key = self._require_project_api_key("list_oauth_providers", project_api_key)
        return await self._request(
            "GET",
            self._config.oauth_providers_endpoint,
            model=OAuthProvidersResponse,
            headers=_request_headers(
                api_key=api_key,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def oauth_start(
        self,
        init_token: str,
        redirect_uri: str,
        *,
        remember_me: bool | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> str:
        """Begin the flow for the connection bound to ``init_token`` and return the
        provider's authorization URL.

        POSTs ``/auth/oauth/start``. The connection, project, provisioning group and
        return origin all come from the init token, so this body carries nothing the
        browser could influence beyond the ``redirect_uri``, which the provider
        validates against the binding's allow-list. Like :meth:`start_google_oauth`,
        the ``303`` is NOT followed — the ``Location`` is returned for the BFF to hand
        to the browser as a top-level navigation.

        ``remember_me`` is the one exception: it is a user preference rather than
        security scope, so the provider lets the start request override the value
        bound at init. It is sent only when it is not ``None``, and only a real JSON
        boolean overrides — omitting it leaves the init-time value in place.

        Raises :class:`AuthApiError` if the provider rejects the request (init token
        invalid/replayed, binding disabled, redirect URI not allowed).
        """
        req_headers: dict[str, str] = {
            constants.HEADER_USER_AGENT: user_agent or self._config.user_agent,
            constants.HEADER_ACCEPT: "application/json",
        }
        if client_ip:
            req_headers[constants.HEADER_FORWARDED_FOR] = client_ip
        body: dict[str, Any] = {"init_token": init_token, "redirect_uri": redirect_uri}
        if remember_me is not None:
            # ``False`` is a meaningful override, so this is an explicit None check.
            body["remember_me"] = bool(remember_me)
        try:
            response = await self._client.request(
                "POST",
                self._config.oauth_start_endpoint,
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
                    "OAuth start returned a redirect without a Location header"
                )
            return location
        if response.status_code >= 400:
            raise parse_error_response(response)
        raise AuthTransportError(
            f"OAuth start expected a redirect, got HTTP {response.status_code}"
        )

    async def oauth_callback(
        self,
        code: str,
        state: str,
        *,
        iss: str | None = None,
        error: str | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> LoginResponse:
        """Complete the provider-agnostic callback and return the issued session.

        GETs ``/auth/oauth/callback``. The connection is read from the one-time state
        record, never from this call. ``iss`` is forwarded when the identity provider
        supplied it (issuer confirmation), and ``error`` when the provider reported one
        instead of a code, which the provider maps to a neutral error code
        (``EXT_8031`` for a user cancellation) rather than a session.

        Raises :class:`AuthApiError` on any OAuth failure. Two codes deserve their own
        message in a UI: ``EXT_8031`` (cancelled at the provider) and ``EXT_8032`` (an
        existing local account owns this e-mail — sign in and link).
        """
        return await self._request(
            "GET",
            self._config.oauth_callback_endpoint,
            model=LoginResponse,
            params={"code": code, "state": state, "iss": iss, "error": error},
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    # Password workflows -------------------------------------------------------
    async def forgot_password(
        self,
        email_or_username: str,
        *,
        user_agent: str | None = None,
        public_base_url: str | None = None,
        idempotency_key: str | None = None,
        client_ip: str | None = None,
    ) -> ActionResponse:
        """Request a password-reset email by email or username.

        Unauthenticated. The provider responds with a generic accepted body
        regardless of whether the identifier resolves to an account (it never
        discloses account existence). ``user_agent`` overrides the configured
        User-Agent for this call. ``public_base_url`` relays the end-user's
        browser origin so the emailed reset link points there (the provider
        validates it against its allowlist). ``idempotency_key`` is forwarded as
        ``Idempotency-Key`` so callers can safely retry the same enqueue request.
        """
        return await self._request(
            "POST",
            self._config.password_forgot_endpoint,
            model=ActionResponse,
            data={"email_or_username": email_or_username},
            headers=_request_headers(
                user_agent=user_agent,
                public_base_url=public_base_url,
                idempotency_key=idempotency_key,
                client_ip=client_ip,
            ),
        )

    async def reset_password(
        self,
        token: str,
        new_password: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> ActionResponse:
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
            model=ActionResponse,
            data={"token": token, "new_password": new_password},
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def change_password(
        self,
        token: str,
        current_password: str,
        new_password: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> ChangePasswordResponse:
        """Change the authenticated user's password (Bearer ``token``).

        Requires the current password for re-authentication. Wrong current
        password raises ``AuthUnauthorizedError`` (``INVALID_CREDENTIALS``); a
        weak new password raises ``WEAK_PASSWORD``. The provider revokes the
        user's *other* sessions but preserves this one, and issues no new token.
        ``user_agent`` overrides the configured User-Agent for this call.
        """
        return await self._request(
            "POST",
            self._config.password_change_endpoint,
            model=ChangePasswordResponse,
            data={"current_password": current_password, "new_password": new_password},
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    # Email workflows ----------------------------------------------------------
    async def verify_email(
        self,
        token: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> ActionResponse:
        """Consume an email-activation link token.

        Unauthenticated; ``token`` is the ``lookup_id.secret`` value from the
        emailed link. Returns a generic accepted body regardless of outcome. On
        success the provider activates the address and revokes the user's
        sessions. ``user_agent`` overrides the configured User-Agent.
        """
        return await self._request(
            "POST",
            self._config.email_verify_endpoint,
            model=ActionResponse,
            data={"token": token},
            headers=_request_headers(user_agent=user_agent, client_ip=client_ip),
        )

    async def list_emails(
        self,
        token: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> EmailListResponse:
        """List the authenticated user's email addresses (Bearer ``token``)."""
        return await self._request(
            "GET",
            self._config.user_emails_endpoint,
            model=EmailListResponse,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def add_email(
        self,
        token: str,
        email: str,
        *,
        user_agent: str | None = None,
        public_base_url: str | None = None,
        idempotency_key: str | None = None,
        client_ip: str | None = None,
    ) -> ActionResponse:
        """Add an email and enqueue an activation link (Bearer ``token``).

        Returns a generic accepted body on success; an invalid address raises a
        4xx. ``user_agent`` overrides the configured User-Agent for this call.
        ``public_base_url`` relays the end-user's browser origin so the emailed
        activation link points there (the provider validates it against its
        allowlist). ``idempotency_key`` is forwarded as ``Idempotency-Key``.
        """
        return await self._request(
            "POST",
            self._config.user_emails_endpoint,
            model=ActionResponse,
            data={"email": email},
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                public_base_url=public_base_url,
                idempotency_key=idempotency_key,
                client_ip=client_ip,
            ),
        )

    async def resend_email_activation(
        self,
        token: str,
        email_id: str,
        *,
        user_agent: str | None = None,
        public_base_url: str | None = None,
        idempotency_key: str | None = None,
        client_ip: str | None = None,
    ) -> ActionResponse:
        """Resend the activation link for a pending email (Bearer ``token``).

        Cooldown- and rate-limited by the provider; returns a generic accepted
        body. ``user_agent`` overrides the configured User-Agent for this call.
        ``public_base_url`` relays the end-user's browser origin so the emailed
        activation link points there (the provider validates it against its
        allowlist). ``idempotency_key`` is forwarded as ``Idempotency-Key``.
        """
        return await self._request(
            "POST",
            self._config.user_email_resend_endpoint(email_id),
            model=ActionResponse,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                public_base_url=public_base_url,
                idempotency_key=idempotency_key,
                client_ip=client_ip,
            ),
        )

    async def remove_email(
        self,
        token: str,
        email_id: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> RemoveEmailResponse:
        """Remove one of the user's email addresses (Bearer ``token``).

        If the removed address was primary, the provider promotes the next
        activated address and returns its id in ``new_primary_email_id``.
        """
        return await self._request(
            "DELETE",
            self._config.user_email_endpoint(email_id),
            model=RemoveEmailResponse,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def set_primary_email(
        self,
        token: str,
        email_id: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> SetPrimaryEmailResponse:
        """Mark an activated email as the user's primary address (Bearer ``token``)."""
        return await self._request(
            "POST",
            self._config.user_email_primary_endpoint(email_id),
            model=SetPrimaryEmailResponse,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    # Patreon entitlement link (current user's Bearer) ---------------------------
    async def request_patreon_link(
        self,
        token: str,
        *,
        patreon_email_hint: str | None = None,
        explicit_user_intent: bool = False,
        confirm_email_match: bool = False,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> PatreonLinkRequestResponse:
        """Begin the Patreon email-loop proof for the authenticated user (Bearer ``token``).

        Patreon is an entitlement source, never a login provider. The provider answers
        with the same generic accepted body whatever the outcome and never returns proof
        or Patreon account material. ``patreon_email_hint`` is only a lookup hint;
        ``explicit_user_intent`` must be true for the provider to act.
        """
        return await self._request(
            "POST",
            self._config.patreon_link_request_endpoint,
            model=PatreonLinkRequestResponse,
            json={
                "patreon_email_hint": patreon_email_hint,
                "explicit_user_intent": explicit_user_intent,
                "confirm_email_match": confirm_email_match,
            },
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def confirm_patreon_link(
        self,
        token: str,
        *,
        proof_token: str | None = None,
        lookup_id: str | None = None,
        secret: str | None = None,
        explicit_user_intent: bool = False,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> PatreonLinkStatusResponse:
        """Consume an emailed Patreon proof for the authenticated user (Bearer ``token``).

        Pass the emailed ``proof_token`` (sent as the provider's ``token`` field), or its
        ``lookup_id`` + ``secret`` parts. Not a login: it needs an existing session and
        recent reauthentication. ``http_status`` is 200 when the link was applied and 202
        for the provider's neutral posture (malformed, expired or replayed proof).
        """
        return await self._request(
            "POST",
            self._config.patreon_link_confirm_endpoint,
            model=PatreonLinkStatusResponse,
            json={
                "token": proof_token,
                "lookup_id": lookup_id,
                "secret": secret,
                "explicit_user_intent": explicit_user_intent,
            },
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def get_patreon_link_status(
        self,
        token: str,
        *,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> PatreonLinkStatusResponse:
        """Read the authenticated user's safe Patreon link status (Bearer ``token``)."""
        return await self._request(
            "GET",
            self._config.patreon_link_status_endpoint,
            model=PatreonLinkStatusResponse,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def unlink_patreon(
        self,
        token: str,
        *,
        explicit_user_intent: bool = False,
        confirm_unlink: bool = False,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> PatreonUnlinkResponse:
        """Soft-unlink the authenticated user's Patreon entitlement (Bearer ``token``).

        Never revokes local sessions or API keys. Needs recent reauthentication. The
        confirmation flags are sent only when set.
        """
        flags = {
            "explicit_user_intent": explicit_user_intent,
            "confirm_unlink": confirm_unlink,
        }
        return await self._request(
            "DELETE",
            self._config.patreon_link_endpoint,
            model=PatreonUnlinkResponse,
            json={name: True for name, is_set in flags.items() if is_set} or None,
            headers=_request_headers(
                bearer_token=token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    # Internal transactional email (root user's Bearer) --------------------------
    async def resolve_email_identity(
        self,
        email: str,
        *,
        bearer_token: str,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> EmailIdentityResponse:
        """Resolve whether ``email`` is an activated address of a provider account.

        Internal surface: ``bearer_token`` must be a *root* user's access token.
        """
        return await self._request(
            "POST",
            self._config.internal_email_resolve_identity_endpoint,
            model=EmailIdentityResponse,
            json={"email": email},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def send_template_email(
        self,
        recipient_email: str,
        template_code: str,
        *,
        bearer_token: str,
        variables: Mapping[str, Any] | None = None,
        provider_idempotency_key: str | None = None,
        priority: int | None = None,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> TemplateEmailResponse:
        """Queue a known transactional template to one recipient (root Bearer).

        ``provider_idempotency_key`` (<= 128 chars) de-duplicates the enqueue;
        ``priority`` is 0-9 (provider default 4). An unknown or disabled template
        raises an :class:`AuthApiError`.
        """
        return await self._request(
            "POST",
            self._config.internal_email_send_template_endpoint,
            model=TemplateEmailResponse,
            json={
                "recipient_email": recipient_email,
                "template_code": template_code,
                "variables": dict(variables) if variables is not None else None,
                "provider_idempotency_key": provider_idempotency_key,
                "priority": priority,
            },
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    async def get_email_message_status(
        self,
        email_message_id: str,
        *,
        bearer_token: str,
        user_agent: str | None = None,
        client_ip: str | None = None,
    ) -> EmailMessageStatusResponse:
        """Read the redacted delivery state of one queued email (root Bearer).

        An unknown id raises :class:`AuthNotFoundError`.
        """
        return await self._request(
            "POST",
            self._config.internal_email_message_status_endpoint,
            model=EmailMessageStatusResponse,
            json={"email_message_id": email_message_id},
            headers=_request_headers(
                bearer_token=bearer_token,
                user_agent=user_agent,
                client_ip=client_ip,
            ),
        )

    # System ---------------------------------------------------------------------
    async def ping(self, *, user_agent: str | None = None) -> PingResponse:
        """Public liveness probe (``GET /system/ping``); needs no credential.

        Raises like any other call when the provider is unreachable or unhealthy, so a
        health check can treat any exception as "down".
        """
        return await self._request(
            "GET",
            self._config.ping_endpoint,
            model=PingResponse,
            headers=_request_headers(user_agent=user_agent),
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
        user_agent: str | None = None,
        client_ip: str | None = None,
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
        api_key_resp = await self.validate_api_key(
            delegation_api_key,
            user_agent=user_agent,
            client_ip=client_ip,
        )
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
        session_resp = await self.validate(
            token=session_token,
            user_agent=user_agent,
            client_ip=client_ip,
        )
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
