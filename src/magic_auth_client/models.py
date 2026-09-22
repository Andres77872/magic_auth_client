"""Pydantic v2 response models mirroring the auth provider's contract.

Field names/types match ``api.auth/src/Util/Models.py``. ``extra="ignore"`` lets the
client tolerate new server fields without breaking, since the provider is actively
developed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


class _AuthModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _HttpStatusMixin(_AuthModel):
    """Adds :attr:`http_status` to responses whose HTTP status carries meaning.

    Some provider endpoints answer the same request with different 2xx codes (e.g.
    checkout: ``202`` for a new session, ``200`` for an idempotent replay; Patreon link
    confirm: ``200`` linked vs ``202`` neutral). The client sets the status after
    parsing so a BFF can mirror it to its own caller. It is a private attribute: it is
    never part of ``model_dump()`` and is ``None`` on hand-built instances.
    """

    _http_status: int | None = PrivateAttr(default=None)

    @property
    def http_status(self) -> int | None:
        return self._http_status


# Shared components ------------------------------------------------------------
class UserInfo(_AuthModel):
    # All fields are optional: this model is reused across login/validate/profile
    # responses and for transparent forwarding of partial user objects. The provider
    # populates ``user_hash`` for identity flows; consumers that require it should
    # check it explicitly rather than relying on parse-time validation.
    user_hash: str | None = None
    # ``username`` is optional: /auth/validate and /auth/validate-api-key responses
    # are guaranteed to carry ``user_hash`` but may omit ``username`` (e.g. a minimal
    # session-validation payload). Consumers should only rely on ``user_hash``.
    username: str | None = None
    email: str | None = None
    user_type: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ProjectInfo(_AuthModel):
    project_hash: str
    # ``project_name`` is optional for the same reason as ``UserInfo.username``:
    # validation responses guarantee ``project_hash`` but may omit the display name.
    project_name: str | None = None
    project_description: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class UserGroupInfo(_AuthModel):
    group_hash: str
    group_name: str
    description: str | None = None
    member_count: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ApiKeyInfo(_AuthModel):
    key_id: str | None = None
    public_id: str | None = None


class SessionPlan(_AuthModel):
    """Subscription-only plan projection embedded in identity/session responses.

    Mirrors ``api.auth`` ``SessionPlanStatus``. ``state`` is one of
    none|free|trial|active|past_due|canceled for the session's project (resolved through
    its billing group). Subscriptions only; packages/credits are consumer-owned.
    """

    provider: str | None = None
    state: str = "none"
    active: bool = False
    plan_code: str | None = None
    tier_code: str | None = None
    current_period_end: datetime | None = None
    trial_end: datetime | None = None
    cancel_at_period_end: bool = False


class BillingCatalogItem(_AuthModel):
    """A subscription plan or credit package from a project's centralized catalog."""

    item_type: str | None = None  # subscription_plan | credit_package
    plan_code: str | None = None
    credit_product_code: str | None = None
    tier_code: str | None = None
    tier_name: str | None = None
    display_name: str | None = None
    amount_cents: int | None = None
    currency: str | None = None
    interval: str | None = None
    credits: int | None = None
    provider: str | None = None
    provider_price_lookup_key: str | None = None
    features: dict[str, Any] = Field(default_factory=dict)
    active: bool = True


class ActionResponse(_AuthModel):
    """Generic result returned by provider actions without endpoint-specific data."""

    success: bool = True
    message: str | None = None


# Kept as a private compatibility alias for code that imported the old implementation
# detail. New code should use the public ``ActionResponse`` name.
_BaseResponse = ActionResponse


class TokenPair(_AuthModel):
    """Shared token-pair fields returned by credential-issuing endpoints."""

    access_token: str | None = None
    refresh_token: str | None = None
    session_token: str | None = None  # deprecated alias for access_token
    token_type: str = "Bearer"
    expires_in: int | None = None
    refresh_expires_in: int | None = None
    expires_at: datetime | None = None
    refresh_expires_at: datetime | None = None
    remember_me: bool = False

    def is_expired(self, now: datetime | None = None) -> bool | None:
        """Whether the access token is past ``expires_at``.

        Returns ``None`` when the server did not provide ``expires_at``. Handles
        both timezone-aware and naive ``expires_at`` values.
        """
        if self.expires_at is None:
            return None
        reference = now if now is not None else datetime.now(self.expires_at.tzinfo)
        return reference >= self.expires_at


# Endpoint responses -----------------------------------------------------------
class LoginResponse(ActionResponse, TokenPair):
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    accessible_projects: list[ProjectInfo] = Field(default_factory=list)
    user_groups: list[UserGroupInfo] = Field(default_factory=list)
    plan: SessionPlan | None = None
    user_id: str | None = None


class RegisterResponse(ActionResponse, TokenPair):
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    user_id: str | None = None


class ValidateSessionResponse(ActionResponse):
    valid: bool
    auth_method: str = "session"
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    session: dict[str, Any] | None = None
    user_groups: list[str] = Field(default_factory=list)
    plan: SessionPlan | None = None


class ValidateApiKeyResponse(ActionResponse):
    valid: bool
    auth_method: str = "api_key"
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    api_key: ApiKeyInfo | None = None
    user_groups: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    plan: SessionPlan | None = None


class BillingCatalogResponse(ActionResponse):
    """Per-project catalog listing (subscriptions + credit packages)."""

    contract_version: int = 2
    project_hash: str | None = None
    billing_group_hash: str | None = None
    provider: str | None = None
    subscriptions: list[BillingCatalogItem] = Field(default_factory=list)
    credit_packs: list[BillingCatalogItem] = Field(default_factory=list)


# Internal billing (S2S) ---------------------------------------------------------
class BillingStatus(_AuthModel):
    """Safe subscription facts for one user/project (``api.auth`` ``BillingSafeStatus``).

    ``status`` is one of free|pending|incomplete|trialing|active|past_due|unpaid|paused|
    canceled|former|stale|unknown; ``link_status`` is none|pending|linked|revoked|stale.
    ``customer_ref``/``subscription_ref`` are opaque provider-side references, never raw
    Stripe ids.
    """

    provider: str | None = None
    status: str = "free"
    plan_code: str = "free"
    tier_code: str | None = None
    tier_name: str | None = None
    link_status: str = "none"
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    trial_end: datetime | None = None
    grace_period_until: datetime | None = None
    last_synced_at: datetime | None = None
    stale_after: datetime | None = None
    classification_version: int | None = None
    customer_ref: str | None = None
    subscription_ref: str | None = None


class BillingPurchase(_AuthModel):
    """Safe one-time purchase facts (``api.auth`` ``BillingSafePurchaseStatus``).

    ``status`` is one of pending|paid|refunded|partially_refunded|disputed|dispute_won|
    dispute_lost|stale|unknown.
    """

    provider: str | None = None
    purchase_ref: str | None = None
    status: str = "pending"
    credit_product_code: str | None = None
    quantity: int | None = None
    paid_at: datetime | None = None
    refunded_at: datetime | None = None
    disputed_at: datetime | None = None
    last_synced_at: datetime | None = None
    stale_after: datetime | None = None
    classification_version: int | None = None


class BillingStatusResponse(ActionResponse, _HttpStatusMixin):
    contract_version: int = 2
    user_hash: str | None = None
    project_hash: str | None = None
    provider: str | None = None
    billing: BillingStatus | None = None
    purchases: list[BillingPurchase] = Field(default_factory=list)


class BillingPurchaseResponse(ActionResponse, _HttpStatusMixin):
    contract_version: int = 2
    user_hash: str | None = None
    project_hash: str | None = None
    provider: str | None = None
    purchase: BillingPurchase | None = None


class BillingCheckoutResponse(ActionResponse, _HttpStatusMixin):
    """Hosted Checkout session. ``http_status`` is 202 when created, 200 on a replay."""

    contract_version: int = 2
    checkout_ref: str | None = None
    purchase_ref: str | None = None
    subscription_ref: str | None = None
    url: str | None = None


class BillingPortalResponse(ActionResponse, _HttpStatusMixin):
    """Hosted, restricted Portal session. ``http_status`` is 202 new, 200 on a replay."""

    contract_version: int = 2
    portal_ref: str | None = None
    url: str | None = None


class BillingResyncResponse(ActionResponse, _HttpStatusMixin):
    """Resync acknowledgement. ``status`` is accepted|queued|disabled|rate_limited|
    degraded; ``accepted`` is false when the provider declined to queue the work."""

    contract_version: int = 2
    accepted: bool = True
    status: str = "accepted"
    user_hash: str | None = None
    project_hash: str | None = None
    provider: str | None = None
    retry_after_seconds: int | None = None
    not_before: datetime | None = None
    correlation_id: str | None = None


# Patreon entitlements -----------------------------------------------------------
class PatreonEntitlement(_AuthModel):
    """Safe Patreon entitlement facts (``api.auth`` ``PatreonSafeEntitlement``).

    ``status`` is active|free|pending|former|revoked|stale; ``link_status`` is
    none|pending|linked|unlinked|revoked|blocked. Never carries Patreon ids or emails.
    """

    external_source: str | None = None
    status: str = "free"
    plan_code: str = "free"
    tier_code: str | None = None
    tier_name: str | None = None
    link_status: str = "none"
    next_renewal_at: datetime | None = None
    grace_period_until: datetime | None = None
    last_synced_at: datetime | None = None
    stale_after: datetime | None = None
    classification_version: int | None = None


class PatreonEntitlementResponse(ActionResponse, _HttpStatusMixin):
    user_hash: str | None = None
    entitlement: PatreonEntitlement | None = None
    contract_version: int = 1


class PatreonResyncResponse(ActionResponse, _HttpStatusMixin):
    """Resync acknowledgement; same ``status``/``accepted`` semantics as billing."""

    accepted: bool = True
    status: str = "accepted"
    user_hash: str | None = None
    retry_after_seconds: int | None = None
    not_before: datetime | None = None
    correlation_id: str | None = None
    contract_version: int = 1


class PatreonLinkRequestResponse(ActionResponse, _HttpStatusMixin):
    """Generic accepted body for a link request (never discloses proof material)."""

    accepted: bool = True
    link_status: str | None = None
    retry_after_seconds: int | None = None


class PatreonLinkStatusResponse(ActionResponse, _HttpStatusMixin):
    """Link status for the current user. On confirm, ``http_status`` is 200 when the
    link was applied and 202 for the provider's neutral (no-disclosure) posture."""

    link_status: str = "none"
    entitlement: PatreonEntitlement | None = None
    retry_after_seconds: int | None = None


class PatreonUnlinkResponse(ActionResponse, _HttpStatusMixin):
    link_status: str = "unlinked"
    entitlement: PatreonEntitlement | None = None


# Internal transactional email (root Bearer) -------------------------------------
# These provider bodies carry no ``success``/``message`` envelope, so the models
# deliberately do not extend ``ActionResponse``.
class EmailIdentityResponse(_AuthModel):
    """Whether an address is an *activated* email of a provider account.

    ``user_hash``/``username``/``user_type`` are only present when ``matched``.
    """

    matched: bool = False
    email: str | None = None
    email_masked: str | None = None
    user_hash: str | None = None
    username: str | None = None
    user_type: str | None = None


class TemplateEmailResponse(_AuthModel):
    """Enqueue result for a transactional template email (provider replies 202)."""

    accepted: bool = False
    email_message_id: str | None = None
    lifecycle_status: str | None = None
    template_code: str | None = None


class EmailMessageStatusResponse(_AuthModel):
    """Redacted delivery state of one queued transactional email."""

    email_message_id: str | None = None
    purpose: str | None = None
    template_code: str | None = None
    recipient_masked: str | None = None
    provider: str | None = None
    provider_message_id: str | None = None
    status: str | None = None
    attempt_count: int | None = None
    max_attempts: int | None = None
    sent_at: datetime | None = None
    terminal_at: datetime | None = None
    last_error_code: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


# Provider-agnostic OAuth ---------------------------------------------------------
class OAuthInitResponse(ActionResponse):
    """Single-use init token minted by ``POST /auth/oauth/init``.

    ``connection`` and ``provider_type`` are echoed from the binding the provider
    resolved for the calling project's credential, so a BFF can log or render which
    provider it is about to start without keeping its own copy of that mapping.
    """

    init_token: str | None = None
    expires_in: int | None = None
    connection: str | None = None
    provider_type: str | None = None


class OAuthProvider(_AuthModel):
    """One enabled sign-in provider, as rendered on a login page."""

    connection: str | None = None
    provider_type: str | None = None
    display_name: str | None = None


class OAuthProvidersResponse(ActionResponse):
    """Enabled sign-in providers for the calling project (``GET /auth/oauth/providers``)."""

    providers: list[OAuthProvider] = Field(default_factory=list)


# System -------------------------------------------------------------------------
class PingResponse(ActionResponse):
    """Public liveness probe. ``timestamp`` is the provider's UTC ISO-8601 clock."""

    timestamp: str | None = None


class LogoutResponse(ActionResponse):
    pass


class SwitchProjectResponse(ActionResponse, TokenPair):
    project: ProjectInfo | None = None
    user_groups: list[str] = Field(default_factory=list)


class CheckAvailabilityResponse(ActionResponse):
    username_available: bool | None = None
    email_available: bool | None = None


class UserProfileResponse(ActionResponse):
    user_hash: str | None = None
    username: str | None = None
    email: str | None = None
    user_type: str | None = None
    user_type_info: dict[str, Any] | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    last_login: datetime | None = None
    is_active: bool | None = None
    groups: list[dict[str, Any]] = Field(default_factory=list)
    projects: list[ProjectInfo] = Field(default_factory=list)


class ChangePasswordResponse(ActionResponse):
    """Result of an authenticated password change (provider returns no new token)."""

    message: str | None = "Password changed successfully"


class EmailAddress(_AuthModel):
    """One of a user's email addresses (owner view).

    Mirrors the provider's owner email row. The provider never returns the raw
    address in list payloads — only ``email_masked`` and the normalized ``email``
    may be present — so consumers should display ``email_masked`` when available.
    """

    id: str | None = None
    email: str | None = None
    email_masked: str | None = None
    status: str | None = None  # "activated" | "pending" | "removed" | "suppressed"
    is_primary: bool = False
    added_at: datetime | None = None
    activated_at: datetime | None = None
    removed_at: datetime | None = None
    last_activation_sent_at: datetime | None = None
    updated_at: datetime | None = None


class EmailListResponse(ActionResponse):
    emails: list[EmailAddress] = Field(default_factory=list)


class RemoveEmailResponse(ActionResponse):
    email_id: str | None = None
    new_primary_email_id: str | None = None


class SetPrimaryEmailResponse(ActionResponse):
    email_id: str | None = None
    status: str | None = None


class DelegatedSession(_AuthModel):
    """Result of a successful delegated-auth resolution.

    The execution identity is the *subject* user (``user_hash`` … ``project_hash``);
    the ``delegator_*``/``key_*`` fields describe the delegation credential. ``session``
    and ``api_key`` hold the raw provider sub-results.
    """

    # Subject identity (from the validated session)
    user_hash: str
    user_type: str | None = None
    username: str | None = None
    email: str | None = None
    user_groups: list[str] = Field(default_factory=list)
    project_hash: str | None = None  # subject's source project
    # Delegation metadata
    source_project_hash: str | None = None
    target_project_hash: str | None = None
    delegator_user_hash: str | None = None
    delegator_project_hash: str | None = None
    key_id: str | None = None
    key_public_id: str | None = None
    # Raw provider sub-results
    session: ValidateSessionResponse
    api_key: ValidateApiKeyResponse
