"""Pydantic v2 response models mirroring the auth provider's contract.

Field names/types match ``api.auth/src/Util/Models.py``. ``extra="ignore"`` lets the
client tolerate new server fields without breaking, since the provider is actively
developed.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class _AuthModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


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


class _BaseResponse(_AuthModel):
    success: bool = True
    message: str | None = None


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
class LoginResponse(_BaseResponse, TokenPair):
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    accessible_projects: list[ProjectInfo] = Field(default_factory=list)
    user_groups: list[UserGroupInfo] = Field(default_factory=list)
    plan: SessionPlan | None = None
    user_id: str | None = None


class RegisterResponse(_BaseResponse, TokenPair):
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    user_id: str | None = None


class ValidateSessionResponse(_BaseResponse):
    valid: bool
    auth_method: str = "session"
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    session: dict[str, Any] | None = None
    user_groups: list[str] = Field(default_factory=list)
    plan: SessionPlan | None = None


class ValidateApiKeyResponse(_BaseResponse):
    valid: bool
    auth_method: str = "api_key"
    user: UserInfo | None = None
    project: ProjectInfo | None = None
    api_key: ApiKeyInfo | None = None
    user_groups: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    plan: SessionPlan | None = None


class BillingCatalogResponse(_BaseResponse):
    """Per-project catalog listing (subscriptions + credit packages)."""

    project_hash: str | None = None
    billing_group_hash: str | None = None
    provider: str | None = None
    subscriptions: list[BillingCatalogItem] = Field(default_factory=list)
    credit_packs: list[BillingCatalogItem] = Field(default_factory=list)


class LogoutResponse(_BaseResponse):
    pass


class SwitchProjectResponse(_BaseResponse, TokenPair):
    project: ProjectInfo | None = None
    user_groups: list[str] = Field(default_factory=list)


class CheckAvailabilityResponse(_BaseResponse):
    username_available: bool | None = None
    email_available: bool | None = None


class UserProfileResponse(_BaseResponse):
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


class ChangePasswordResponse(_BaseResponse):
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


class EmailListResponse(_BaseResponse):
    emails: list[EmailAddress] = Field(default_factory=list)


class RemoveEmailResponse(_BaseResponse):
    email_id: str | None = None
    new_primary_email_id: str | None = None


class SetPrimaryEmailResponse(_BaseResponse):
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
