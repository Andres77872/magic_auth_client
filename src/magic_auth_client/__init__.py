"""magic_auth_client — async client for the magic auth provider (api.auth).

Exposes the :class:`MagicAuthClient`, its :class:`MagicAuthConfig`, the typed
response models, and the exception hierarchy.
"""

from __future__ import annotations

from .client import MagicAuthClient
from .config import MagicAuthConfig, parse_trusted_clients
from .constants import __version__
from .exceptions import (
    AuthApiError,
    AuthBadRequestError,
    AuthConflictError,
    AuthForbiddenError,
    AuthNotFoundError,
    AuthServerError,
    AuthTransportError,
    AuthUnauthorizedError,
    AuthValidationError,
    DelegationError,
    MagicAuthError,
    parse_error_response,
)
from .models import (
    ApiKeyInfo,
    ChangePasswordResponse,
    CheckAvailabilityResponse,
    DelegatedSession,
    EmailAddress,
    EmailListResponse,
    LoginResponse,
    LogoutResponse,
    ProjectInfo,
    RegisterResponse,
    RemoveEmailResponse,
    SetPrimaryEmailResponse,
    SwitchProjectResponse,
    TokenPair,
    UserGroupInfo,
    UserInfo,
    UserProfileResponse,
    ValidateApiKeyResponse,
    ValidateSessionResponse,
)

__all__ = [
    "__version__",
    # client + config
    "MagicAuthClient",
    "MagicAuthConfig",
    "parse_trusted_clients",
    # models
    "ApiKeyInfo",
    "ChangePasswordResponse",
    "CheckAvailabilityResponse",
    "DelegatedSession",
    "EmailAddress",
    "EmailListResponse",
    "LoginResponse",
    "LogoutResponse",
    "ProjectInfo",
    "RegisterResponse",
    "RemoveEmailResponse",
    "SetPrimaryEmailResponse",
    "SwitchProjectResponse",
    "TokenPair",
    "UserGroupInfo",
    "UserInfo",
    "UserProfileResponse",
    "ValidateApiKeyResponse",
    "ValidateSessionResponse",
    # exceptions
    "MagicAuthError",
    "AuthTransportError",
    "AuthApiError",
    "AuthBadRequestError",
    "AuthUnauthorizedError",
    "AuthForbiddenError",
    "AuthNotFoundError",
    "AuthConflictError",
    "AuthValidationError",
    "AuthServerError",
    "DelegationError",
    "parse_error_response",
]
