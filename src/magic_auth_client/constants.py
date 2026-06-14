"""Static configuration values, endpoint paths, header names, and the error-code map.

The error-code map mirrors ``ErrorCode`` in the auth provider
(``api.auth/src/Util/error_handler.py``). The provider serializes the enum *value*
(e.g. ``"AUTH_1001"``) on the wire, so clients receive namespaced ids rather than the
semantic names. ``ERROR_CODE_NAMES`` lets callers branch on the friendly name instead.
"""

from __future__ import annotations

__version__ = "0.2.0"

# Defaults ---------------------------------------------------------------------
DEFAULT_BASE_URL = "http://localhost:8005"
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_USER_AGENT = f"magic_auth_client/{__version__}"

# Endpoint paths (resolved against base_url unless an explicit override URL is set) --
PATH_LOGIN = "/auth/login"
PATH_PLATFORM_LOGIN = "/auth/platform/login"
PATH_REGISTER = "/auth/register"
PATH_VALIDATE = "/auth/validate"
PATH_VALIDATE_API_KEY = "/auth/validate-api-key"
PATH_LOGOUT = "/auth/logout"
PATH_REFRESH = "/auth/refresh"
PATH_SWITCH_PROJECT = "/auth/switch-project"
PATH_CHECK_AVAILABILITY = "/auth/check-availability"
PATH_PROFILE = "/users/profile"
# Google OAuth (agnostic legs only — the BFF owns provider-init + the browser return) -
PATH_GOOGLE_OAUTH_START = "/auth/google/start"
PATH_GOOGLE_OAUTH_CALLBACK = "/auth/google/callback"
# Password & email workflows (no env overrides; resolved against base_url) ----------
PATH_PASSWORD_FORGOT = "/auth/password/forgot"
PATH_PASSWORD_RESET = "/auth/password/reset"
PATH_PASSWORD_CHANGE = "/auth/password/change"
PATH_EMAIL_VERIFY = "/auth/email/verify"
PATH_USER_EMAILS = "/users/me/emails"

# Header / cookie names --------------------------------------------------------
HEADER_AUTHORIZATION = "Authorization"
HEADER_API_KEY = "X-API-Key"
HEADER_USER_AGENT = "User-Agent"
HEADER_ACCEPT = "Accept"
# Origin of the end-user's browser, relayed by a reverse-proxy/BFF consumer so the
# provider can build agnostic user-facing links (email activation / password reset)
# from where the user actually is, instead of its own bind address.
HEADER_PUBLIC_BASE_URL = "X-Public-Base-Url"
COOKIE_SESSION = "session_token"
COOKIE_REFRESH = "refresh_token"

# Wire error code -> friendly name (mirrors api.auth/src/Util/error_handler.py) ----
ERROR_CODE_NAMES: dict[str, str] = {
    # Authentication (1xxx)
    "AUTH_1001": "INVALID_CREDENTIALS",
    "AUTH_1002": "SESSION_EXPIRED",
    "AUTH_1003": "SESSION_INVALID",
    "AUTH_1004": "TOKEN_INVALID",
    "AUTH_1005": "ACCOUNT_INACTIVE",
    "AUTH_1006": "ACCOUNT_LOCKED",
    "AUTH_1007": "PASSWORD_RESET_REQUIRED",
    "AUTH_1008": "MFA_REQUIRED",
    "AUTH_1009": "MFA_INVALID",
    "AUTH_1010": "API_KEY_INVALID",
    "AUTH_1011": "API_KEY_EXPIRED",
    "AUTH_1012": "API_KEY_REVOKED",
    "AUTH_1013": "REFRESH_TOKEN_INVALID",
    "AUTH_1014": "REFRESH_TOKEN_MISSING",
    "AUTH_1015": "REFRESH_TOKEN_REUSED",
    "AUTH_1016": "REFRESH_TOKEN_MISMATCH",
    "AUTH_1017": "REFRESH_FAMILY_REVOKED",
    "AUTH_1018": "TOKEN_TYPE_INVALID",
    "AUTH_1019": "TOKEN_EXPIRED",
    "AUTH_1020": "SESSION_REVOKED",
    "AUTH_1021": "JWT_CONFIGURATION_FAILURE",
    # Authorization (2xxx)
    "AUTHZ_2001": "ACCESS_DENIED",
    "AUTHZ_2002": "INSUFFICIENT_PERMISSIONS",
    "AUTHZ_2003": "PROJECT_ACCESS_DENIED",
    "AUTHZ_2004": "GROUP_ACCESS_DENIED",
    "AUTHZ_2005": "RESOURCE_ACCESS_DENIED",
    "AUTHZ_2006": "ROLE_ASSIGNMENT_DENIED",
    "AUTHZ_2007": "PERMISSION_DENIED",
    "AUTHZ_2008": "API_KEY_NO_ACCESS",
    # Validation (3xxx)
    "VAL_3001": "INVALID_INPUT",
    "VAL_3002": "MISSING_REQUIRED_FIELD",
    "VAL_3003": "INVALID_FORMAT",
    "VAL_3004": "INVALID_UUID",
    "VAL_3005": "INVALID_EMAIL",
    "VAL_3006": "INVALID_USERNAME",
    "VAL_3007": "WEAK_PASSWORD",
    "VAL_3008": "INVALID_DATE",
    "VAL_3009": "INVALID_RANGE",
    "VAL_3010": "INVALID_LENGTH",
    "VAL_3011": "INVALID_TYPE",
    "VAL_3012": "INVALID_ENUM_VALUE",
    # Not found (4xxx)
    "NF_4001": "USER_NOT_FOUND",
    "NF_4002": "PROJECT_NOT_FOUND",
    "NF_4003": "GROUP_NOT_FOUND",
    "NF_4004": "RESOURCE_NOT_FOUND",
    "NF_4005": "PERMISSION_NOT_FOUND",
    "NF_4006": "SESSION_NOT_FOUND",
    "NF_4007": "ROLE_NOT_FOUND",
    "NF_4008": "ENDPOINT_NOT_FOUND",
    "NF_4009": "USER_TYPE_NOT_FOUND",
    "NF_4010": "API_KEY_NOT_FOUND",
    # Conflict (5xxx)
    "CONF_5001": "USERNAME_EXISTS",
    "CONF_5002": "EMAIL_EXISTS",
    "CONF_5003": "RESOURCE_EXISTS",
    "CONF_5004": "DUPLICATE_ENTRY",
    "CONF_5005": "STATE_CONFLICT",
    "CONF_5006": "VERSION_CONFLICT",
    # Database (6xxx)
    "DB_6001": "DATABASE_ERROR",
    "DB_6002": "CONNECTION_ERROR",
    "DB_6003": "QUERY_ERROR",
    "DB_6004": "TRANSACTION_ERROR",
    "DB_6005": "CONSTRAINT_VIOLATION",
    "DB_6006": "DEADLOCK",
    # Internal (7xxx)
    "INT_7001": "INTERNAL_ERROR",
    "INT_7002": "CONFIGURATION_ERROR",
    "INT_7003": "SERVICE_UNAVAILABLE",
    "INT_7004": "TIMEOUT",
    "INT_7005": "RATE_LIMIT_EXCEEDED",
    "INT_7006": "FEATURE_NOT_IMPLEMENTED",
    # External (8xxx)
    "EXT_8001": "EXTERNAL_SERVICE_ERROR",
    "EXT_8002": "EXTERNAL_API_ERROR",
    "EXT_8003": "EXTERNAL_TIMEOUT",
}
