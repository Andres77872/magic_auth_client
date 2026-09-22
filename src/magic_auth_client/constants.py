"""Static configuration values, endpoint paths, header names, and the error-code map.

The error-code map mirrors ``ErrorCode`` in the auth provider
(``api.auth/src/Util/error_handler.py``). The provider serializes the enum *value*
(e.g. ``"AUTH_1001"``) on the wire, so clients receive namespaced ids rather than the
semantic names. ``ERROR_CODE_NAMES`` lets callers branch on the friendly name instead.
"""

from __future__ import annotations

__version__ = "0.4.0"

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
# Deprecated aliases onto the provider-agnostic pipeline below; kept working by the
# provider for at least one consumer release cycle.
PATH_GOOGLE_OAUTH_START = "/auth/google/start"
PATH_GOOGLE_OAUTH_CALLBACK = "/auth/google/callback"
# Provider-agnostic OAuth (any connection key: google, microsoft, …) ----------------
# Inverted handshake: the project's backend authenticates to ``/auth/oauth/init`` with
# its project-scoped API key and receives an init token. The provider derives project,
# binding and provisioning group from that credential — they are never sent on the wire
# and the provider never calls back into the consumer.
PATH_OAUTH_INIT = "/auth/oauth/init"
PATH_OAUTH_START = "/auth/oauth/start"
PATH_OAUTH_CALLBACK = "/auth/oauth/callback"
PATH_OAUTH_PROVIDERS = "/auth/oauth/providers"
# Password & email workflows (no env overrides; resolved against base_url) ----------
PATH_PASSWORD_FORGOT = "/auth/password/forgot"
PATH_PASSWORD_RESET = "/auth/password/reset"
PATH_PASSWORD_CHANGE = "/auth/password/change"
PATH_EMAIL_VERIFY = "/auth/email/verify"
PATH_USER_EMAILS = "/users/me/emails"
# Patreon entitlement link (current user's Bearer; Patreon is never a login provider) -
PATH_PATREON_LINK = "/auth/patreon/link"
PATH_PATREON_LINK_REQUEST = "/auth/patreon/link/request"
PATH_PATREON_LINK_CONFIRM = "/auth/patreon/link/confirm"
PATH_PATREON_LINK_STATUS = "/auth/patreon/link/status"
# Internal, consumer-safe billing surface (billing S2S bearer) ------------------
PATH_BILLING_CATALOG = "/internal/projects/{project_hash}/billing/catalog"
PATH_BILLING_STATUS = "/internal/users/{user_hash}/billing"
PATH_BILLING_CHECKOUT = "/internal/users/{user_hash}/billing/checkout"
PATH_BILLING_PORTAL = "/internal/users/{user_hash}/billing/portal"
PATH_BILLING_PURCHASE = "/internal/users/{user_hash}/billing/purchases/{purchase_ref}"
PATH_BILLING_RESYNC = "/internal/users/{user_hash}/billing/resync"
# Internal Patreon entitlement surface (Patreon S2S bearer) ---------------------
PATH_PATREON_ENTITLEMENT = "/internal/users/{user_hash}/entitlements"
PATH_PATREON_ENTITLEMENT_RESYNC = "/internal/users/{user_hash}/entitlements/patreon/resync"
# Internal transactional email surface (root user's Bearer) ---------------------
PATH_INTERNAL_EMAIL_RESOLVE_IDENTITY = "/internal/email/resolve-identity"
PATH_INTERNAL_EMAIL_SEND_TEMPLATE = "/internal/email/send-template"
PATH_INTERNAL_EMAIL_MESSAGE_STATUS = "/internal/email/message-status"
# Public liveness probe (no credential) -----------------------------------------
PATH_PING = "/system/ping"

# Header / cookie names --------------------------------------------------------
HEADER_AUTHORIZATION = "Authorization"
HEADER_API_KEY = "X-API-Key"
HEADER_USER_AGENT = "User-Agent"
HEADER_ACCEPT = "Accept"
HEADER_IDEMPOTENCY_KEY = "Idempotency-Key"
HEADER_FORWARDED_FOR = "X-Forwarded-For"
HEADER_RETRY_AFTER = "Retry-After"
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
    "AUTH_1022": "REFRESH_TOKEN_REPLAYED",
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
    # Google OAuth / external identity
    "EXT_8010": "OAUTH_PROVIDER_NOT_CONFIGURED",
    "EXT_8011": "OAUTH_PROVIDER_DISABLED",
    "EXT_8012": "OAUTH_PROVIDER_INIT_INVALID",
    "EXT_8013": "OAUTH_REDIRECT_URI_NOT_ALLOWED",
    "EXT_8014": "OAUTH_STATE_INVALID",
    "EXT_8015": "OAUTH_STATE_EXPIRED",
    "EXT_8016": "OAUTH_STATE_REUSED",
    "EXT_8017": "OAUTH_NONCE_MISMATCH",
    "EXT_8018": "OAUTH_CODE_EXCHANGE_FAILED",
    "EXT_8019": "OAUTH_ID_TOKEN_INVALID",
    "EXT_8020": "OAUTH_ISSUER_MISMATCH",
    "EXT_8021": "OAUTH_AUDIENCE_MISMATCH",
    "EXT_8022": "OAUTH_TOKEN_EXPIRED",
    "EXT_8023": "OAUTH_WORKSPACE_DENIED",
    "EXT_8024": "OAUTH_PROVISIONING_DENIED",
    "EXT_8025": "OAUTH_PROJECT_ACCESS_DENIED",
    "EXT_8026": "EXTERNAL_IDENTITY_ALREADY_LINKED",
    "EXT_8027": "EXTERNAL_IDENTITY_SUB_CONFLICT",
    "EXT_8028": "EXTERNAL_IDENTITY_NOT_LINKED",
    "EXT_8029": "OAUTH_PASSWORD_REQUIRED_FOR_UNLINK",
    "EXT_8030": "OAUTH_RATE_LIMITED",
    # The user cancelled at the provider's consent screen (HTTP 400) — not a failure.
    "EXT_8031": "OAUTH_USER_CANCELLED",
    # A local account already owns this e-mail: the user must sign in with their
    # existing method and link the provider from their account (HTTP 409).
    "EXT_8032": "OAUTH_ACCOUNT_LINK_REQUIRED",
    # Patreon
    "EXT_8100": "PATREON_PROVIDER_NOT_CONFIGURED",
    "EXT_8101": "PATREON_PROVIDER_DISABLED",
    "EXT_8102": "PATREON_CONFIGURATION_INVALID",
    "EXT_8103": "PATREON_CREATOR_API_UNAVAILABLE",
    "EXT_8104": "PATREON_CREATOR_API_TIMEOUT",
    "EXT_8105": "PATREON_CREATOR_API_RATE_LIMITED",
    "EXT_8106": "PATREON_CREATOR_API_ERROR",
    "EXT_8107": "PATREON_LINK_ACTION_DENIED",
    "EXT_8108": "PATREON_LINK_CONFLICT",
    "EXT_8109": "PATREON_PROOF_INVALID",
    "EXT_8110": "PATREON_PROOF_RATE_LIMITED",
    "EXT_8111": "PATREON_WEBHOOK_SIGNATURE_INVALID",
    "EXT_8112": "PATREON_S2S_UNAUTHORIZED",
    "EXT_8113": "PATREON_SYNC_DEGRADED",
    "EXT_8114": "PATREON_TIER_MAP_NOT_READY",
    "EXT_8115": "PATREON_SECURITY_EVENT",
    "EXT_8116": "PATREON_RATE_LIMITED",
    # Stripe / billing
    "EXT_8200": "STRIPE_PROVIDER_NOT_CONFIGURED",
    "EXT_8201": "STRIPE_PROVIDER_DISABLED",
    "EXT_8202": "STRIPE_CONFIGURATION_INVALID",
    "EXT_8203": "STRIPE_SDK_VERSION_MISMATCH",
    "EXT_8204": "STRIPE_API_VERSION_MISMATCH",
    "EXT_8205": "STRIPE_WEBHOOK_SIGNATURE_INVALID",
    "EXT_8206": "BILLING_S2S_UNAUTHORIZED",
    "EXT_8207": "BILLING_PROJECT_SCOPE_DENIED",
    "EXT_8208": "BILLING_IDEMPOTENCY_CONFLICT",
    "EXT_8209": "STRIPE_CHECKOUT_UNAVAILABLE",
    "EXT_8210": "STRIPE_PORTAL_UNAVAILABLE",
    "EXT_8211": "STRIPE_PORTAL_CONFIGURATION_INVALID",
    "EXT_8212": "BILLING_PROVIDER_REF_DECRYPT_FAILED",
    "EXT_8213": "BILLING_SYNC_DEGRADED",
    "EXT_8214": "BILLING_RATE_LIMITED",
    "EXT_8215": "BILLING_SECURITY_EVENT",
    # Transactional auth email (9xxx)
    "EMAIL_9001": "EMAIL_DELIVERY_DISABLED",
    "EMAIL_9002": "EMAIL_PROVIDER_NOT_READY",
    "EMAIL_9003": "EMAIL_REAL_SEND_BLOCKED_IN_TEST",
    "EMAIL_9004": "EMAIL_TOKEN_INVALID",
    "EMAIL_9005": "EMAIL_IDEMPOTENCY_CONFLICT",
    "EMAIL_9006": "EMAIL_SUPPRESSED",
    "EMAIL_9007": "EMAIL_WEBHOOK_INVALID",
    "EMAIL_9008": "EMAIL_OUTBOX_FAILURE",
    "EMAIL_9009": "EMAIL_PROVIDER_SEND_FAILED",
    "EMAIL_9010": "EMAIL_TEMPLATE_INVALID",
}
