# magic_auth_client

Async, framework-agnostic Python client for the **magic auth** provider (`api.auth`).
It owns all communication with the auth service: HTTP calls, typed request/response
models, and a typed exception hierarchy — so consuming services don't reimplement
auth plumbing.

- **Async-first** (`httpx.AsyncClient`).
- **Typed package** (Pydantic v2 models plus a PEP 561 `py.typed` marker).
- **Scope:** the auth-consumer core (login, register, validate, refresh, logout,
  switch-project, API-key validation, profile). Not a full admin SDK.
- **Framework-agnostic:** no FastAPI dependency. Wire your own request handling.
- **Backend-safe cookie handling:** provider `Set-Cookie` credentials are never
  retained in the process-wide HTTP client.

## Install

```bash
pip install "magic-auth-client @ git+https://github.com/Andres77872/magic_auth_client.git@master"
# or, for local development:
pip install -e ".[dev]"
```

Requires Python ≥ 3.10. Depends only on `httpx` and `pydantic` v2.
Production consumers should pin a release tag or immutable commit SHA; keep sibling
editable installs only in development requirements.

## Quickstart

```python
import asyncio
from magic_auth_client import MagicAuthClient, MagicAuthConfig, AuthUnauthorizedError

async def main():
    async with MagicAuthClient(MagicAuthConfig.from_env()) as auth:
        login = await auth.login("alice", "pw", project_hash="ABC...")
        print(login.access_token, login.accessible_projects)

        # 2xx-with-valid:false is NOT an exception — inspect .valid
        result = await auth.validate(token=login.access_token)
        if not result.valid:
            print("token rejected:", result.message)

        try:
            await auth.refresh(login.refresh_token)   # form body, never Bearer
        except AuthUnauthorizedError as e:
            print(e.error_name, e.error_code)         # REFRESH_TOKEN_MISMATCH AUTH_1016

asyncio.run(main())
```

## Configuration

`MagicAuthConfig.from_env()` reads the same `AUTH_*` variables the existing
`api.magic_llm` consumer uses, so it's a drop-in:

| Env var | Purpose | Default |
|---|---|---|
| `AUTH_SERVICE_BASE_URL` | Base URL of the auth provider | `http://localhost:8005` |
| `AUTH_LOGIN_URL` … `AUTH_PROFILE_URL` | Per-endpoint URL overrides (optional) | derived from base URL |
| `PROJECT_HASH` | Default `project_hash` for `login()` (and delegation target) | `None` |
| `USER_GROUP_HASH` | Default `user_group_hash` for `register()` | `None` |
| `AUTH_FORWARD_USER_AGENT` | `User-Agent` sent on every request | `magic_auth_client/<version>` |
| `AUTH_FORWARD_TIMEOUT_SECONDS` | Request timeout (owned client only) | `10` |
| `AUTH_VERIFY_TLS` | Verify provider TLS certificates (owned client only) | `true` |
| `DELEGATED_AUTH_ENABLED` | Enable delegated auth (`validate_delegated_session`) | `false` |
| `DELEGATED_AUTH_TRUSTED_CLIENTS` | Trust map (see [Delegated auth](#delegated-auth)) | `{}` |

Per-endpoint override URLs (`AUTH_LOGIN_URL`, `AUTH_VALIDATE_URL`, …) take precedence
over `base_url`. `platform/login`, `switch-project`, and `check-availability` have no
override and always resolve from `base_url`.

**Env-var aliases.** `from_env()` also accepts `magic-worlds-api`'s names as fallbacks
(the canonical name wins when both are set): `AUTH_API_URL` → `base_url`,
`AUTH_PROVIDER_USER_AGENT` → `user_agent`, `AUTH_API_TIMEOUT` → `timeout_seconds`. So a
single `MagicAuthConfig.from_env()` is a drop-in for both `api.magic_llm` and
`magic-worlds-api`.

## Connection pooling

Pass a dedicated `httpx.AsyncClient` to reuse a connection pool across auth requests.
The client **borrows** it and will not close it on `aclose()`. `api.auth` emits
browser-oriented access/refresh cookies, but a backend pool serves many users; the
library therefore replaces an empty borrowed cookie jar with `RejectingCookieJar`.
A borrowed client with preloaded cookies or default `Authorization`, `X-API-Key`, or
`Cookie` headers is rejected:

```python
import httpx
from magic_auth_client import MagicAuthClient, MagicAuthConfig, RejectingCookieJar

shared = httpx.AsyncClient(timeout=10.0, cookies=RejectingCookieJar())
auth = MagicAuthClient(MagicAuthConfig.from_env(), http_client=shared)
# ... reuse across many requests; close `shared` at app shutdown.
```

When no client is passed, `MagicAuthClient` creates and owns one (closed by `aclose()`
/ `async with`) with the same reject-all cookie behavior. Explicit per-call cookie
transports such as `validate(session_token=...)` and `refresh(..., use_cookie=True)`
still work; only response-cookie persistence is disabled.

## API

All methods are `async` and return a typed pydantic model.

| Method | Endpoint | Notes |
|---|---|---|
| `login(username, password, *, project_hash=None, remember_me=False)` | `POST /auth/login` | `project_hash` required (or config default) |
| `platform_login(username, password, *, remember_me=False)` | `POST /auth/platform/login` | root/admin, no project |
| `register(username, password, *, email=None, user_group_hash=None)` | `POST /auth/register` | `user_group_hash` required (or config default) |
| `validate(*, token=None, session_token=None)` | `GET /auth/validate` | Bearer or `session_token` cookie; 200/`valid=False` not raised |
| `validate_api_key(api_key)` | `POST /auth/validate-api-key` | `X-API-Key` only; never sends `Authorization` |
| `logout(*, token=None, session_token=None)` | `POST /auth/logout` | |
| `refresh(refresh_token, *, use_cookie=False)` | `POST /auth/refresh` | form/cookie, never Bearer |
| `switch_project(access_token, project_hash, *, refresh_token=None)` | `POST /auth/switch-project` | Bearer header + form body |
| `check_availability(*, username=None, email=None)` | `POST /auth/check-availability` | |
| `get_profile(token)` | `GET /users/profile` | |
| `forgot_password(email_or_username, *, idempotency_key=None)` | `POST /auth/password/forgot` | no auth; optional `Idempotency-Key`; generic 202 (no enumeration) |
| `reset_password(token, new_password)` | `POST /auth/password/reset` | no auth; weak password raises `WEAK_PASSWORD`; revokes all sessions, mints none |
| `change_password(token, current_password, new_password)` | `POST /auth/password/change` | Bearer; wrong current → `INVALID_CREDENTIALS`; preserves current session |
| `verify_email(token)` | `POST /auth/email/verify` | no auth; generic 202; revokes sessions on success |
| `list_emails(token)` | `GET /users/me/emails` | Bearer |
| `add_email(token, email, *, idempotency_key=None)` | `POST /users/me/emails` | Bearer; optional `Idempotency-Key`; enqueues an activation link |
| `resend_email_activation(token, email_id, *, idempotency_key=None)` | `POST /users/me/emails/{id}/resend` | Bearer; optional `Idempotency-Key`; cooldown-limited |
| `remove_email(token, email_id)` | `DELETE /users/me/emails/{id}` | Bearer; promotes next primary |
| `set_primary_email(token, email_id)` | `POST /users/me/emails/{id}/primary` | Bearer; address must be activated |
| `oauth_init(connection, *, return_origin, remember_me=False, purpose="login")` | `POST /auth/oauth/init` | project-scoped `X-API-Key`; returns an `OAuthInitResponse` carrying a single-use `init_token` |
| `oauth_start(init_token, redirect_uri, *, remember_me=None)` | `POST /auth/oauth/start` | returns the provider's authorization URL (the 303 `Location`; not followed); `remember_me` is sent only when not `None` |
| `oauth_callback(code, state, *, iss=None, error=None)` | `GET /auth/oauth/callback` | server-to-server; returns a `LoginResponse` |
| `list_oauth_providers()` | `GET /auth/oauth/providers` | project-scoped `X-API-Key`; enabled connections for the login page |
| `start_google_oauth(provider_init_token, *, redirect_uri, return_origin, remember_me=False)` | `POST /auth/google/start` | **deprecated alias**; returns Google's authorization URL (the 303 `Location`; not followed) |
| `complete_google_oauth(code, state)` | `GET /auth/google/callback` | **deprecated alias**; server-to-server; returns a `LoginResponse` |
| `validate_delegated_session(*, delegation_api_key, session_token, …)` | `validate-api-key` + `validate` | see [Delegated auth](#delegated-auth) |

### Server-to-server, entitlement and system surfaces

These use a credential other than the end user's session (noted per row), send JSON
bodies, and return models that expose `http_status` — the provider answers some of
them with different 2xx codes that carry meaning (e.g. checkout: `202` created vs
`200` idempotent replay; Patreon confirm: `200` linked vs `202` neutral posture).
`http_status` is a private attribute: it never appears in `model_dump()`.

| Method | Endpoint | Notes |
|---|---|---|
| `get_billing_catalog(*, project_hash, bearer_token, provider="stripe", item_type=None)` | `GET /internal/projects/{hash}/billing/catalog` | billing S2S Bearer; consumer-safe catalog; `item_type` filters to `subscription_plan` / `credit_package` |
| `get_billing_status(user_hash, *, project_hash, bearer_token, provider="stripe")` | `GET /internal/users/{hash}/billing` | billing S2S Bearer; subscription facts + purchases; no history → `status="free"` |
| `get_billing_purchase(user_hash, purchase_ref, *, project_hash, bearer_token, provider="stripe")` | `GET /internal/users/{hash}/billing/purchases/{ref}` | billing S2S Bearer; unknown ref → `AuthNotFoundError` |
| `create_billing_checkout(user_hash, *, bearer_token, project_hash, intent_type, price_ref, success_url, cancel_url, …, idempotency_key=None)` | `POST /internal/users/{hash}/billing/checkout` | billing S2S Bearer; `intent_type` `subscription` / `credit_purchase`; `price_ref={"ref_type": "lookup_key", "value": …}`; key reuse with another body → `AuthConflictError` |
| `create_billing_portal(user_hash, *, bearer_token, project_hash, return_url, provider="stripe", idempotency_key=None)` | `POST /internal/users/{hash}/billing/portal` | billing S2S Bearer; hosted, restricted portal session |
| `request_billing_resync(user_hash, *, bearer_token, project_hash, reason=None)` | `POST /internal/users/{hash}/billing/resync` | billing S2S Bearer; always 202 — read `accepted` / `status` |
| `get_patreon_entitlement(user_hash, *, bearer_token)` | `GET /internal/users/{hash}/entitlements` | Patreon S2S Bearer; user-scoped (no project); no link → `status="free"` |
| `request_patreon_resync(user_hash, *, bearer_token, force=False, reason=None)` | `POST /internal/users/{hash}/entitlements/patreon/resync` | Patreon S2S Bearer; always 202 — read `accepted` / `status` |
| `request_patreon_link(token, *, patreon_email_hint=None, explicit_user_intent=False, confirm_email_match=False)` | `POST /auth/patreon/link/request` | user Bearer; generic accepted body, never returns proof material |
| `confirm_patreon_link(token, *, proof_token=None, lookup_id=None, secret=None, explicit_user_intent=False)` | `POST /auth/patreon/link/confirm` | user Bearer; `proof_token` is sent as the provider's `token` field; needs recent reauth |
| `get_patreon_link_status(token)` | `GET /auth/patreon/link/status` | user Bearer |
| `unlink_patreon(token, *, explicit_user_intent=False, confirm_unlink=False)` | `DELETE /auth/patreon/link` | user Bearer; never revokes sessions; needs recent reauth |
| `resolve_email_identity(email, *, bearer_token)` | `POST /internal/email/resolve-identity` | **root** user's Bearer; is this an activated address of an account? |
| `send_template_email(recipient_email, template_code, *, bearer_token, variables=None, provider_idempotency_key=None, priority=None)` | `POST /internal/email/send-template` | **root** user's Bearer; queues a known transactional template |
| `get_email_message_status(email_message_id, *, bearer_token)` | `POST /internal/email/message-status` | **root** user's Bearer; redacted delivery state; unknown id → `AuthNotFoundError` |
| `ping()` | `GET /system/ping` | no credential; raises like any call when the provider is down, so a health check can treat any exception as unhealthy |

Patreon is an **entitlement source, never a login provider**: the link routes act on
the already-authenticated user and mint no session. The internal email bodies carry no
`success`/`message` envelope, so those models do not extend `ActionResponse`.

A BFF that mirrors a provider reply to its own caller can reproduce it exactly with
`(resp.http_status, resp.model_dump(mode="json", exclude_unset=True))` — `exclude_unset`
keeps the explicit nulls the provider sent and invents no defaults — and on failure
with `(exc.status_code, exc.raw)`.

**Email login** needs no new method: `login()` already forwards the `username` field
verbatim, and the provider accepts an **activated email** there. Password login and
platform login send `remember_me`; credential responses expose the provider's resolved
value as `TokenPair.remember_me`.

Action-only password/email methods return the public `ActionResponse` model. For email
enqueue operations, reuse a stable `idempotency_key` when retrying the same logical
request; the client forwards it as `Idempotency-Key`.

Every method that reaches the provider on behalf of a user also accepts an optional `client_ip`. It is forwarded as
`X-Forwarded-For` so a trusted BFF can preserve end-user rate-limit attribution. Only
pass an address derived from the server-observed peer after applying the deployment's
trusted-proxy policy; never copy a browser-supplied forwarding header into this field.
They also accept a per-call `user_agent` override where request attribution is useful.

**OAuth sign-in** exposes only the *agnostic* legs. The project-specific concerns — the browser entry/return, the one-time delivery code, and the session cookie — belong to the consuming BFF, not this client. Neither start method follows the `303`; both return the provider's authorization URL for the BFF to hand to the browser as a top-level navigation. Both callback methods are server-to-server calls (no browser cookies) and return the same `LoginResponse` as password login, including the refresh token.

`oauth_init` / `oauth_start` / `oauth_callback` / `list_oauth_providers` are connection-parameterised and use the **inverted handshake**: the BFF authenticates to `/auth/oauth/init` with a project-scoped API key (`project_api_key` on the config, or `AUTH_PROJECT_API_KEY` via `from_env`; sent as `X-API-Key`, never logged, excluded from the config's `repr`). The provider derives the project from that credential and the provisioning group from the binding, so the body must not carry `project_hash` or `user_group_hash` — and the provider never calls back into the consumer. After `oauth_init`, `oauth_start` takes the `init_token`, the `redirect_uri` and optionally `remember_me`; everything that is *scope* — project, connection, return origin, provisioning group — was fixed at init time and cannot be influenced here. `remember_me` is the exception: it is a user preference, so the provider lets a start request override the value bound at init. It is sent only when it is not `None`, and only a real JSON boolean overrides — pass `None` (the default) to leave the init-time value alone, which is not the same as passing `False`.

`start_google_oauth` / `complete_google_oauth` are the **deprecated** Google-named wrappers for the legacy handshake, where the consumer mints the opaque `provider_init_token` itself and the provider redeems it at the consumer's internal endpoint. They are unchanged and keep working; new code should use the connection-parameterised methods.

Two callback error codes deserve their own message in a UI rather than a generic failure: `EXT_8031` (`OAUTH_USER_CANCELLED` — the user cancelled at the provider, HTTP 400) and `EXT_8032` (`OAUTH_ACCOUNT_LINK_REQUIRED` — an existing local account owns this e-mail, so the user must sign in and link, HTTP 409). Branch on `AuthApiError.error_name`, never on the provider's name.

## Delegated auth

Delegated (service-to-service) auth lets a trusted caller act on behalf of a *subject*
user from another project. There is **no special provider endpoint** — the client
composes two existing calls and applies a local trust policy:

1. `validate_api_key(delegation_api_key)` — validate the delegation key (`X-API-Key`).
2. `validate(token=session_token)` — validate the subject's Bearer session.
3. Run the trust-policy checks below; on success return a `DelegatedSession` whose
   identity is the **subject** user, with the delegator/key as metadata.

```python
result = await auth.validate_delegated_session(
    delegation_api_key="sk_pub1.secret",   # X-API-Key of the calling service
    session_token="subject-bearer-token",  # the subject user's session
    # target_project_hash / trusted_clients / enabled default to the config below
)
print(result.user_hash, result.source_project_hash, result.delegator_user_hash)
```

**Configuration.** Set on `MagicAuthConfig` (or via env in `from_env()`):

- `delegation_enabled` (`DELEGATED_AUTH_ENABLED`) — master switch.
- `project_hash` (`PROJECT_HASH`) — the **target** project the delegation key must belong to.
- `delegation_trusted_clients` (`DELEGATED_AUTH_TRUSTED_CLIENTS`) — a trust map
  `{source_project_hash: {key_public_id, …}}`. The env format is a CSV of
  `source:key` pairs, one per item (repeat the source for multiple keys), e.g.
  `"srcA:pub1,srcA:pub2,srcB:pub3"`. Parse it yourself with `parse_trusted_clients()`.

Any arg may be passed per-call to override config.

**Trust-policy checks** (mirroring `api.magic_llm`, evaluated in order). Failures raise
`DelegationError(reason, status_code)`:

| reason | status |
|---|---|
| `delegated_auth_disabled` | 403 |
| `delegated_missing_subject` | 401 |
| `delegated_trusted_clients_empty` | 403 |
| `delegation_key_invalid` | 401 |
| `delegation_key_wrong_project` | 403 |
| `delegation_key_not_registered` | 403 |
| `delegated_subject_invalid` | 401 |
| `delegated_source_project_not_allowed` | 403 |
| `delegation_key_not_trusted_for_source_project` | 403 |

Map `DelegationError.reason` / `.status_code` to your own HTTP response.

## Error handling

Transport failures raise `AuthTransportError`. Any non-2xx response raises an
`AuthApiError` subclass keyed on HTTP status:

```
MagicAuthError
├── AuthTransportError                # network/timeout/unparseable response
└── AuthApiError(status_code, error_code, error_name, category, message, details,
                 retry_after, retry_after_seconds, raw)
    ├── AuthBadRequestError      # 400 (incl. ambiguous_credentials)
    ├── AuthUnauthorizedError    # 401
    ├── AuthForbiddenError       # 403
    ├── AuthNotFoundError        # 404
    ├── AuthConflictError        # 409
    ├── AuthValidationError      # 422
    ├── AuthRateLimitError       # 429
    └── AuthServerError          # 5xx
```

The provider's `code` is a namespaced id (e.g. `AUTH_1001`); `error_name` is the
friendly alias (`INVALID_CREDENTIALS`). Branch on whichever you prefer:

```python
except AuthUnauthorizedError as e:
    if e.error_name == "REFRESH_TOKEN_MISMATCH":   # or e.error_code == "AUTH_1016"
        ...
```

Rate-limited responses preserve the raw `Retry-After` header in `.retry_after`.
`.retry_after_seconds` prefers the structured provider
`details.retry_after_seconds` value and otherwise parses a delta-seconds header; an
HTTP-date remains available only in `.retry_after`. Invalid JSON raises
`AuthTransportError`; a syntactically valid but malformed 2xx response preserves
Pydantic's `ValidationError` for backward compatibility with existing consumers.

## Notes / non-goals

- **`valid=False` is not an error.** `validate` / `validate_api_key` can return HTTP
  200 with `valid=False`; inspect the field rather than catching an exception.
- **No JWT signature verification** — tokens are validated server-side.

### Not in the client (consumer responsibilities)

The client is intentionally **thin and stateless**. The following are left to each
consumer because they are stateful and deployment-specific (both `api.magic_llm` and
`magic-worlds-api` already implement their own):

- **Validation caching** — caching `validate` results would break revocation
  correctness; cache positives only, with a short TTL, in your app if needed.
- **Refresh coalescing / single-flight** — wrap `refresh()` to serialize concurrent
  refreshes of the same token and avoid "refresh reused" rejections.
- **Circuit breaker / retries** — wrap calls or inject a configured `httpx.AsyncClient`.
- **Transport** — e.g. WebSocket subprotocol token extraction; pass the extracted token
  string to `validate(token=...)`.

### Recommended consumer boundary

The shared client owns provider-stable behavior: endpoint resolution, form/JSON
encoding, credential placement, provider-cookie isolation, response parsing, and the
provider error vocabulary. Each consuming project should keep deployment/application
policy in its own adapter:

- browser refresh-cookie attributes and CSRF checks;
- expected-project enforcement and local user provisioning;
- validation caches, retries/circuit breakers, and refresh single-flight;
- mapping provider exceptions/models into that project's public HTTP contract.

This is the split used by `magic-worlds-api`, `api.findit.moe`, and `api.magic_llm`;
their existing reject-all cookie-jar implementations can be replaced by the exported
`RejectingCookieJar` or omitted when they pass an otherwise empty dedicated client.

## Testing

```bash
pip install -e ".[dev]"
pytest -p no:cacheprovider
```

Tests run fully offline using `httpx.MockTransport` — no live auth service needed.
