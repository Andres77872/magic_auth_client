# magic_auth_client

Async, framework-agnostic Python client for the **magic auth** provider (`api.auth`).
It owns all communication with the auth service: HTTP calls, typed request/response
models, and a typed exception hierarchy — so consuming services don't reimplement
auth plumbing.

- **Async-first** (`httpx.AsyncClient`).
- **Scope:** the auth-consumer core (login, register, validate, refresh, logout,
  switch-project, API-key validation, profile). Not a full admin SDK.
- **Framework-agnostic:** no FastAPI dependency. Wire your own request handling.

## Install

```bash
pip install git+https://<host>/magic_auth_client
# or, for local development:
pip install -e ".[dev]"
```

Requires Python ≥ 3.10. Depends only on `httpx` and `pydantic` v2.

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

Pass your own `httpx.AsyncClient` to reuse a connection pool across requests. The
client **borrows** it and will not close it on `aclose()`:

```python
import httpx
from magic_auth_client import MagicAuthClient, MagicAuthConfig

shared = httpx.AsyncClient(timeout=10.0)
auth = MagicAuthClient(MagicAuthConfig.from_env(), http_client=shared)
# ... reuse across many requests; close `shared` at app shutdown.
```

When no client is passed, `MagicAuthClient` creates and owns one (closed by `aclose()`
/ `async with`).

## API

All methods are `async` and return a typed pydantic model.

| Method | Endpoint | Notes |
|---|---|---|
| `login(username, password, *, project_hash=None)` | `POST /auth/login` | `project_hash` required (or config default) |
| `platform_login(username, password)` | `POST /auth/platform/login` | root/admin, no project |
| `register(username, password, *, email=None, user_group_hash=None)` | `POST /auth/register` | `user_group_hash` required (or config default) |
| `validate(*, token=None, session_token=None)` | `GET /auth/validate` | Bearer or `session_token` cookie; 200/`valid=False` not raised |
| `validate_api_key(api_key)` | `POST /auth/validate-api-key` | `X-API-Key` only; never sends `Authorization` |
| `logout(*, token=None, session_token=None)` | `POST /auth/logout` | |
| `refresh(refresh_token, *, use_cookie=False)` | `POST /auth/refresh` | form/cookie, never Bearer |
| `switch_project(access_token, project_hash, *, refresh_token=None)` | `POST /auth/switch-project` | Bearer header + form body |
| `check_availability(*, username=None, email=None)` | `POST /auth/check-availability` | |
| `get_profile(token)` | `GET /users/profile` | |
| `forgot_password(email_or_username)` | `POST /auth/password/forgot` | no auth; provider returns a generic 202 (no enumeration) |
| `reset_password(token, new_password)` | `POST /auth/password/reset` | no auth; weak password raises `WEAK_PASSWORD`; revokes all sessions, mints none |
| `change_password(token, current_password, new_password)` | `POST /auth/password/change` | Bearer; wrong current → `INVALID_CREDENTIALS`; preserves current session |
| `verify_email(token)` | `POST /auth/email/verify` | no auth; generic 202; revokes sessions on success |
| `list_emails(token)` | `GET /users/me/emails` | Bearer |
| `add_email(token, email)` | `POST /users/me/emails` | Bearer; enqueues an activation link |
| `resend_email_activation(token, email_id)` | `POST /users/me/emails/{id}/resend` | Bearer; cooldown-limited |
| `remove_email(token, email_id)` | `DELETE /users/me/emails/{id}` | Bearer; promotes next primary |
| `set_primary_email(token, email_id)` | `POST /users/me/emails/{id}/primary` | Bearer; address must be activated |
| `start_google_oauth(provider_init_token, *, redirect_uri, return_origin, remember_me=False)` | `POST /auth/google/start` | returns Google's authorization URL (the 303 `Location`; not followed) |
| `complete_google_oauth(code, state)` | `GET /auth/google/callback` | server-to-server; returns a `LoginResponse` |
| `validate_delegated_session(*, delegation_api_key, session_token, …)` | `validate-api-key` + `validate` | see [Delegated auth](#delegated-auth) |

**Email login** needs no new method: `login()` already forwards the `username` field verbatim, and the provider accepts an **activated email** there. A 429 rate-limit surfaces as a base `AuthApiError(status_code=429)` whose `.details` carries `retry_after_seconds` (the raw `Retry-After` header is not captured by the client).

**Google sign-in** exposes only the two *agnostic* legs (`start_google_oauth` / `complete_google_oauth`). The project-specific concerns — minting the opaque `provider_init_token`, the browser entry/return, the one-time delivery code, and the session cookie — belong to the consuming BFF, not this client. `start_google_oauth` does **not** follow the `303`; it returns Google's authorization URL for the BFF to hand to the browser. `complete_google_oauth` is a server-to-server call (no browser cookies) and returns the same `LoginResponse` as password login, including the refresh token.

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
└── AuthApiError(status_code, error_code, error_name, category, message, details, raw)
    ├── AuthBadRequestError      # 400 (incl. ambiguous_credentials)
    ├── AuthUnauthorizedError    # 401
    ├── AuthForbiddenError       # 403
    ├── AuthNotFoundError        # 404
    ├── AuthConflictError        # 409
    ├── AuthValidationError      # 422
    └── AuthServerError          # 5xx
```

The provider's `code` is a namespaced id (e.g. `AUTH_1001`); `error_name` is the
friendly alias (`INVALID_CREDENTIALS`). Branch on whichever you prefer:

```python
except AuthUnauthorizedError as e:
    if e.error_name == "REFRESH_TOKEN_MISMATCH":   # or e.error_code == "AUTH_1016"
        ...
```

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

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Tests run fully offline using `httpx.MockTransport` — no live auth service needed.
