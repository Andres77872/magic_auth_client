"""Exception hierarchy and error-response parsing.

The auth provider returns two error body shapes:

* App envelope (custom errors)::

      {"status": "error",
       "error": {"code": "AUTH_1001", "category": "authentication", "message": "..."}}

  ``code`` is a namespaced id (``CATEGORY_NNNN``); ``details``/``trace`` appear only
  when the server runs in DEBUG mode.

* FastAPI errors::

      {"detail": "ambiguous_credentials"}        # e.g. 400
      {"detail": [ {<validation error>}, ... ]}  # e.g. 422
"""

from __future__ import annotations

from typing import Any

import httpx

from .constants import ERROR_CODE_NAMES


class MagicAuthError(Exception):
    """Base class for every error raised by this package."""


class AuthTransportError(MagicAuthError):
    """The auth service could not be reached or returned an unparseable response."""

    def __init__(self, message: str = "Auth service unavailable", *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.cause = cause


class AuthApiError(MagicAuthError):
    """A non-2xx HTTP response from the auth service.

    Attributes:
        status_code: HTTP status code.
        error_code: Wire code, e.g. ``"AUTH_1001"`` (or a FastAPI detail string,
            or ``None`` when absent).
        error_name: Friendly alias, e.g. ``"INVALID_CREDENTIALS"`` (``None`` if
            the code is unknown).
        category: Error category from the app envelope, e.g. ``"authentication"``.
        message: Human-readable message.
        details: Optional structured details (DEBUG mode or FastAPI validation list).
        raw: The full decoded body, for escape-hatch access.
    """

    def __init__(
        self,
        *,
        status_code: int,
        message: str,
        error_code: str | None = None,
        error_name: str | None = None,
        category: str | None = None,
        details: dict[str, Any] | None = None,
        raw: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.error_code = error_code
        self.error_name = error_name
        self.category = category
        self.details = details
        self.raw = raw

    def __str__(self) -> str:
        label = self.error_name or self.error_code or "error"
        return f"[{self.status_code} {label}] {self.message}"


class AuthBadRequestError(AuthApiError):
    """HTTP 400 (includes ``ambiguous_credentials``)."""


class AuthUnauthorizedError(AuthApiError):
    """HTTP 401 (invalid credentials, refresh mismatch, expired/revoked session)."""


class AuthForbiddenError(AuthApiError):
    """HTTP 403 (access/permission denied)."""


class AuthNotFoundError(AuthApiError):
    """HTTP 404."""


class AuthConflictError(AuthApiError):
    """HTTP 409 (username/email already exists)."""


class AuthValidationError(AuthApiError):
    """HTTP 422 (FastAPI validation; e.g. missing User-Agent or form field)."""


class AuthServerError(AuthApiError):
    """HTTP 5xx."""


class DelegationError(MagicAuthError):
    """A delegated-auth trust-policy check failed locally (not a provider HTTP error).

    Carries a stable ``reason`` and a suggested ``status_code`` (403 or 401) matching
    ``api.magic_llm``'s delegated-auth rejections, so a consumer can map it to an
    identical HTTP response. Reasons: ``delegated_auth_disabled``,
    ``delegated_missing_subject``, ``delegated_trusted_clients_empty``,
    ``delegation_key_invalid``, ``delegation_key_wrong_project``,
    ``delegation_key_not_registered``, ``delegated_subject_invalid``,
    ``delegated_source_project_not_allowed``,
    ``delegation_key_not_trusted_for_source_project``.
    """

    def __init__(self, reason: str, *, status_code: int, message: str | None = None) -> None:
        super().__init__(message or reason)
        self.reason = reason
        self.status_code = status_code
        self.message = message or reason

    def __str__(self) -> str:
        return f"[{self.status_code} {self.reason}] {self.message}"


_STATUS_TO_EXC: dict[int, type[AuthApiError]] = {
    400: AuthBadRequestError,
    401: AuthUnauthorizedError,
    403: AuthForbiddenError,
    404: AuthNotFoundError,
    409: AuthConflictError,
    422: AuthValidationError,
}


def parse_error_response(response: httpx.Response) -> AuthApiError:
    """Map a non-2xx ``httpx.Response`` to the appropriate :class:`AuthApiError`."""
    status = response.status_code
    try:
        body: Any = response.json()
    except ValueError:
        body = None

    error_code: str | None = None
    error_name: str | None = None
    category: str | None = None
    details: dict[str, Any] | None = None
    message = response.reason_phrase or "request failed"

    if isinstance(body, dict) and body.get("status") == "error" and isinstance(body.get("error"), dict):
        err = body["error"]
        error_code = err.get("code")
        error_name = ERROR_CODE_NAMES.get(error_code) if error_code else None
        category = err.get("category")
        message = err.get("message") or message
        raw_details = err.get("details")
        if isinstance(raw_details, dict):
            details = raw_details
    elif isinstance(body, dict) and "detail" in body:
        detail = body["detail"]
        if isinstance(detail, str):
            message = detail
            error_code = detail
        else:
            message = "validation_error"
            details = {"errors": detail}
    elif isinstance(body, dict) and body.get("message"):
        # Some provider/proxy error bodies are a bare ``{"message": ...}`` without the
        # app envelope or a FastAPI ``detail`` key. Surface that message rather than the
        # bare HTTP reason phrase. Additive: only reached when the shapes above did not.
        message = str(body["message"])
    elif body is None:
        # Non-JSON error body (e.g. an HTML 5xx page or plain text). Prefer the raw
        # response text over the reason phrase when it carries something useful.
        text = (response.text or "").strip()
        if text:
            message = text[:500]

    if status in _STATUS_TO_EXC:
        cls: type[AuthApiError] = _STATUS_TO_EXC[status]
    elif status >= 500:
        cls = AuthServerError
    else:
        cls = AuthApiError

    return cls(
        status_code=status,
        message=message,
        error_code=error_code,
        error_name=error_name,
        category=category,
        details=details,
        raw=body,
    )
