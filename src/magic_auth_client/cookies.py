"""Cookie isolation for process-wide auth-provider HTTP clients.

``api.auth`` sets browser-oriented access and refresh cookies on credential-issuing
responses. A backend client is shared by many users, so retaining those cookies would
turn request-scoped credentials into process-wide state and could replay one user's
refresh token during another user's request.
"""

from __future__ import annotations

from http.cookiejar import Cookie, CookieJar

import httpx


class RejectingCookieJar(CookieJar):
    """A cookie jar that never stores response cookies.

    Explicit per-request ``Cookie`` headers still work; this only prevents cookies
    received from the provider from becoming shared client state.
    """

    def set_cookie(
        self,
        cookie: Cookie,
        *args: object,
        **kwargs: object,
    ) -> None:
        return None


def isolate_provider_cookies(http_client: httpx.AsyncClient) -> None:
    """Make a borrowed provider client stateless with respect to cookies.

    An empty jar is replaced in place so the caller keeps ownership of the connection
    pool. Preloaded cookies or default credential headers are rejected instead of
    silently deleting caller-owned state.
    """

    default_credential_headers = [
        name
        for name in ("authorization", "x-api-key", "cookie")
        if http_client.headers.get(name)
    ]
    if default_credential_headers:
        raise ValueError(
            "http_client must not define default credential headers "
            f"({', '.join(default_credential_headers)}); auth credentials are "
            "request-scoped"
        )
    if len(http_client.cookies):
        raise ValueError(
            "http_client must not contain cookies; use a dedicated cookie-free "
            "client for api.auth"
        )
    if not isinstance(http_client.cookies.jar, RejectingCookieJar):
        http_client.cookies.jar = RejectingCookieJar()
