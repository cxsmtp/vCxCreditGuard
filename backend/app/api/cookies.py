"""Cookie handling for the session and CSRF tokens.

The session cookie is HttpOnly so script cannot read it. The CSRF cookie is
deliberately readable by script: the SPA echoes it back in the X-CSRF-Token
header, and the backend compares that header against the digest stored on the
session row. SameSite=Strict is set on both, which alone blocks most cross site
request forgery; the header check is the belt to that braces.
"""

from __future__ import annotations

from fastapi import Response

from app.core.config import Settings

SESSION_COOKIE = "cxcg_session"
CSRF_COOKIE = "cxcg_csrf"
CSRF_HEADER = "X-CSRF-Token"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def set_auth_cookies(
    response: Response,
    *,
    session_token: str,
    csrf_token: str,
    settings: Settings,
) -> None:
    # Session cookies (no max_age) so closing the browser ends the session. The
    # server side idle and absolute expiry are the real enforcement.
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def clear_auth_cookies(response: Response, *, settings: Settings) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(
            name,
            path="/",
            secure=settings.cookie_secure,
            samesite="strict",
            httponly=name == SESSION_COOKIE,
        )
