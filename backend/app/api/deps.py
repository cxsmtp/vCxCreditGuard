"""FastAPI dependencies: session loading, CSRF enforcement and RBAC.

CSRF is checked inside the authentication dependency rather than in a separate
one. Every state changing route requires authentication, so putting the check
here means a new route cannot accidentally ship without CSRF protection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.cookies import CSRF_HEADER, SAFE_METHODS, SESSION_COOKIE
from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.models.auth import UtilitySession, UtilityUser
from app.models.enums import UtilityRole
from app.services import auth as auth_service
from app.services.audit import AuditActor


@dataclass(frozen=True, slots=True)
class AuthContext:
    user: UtilityUser
    session_row: UtilitySession
    ip_address: str
    user_agent: str | None

    @property
    def actor(self) -> AuditActor:
        return AuditActor.admin(self.user, ip_address=self.ip_address, user_agent=self.user_agent)

    @property
    def is_admin(self) -> bool:
        return self.user.role == UtilityRole.ADMIN


# What a signed-in account may still reach while it owes a password change:
# enough to see who it is, set the new password, and sign out.
_ALLOWED_BEFORE_PASSWORD_CHANGE = frozenset(
    {"/api/me", "/api/auth/session", "/api/auth/password", "/api/auth/logout"}
)


def client_ip(request: Request) -> str:
    """The client's address, as seen by something we trust.

    ``X-Forwarded-For`` is a list each proxy appends to, so its left-hand end is
    whatever the client chose to send. Only the entries added by our own proxies
    can be believed: with ``trusted_proxy_hops`` proxies in front of the app, the
    client is the entry that many places from the right. With none configured the
    header is ignored and the connection's own address is used.

    This feeds sign-in throttling and the audit log, so a client must not be able
    to pick its own value: it could dodge the throttle and forge audit entries.
    """
    peer = (request.client.host if request.client else "unknown")[:64]
    hops = get_settings().trusted_proxy_hops
    if hops <= 0:
        return peer
    entries = [
        entry.strip()
        for entry in request.headers.get("X-Forwarded-For", "").split(",")
        if entry.strip()
    ]
    if len(entries) < hops:
        # The proxy we were told about did not add its entry, so the request did
        # not come through it. Fall back to what we can see for ourselves.
        return peer
    return entries[-hops][:64]


def user_agent(request: Request) -> str | None:
    value = request.headers.get("User-Agent")
    return value[:256] if value else None


def get_settings_dep() -> Settings:
    return get_settings()


def require_auth(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> AuthContext:
    token = request.cookies.get(SESSION_COOKIE, "")
    session_row = auth_service.load_session(db, token)
    if session_row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")

    user = session_row.user
    if user is None or not user.is_active:
        auth_service.revoke_session(db, row=session_row)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is no longer active."
        )

    if request.method.upper() not in SAFE_METHODS and not auth_service.verify_csrf(
        session_row, request.headers.get(CSRF_HEADER)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Missing or invalid {CSRF_HEADER} header.",
        )

    db.commit()  # persist the slid idle expiry

    # An account flagged for a password change can do nothing else until it has
    # one: a temporary password handed out by an admin is known to two people.
    if user.must_change_password and request.url.path not in _ALLOWED_BEFORE_PASSWORD_CHANGE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "password_change_required",
                "message": "Choose a new password before continuing.",
            },
        )
    return AuthContext(
        user=user,
        session_row=session_row,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )


def require_admin(ctx: Annotated[AuthContext, Depends(require_auth)]) -> AuthContext:
    if not ctx.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the Admin role.",
        )
    return ctx


CurrentUser = Annotated[AuthContext, Depends(require_auth)]
AdminUser = Annotated[AuthContext, Depends(require_admin)]
DbSession = Annotated[Session, Depends(get_db)]
AppSettings = Annotated[Settings, Depends(get_settings_dep)]
