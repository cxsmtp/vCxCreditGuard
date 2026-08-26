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


def client_ip(request: Request) -> str:
    """Client address, honouring one hop of X-Forwarded-For.

    Only the left most entry of the last proxy hop is used, and it is only a log
    and rate limit input, never an authorisation input, so a spoofed header
    cannot grant access. Deploy behind the documented reverse proxy for accuracy.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first[:64]
    return (request.client.host if request.client else "unknown")[:64]


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
