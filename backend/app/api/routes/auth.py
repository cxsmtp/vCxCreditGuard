"""Login, logout, session introspection, password change and TOTP enrolment."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.cookies import clear_auth_cookies, set_auth_cookies
from app.api.deps import AppSettings, CurrentUser, DbSession, client_ip, user_agent
from app.core.passwords import PasswordPolicyError, verify_password
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    SessionInfo,
    TotpConfirmRequest,
    TotpEnrollResponse,
)
from app.services import auth as auth_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=SessionInfo)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
    settings: AppSettings,
) -> SessionInfo:
    ip = client_ip(request)
    agent = user_agent(request)
    try:
        user = auth_service.authenticate(
            db,
            username=payload.username,
            password=payload.password,
            totp_code=payload.totp_code,
            ip_address=ip,
            user_agent=agent,
            settings=settings,
        )
    except auth_service.TotpRequired as exc:
        # The password was correct. Ask the client for the second factor. Audit
        # rows written so far (rate limit counters) still need committing.
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "totp_required", "message": str(exc)},
        ) from exc
    except auth_service.RateLimited as exc:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limited", "message": str(exc)},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except auth_service.AccountLocked as exc:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={"code": "account_locked", "message": str(exc)},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    except auth_service.AccountDisabled as exc:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "account_disabled", "message": str(exc)},
        ) from exc
    except auth_service.InvalidCredentials as exc:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_credentials", "message": str(exc)},
        ) from exc

    issued = auth_service.issue_session(
        db, user=user, ip_address=ip, user_agent=agent, settings=settings
    )
    db.commit()
    set_auth_cookies(
        response,
        session_token=issued.session_token,
        csrf_token=issued.csrf_token,
        settings=settings,
    )
    return SessionInfo(
        username=user.username,
        role=user.role,  # type: ignore[arg-type]
        email=user.email,
        totp_enabled=user.totp_enabled,
        must_change_password=user.must_change_password,
        idle_expires_at=issued.idle_expires_at,
        absolute_expires_at=issued.absolute_expires_at,
        last_login_at=user.last_login_at,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    ctx: CurrentUser,
    response: Response,
    db: DbSession,
    settings: AppSettings,
) -> MessageResponse:
    auth_service.revoke_session(db, row=ctx.session_row)
    db.commit()
    clear_auth_cookies(response, settings=settings)
    return MessageResponse(message="Signed out.")


@router.get("/session", response_model=SessionInfo)
def current_session(ctx: CurrentUser) -> SessionInfo:
    return SessionInfo(
        username=ctx.user.username,
        role=ctx.user.role,  # type: ignore[arg-type]
        email=ctx.user.email,
        totp_enabled=ctx.user.totp_enabled,
        must_change_password=ctx.user.must_change_password,
        idle_expires_at=ctx.session_row.idle_expires_at,
        absolute_expires_at=ctx.session_row.absolute_expires_at,
        last_login_at=ctx.user.last_login_at,
    )


@router.post("/password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest,
    ctx: CurrentUser,
    db: DbSession,
) -> MessageResponse:
    if not verify_password(ctx.user.password_hash, payload.current_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "wrong_password", "message": "Current password is incorrect."},
        )
    try:
        auth_service.set_password(
            db, user=ctx.user, new_password=payload.new_password, actor=ctx.actor
        )
    except PasswordPolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "weak_password",
                "message": "Password rejected.",
                "problems": exc.problems,
            },
        ) from exc
    # set_password revokes every session including this one, on purpose.
    db.commit()
    return MessageResponse(message="Password changed. Sign in again with the new password.")


@router.post("/totp/enroll", response_model=TotpEnrollResponse)
def enroll_totp(ctx: CurrentUser, db: DbSession) -> TotpEnrollResponse:
    if ctx.user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "totp_already_enabled",
                "message": "Two factor authentication is already enabled. Disable it first.",
            },
        )
    secret, uri = auth_service.provision_totp(db, user=ctx.user)
    db.commit()
    return TotpEnrollResponse(secret=secret, otpauth_uri=uri)


@router.post("/totp/confirm", response_model=MessageResponse)
def confirm_totp(payload: TotpConfirmRequest, ctx: CurrentUser, db: DbSession) -> MessageResponse:
    if not auth_service.confirm_totp(db, user=ctx.user, code=payload.code, actor=ctx.actor):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_totp", "message": "That code did not match. Try again."},
        )
    db.commit()
    return MessageResponse(message="Two factor authentication enabled.")


@router.delete("/totp", response_model=MessageResponse)
def remove_totp(ctx: CurrentUser, db: DbSession) -> MessageResponse:
    auth_service.disable_totp(db, user=ctx.user, actor=ctx.actor)
    db.commit()
    return MessageResponse(message="Two factor authentication disabled.")
