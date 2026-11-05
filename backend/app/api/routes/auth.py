"""Login, logout, session introspection, password change and TOTP enrolment."""

from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.cookies import clear_auth_cookies, set_auth_cookies
from app.api.deps import AppSettings, CurrentUser, DbSession, client_ip, user_agent
from app.core.passwords import PasswordPolicyError, verify_password
from app.schemas.auth import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    SessionInfo,
    TotpConfirmRequest,
    TotpEnrollResponse,
)
from app.services import auth as auth_service
from app.services import delivery as delivery_service
from app.services.delivery import DeliveryConfig

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


# The same response whether or not the account exists, so the endpoint never
# reveals which usernames or emails are registered.
_RESET_REQUESTED_MESSAGE = (
    "If that account exists and has an email address on file, a reset link has been sent. "
    "The link expires in one hour."
)


def _reset_email_body(token: str) -> str:
    return (
        "A password reset was requested for your CxCreditGuard account.\n\n"
        "If this was you, open the sign-in page, choose 'Forgot password?', and enter "
        "this one-time code to set a new password:\n\n"
        f"    {token}\n\n"
        "The code expires in one hour and can be used once. If you did not request this, "
        "you can ignore this email; your password has not changed."
    )


def _dispatch_reset_email(config: DeliveryConfig, *, email: str, token: str) -> None:
    """Send the reset email off the request thread.

    Deliberately asynchronous: a synchronous SMTP call (up to the transport
    timeout) in this unauthenticated endpoint would both block a worker and, by
    making the response slower only when an account with an email exists, hand
    the caller a timing oracle that undoes the deliberately generic response.
    The worker never raises into the request and swallows every error so a mail
    failure cannot signal whether the account exists.
    """

    def _run() -> None:
        try:
            delivery_service.send_direct_email(
                config=config,
                to=email,
                subject="Password reset",
                text_body=_reset_email_body(token),
            )
        except Exception:  # noqa: BLE001 - detached worker; nothing may surface
            logger.warning("Password reset email could not be sent", exc_info=True)

    threading.Thread(target=_run, name="password-reset-email", daemon=True).start()


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db: DbSession,
    settings: AppSettings,
) -> MessageResponse:
    """Start a self-service reset. Always returns the same generic message.

    Enumeration defence: the response body is constant, the email goes out on a
    background thread (so an existing account with email is not slower), and the
    only remaining per-request difference is a single indexed insert for an
    account that exists, which is not a practical oracle for this single-node,
    rate-limited deployment.
    """
    ip = client_ip(request)
    # Normalise the throttle key exactly as the resolver does, so whitespace
    # variants of one identifier cannot each get their own bucket and bypass it.
    needle = payload.identifier.strip().lower()
    try:
        auth_service.throttle(db, bucket=f"reset:{needle}", ip_address=ip, settings=settings)
    except auth_service.RateLimited as exc:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limited", "message": str(exc)},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc

    result = auth_service.request_password_reset(db, identifier=payload.identifier, ip_address=ip)
    config = delivery_service.load_config(db) if result and result[0].email else None
    db.commit()
    if result is not None and config is not None:
        user, token = result
        _dispatch_reset_email(config, email=user.email, token=token)  # type: ignore[arg-type]
    return MessageResponse(message=_RESET_REQUESTED_MESSAGE)


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: DbSession,
    settings: AppSettings,
) -> MessageResponse:
    """Finish a reset by redeeming a token and setting a new password."""
    ip = client_ip(request)
    # Per-IP throttle: redemption tokens are high-entropy, but this closes off
    # brute-force and weak-password retry spam as defence in depth.
    try:
        auth_service.throttle(db, bucket="reset-redeem", ip_address=ip, settings=settings)
    except auth_service.RateLimited as exc:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "rate_limited", "message": str(exc)},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
    try:
        auth_service.complete_password_reset(
            db, token=payload.token, new_password=payload.new_password, ip_address=ip
        )
    except auth_service.InvalidResetToken as exc:
        db.commit()  # persist the rejected-redemption audit row
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_token", "message": str(exc)},
        ) from exc
    except PasswordPolicyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "weak_password",
                "message": "Password rejected.",
                "problems": exc.problems,
            },
        ) from exc
    db.commit()
    return MessageResponse(message="Password set. Sign in with your new password.")


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
