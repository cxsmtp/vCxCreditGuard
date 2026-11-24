"""Admin management of CxCreditGuard's own accounts."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AdminUser, AuthContext, DbSession
from app.core.passwords import PasswordPolicyError
from app.db import locking
from app.db.base import utcnow
from app.models.auth import UtilityUser
from app.models.enums import UtilityRole
from app.schemas.auth import (
    AdminResetResponse,
    CreateUserRequest,
    MessageResponse,
    UpdateUserRequest,
    UserSummary,
)
from app.services import auth as auth_service
from app.services.audit import record_audit

router = APIRouter(prefix="/accounts", tags=["accounts"])


def _to_summary(user: UtilityUser) -> UserSummary:
    return UserSummary(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,  # type: ignore[arg-type]
        is_active=user.is_active,
        totp_enabled=user.totp_enabled,
        last_login_at=user.last_login_at,
        locked_until=user.locked_until,
        created_at=user.created_at,
    )


@router.get("", response_model=list[UserSummary])
def list_accounts(ctx: AdminUser, db: DbSession) -> list[UserSummary]:
    users = db.scalars(select(UtilityUser).order_by(UtilityUser.username)).all()
    return [_to_summary(user) for user in users]


@router.post("", response_model=UserSummary, status_code=status.HTTP_201_CREATED)
def create_account(payload: CreateUserRequest, ctx: AdminUser, db: DbSession) -> UserSummary:
    try:
        user = auth_service.create_user(
            db,
            username=payload.username,
            password=payload.password,
            role=payload.role,
            email=str(payload.email) if payload.email else None,
            actor=ctx.actor,
            must_change_password=payload.must_change_password,
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
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_account", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_summary(user)


@router.patch("/{user_id}", response_model=UserSummary)
def update_account(
    user_id: int, payload: UpdateUserRequest, ctx: AdminUser, db: DbSession
) -> UserSummary:
    user = db.get(UtilityUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")

    before = {"role": user.role, "is_active": user.is_active, "email": user.email}

    # Guard against locking the utility out of its own administration.
    if user.id == ctx.user.id and (
        payload.role == UtilityRole.VIEWER or payload.is_active is False
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "self_demotion",
                "message": "You cannot remove your own Admin role or disable your own account.",
            },
        )
    removes_admin = user.role == UtilityRole.ADMIN and (
        payload.role == UtilityRole.VIEWER or payload.is_active is False
    )
    if removes_admin:
        # Two admins demoting each other at the same moment would each find the
        # other still an Admin. One such change at a time, each counting what
        # the one before it committed.
        user = _serialize_admin_changes(db, ctx, user_id)
        before = {"role": user.role, "is_active": user.is_active, "email": user.email}
        if (
            user.role == UtilityRole.ADMIN
            and _count_other_active_admins(db, exclude_id=user.id) == 0
        ):
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "last_admin",
                    "message": "This is the last active Admin account. Promote another "
                    "account before changing this one.",
                },
            )

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
        if not payload.is_active:
            auth_service.revoke_all_sessions(db, user_id=user.id)
    if payload.email is not None:
        user.email = str(payload.email)
    db.flush()

    record_audit(
        db,
        action="account.updated",
        actor=ctx.actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        before=before,
        after={"role": user.role, "is_active": user.is_active, "email": user.email},
    )
    db.commit()
    return _to_summary(user)


@router.post("/{user_id}/reset-password", response_model=AdminResetResponse)
def admin_reset_password(user_id: int, ctx: AdminUser, db: DbSession) -> AdminResetResponse:
    """Issue a one-time reset token for a user and return it to the admin.

    For deployments without email, or when a user cannot receive the self-service
    mail, an admin hands this code to the user out of band; the user redeems it on
    the sign-in page. The token is shown once and only its digest is stored.
    """
    user = db.get(UtilityUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "inactive", "message": "Re-enable the account before resetting it."},
        )
    if user.id == ctx.user.id:
        # A reset code for your own account would let a session alone - someone
        # at an unlocked screen, a stolen cookie - set a new password without
        # knowing the old one.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "own_account",
                "message": "Change your own password on the Account page, with your current one.",
            },
        )
    token = auth_service.admin_issue_reset_token(db, user=user, actor=ctx.actor)
    expires_at = utcnow() + auth_service.PASSWORD_RESET_TTL
    db.commit()
    return AdminResetResponse(reset_token=token, expires_at=expires_at)


@router.post("/{user_id}/totp/reset", response_model=MessageResponse)
def reset_totp(user_id: int, ctx: AdminUser, db: DbSession) -> MessageResponse:
    """Turn off two factor authentication for someone who has lost their device.

    Their sessions are ended and their recovery codes discarded; they sign in with
    their password and can enrol a new authenticator.
    """
    user = db.get(UtilityUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    if user.id == ctx.user.id:
        # Turning off your own second factor needs your password (Account page).
        # Allowing it here would let a session alone remove it.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "own_account",
                "message": (
                    "Turn off your own two factor on the Account page. If you have lost "
                    "your device, use a recovery code or ask another administrator."
                ),
            },
        )
    if not user.totp_enabled and not user.totp_secret_encrypted:
        return MessageResponse(
            message=f"Two factor authentication is not enabled for {user.username}."
        )
    auth_service.disable_totp(db, user=user, actor=ctx.actor, action="account.totp_reset")
    auth_service.revoke_all_sessions(db, user_id=user.id)
    db.commit()
    return MessageResponse(message=f"Two factor authentication reset for {user.username}.")


@router.post("/{user_id}/unlock", response_model=MessageResponse)
def unlock_account(user_id: int, ctx: AdminUser, db: DbSession) -> MessageResponse:
    user = db.get(UtilityUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    before = {"locked_until": user.locked_until, "failed_login_count": user.failed_login_count}
    user.locked_until = None
    user.failed_login_count = 0
    # Also forget the per-address lockouts, or the account would look unlocked
    # while its owner still could not sign in from the address that failed.
    auth_service.clear_login_throttle(db, username=user.username)
    db.flush()
    record_audit(
        db,
        action="account.unlocked",
        actor=ctx.actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        before={
            "locked_until": str(before["locked_until"]),
            "failed_login_count": before["failed_login_count"],
        },
        after={"locked_until": None, "failed_login_count": 0},
    )
    db.commit()
    return MessageResponse(message=f"Account {user.username} unlocked.")


@router.delete("/{user_id}", response_model=MessageResponse)
def delete_account(user_id: int, ctx: AdminUser, db: DbSession) -> MessageResponse:
    user = db.get(UtilityUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    if user.id == ctx.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "self_delete", "message": "You cannot delete your own account."},
        )
    if user.role == UtilityRole.ADMIN:
        # As in update_account: one change that can remove an Admin at a time.
        user = _serialize_admin_changes(db, ctx, user_id)
        if (
            user.role == UtilityRole.ADMIN
            and _count_other_active_admins(db, exclude_id=user.id) == 0
        ):
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "last_admin",
                    "message": "This is the last active Admin account and cannot be deleted.",
                },
            )

    username = user.username
    record_audit(
        db,
        action="account.deleted",
        actor=ctx.actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=username,
        before={"username": username, "role": user.role, "is_active": user.is_active},
    )
    db.delete(user)
    db.commit()
    return MessageResponse(message=f"Account {username} deleted.")


def _serialize_admin_changes(db: Session, ctx: AuthContext, user_id: int) -> UtilityUser:
    """Take the lock every change able to remove an active Admin takes first, and
    return the target account as it is now.

    Held to the end of the transaction, so the count that follows sees every such
    change committed before it, and none can commit between the count and the
    write it allows. The acting admin is read again under it too: one who was
    demoted, disabled or deleted by the change just before may not make this one.
    """
    locking.serialize(db, locking.ADMIN_SET_LOCK_KEY)
    acting = db.get(UtilityUser, ctx.user.id, populate_existing=True)
    if acting is None or acting.role != UtilityRole.ADMIN or not acting.is_active:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires the Admin role.",
        )
    user = db.get(UtilityUser, user_id, populate_existing=True)
    if user is None:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    return user


def _count_other_active_admins(db: Session, *, exclude_id: int) -> int:
    rows = db.scalars(
        select(UtilityUser.id).where(
            UtilityUser.role == UtilityRole.ADMIN,
            UtilityUser.is_active.is_(True),
            UtilityUser.id != exclude_id,
        )
    ).all()
    return len(rows)
