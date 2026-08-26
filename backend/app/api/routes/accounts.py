"""Admin management of CxCreditGuard's own accounts."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AdminUser, DbSession
from app.core.passwords import PasswordPolicyError
from app.models.auth import UtilityUser
from app.models.enums import UtilityRole
from app.schemas.auth import CreateUserRequest, MessageResponse, UpdateUserRequest, UserSummary
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
    if payload.role == UtilityRole.VIEWER or payload.is_active is False:
        remaining_admins = _count_other_active_admins(db, exclude_id=user.id)
        if user.role == UtilityRole.ADMIN and remaining_admins == 0:
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


@router.post("/{user_id}/unlock", response_model=MessageResponse)
def unlock_account(user_id: int, ctx: AdminUser, db: DbSession) -> MessageResponse:
    user = db.get(UtilityUser, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    before = {"locked_until": user.locked_until, "failed_login_count": user.failed_login_count}
    user.locked_until = None
    user.failed_login_count = 0
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
    if user.role == UtilityRole.ADMIN and _count_other_active_admins(db, exclude_id=user.id) == 0:
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


def _count_other_active_admins(db: Session, *, exclude_id: int) -> int:
    rows = db.scalars(
        select(UtilityUser.id).where(
            UtilityUser.role == UtilityRole.ADMIN,
            UtilityUser.is_active.is_(True),
            UtilityUser.id != exclude_id,
        )
    ).all()
    return len(rows)
