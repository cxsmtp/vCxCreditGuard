"""Settings -> Updates: admin-only endpoints for the in-app updater.

Every route needs an admin session (and, for changes, the CSRF header, as every
other admin route). The registry token is write-only: it is accepted here and
never returned, logged, or written to the audit log.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import AdminUser, DbSession
from app.updates.service import UpdateError, get_service

router = APIRouter(prefix="/ops/updates", tags=["updates"])


class InstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=5, max_length=16)
    # PostgreSQL only: the admin has a backup of their own for a schema change.
    accept_no_backup: bool = False


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Required when the rollback restores the pre-update database backup.
    confirm_data_loss: bool = False


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Empty or null removes the stored token.
    token: str | None = Field(default=None, max_length=255)


class UpdateSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    auto_enabled: bool
    quiet_hour: int = Field(ge=0, le=23)


def _refuse(exc: UpdateError) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code, detail={"code": exc.code, "message": str(exc)}
    )


@router.get("")
def update_status(ctx: AdminUser, db: DbSession) -> dict[str, Any]:
    return get_service().status(db)


@router.post("/check")
def check_now(ctx: AdminUser, db: DbSession) -> dict[str, Any]:
    service = get_service()
    service.check(db, actor=ctx.actor)
    db.commit()
    return service.status(db)


@router.post("/install", status_code=status.HTTP_202_ACCEPTED)
def install(payload: InstallRequest, ctx: AdminUser, db: DbSession) -> dict[str, Any]:
    service = get_service()
    try:
        service.install(
            db, payload.version, actor=ctx.actor, accept_no_backup=payload.accept_no_backup
        )
    except UpdateError as exc:
        db.rollback()
        raise _refuse(exc) from exc
    return service.status(db)


@router.post("/rollback", status_code=status.HTTP_202_ACCEPTED)
def rollback(payload: RollbackRequest, ctx: AdminUser, db: DbSession) -> dict[str, Any]:
    service = get_service()
    try:
        service.rollback(db, actor=ctx.actor, confirm_data_loss=payload.confirm_data_loss)
    except UpdateError as exc:
        db.rollback()
        raise _refuse(exc) from exc
    return service.status(db)


@router.post("/restart", status_code=status.HTTP_202_ACCEPTED)
def restart(ctx: AdminUser, db: DbSession) -> dict[str, bool]:
    try:
        get_service().restart(db, actor=ctx.actor)
    except UpdateError as exc:
        raise _refuse(exc) from exc
    return {"restarting": True}


@router.put("/token")
def set_token(payload: TokenRequest, ctx: AdminUser, db: DbSession) -> dict[str, Any]:
    service = get_service()
    try:
        service.set_token(db, payload.token, actor=ctx.actor)
    except UpdateError as exc:
        db.rollback()
        raise _refuse(exc) from exc
    db.commit()
    if payload.token:
        # Tried at once, so a wrong token shows here rather than six hours later.
        service.check(db)
        db.commit()
    return service.status(db)


@router.put("/settings")
def save_settings(payload: UpdateSettingsRequest, ctx: AdminUser, db: DbSession) -> dict[str, Any]:
    service = get_service()
    try:
        service.save_settings(
            db, auto_enabled=payload.auto_enabled, quiet_hour=payload.quiet_hour, actor=ctx.actor
        )
    except UpdateError as exc:
        db.rollback()
        raise _refuse(exc) from exc
    db.commit()
    return service.status(db)
