"""The readiness checklist (Settings → Enforcement, Diagnose).

``GET`` is for everyone signed in; marking the dry run reviewed and turning
enforcement on (with the typed override when not every item is green) are for
admins. See ``app.services.readiness``.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.schemas.auth import StrictModel
from app.services import readiness

router = APIRouter(prefix="/readiness", tags=["settings"])


class EnableRequest(StrictModel):
    # The override word, typed by the admin, when not every item is green.
    confirm: str | None = Field(default=None, max_length=32)


def refusal(exc: readiness.ReadinessError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": exc.code,
            "message": exc.message,
            "items": [
                {"key": item.key, "label": item.label, "status": item.status} for item in exc.items
            ],
        },
    )


@router.get("")
def get_readiness(ctx: CurrentUser, db: DbSession) -> dict[str, object]:
    return readiness.report(db).as_dict()


@router.post("/reviewed")
def mark_reviewed(ctx: AdminUser, db: DbSession) -> dict[str, object]:
    return readiness.mark_reviewed(db, actor=ctx.actor).as_dict()


@router.post("/enable")
def enable_enforcement(body: EnableRequest, ctx: AdminUser, db: DbSession) -> dict[str, object]:
    try:
        return readiness.leave_watch_only(db, actor=ctx.actor, confirm=body.confirm).as_dict()
    except readiness.ReadinessError as exc:
        db.rollback()
        raise refusal(exc) from exc
