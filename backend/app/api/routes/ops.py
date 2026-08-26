"""Operational endpoints: run a cycle now, sync now, scheduler status."""

from __future__ import annotations

import logging

from fastapi import APIRouter
from sqlalchemy import func, select

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.models.enums import EnforcementStatus, LimitStatus, RunStatus
from app.models.limits import EnforcementAction, LimitPeriodState
from app.models.usage import SchedulerRun, UnresolvedSubject
from app.schemas.limits import CycleRunResponse, SchedulerStatusResponse
from app.services import notifications as notification_service
from app.services import settings_store
from app.services.audit import record_audit
from app.services.cycle import run_cycle

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ops", tags=["ops"])


@router.post("/run-cycle", response_model=CycleRunResponse)
def run_cycle_now(ctx: AdminUser, db: DbSession, force_org_sync: bool = False) -> CycleRunResponse:
    """Run one cycle synchronously.

    Audited before the run, not after, so the record survives a cycle that hangs
    or crashes the request.
    """
    record_audit(
        db,
        action="ops.cycle_triggered",
        actor=ctx.actor,
        target_type="scheduler",
        detail=f"Manual cycle requested (force_org_sync={force_org_sync}).",
    )
    db.commit()

    result = run_cycle(trigger="manual", force_org_sync=force_org_sync)
    return CycleRunResponse(
        run_id=result.run_id,
        status=result.status,
        steps=result.steps,
        errors=result.errors,
        skipped_reason=result.skipped_reason,
    )


@router.post("/sync-org", response_model=CycleRunResponse)
def sync_org_now(ctx: AdminUser, db: DbSession) -> CycleRunResponse:
    """Refresh the organisation model on demand, then evaluate."""
    record_audit(
        db,
        action="ops.org_sync_triggered",
        actor=ctx.actor,
        target_type="org_model",
        detail="Manual organisation model refresh requested.",
    )
    db.commit()
    result = run_cycle(trigger="manual", force_org_sync=True)
    return CycleRunResponse(
        run_id=result.run_id,
        status=result.status,
        steps=result.steps,
        errors=result.errors,
        skipped_reason=result.skipped_reason,
    )


@router.get("/status", response_model=SchedulerStatusResponse)
def scheduler_status(ctx: CurrentUser, db: DbSession) -> SchedulerStatusResponse:
    from app import scheduler as scheduler_module

    config = settings_store.schedule_config(db)
    last_run = db.scalar(select(SchedulerRun).order_by(SchedulerRun.started_at.desc()).limit(1))
    last_success = db.scalar(
        select(SchedulerRun.finished_at)
        .where(SchedulerRun.status.in_([RunStatus.SUCCESS, RunStatus.PARTIAL]))
        .order_by(SchedulerRun.started_at.desc())
        .limit(1)
    )

    warned = int(
        db.scalar(
            select(func.count())
            .select_from(LimitPeriodState)
            .where(LimitPeriodState.status == LimitStatus.WARNED)
        )
        or 0
    )
    restricted = int(
        db.scalar(
            select(func.count(func.distinct(EnforcementAction.entity_id))).where(
                EnforcementAction.status == EnforcementStatus.APPLIED
            )
        )
        or 0
    )
    unresolved = int(
        db.scalar(
            select(func.count())
            .select_from(UnresolvedSubject)
            .where(UnresolvedSubject.mapped_user_id.is_(None))
        )
        or 0
    )

    return SchedulerStatusResponse(
        schedule=scheduler_module.describe_schedule(),
        enabled=config.enabled,
        next_run_at=scheduler_module.next_run_time(),
        last_run_at=last_run.started_at if last_run else None,
        last_run_status=last_run.status if last_run else None,
        last_success_at=last_success,
        entities_in_warning=warned,
        entities_restricted=restricted,
        unread_notifications=notification_service.unread_count(db),
        unresolved_subjects=unresolved,
    )
