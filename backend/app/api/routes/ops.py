"""Operational endpoints: run a cycle now, sync now, scheduler status."""

from __future__ import annotations

import logging

from fastapi import APIRouter
from sqlalchemy import func, select

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.models.enums import EnforcementStatus, LimitStatus, RunStatus
from app.models.limits import EnforcementAction, LimitPeriodState
from app.models.usage import SchedulerRun, UnresolvedSubject
from app.schemas.limits import (
    AuditChainResponse,
    CycleRunResponse,
    DiagnosticCheckResponse,
    DiagnosticsResponse,
    SchedulerStatusResponse,
)
from app.services import audit_chain, demo_service, settings_store
from app.services import diagnostics as diagnostics_service
from app.services import notifications as notification_service
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


@router.get("/demo")
def demo_status(ctx: CurrentUser, db: DbSession) -> dict[str, bool]:
    return {"demo_mode": settings_store.demo_mode(db), "seeded": demo_service.is_seeded(db)}


@router.post("/demo/seed")
def demo_seed(ctx: AdminUser, db: DbSession) -> dict[str, bool]:
    """Populate the synthetic demo dataset and enter demo mode.

    Entering demo mode is coupled to seeding on purpose: it stops the cycle from
    reading the demo usage snapshots as if they were live and enforcing against
    entities that do not exist in Checkmarx.
    """
    demo_service.seed(db)
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
    record_audit(
        db,
        action="demo.seeded",
        actor=ctx.actor,
        target_type="demo",
        detail="Synthetic demo data seeded; demo mode on.",
    )
    db.commit()
    return {"demo_mode": True, "seeded": True}


@router.post("/demo/clear")
def demo_clear(ctx: AdminUser, db: DbSession) -> dict[str, bool]:
    """Remove the synthetic demo dataset and leave demo mode (back to live)."""
    demo_service.clear(db)
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, False)
    record_audit(
        db,
        action="demo.cleared",
        actor=ctx.actor,
        target_type="demo",
        detail="Synthetic demo data cleared; demo mode off.",
    )
    db.commit()
    return {"demo_mode": False, "seeded": False}


@router.get("/diagnostics", response_model=DiagnosticsResponse)
def diagnostics(ctx: CurrentUser, db: DbSession) -> DiagnosticsResponse:
    """A read-only health read: connection, scheduler, usage freshness and more."""
    report = diagnostics_service.run_diagnostics(db, include_detail=ctx.is_admin)
    return DiagnosticsResponse(
        generated_at=report.generated_at,
        overall=report.overall,
        checks=[
            DiagnosticCheckResponse(
                key=check.key,
                label=check.label,
                status=check.status,
                detail=check.detail,
                remediation=check.remediation,
            )
            for check in report.checks
        ],
    )


@router.get("/audit/verify", response_model=AuditChainResponse)
def verify_audit_chain(ctx: AdminUser, db: DbSession) -> AuditChainResponse:
    """Re-walk the audit hash chain and report whether it is intact.

    Read-only, and deliberately not itself audited: verifying must not append to
    the very chain it inspects. A broken result names the first offending entry.
    """
    result = audit_chain.verify_chain(db)
    return AuditChainResponse(
        ok=result.ok,
        entries_checked=result.entries_checked,
        tip=result.tip,
        broken_at_id=result.broken_at_id,
        reason=result.reason,
    )
