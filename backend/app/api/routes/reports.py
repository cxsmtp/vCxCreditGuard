"""Forward projection, governance impact, and the exportable/emailable report."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.schemas.reports import (
    ChargebackResponse,
    ChargebackRowResponse,
    ImpactResponse,
    ProjectionResponse,
    ReportEmailResult,
    ReportResponse,
)
from app.services import delivery, reporting_service
from app.services.audit import record_audit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])


def _projection_to_response(p: reporting_service.Projection) -> ProjectionResponse:
    return ProjectionResponse(
        limit_id=p.limit_id,
        entity_type=p.entity_type,  # type: ignore[arg-type]
        entity_id=p.entity_id,
        entity_label=p.entity_label,
        credit_limit=p.credit_limit,
        enforce=p.enforce,
        period_key=p.period_key,
        credits_used=p.credits_used,
        burn_per_day=p.burn_per_day,
        projected_period_end=p.projected_period_end,
        percent_at_period_end=p.percent_at_period_end,
        days_to_exhaustion=p.days_to_exhaustion,
        exhaustion_at=p.exhaustion_at,
        will_breach=p.will_breach,
    )


def _impact_to_response(i: reporting_service.Impact) -> ImpactResponse:
    return ImpactResponse(
        enforced_limits=i.enforced_limits,
        active_restrictions=i.active_restrictions,
        entities_restricted=i.entities_restricted,
        credits_over_budget=i.credits_over_budget,
        warnings_active=i.warnings_active,
        monitor_only_breaches=i.monitor_only_breaches,
    )


@router.get("/summary", response_model=ReportResponse)
def report_summary(ctx: CurrentUser, db: DbSession) -> ReportResponse:
    """The full report: headline totals, impact, and forward projections."""
    report = reporting_service.build_report(db)
    return ReportResponse(
        generated_at=report.generated_at,
        limits_total=report.limits_total,
        limits_enforcing=report.limits_enforcing,
        breaching_soon=report.breaching_soon,
        impact=_impact_to_response(report.impact)
        if report.impact
        else ImpactResponse(
            enforced_limits=0,
            active_restrictions=0,
            entities_restricted=0,
            credits_over_budget=0,
            warnings_active=0,
            monitor_only_breaches=0,
        ),
        projections=[_projection_to_response(p) for p in report.projections],
    )


@router.get("/projection", response_model=list[ProjectionResponse])
def projection(ctx: CurrentUser, db: DbSession) -> list[ProjectionResponse]:
    return [_projection_to_response(p) for p in reporting_service.forward_projection(db)]


@router.get("/chargeback", response_model=ChargebackResponse)
def chargeback(ctx: CurrentUser, db: DbSession) -> ChargebackResponse:
    """Current-period consumption grouped by the business unit on each limit."""
    result = reporting_service.chargeback(db)
    return ChargebackResponse(
        generated_at=result.generated_at,
        unit_cost=result.unit_cost,
        currency_known=result.currency_known,
        unassigned_limits=result.unassigned_limits,
        rows=[
            ChargebackRowResponse(
                business_unit=row.business_unit,
                limits=row.limits,
                credits_used=row.credits_used,
                estimated_cost=row.estimated_cost,
            )
            for row in result.rows
        ],
    )


@router.post("/email", response_model=ReportEmailResult)
def email_report(ctx: AdminUser, db: DbSession) -> ReportEmailResult:
    """Email the current report to the configured recipients, on demand."""
    config = delivery.load_config(db)
    if not config.email_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "email_not_configured",
                "message": "Configure SMTP and recipients on the Settings page first.",
            },
        )
    report = reporting_service.build_report(db)
    try:
        delivery.send_report_email(
            config=config,
            subject="Credit governance report",
            text_body=reporting_service.report_as_text(report),
        )
    except delivery.DeliveryError as exc:
        record_audit(
            db,
            action="report.email_failed",
            actor=ctx.actor,
            target_type="report",
            detail=str(exc),
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "email_failed", "message": f"The report could not be sent: {exc}"},
        ) from exc
    # A distinct action from the scheduled "report.emailed" so sending on demand
    # does not reset the weekly schedule's due clock.
    record_audit(
        db,
        action="report.emailed_ondemand",
        actor=ctx.actor,
        target_type="report",
        detail=f"Report emailed to {len(config.smtp_recipients)} recipient(s) on demand.",
    )
    db.commit()
    return ReportEmailResult(
        sent=True,
        recipients=len(config.smtp_recipients),
        message="Report sent.",
    )
