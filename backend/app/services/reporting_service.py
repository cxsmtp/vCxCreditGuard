"""Forward projection, governance impact, and a report that can be exported or
emailed.

All read-only. The projection is a straight-line burn-rate estimate from the
current period's usage; the impact summary quantifies what governance is holding
back right now. The report bundles both with the headline totals so it can be
emailed on a schedule or exported from the GUI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EnforcementStatus, LimitStatus
from app.models.limits import CreditLimit, EnforcementAction, LimitPeriodState
from app.services import enforcement, evaluation
from app.services.periods import PeriodError, current_window

# A day in seconds, as a Decimal, for burn-rate arithmetic.
_DAY = Decimal(86400)


@dataclass(slots=True)
class Projection:
    limit_id: int
    entity_type: str
    entity_id: str
    entity_label: str | None
    credit_limit: int
    enforce: bool
    period_key: str
    credits_used: Decimal
    burn_per_day: Decimal
    projected_period_end: Decimal
    percent_at_period_end: float | None
    days_to_exhaustion: float | None
    exhaustion_at: datetime | None
    will_breach: bool


@dataclass(slots=True)
class Impact:
    enforced_limits: int
    active_restrictions: int
    entities_restricted: int
    credits_over_budget: Decimal
    warnings_active: int
    monitor_only_breaches: int


@dataclass(slots=True)
class Report:
    generated_at: datetime
    limits_total: int
    limits_enforcing: int
    projections: list[Projection] = field(default_factory=list)
    impact: Impact | None = None
    breaching_soon: int = 0


def forward_projection(session: Session, *, now: datetime | None = None) -> list[Projection]:
    """Straight-line projection of where each active limit lands by period end."""
    moment = now or utcnow()
    index = evaluation.UsageIndex(session)
    projections: list[Projection] = []

    limits = list(session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))))
    for limit in limits:
        projection = _project(session, limit=limit, index=index, moment=moment)
        if projection is not None:
            projections.append(projection)

    # Soonest to run out first. Use an explicit sentinel for "no exhaustion" so a
    # value of 0.0 (already over the limit) is not mistaken for infinity by `or`.
    projections.sort(
        key=lambda p: (
            not p.will_breach,
            p.days_to_exhaustion if p.days_to_exhaustion is not None else float("inf"),
        )
    )
    return projections


def _project(
    session: Session, *, limit: CreditLimit, index: evaluation.UsageIndex, moment: datetime
) -> Projection | None:
    try:
        window = current_window(limit, moment)
    except PeriodError:
        return None
    # A projection needs a bounded period and a start that has passed.
    if window.end is None or not window.is_active or moment <= window.start:
        return None

    reported_total, available = index.reported_total(limit)
    if not available:
        return None
    state = session.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == window.key
        )
    )
    baseline = (
        state.baseline_credits
        if state is not None
        else evaluation.baseline_for(
            limit, window=window, reported_total=reported_total, available=available
        )
    )
    credits_used = max(Decimal("0"), reported_total - baseline)
    if credits_used <= 0:
        return None

    elapsed_days = Decimal((moment - window.start).total_seconds()) / _DAY
    total_days = Decimal((window.end - window.start).total_seconds()) / _DAY
    if elapsed_days <= 0:
        return None

    burn_per_day = credits_used / elapsed_days
    projected_end = burn_per_day * total_days
    percent_at_end = (
        float(projected_end) / limit.credit_limit * 100 if limit.credit_limit > 0 else 100.0
    )

    days_to_exhaustion: float | None = None
    exhaustion_at: datetime | None = None
    remaining = Decimal(limit.credit_limit) - credits_used
    if remaining > 0 and burn_per_day > 0:
        days = remaining / burn_per_day
        days_to_exhaustion = float(days)
        exhaustion_at = moment + _timedelta_days(days)
    elif remaining <= 0:
        days_to_exhaustion = 0.0
        exhaustion_at = moment

    will_breach = projected_end >= Decimal(limit.credit_limit)

    return Projection(
        limit_id=limit.id,
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        credit_limit=limit.credit_limit,
        enforce=limit.enforce,
        period_key=window.key,
        credits_used=credits_used,
        burn_per_day=burn_per_day,
        projected_period_end=projected_end,
        percent_at_period_end=percent_at_end,
        days_to_exhaustion=days_to_exhaustion,
        exhaustion_at=exhaustion_at,
        will_breach=will_breach,
    )


def _timedelta_days(days: Decimal):  # type: ignore[no-untyped-def]
    from datetime import timedelta

    # Cap the horizon so an almost-idle entity does not project a date centuries
    # out; a year is plenty for "won't run out any time soon".
    capped = min(days, Decimal(366))
    return timedelta(seconds=float(capped * _DAY))


def impact_summary(session: Session, *, now: datetime | None = None) -> Impact:
    """What governance is holding back right now, from stored state only."""
    index = evaluation.UsageIndex(session)
    enforced_limits = 0
    credits_over_budget = Decimal("0")
    monitor_only_breaches = 0

    limits = list(session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))))
    for limit in limits:
        reported_total, available = index.reported_total(limit)
        if not available:
            continue
        try:
            window = current_window(limit, now or utcnow())
        except PeriodError:
            continue
        state = session.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == window.key
            )
        )
        baseline = (
            state.baseline_credits
            if state is not None
            else evaluation.baseline_for(
                limit, window=window, reported_total=reported_total, available=available
            )
        )
        used = max(Decimal("0"), reported_total - baseline)
        over = max(Decimal("0"), used - Decimal(limit.credit_limit))
        exempt = enforcement.is_exempt(
            session, entity_type=limit.entity_type, entity_id=limit.entity_id
        )
        if limit.enforce and not exempt:
            enforced_limits += 1
            # Only count over-budget that enforcement would actually act on; an
            # exempt entity is never restricted, so it is not "held back". Note
            # overlapping limits (a user and their group/project/application) each
            # contribute their own overage, matching the "every breached limit
            # enforces" model, so this headline can exceed the raw credits at risk.
            credits_over_budget += over
        elif over > 0 and (not limit.enforce or exempt):
            monitor_only_breaches += 1

    active_restrictions = int(
        session.scalar(
            select(func.count())
            .select_from(EnforcementAction)
            .where(EnforcementAction.status == EnforcementStatus.APPLIED)
        )
        or 0
    )
    entities_restricted = int(
        session.scalar(
            select(func.count(func.distinct(EnforcementAction.entity_id))).where(
                EnforcementAction.status == EnforcementStatus.APPLIED
            )
        )
        or 0
    )
    warnings_active = int(
        session.scalar(
            select(func.count())
            .select_from(LimitPeriodState)
            .where(LimitPeriodState.status == LimitStatus.WARNED)
        )
        or 0
    )

    return Impact(
        enforced_limits=enforced_limits,
        active_restrictions=active_restrictions,
        entities_restricted=entities_restricted,
        credits_over_budget=credits_over_budget,
        warnings_active=warnings_active,
        monitor_only_breaches=monitor_only_breaches,
    )


def build_report(session: Session, *, now: datetime | None = None) -> Report:
    moment = now or utcnow()
    projections = forward_projection(session, now=moment)
    impact = impact_summary(session, now=moment)
    limits_total = int(session.scalar(select(func.count()).select_from(CreditLimit)) or 0)
    limits_enforcing = int(
        session.scalar(
            select(func.count()).select_from(CreditLimit).where(CreditLimit.enforce.is_(True))
        )
        or 0
    )
    return Report(
        generated_at=moment,
        limits_total=limits_total,
        limits_enforcing=limits_enforcing,
        projections=projections,
        impact=impact,
        breaching_soon=sum(1 for p in projections if p.will_breach),
    )


def report_as_text(report: Report) -> str:
    """A plain-text rendering for an email body."""
    lines = [
        "CxCreditGuard report",
        f"Generated: {report.generated_at.isoformat()}",
        "",
        f"Limits: {report.limits_total} ({report.limits_enforcing} enforcing)",
        f"Projected to breach this period: {report.breaching_soon}",
    ]
    if report.impact is not None:
        lines += [
            "",
            "Impact right now:",
            f"  Active restrictions: {report.impact.active_restrictions} "
            f"across {report.impact.entities_restricted} entity(ies)",
            f"  Credits over budget on enforced limits: {report.impact.credits_over_budget}",
            f"  Entities warned: {report.impact.warnings_active}",
            f"  Monitor-only limits over budget (not restricted): "
            f"{report.impact.monitor_only_breaches}",
        ]
    if report.projections:
        lines += ["", "Projections (soonest to run out first):"]
        for p in report.projections[:25]:
            when = p.exhaustion_at.date().isoformat() if p.exhaustion_at else "not this period"
            lines.append(
                f"  {p.entity_label or p.entity_id} ({p.entity_type}): "
                f"{p.credits_used} of {p.credit_limit} used, "
                f"~{p.projected_period_end.quantize(Decimal('1'))} by period end, "
                f"exhausts {when}"
            )
    return "\n".join(lines)
