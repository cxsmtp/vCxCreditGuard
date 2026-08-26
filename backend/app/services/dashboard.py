"""Read side aggregation for the dashboard.

Everything here derives from the stored snapshots, never from a live Checkmarx
call, so opening the dashboard cannot rate limit the tenant or slow down while an
API is having a bad day. A dashboard with no snapshot yet reports null rather than
zero, because "we have not polled" and "nobody used any credits" must not look the
same.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import EntityType, LimitStatus, UsageView
from app.models.limits import CreditLimit, LimitPeriodState
from app.models.org import CxApplication, CxGroup, CxProject, CxProjectGroup, CxUser
from app.models.usage import UsageRecord, UsageSnapshot
from app.services import ingestion
from app.services.periods import PeriodError, current_window, describe_window

logger = logging.getLogger(__name__)

DEFAULT_TOP_N = 10
DEFAULT_TREND_POINTS = 60


@dataclass
class Consumer:
    entity_type: str
    entity_id: str | None
    label: str
    credits: Decimal
    resolved: bool = True
    limit: int | None = None
    limit_id: int | None = None
    credits_used_in_period: Decimal | None = None
    status: str | None = None
    percent_of_total: float | None = None


@dataclass
class ActionBreakdown:
    action_type: str
    credits: Decimal
    transactions: int | None = None
    percent_of_total: float | None = None


@dataclass
class Trend:
    points: list[tuple] = field(default_factory=list)


def latest_snapshot_records(session: Session, view: UsageView) -> list[UsageRecord]:
    snapshot = ingestion.latest_snapshot(session, view)
    if snapshot is None:
        return []
    return list(
        session.scalars(
            select(UsageRecord)
            .where(UsageRecord.snapshot_id == snapshot.id)
            .order_by(UsageRecord.credits_used.desc())
        )
    )


def tenant_total(session: Session) -> tuple[Decimal | None, object]:
    """Tenant wide credits from the action dimension, which is the closest thing
    the API offers to an authoritative total."""
    snapshot = ingestion.latest_snapshot(session, UsageView.ACTION)
    if snapshot is None:
        # Fall back to the user dimension when the action view has not been polled.
        snapshot = ingestion.latest_snapshot(session, UsageView.USER)
    if snapshot is None:
        return None, None
    return snapshot.total_credits, snapshot.collected_at


def action_breakdown(session: Session) -> list[ActionBreakdown]:
    records = latest_snapshot_records(session, UsageView.ACTION)
    if not records:
        # Derive it from the per user action counts if the action view is absent.
        return _breakdown_from_user_actions(session)

    total = sum((record.credits_used for record in records), Decimal("0"))
    breakdown: list[ActionBreakdown] = []
    for record in records:
        transactions = record.transactions
        if transactions is None and record.actions:
            transactions = sum(record.actions.values())
        breakdown.append(
            ActionBreakdown(
                action_type=record.subject_key,
                credits=record.credits_used,
                transactions=transactions,
                percent_of_total=_percent(record.credits_used, total),
            )
        )
    return breakdown


def _breakdown_from_user_actions(session: Session) -> list[ActionBreakdown]:
    """Transaction counts per action type, summed across users.

    Credits cannot be split across a user's action types, because the feed reports
    one credit figure per user rather than per action. Those rows carry a null
    credits figure so the GUI shows transactions and does not invent a split.
    """
    records = latest_snapshot_records(session, UsageView.USER)
    counts: dict[str, int] = {}
    for record in records:
        for action, count in (record.actions or {}).items():
            counts[action] = counts.get(action, 0) + count
    return [
        ActionBreakdown(action_type=action, credits=Decimal("0"), transactions=count)
        for action, count in sorted(counts.items(), key=lambda item: -item[1])
    ]


def trend(session: Session, *, points: int = DEFAULT_TREND_POINTS) -> list[tuple]:
    """Cumulative totals per poll, with the delta between consecutive polls.

    The cumulative figure is what Checkmarx reports for its lookback window, so the
    delta is the interesting series: it is credits actually consumed between polls.
    """
    view = UsageView.ACTION
    if ingestion.latest_snapshot(session, view) is None:
        view = UsageView.USER
    rows = list(
        session.scalars(
            select(UsageSnapshot)
            .where(UsageSnapshot.view_by == str(view))
            .order_by(UsageSnapshot.collected_at.desc())
            .limit(points)
        )
    )
    rows.reverse()

    result: list[tuple] = []
    previous: Decimal | None = None
    for row in rows:
        delta = None if previous is None else max(Decimal("0"), row.total_credits - previous)
        result.append((row.collected_at, row.total_credits, delta))
        previous = row.total_credits
    return result


def top_users(session: Session, *, limit: int = DEFAULT_TOP_N) -> list[Consumer]:
    records = latest_snapshot_records(session, UsageView.USER)
    total = sum((record.credits_used for record in records), Decimal("0"))
    consumers: list[Consumer] = []
    for record in records[:limit]:
        label = record.subject_name or record.subject_key
        if record.entity_id:
            user = session.get(CxUser, record.entity_id)
            if user is not None:
                label = user.display_name
        consumers.append(
            Consumer(
                entity_type=EntityType.USER,
                entity_id=record.entity_id,
                label=label,
                credits=record.credits_used,
                resolved=record.entity_id is not None,
                percent_of_total=_percent(record.credits_used, total),
            )
        )
    return _attach_limits(session, consumers)


def top_projects(session: Session, *, limit: int = DEFAULT_TOP_N) -> list[Consumer]:
    records = latest_snapshot_records(session, UsageView.PROJECT)
    total = sum((record.credits_used for record in records), Decimal("0"))
    consumers = [
        Consumer(
            entity_type=EntityType.PROJECT,
            entity_id=record.entity_id,
            label=_label_for(session, CxProject, record),
            credits=record.credits_used,
            resolved=record.entity_id is not None,
            percent_of_total=_percent(record.credits_used, total),
        )
        for record in records[:limit]
    ]
    return _attach_limits(session, consumers)


def top_applications(session: Session, *, limit: int = DEFAULT_TOP_N) -> list[Consumer]:
    records = latest_snapshot_records(session, UsageView.APPLICATION)
    total = sum((record.credits_used for record in records), Decimal("0"))
    consumers = [
        Consumer(
            entity_type=EntityType.APPLICATION,
            entity_id=record.entity_id,
            label=_label_for(session, CxApplication, record),
            credits=record.credits_used,
            resolved=record.entity_id is not None,
            percent_of_total=_percent(record.credits_used, total),
        )
        for record in records[:limit]
    ]
    return _attach_limits(session, consumers)


def top_groups(session: Session, *, limit: int = DEFAULT_TOP_N) -> list[Consumer]:
    """Groups have no API dimension, so they are rolled up from project usage."""
    project_totals = ingestion.latest_totals(session, UsageView.PROJECT)
    if not project_totals:
        return []

    per_group: dict[str, Decimal] = {}
    for row in session.scalars(select(CxProjectGroup)):
        credits = project_totals.get(row.project_id)
        if credits is None:
            continue
        per_group[row.group_id] = per_group.get(row.group_id, Decimal("0")) + credits

    total = sum(per_group.values(), Decimal("0"))
    ordered = sorted(per_group.items(), key=lambda item: -item[1])[:limit]
    consumers: list[Consumer] = []
    for group_id, credits in ordered:
        group = session.get(CxGroup, group_id)
        consumers.append(
            Consumer(
                entity_type=EntityType.GROUP,
                entity_id=group_id,
                label=group.name if group else group_id,
                credits=credits,
                percent_of_total=_percent(credits, total),
            )
        )
    return _attach_limits(session, consumers)


def unavailable_dimensions(session: Session) -> list[str]:
    return [
        str(view)
        for view in (UsageView.USER, UsageView.ACTION, UsageView.APPLICATION, UsageView.PROJECT)
        if not ingestion.dimension_supported(session, view)
    ]


def _label_for(session: Session, model, record: UsageRecord) -> str:
    if record.entity_id:
        row = session.get(model, record.entity_id)
        if row is not None:
            return row.name
    return record.subject_name or record.subject_key


def _percent(value: Decimal, total: Decimal) -> float | None:
    if total <= 0:
        return None
    return round(float(value) / float(total) * 100, 2)


def _attach_limits(session: Session, consumers: list[Consumer]) -> list[Consumer]:
    """Annotate each consumer with its configured limit and current period status."""
    ids = [consumer.entity_id for consumer in consumers if consumer.entity_id]
    if not ids:
        return consumers

    limits = {
        (row.entity_type, row.entity_id): row
        for row in session.scalars(select(CreditLimit).where(CreditLimit.entity_id.in_(ids)))
    }
    for consumer in consumers:
        limit = limits.get((consumer.entity_type, consumer.entity_id))
        if limit is None:
            continue
        consumer.limit = limit.credit_limit
        consumer.limit_id = limit.id
        try:
            window = current_window(limit)
        except PeriodError:
            continue
        state = session.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id,
                LimitPeriodState.period_key == window.key,
            )
        )
        if state is not None:
            consumer.credits_used_in_period = state.credits_used
            consumer.status = state.status
    return consumers


def period_label(session: Session) -> str:
    """The period most limits use, for the dashboard heading.

    Limits can each have their own period, so this reports the most common one
    rather than pretending there is a single tenant wide budget period.
    """
    row = session.execute(
        select(CreditLimit.period_type, func.count())
        .where(CreditLimit.is_active.is_(True))
        .group_by(CreditLimit.period_type)
        .order_by(func.count().desc())
        .limit(1)
    ).first()
    if row is None:
        return "current month"
    period_type = row[0]
    sample = session.scalar(
        select(CreditLimit).where(
            CreditLimit.is_active.is_(True), CreditLimit.period_type == period_type
        )
    )
    if sample is None:
        return "current month"
    try:
        return describe_window(current_window(sample))
    except PeriodError:
        return "current month"


def warning_and_restriction_counts(session: Session) -> tuple[int, int]:
    warned = int(
        session.scalar(
            select(func.count())
            .select_from(LimitPeriodState)
            .where(LimitPeriodState.status == LimitStatus.WARNED)
        )
        or 0
    )
    breached = int(
        session.scalar(
            select(func.count())
            .select_from(LimitPeriodState)
            .where(LimitPeriodState.status.in_([LimitStatus.BREACHED, LimitStatus.RESTRICTED]))
        )
        or 0
    )
    return warned, breached
