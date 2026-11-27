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

from app.checkmarx import credits as credits_api
from app.models.enums import EntityType, LimitStatus, UsageView
from app.models.limits import CreditLimit, LimitPeriodState
from app.models.org import CxApplication, CxGroup, CxProject, CxProjectGroup, CxUser
from app.models.usage import (
    CreditBalanceSnapshot,
    UnresolvedSubject,
    UsageRecord,
    UsageSnapshot,
)
from app.services import auto_triage_attribution, ingestion, settings_store
from app.services.periods import PeriodError, current_window, describe_window
from app.services.subject_matching import MatchMethod

logger = logging.getLogger(__name__)

DEFAULT_TOP_N = 10
DEFAULT_TREND_POINTS = 60


@dataclass
class CreditPool:
    """The tenant credit pool next to what the utility's budgets have claimed.

    ``total``/``used``/``available`` come from the last good Checkmarx balance
    snapshot and are ``None`` when the pool has never been read. ``assigned`` is
    the sum of the active budgets; ``over_allocation`` is how far the budgets
    exceed the pool, only when the total is known.
    """

    total: Decimal | None
    used: Decimal | None
    available: Decimal | None
    collected_at: object
    assigned: Decimal
    over_allocation: Decimal | None
    # Granted - Used - Available, when Checkmarx sent all three itself and they
    # do not add up (its own figures; none is derived here). Shown as it is,
    # never filled in or explained away.
    unexplained: Decimal | None = None
    # Other figures /credits/info carries (a reserved amount, say), as given.
    other_figures: dict[str, str] = field(default_factory=dict)


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
    # Users only, while auto-triage credits are charged to scan initiators.
    auto_triage_attributed: Decimal | None = None
    # Users only: automation (Auto Triage, a bot, an integration identity)
    # rather than an unmatched person.
    automation: bool = False


@dataclass
class ActionBreakdown:
    # As Checkmarx reports it ("Fusion Scan - Opus 5.5"), or the normalised
    # type when the breakdown is derived from per-user counts.
    action_type: str
    credits: Decimal
    transactions: int | None = None
    percent_of_total: float | None = None
    # The normalised type ("fusion", "triage"), for a stable colour.
    action_bucket: str | None = None
    # Credits per transaction as the feed reports it (credits / transactions).
    credits_per_transaction: Decimal | None = None
    # The listed rate (GET /api/v1/credits/action-rates), when there is one.
    listed_rate: Decimal | None = None
    # Which figure CreditGuard prices this action at: "rate" or "observed"
    # (see usage_mix.price_table).
    price_source: str | None = None


@dataclass
class UnmatchedEntities:
    """One non-user dimension's rows that matched no synced entity."""

    count: int = 0
    credits: Decimal = Decimal("0")
    total_credits: Decimal = Decimal("0")
    # The largest few, for the explanation: (reported name, credits).
    top: list[tuple[str, Decimal]] = field(default_factory=list)


@dataclass
class AttributionSummary:
    """Usage that counts towards no limit, by why, from the latest readings.

    ``unmatched_people`` is the same number every page shows (see
    ingestion.unresolved_person_filter). Automation and unmatched projects or
    applications are shown next to it so their usage is never silently
    dropped.
    """

    unmatched_people: int = 0
    unmatched_people_credits: Decimal = Decimal("0")
    automation: int = 0
    automation_credits: Decimal = Decimal("0")
    user_total_credits: Decimal = Decimal("0")
    projects: UnmatchedEntities = field(default_factory=UnmatchedEntities)
    applications: UnmatchedEntities = field(default_factory=UnmatchedEntities)
    # The tenant total of the same window (action view, else user view), and
    # how much of it the project view does not account for: usage Checkmarx
    # reported under no project row, or a row the read did not return. Shown,
    # so no project usage vanishes without a trace.
    tenant_total_credits: Decimal | None = None
    projects_unreported: Decimal = Decimal("0")
    # So the counts reconcile with Settings → Attribution: unmatched people
    # waiting under Disputes (the rest are under Unmatched), and automation
    # that is Checkmarx One's own (Auto Triage, Auto Remediation), which that
    # page does not list (the rest are listed under Unmatched, marked).
    unmatched_people_disputed: int = 0
    automation_builtin: int = 0


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


def credit_pool(session: Session) -> CreditPool:
    """The latest tenant credit balance alongside the budgets' total claim."""
    snapshot = session.scalar(
        select(CreditBalanceSnapshot).order_by(
            CreditBalanceSnapshot.collected_at.desc(), CreditBalanceSnapshot.id.desc()
        )
    )
    assigned = session.scalar(
        select(func.coalesce(func.sum(CreditLimit.credit_limit), 0)).where(
            CreditLimit.is_active.is_(True)
        )
    )
    assigned_dec = Decimal(str(assigned or 0))

    total = snapshot.total_credits if snapshot else None
    over = total is not None and assigned_dec > total
    raw = snapshot.raw if snapshot is not None else None
    unexplained = None
    granted, used, available = credits_api.reported_figures(raw)
    if granted is not None and used is not None and available is not None:
        gap = granted - used - available
        if gap != 0:
            unexplained = gap
    return CreditPool(
        total=total,
        used=snapshot.used_credits if snapshot else None,
        available=snapshot.available_credits if snapshot else None,
        collected_at=snapshot.collected_at if snapshot else None,
        assigned=assigned_dec,
        over_allocation=(assigned_dec - total) if over else None,
        unexplained=unexplained,
        other_figures=credits_api.other_figures(raw) if unexplained is not None else {},
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

    from app.checkmarx import usage as usage_api
    from app.services import usage_mix

    prices = usage_mix.price_table(session)
    total = sum((record.credits_used for record in records), Decimal("0"))
    breakdown: list[ActionBreakdown] = []
    for record in records:
        transactions = record.transactions
        if transactions is None and record.actions:
            transactions = sum(record.actions.values())
        name = record.subject_name or record.subject_key
        buckets = {usage_mix.bucket(action) for action in (record.actions or {})}
        price = prices.get(usage_api.action_key(name))
        breakdown.append(
            ActionBreakdown(
                # As Checkmarx reports it, not lowercased.
                action_type=name,
                credits=record.credits_used,
                transactions=transactions,
                percent_of_total=_percent(record.credits_used, total),
                action_bucket=(
                    next(iter(buckets)) if len(buckets) == 1 else usage_mix.bucket(name)
                ),
                credits_per_transaction=(
                    (record.credits_used / transactions).quantize(Decimal("0.01"))
                    if transactions
                    else None
                ),
                listed_rate=price.rate if price is not None else None,
                price_source=price.source if price is not None else None,
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
            .where(UsageSnapshot.view_by == str(view), UsageSnapshot.held_reason.is_(None))
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


def automation_keys(session: Session, keys: list[str]) -> set[str]:
    """Which of these user subject keys are automation rather than a person:
    a synthetic subject (Auto Triage) or a subject classified as a bot or an
    integration identity, and not mapped to a person by an admin."""
    found = {key for key in keys if ingestion.is_synthetic_subject(key)}
    rest = [key for key in keys if key not in found]
    for start in range(0, len(rest), 500):
        chunk = rest[start : start + 500]
        found.update(
            session.scalars(
                select(UnresolvedSubject.subject_key).where(
                    UnresolvedSubject.subject_key.in_(chunk),
                    UnresolvedSubject.is_bot.is_(True),
                    UnresolvedSubject.mapped_user_id.is_(None),
                )
            )
        )
    return found


def top_users(session: Session, *, limit: int = DEFAULT_TOP_N) -> list[Consumer]:
    """The largest consumers, one row per person.

    Every handle that counts towards one user (their email and a mapped
    handle, say) is one row with their credits added up, as their budget
    counts them. Rows that would still read the same (a separate account
    that shares a person's display name) carry the reported handle."""
    records = latest_snapshot_records(session, UsageView.USER)
    total = sum((record.credits_used for record in records), Decimal("0"))
    rows: dict[str, list[UsageRecord]] = {}
    for record in records:
        key = f"user:{record.entity_id}" if record.entity_id else f"subject:{record.subject_key}"
        rows.setdefault(key, []).append(record)
    ranked = sorted(
        rows.values(),
        key=lambda group: -sum((r.credits_used for r in group), Decimal("0")),
    )[:limit]
    automated = automation_keys(
        session, [group[0].subject_key for group in ranked if group[0].entity_id is None]
    )
    consumers: list[Consumer] = []
    handles: list[str] = []
    for group in ranked:
        first = group[0]
        credits = sum((r.credits_used for r in group), Decimal("0"))
        label = first.subject_name or first.subject_key
        handle = first.subject_email or first.subject_key
        if first.entity_id:
            user = session.get(CxUser, first.entity_id)
            if user is not None:
                label = user.display_name
                handle = user.email or user.username or handle
        handles.append(handle)
        consumers.append(
            Consumer(
                entity_type=EntityType.USER,
                entity_id=first.entity_id,
                label=label,
                credits=credits,
                resolved=first.entity_id is not None,
                percent_of_total=_percent(credits, total),
                automation=first.subject_key in automated,
            )
        )
    seen: dict[str, int] = {}
    for consumer in consumers:
        seen[consumer.label.casefold()] = seen.get(consumer.label.casefold(), 0) + 1
    for consumer, handle in zip(consumers, handles, strict=True):
        if seen[consumer.label.casefold()] > 1 and handle.casefold() != consumer.label.casefold():
            consumer.label = f"{consumer.label} ({handle})"
    if settings_store.auto_triage_to_initiator(session):
        model = auto_triage_attribution.build_model(session)
        for consumer in consumers:
            if consumer.entity_id:
                consumer.auto_triage_attributed = model.window_total(consumer.entity_id)
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


def _unmatched_entities(session: Session, view: UsageView) -> UnmatchedEntities:
    found = UnmatchedEntities()
    snapshot = ingestion.latest_snapshot(session, view)
    if snapshot is None:
        return found
    found.total_credits = Decimal(snapshot.total_credits or 0)
    count, credits = session.execute(
        select(func.count(), func.coalesce(func.sum(UsageRecord.credits_used), 0)).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.is_(None)
        )
    ).one()
    found.count = int(count or 0)
    found.credits = Decimal(str(credits or 0))
    top = [
        (record.subject_name or record.subject_key, record.credits_used)
        for record in session.scalars(
            select(UsageRecord)
            .where(UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.is_(None))
            .order_by(UsageRecord.credits_used.desc())
            .limit(5)
        )
    ]
    model = CxProject if view == UsageView.PROJECT else CxApplication
    gone = deleted_names(session, model, [name for name, _credits in top])
    found.top = [
        (f"{name}{DELETED_SUFFIX}" if name.strip().lower() in gone else name, credits)
        for name, credits in top
    ]
    return found


def attribution_summary(session: Session) -> AttributionSummary:
    """What counts towards no limit, and why. Read only, from stored readings."""
    summary = AttributionSummary()
    people = ingestion.unresolved_person_filter()
    count, credits = session.execute(
        select(func.count(), func.coalesce(func.sum(UnresolvedSubject.credits_used), 0)).where(
            *people
        )
    ).one()
    summary.unmatched_people = int(count or 0)
    summary.unmatched_people_credits = Decimal(str(credits or 0))
    summary.unmatched_people_disputed = int(
        session.scalar(
            select(func.count()).where(*people, UnresolvedSubject.status == MatchMethod.DISPUTED)
        )
        or 0
    )

    snapshot = ingestion.latest_snapshot(session, UsageView.USER)
    if snapshot is not None:
        summary.user_total_credits = Decimal(snapshot.total_credits or 0)
        unattributed = list(
            session.execute(
                select(UsageRecord.subject_key, UsageRecord.credits_used).where(
                    UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.is_(None)
                )
            )
        )
        automated = automation_keys(session, [key for key, _credits in unattributed])
        counted: set[str] = set()
        for key, row_credits in unattributed:
            if key in automated:
                summary.automation_credits += Decimal(row_credits or 0)
                counted.add(key)
        # One per distinct subject, however many rows it has.
        summary.automation = len(counted)
        summary.automation_builtin = sum(
            1 for key in counted if ingestion.is_synthetic_subject(key)
        )

    summary.projects = _unmatched_entities(session, UsageView.PROJECT)
    summary.applications = _unmatched_entities(session, UsageView.APPLICATION)
    summary.tenant_total_credits, summary.projects_unreported = _projects_unreported(session)
    return summary


def _projects_unreported(session: Session) -> tuple[Decimal | None, Decimal]:
    """(tenant total, the part of it no project row accounts for).

    Compared only between readings of the same window. The project view can
    fall short of the tenant total: usage Checkmarx files under no project, a
    row with no name (the parser cannot keep it), or a row a read did not
    return. Whatever the cause, the shortfall is shown, never dropped."""
    projects = ingestion.latest_snapshot(session, UsageView.PROJECT)
    tenant = ingestion.latest_snapshot(session, UsageView.ACTION) or ingestion.latest_snapshot(
        session, UsageView.USER
    )
    if tenant is None:
        return None, Decimal("0")
    total = Decimal(tenant.total_credits or 0)
    if projects is None or projects.period_param != tenant.period_param:
        return total, Decimal("0")
    gap = total - Decimal(projects.total_credits or 0)
    return total, gap if gap > 0 else Decimal("0")


def credit_enforcement(session: Session) -> dict[str, object] | None:
    """Checkmarx's own ``enforcement`` block from the last /credits/info read
    (state and thresholds), verbatim and read only; None when it carried none."""
    snapshot = session.scalar(
        select(CreditBalanceSnapshot).order_by(
            CreditBalanceSnapshot.collected_at.desc(), CreditBalanceSnapshot.id.desc()
        )
    )
    raw = getattr(snapshot, "raw", None) if snapshot is not None else None
    block = raw.get("enforcement") if isinstance(raw, dict) else None
    if not isinstance(block, dict):
        return None
    allowed = ("state", "consumptionPct", "warningThresholdPct", "cutoffThresholdPct")
    picked = {
        key: block[key]
        for key in allowed
        if isinstance(block.get(key), str | int | float) and not isinstance(block.get(key), bool)
    }
    return picked or None


def unavailable_dimensions(session: Session) -> list[str]:
    return [
        str(view)
        for view in (UsageView.USER, UsageView.ACTION, UsageView.APPLICATION, UsageView.PROJECT)
        if not ingestion.dimension_supported(session, view)
    ]


DELETED_SUFFIX = " (deleted)"


def deleted_names(session: Session, model, names: list[str]) -> set[str]:
    """Which of these reported names (lowercased) are a deleted project or
    application, and no live one: Checkmarx keeps reporting a deleted
    project's usage under its name, which then matches nothing."""
    wanted = {name.strip().lower() for name in names if name}
    if not wanted:
        return set()
    found: dict[str, bool] = {}
    for name, is_deleted in session.execute(
        select(model.name, model.is_deleted).where(
            func.lower(func.trim(model.name)).in_(sorted(wanted))
        )
    ):
        key = (name or "").strip().lower()
        if key in wanted:
            found[key] = found.get(key, True) and bool(is_deleted)
    return {key for key, gone in found.items() if gone}


def _label_for(session: Session, model, record: UsageRecord) -> str:
    if record.entity_id:
        row = session.get(model, record.entity_id)
        if row is not None:
            return f"{row.name}{DELETED_SUFFIX}" if row.is_deleted else row.name
    name = record.subject_name or record.subject_key
    if deleted_names(session, model, [name]):
        # Usage of a deleted project counts towards no project budget; the
        # label says why it is not matched, as Checkmarx One marks it.
        return f"{name}{DELETED_SUFFIX}"
    return name


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
    from app.services import enforcement

    # Restrictions in force, counted as every other page counts them; a period
    # over its limit without one (held, deferred, an earlier period) is not.
    return warned, len(enforcement.restricted_entities(session))
