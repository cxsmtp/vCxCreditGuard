"""Data retention.

The audit log is append only at the application layer, and this module is the one
documented exception: pruning is the only code anywhere that deletes audit rows, it
only ever removes rows older than the configured window, and **the prune itself is
audited**, so the log always explains its own gaps.

Enforcement records are deliberately excluded from pruning while they are still
applied. An undo snapshot has to outlive any retention window, because losing it
would leave a restriction that can no longer be reversed.

Usage snapshots are the bulk of the database (one row per entity per dimension
per cycle), so besides the window two things keep them in check:

* **Raw rows** (``usage_record.raw``, the row as the feed sent it) are cleared
  once a week old. Every reader of them needs only recent ones: the latest
  snapshot (auto-triage readings, a project's identities), the readings an
  open budget period's usage breakdown starts from (Fusion models), and rows
  that matched no entity (their reported id). Those keep theirs.
* **Thinning** (``retention.thin_snapshots``, on by default): whole snapshots,
  never single rows, are thinned to every one of the last 3 days, one an hour
  per dimension up to 40 days, and one a day after that. The tiers are a
  resolution choice for the trend and for someone reading the history, not
  what correctness rests on: every snapshot a calculation refers to is pinned
  exactly (``pinned_snapshots``) and never removed, whatever its age. Batched,
  a transaction per batch, so no long lock; idempotent; summarised in the
  prune's audit entry.
"""

from __future__ import annotations

import bisect
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, func, null, select, update
from sqlalchemy.orm import Session

from app.checkmarx import usage as usage_api
from app.db.base import utcnow
from app.models.audit import AuditLogEntry, Notification
from app.models.auth import LoginAttempt
from app.models.enums import EnforcementStatus, UsageView
from app.models.limits import EnforcementAction, LimitPeriodState
from app.models.usage import (
    AutoTriageCharge,
    CreditBalanceSnapshot,
    SchedulerRun,
    UsageRecord,
    UsageSnapshot,
)
from app.models.violations import INFO_KINDS, STATUS_RESOLVED, PolicyViolation
from app.services import audit_chain, pacing, settings_store
from app.services import auth as auth_service
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

# Never prune below this, whatever the setting says. A governance tool with a
# week of history cannot answer the question it exists to answer.
MINIMUM_RETENTION_DAYS = 7
# Always keep at least this many usage snapshots per dimension, so the trend chart
# and the period baselines survive a short retention window.
KEEP_RECENT_SNAPSHOTS = 200

# Raw consumption rows are kept this long (except where a reader needs them).
RAW_KEEP_DAYS = 7
# Thinning: every snapshot younger than this ...
THIN_KEEP_ALL_DAYS = 3
# ... one an hour per dimension up to this age, one a day beyond it. A choice
# of resolution for the trend and the history, not of correctness: every
# snapshot something reads is pinned (pinned_snapshots), whatever its age.
THIN_HOURLY_DAYS = 40
# Ids per IN list in a statement: far below PostgreSQL's 65,535 parameters.
ID_BATCH = 1000
# Snapshots per transaction when deleting or clearing, and at most this many
# per run (a large backlog after an upgrade is worked through over several
# daily runs, and a run also stops when the cycle's time budget is spent).
THIN_BATCH = 100
RAW_BATCH = 50
MAX_SNAPSHOTS_PER_RUN = 20_000


@dataclass
class RetentionResult:
    usage_snapshots: int = 0
    usage_records: int = 0
    notifications: int = 0
    audit_entries: int = 0
    scheduler_runs: int = 0
    credit_balances: int = 0
    sessions: int = 0
    login_attempts: int = 0
    enforcement_actions: int = 0
    auto_triage_charges: int = 0
    policy_violations: int = 0
    ledger_rows: int = 0
    # Thinning and raw rows (see the module docstring).
    thinning: bool = True
    thinned_snapshots: int = 0
    thinned_records: int = 0
    pinned_snapshots: int = 0
    raw_cleared_records: int = 0
    raw_cleared_snapshots: int = 0
    baselines_recorded: int = 0
    skipped: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            self.usage_snapshots
            + self.notifications
            + self.audit_entries
            + self.scheduler_runs
            + self.credit_balances
            + self.sessions
            + self.login_attempts
            + self.enforcement_actions
            + self.auto_triage_charges
            + self.policy_violations
            + self.thinned_snapshots
            + self.ledger_rows
        )

    def as_stats(self) -> dict[str, object]:
        return {
            "usage_snapshots": self.usage_snapshots,
            "usage_records": self.usage_records,
            "ledger_rows": self.ledger_rows,
            "notifications": self.notifications,
            "audit_entries": self.audit_entries,
            "scheduler_runs": self.scheduler_runs,
            "credit_balances": self.credit_balances,
            "sessions": self.sessions,
            "login_attempts": self.login_attempts,
            "enforcement_actions": self.enforcement_actions,
            "auto_triage_charges": self.auto_triage_charges,
            "policy_violations": self.policy_violations,
            "thinning": self.thinning,
            "thinned_snapshots": self.thinned_snapshots,
            "thinned_records": self.thinned_records,
            "pinned_snapshots": self.pinned_snapshots,
            "raw_cleared_records": self.raw_cleared_records,
            "raw_cleared_snapshots": self.raw_cleared_snapshots,
            "baselines_recorded": self.baselines_recorded,
            "skipped": self.skipped,
        }


def prune(
    session: Session, *, retention_days: int, actor: AuditActor | None = None
) -> RetentionResult:
    """Delete data older than the retention window. Returns what was removed."""
    result = RetentionResult()
    effective_days = max(retention_days, MINIMUM_RETENTION_DAYS)
    if effective_days != retention_days:
        result.skipped.append(
            f"retention of {retention_days} days raised to the {MINIMUM_RETENTION_DAYS} day minimum"
        )
    now = utcnow()
    cutoff = now - timedelta(days=effective_days)

    # Restrictions applied before baselines were pinned get theirs first, so
    # nothing below can remove the reading they are measured from.
    result.baselines_recorded = record_missing_baselines(session)
    keep, keep_raw = pinned_snapshots(session, now)
    result.pinned_snapshots = len(keep)
    result.usage_snapshots, result.usage_records = _prune_snapshots(session, cutoff, keep)
    result.thinning = settings_store.thin_snapshots(session)
    if result.thinning:
        _thin_snapshots(session, now, keep, result)
    _clear_old_raw(session, now, keep_raw, result)
    result.notifications = _prune_notifications(session, cutoff)
    result.scheduler_runs = _delete_where(session, SchedulerRun, SchedulerRun.started_at < cutoff)
    result.credit_balances = _prune_credit_balances(session, cutoff)
    result.enforcement_actions = _prune_enforcement(session, cutoff)
    result.sessions = auth_service.purge_expired_sessions(session)
    # Rate limit counters are only meaningful for a minute, but the rows never
    # expired on their own, so every distinct username and IP pair seen at the login
    # form accumulated forever. That is an unbounded table fed by unauthenticated
    # input, which is worth closing.
    result.login_attempts = _prune_login_attempts(session)
    _prune_period_states(session, cutoff)
    result.auto_triage_charges = _prune_auto_triage_charges(session, cutoff)
    result.policy_violations = _prune_policy_violations(session, cutoff)
    result.ledger_rows = _prune_ledger(session, cutoff)

    # Audited last, and only if something was removed, so the entry can state the
    # counts. This is the single place that deletes audit rows.
    result.audit_entries = _prune_audit(session, cutoff)
    if result.total or result.raw_cleared_records:
        record_audit(
            session,
            action="retention.pruned",
            actor=actor or AuditActor.system("retention"),
            target_type="retention",
            after=result.as_stats(),
            detail=(
                f"Removed data older than {effective_days} days. "
                f"{result.audit_entries} audit entries were included in the prune."
            ),
        )
    # Pruning the oldest audit rows leaves the earliest survivor pointing at a
    # hash no row carries any more. Record that boundary so the hash-chain
    # verifier can tell a legitimate prune from a deletion.
    if result.audit_entries:
        audit_chain.record_prune_checkpoint(session)
    session.flush()
    return result


def _prune_credit_balances(session: Session, cutoff) -> int:
    """Drop credit balance snapshots older than the window, but always keep the
    most recent one so the last known good pool balance survives any window."""
    latest_id = session.scalar(
        select(CreditBalanceSnapshot.id).order_by(
            CreditBalanceSnapshot.collected_at.desc(), CreditBalanceSnapshot.id.desc()
        )
    )
    condition = CreditBalanceSnapshot.collected_at < cutoff
    if latest_id is not None:
        condition = condition & (CreditBalanceSnapshot.id != latest_id)
    return _delete_where(session, CreditBalanceSnapshot, condition)


def _prune_snapshots(session: Session, cutoff, pinned: set[int] | None = None) -> tuple[int, int]:
    """Drop old snapshots, but always keep a recent tail per dimension, and
    every snapshot something refers to (``pinned``).

    The set to delete is worked out here, not in a ``NOT IN`` list (which on
    PostgreSQL fails beyond 65,535 ids), and deleted in batches, records
    first, a transaction each, so no orphan rows are left and no lock is long.
    """
    keep_ids: set[int] = set(pinned or ())
    for view in session.scalars(select(UsageSnapshot.view_by).distinct()):
        recent = session.scalars(
            select(UsageSnapshot.id)
            .where(UsageSnapshot.view_by == view)
            .order_by(UsageSnapshot.collected_at.desc())
            .limit(KEEP_RECENT_SNAPSHOTS)
        )
        keep_ids.update(recent)
        # The newest *believed* snapshot is what limits are judged on. It is kept
        # even if a long run of held reads has pushed it out of the recent tail.
        believed = session.scalar(
            select(UsageSnapshot.id)
            .where(UsageSnapshot.view_by == view, UsageSnapshot.held_reason.is_(None))
            .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
            .limit(1)
        )
        if believed is not None:
            keep_ids.add(believed)

    doomed = [
        snapshot_id
        for snapshot_id in session.scalars(
            select(UsageSnapshot.id)
            .where(UsageSnapshot.collected_at < cutoff)
            .order_by(UsageSnapshot.id)
        )
        if snapshot_id not in keep_ids
    ]
    return _delete_snapshots(session, doomed)


def _delete_snapshots(session: Session, doomed: list[int]) -> tuple[int, int]:
    """Delete these snapshots and their records in batches. (snapshots, records)."""
    snapshots = records = 0
    session.commit()
    for start in range(0, len(doomed), ID_BATCH):
        chunk = doomed[start : start + ID_BATCH]
        deleted = session.execute(delete(UsageRecord).where(UsageRecord.snapshot_id.in_(chunk)))
        session.execute(delete(UsageSnapshot).where(UsageSnapshot.id.in_(chunk)))
        session.commit()  # one short transaction per batch
        snapshots += len(chunk)
        records += int(deleted.rowcount or 0)
    return snapshots, records


# ------------------------------------------------------------ snapshot thinning


def _believed(view: str):  # type: ignore[no-untyped-def]
    """Believed, non-demo snapshots of one dimension (what readers see live)."""
    return (
        select(UsageSnapshot.collected_at, UsageSnapshot.id)
        .where(
            UsageSnapshot.view_by == view,
            UsageSnapshot.held_reason.is_(None),
            UsageSnapshot.period_param.is_distinct_from(settings_store.DEMO_PERIOD_PARAM),
        )
        .order_by(UsageSnapshot.collected_at, UsageSnapshot.id)
    )


def _timeline(session: Session, view: str) -> list[tuple[datetime, int]]:
    return [(row.collected_at, row.id) for row in session.execute(_believed(view))]


def _at(timeline: list[tuple[datetime, int]], moment: datetime) -> int | None:
    """The newest snapshot taken at or before ``moment`` (usage_mix._snapshot_at)."""
    position = bisect.bisect_right(timeline, (moment, math.inf))
    return timeline[position - 1][1] if position else None


def record_missing_baselines(session: Session) -> int:
    """Pin the baseline of restrictions applied before it was recorded.

    The newest believed snapshot at or before ``applied_at``, of the view their
    usage is read from: exactly what was used before, now kept by id.
    """
    from app.services import enforcement

    rows = session.execute(
        select(
            EnforcementAction.id, EnforcementAction.target_type, EnforcementAction.applied_at
        ).where(
            EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
            EnforcementAction.applied_at.is_not(None),
            EnforcementAction.baseline_snapshot_id.is_(None),
        )
    ).all()
    if not rows:
        return 0
    timelines = {
        view: _timeline(session, view) for view in (UsageView.USER.value, UsageView.PROJECT.value)
    }
    changes = []
    for row in rows:
        view = (
            UsageView.USER.value
            if row.target_type == enforcement.TARGET_USER
            else UsageView.PROJECT.value
        )
        snapshot_id = _at(timelines[view], row.applied_at)
        if snapshot_id is not None:
            changes.append({"id": row.id, "baseline_snapshot_id": snapshot_id})
    for start in range(0, len(changes), 1000):
        session.execute(update(EnforcementAction), changes[start : start + 1000])
    session.commit()
    return len(changes)


def pinned_snapshots(session: Session, now: datetime) -> tuple[set[int], set[int]]:
    """Snapshots nothing may remove, and those whose raw rows are kept too.

    Kept whole, with their raw rows:

    * the latest believed snapshot of each dimension and lookback window
      (what limits are judged on, what the next read is compared with);
    * the reading each open budget period's usage breakdown starts from
      (``usage_mix``: newest at or before the period's baseline, every
      dimension), which reads the Fusion models from the raw rows;
    * the baseline of every restriction that is, or may be, in force (the
      rise in usage since it is measured from it: policy violations).

    Not pinned: the snapshot an auto-triage charge was observed on
    (``AutoTriageCharge.snapshot_id``) and a project's auto-triage cursor
    (``AutoTriageProjectState.last_snapshot_id``). Both are plain integers,
    not foreign keys: the first is only written, the second only compared with
    the latest snapshot's id; neither is ever loaded. Pinning them kept nearly
    every project snapshot for the whole lookback window while attribution
    was on, and a stuck cursor for ever. The charge rows themselves are kept
    (their own retention: ``_prune_auto_triage_charges``).

    Both sets are the same today; kept apart so a pin that needs the snapshot
    but not its raw rows can be added without touching the raw clearing.
    """
    from app.services import enforcement

    keep_raw: set[int] = set()
    for view, param in session.execute(
        select(UsageSnapshot.view_by, UsageSnapshot.period_param)
        .where(UsageSnapshot.held_reason.is_(None))
        .distinct()
    ):
        latest = session.scalar(
            select(UsageSnapshot.id)
            .where(
                UsageSnapshot.view_by == view,
                UsageSnapshot.period_param == param,
                UsageSnapshot.held_reason.is_(None),
            )
            .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
            .limit(1)
        )
        if latest is not None:
            keep_raw.add(latest)

    open_after = now - timedelta(days=1)
    moments = {
        state.baseline_at or state.period_start
        for state in session.scalars(select(LimitPeriodState))
        if state.period_end is None
        or state.period_end >= open_after
        or state.status in ("restricted", "breached")
    }
    if moments:
        for view in session.scalars(select(UsageSnapshot.view_by).distinct()):
            timeline = _timeline(session, view)
            keep_raw.update(
                snapshot_id
                for snapshot_id in (_at(timeline, moment) for moment in moments)
                if snapshot_id is not None
            )
    keep_raw.update(
        session.scalars(
            select(EnforcementAction.baseline_snapshot_id)
            .where(
                EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
                EnforcementAction.baseline_snapshot_id.is_not(None),
            )
            .distinct()
        )
    )
    keep_raw.discard(None)  # type: ignore[arg-type]
    return set(keep_raw), keep_raw


def _thin_snapshots(
    session: Session, now: datetime, keep: set[int], result: RetentionResult
) -> None:
    """Thin believed snapshots older than 3 days to one per hour, then per day.

    Per dimension and lookback window. In a period (hour or day) holding a
    pinned snapshot, the pinned ones stay and the rest go; otherwise the
    newest stays. Held snapshots (no records, the evidence of a refused read)
    and demo snapshots are never thinned.
    """
    keep_all_after = now - timedelta(days=THIN_KEEP_ALL_DAYS)
    hourly_after = now - timedelta(days=THIN_HOURLY_DAYS)
    rows = session.execute(
        select(
            UsageSnapshot.id,
            UsageSnapshot.view_by,
            UsageSnapshot.period_param,
            UsageSnapshot.collected_at,
        )
        .where(
            UsageSnapshot.held_reason.is_(None),
            UsageSnapshot.period_param.is_distinct_from(settings_store.DEMO_PERIOD_PARAM),
            UsageSnapshot.collected_at < keep_all_after,
        )
        .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
    ).all()

    def bucket(row) -> tuple[str, str, datetime]:  # type: ignore[no-untyped-def]
        moment = row.collected_at
        span = (
            moment.replace(minute=0, second=0, microsecond=0)
            if moment >= hourly_after
            else moment.replace(hour=0, minute=0, second=0, microsecond=0)
        )
        return (row.view_by, row.period_param, span)

    with_pin = {bucket(row) for row in rows if row.id in keep}
    kept: set[tuple[str, str, datetime]] = set()
    doomed: list[int] = []
    for row in rows:  # newest first
        key = bucket(row)
        if row.id in keep:
            continue
        if key in with_pin or key in kept:
            doomed.append(row.id)
        else:
            kept.add(key)
    if len(doomed) > MAX_SNAPSHOTS_PER_RUN:
        result.skipped.append(
            f"{len(doomed) - MAX_SNAPSHOTS_PER_RUN:,} snapshots left to thin by the next run"
        )
    doomed = sorted(doomed)[:MAX_SNAPSHOTS_PER_RUN]  # the oldest first
    session.commit()
    for start in range(0, len(doomed), THIN_BATCH):
        chunk = doomed[start : start + THIN_BATCH]
        records = session.execute(delete(UsageRecord).where(UsageRecord.snapshot_id.in_(chunk)))
        session.execute(delete(UsageSnapshot).where(UsageSnapshot.id.in_(chunk)))
        session.commit()  # one short transaction per batch
        result.thinned_snapshots += len(chunk)
        result.thinned_records += int(records.rowcount or 0)
        if pacing.out_of_time():
            result.skipped.append(
                "thinning stopped at the cycle's time budget; the next run goes on"
            )
            break


def _clear_raw_of(session: Session, ids: list[int], result: RetentionResult) -> None:
    """Clear the raw rows of these snapshots (rows that matched nothing keep theirs)."""
    for start in range(0, len(ids), RAW_BATCH):
        chunk = ids[start : start + RAW_BATCH]
        cleared = session.execute(
            update(UsageRecord)
            .where(
                UsageRecord.snapshot_id.in_(chunk),
                UsageRecord.raw.is_not(None),
                UsageRecord.entity_id.is_not(None),
            )
            .values(raw=null())
        )
        session.execute(
            update(UsageSnapshot)
            .where(UsageSnapshot.id.in_(chunk), UsageSnapshot.raw.is_not(None))
            .values(raw=null())
        )
        result.raw_cleared_records += int(cleared.rowcount or 0)
        result.raw_cleared_snapshots += len(chunk)


def _clear_old_raw(
    session: Session, now: datetime, keep_raw: set[int], result: RetentionResult
) -> None:
    """Clear the raw rows of snapshots more than a week old (see the module docstring).

    Rows that matched no entity keep theirs (auto-triage attribution reads the
    reported id of such earlier rows); so do the pinned snapshots. A cursor
    (the collection time cleared up to) makes each run start where the last
    stopped, so rows already cleared are never scanned again. A snapshot the
    cursor passes while it is pinned is remembered, and cleared by the first
    run after its pin is released (a period ended, a restriction lifted).
    """
    until = now - timedelta(days=RAW_KEEP_DAYS)
    stored = settings_store.get_value(session, settings_store.KEY_RETENTION_RAW_CLEARED_UNTIL)
    if isinstance(stored, str):  # the first form: the timestamp alone
        stored = {"until": stored}
    stored = stored if isinstance(stored, dict) else {}
    try:
        since = datetime.fromisoformat(stored["until"]) if stored.get("until") else None
    except (TypeError, ValueError):
        since = None
    passed_pinned = {int(i) for i in stored.get("pinned") or [] if isinstance(i, int)}

    # Pins released since: clear those now (the ones deleted meanwhile drop out).
    released = sorted(passed_pinned - keep_raw)
    if released:
        existing = [
            snapshot_id
            for start in range(0, len(released), ID_BATCH)
            for snapshot_id in session.scalars(
                select(UsageSnapshot.id).where(
                    UsageSnapshot.id.in_(released[start : start + ID_BATCH])
                )
            )
        ]
        _clear_raw_of(session, existing, result)
        passed_pinned -= set(released)

    def save(cursor: datetime | None) -> None:
        settings_store.set_value(
            session,
            settings_store.KEY_RETENTION_RAW_CLEARED_UNTIL,
            {
                "until": cursor.isoformat() if cursor is not None else None,
                "pinned": sorted(passed_pinned),
            },
        )
        session.commit()  # one short transaction per batch

    query = select(UsageSnapshot.id, UsageSnapshot.collected_at).where(
        UsageSnapshot.collected_at < until, UsageSnapshot.held_reason.is_(None)
    )
    if since is not None:
        query = query.where(UsageSnapshot.collected_at >= since)
    rows = session.execute(
        query.order_by(UsageSnapshot.collected_at, UsageSnapshot.id).limit(MAX_SNAPSHOTS_PER_RUN)
    ).all()
    session.commit()
    if not rows:
        save(since)
        return
    for start in range(0, len(rows), RAW_BATCH):
        chunk = rows[start : start + RAW_BATCH]
        _clear_raw_of(session, [row.id for row in chunk if row.id not in keep_raw], result)
        passed_pinned.update(row.id for row in chunk if row.id in keep_raw)
        save(chunk[-1].collected_at)
        if pacing.out_of_time():
            result.skipped.append("raw rows: stopped at the cycle's time budget")
            break


def _prune_notifications(session: Session, cutoff) -> int:
    """Old notifications go, except ones attached to a live restriction.

    A restriction that is still in force must keep the notification that carries its
    Restore access button, however old it is.
    """
    # A subquery, not a list of ids: no parameter limit, however many are live.
    live_action_ids = select(EnforcementAction.id).where(
        EnforcementAction.status == EnforcementStatus.APPLIED
    )
    condition = (Notification.created_at < cutoff) & (
        Notification.enforcement_action_id.is_(None)
        | Notification.enforcement_action_id.notin_(live_action_ids)
    )
    return _delete_where(session, Notification, condition)


def _prune_enforcement(session: Session, cutoff) -> int:
    """Only reversed or failed actions are pruned. Applied ones are never touched.

    Their undo snapshot is the only record of how to give access back.
    """
    return _delete_where(
        session,
        EnforcementAction,
        (EnforcementAction.created_at < cutoff)
        & EnforcementAction.status.in_([EnforcementStatus.REVERSED, EnforcementStatus.FAILED]),
    )


def _prune_policy_violations(session: Session, cutoff) -> int:
    """Policy violations older than the window, like reversed actions.

    An open or acknowledged violation is still an admin's to-do and is kept,
    however old, just as an applied restriction is. A resolved one goes once
    both its last finding and its resolution are older than the window. The
    information rows (the AI-scan daily count, scans not checked: nothing to
    act on) go once they are older than the window, whatever their status,
    like notifications.
    """
    old = func.coalesce(PolicyViolation.updated_at, PolicyViolation.detected_at) < cutoff
    resolved = (PolicyViolation.status == STATUS_RESOLVED) & (PolicyViolation.resolved_at < cutoff)
    return _delete_where(
        session,
        PolicyViolation,
        old & (resolved | PolicyViolation.kind.in_(INFO_KINDS)),
    )


def _prune_period_states(session: Session, cutoff) -> int:
    """Closed period states older than the window, and their ledger counters.
    The current period is kept by virtue of its period_start being recent."""
    from sqlalchemy import tuple_

    from app.models.usage import BudgetUsage

    old = (LimitPeriodState.period_end.is_not(None)) & (LimitPeriodState.period_end < cutoff)
    _delete_where(
        session,
        BudgetUsage,
        tuple_(BudgetUsage.limit_id, BudgetUsage.period_key).in_(
            select(LimitPeriodState.limit_id, LimitPeriodState.period_key).where(old)
        ),
    )
    deleted = _delete_where(session, LimitPeriodState, old)
    _prune_counters(session, cutoff)
    return deleted


def _prune_counters(session: Session, cutoff) -> int:  # type: ignore[no-untyped-def]
    """Month and quarter counters whose period ended before the window, also
    those of periods that never had a state (every budget is fed per month and
    per quarter, whatever its type)."""
    from app.models.usage import BudgetUsage

    stale: list[int] = []
    for row_id, key in session.execute(select(BudgetUsage.id, BudgetUsage.period_key)):
        end = _period_end(key)
        if end is not None and end < cutoff:
            stale.append(row_id)
    for start in range(0, len(stale), 1000):
        _delete_where(session, BudgetUsage, BudgetUsage.id.in_(stale[start : start + 1000]))
    return len(stale)


def _period_end(key: str):  # type: ignore[no-untyped-def]
    """When a "YYYY-MM" or "YYYY-Qn" period ends; None for any other key."""
    from datetime import UTC, datetime

    try:
        year, rest = key.split("-", 1)
        # The month after the period's last month.
        month = int(rest[1:]) * 3 + 1 if rest.startswith("Q") else int(rest) + 1
        year_number = int(year) + (month - 1) // 12
        return datetime(year_number, (month - 1) % 12 + 1, 1, tzinfo=UTC)
    except (ValueError, IndexError):
        return None


def _prune_auto_triage_charges(session: Session, cutoff) -> int:
    """Auto-triage charges older than the window *and* the consumption window.

    A charge still inside the lookback window the usage figures are read with
    is part of someone's current figure, so it is kept even when the retention
    setting is shorter: dropping it would quietly move those credits from the
    person back to the project. A day of margin covers the window sliding
    between cycles.
    """
    lookback = usage_api.PERIOD_DAYS.get(settings_store.usage_period(session), 365)
    floor = utcnow() - timedelta(days=lookback + 1)
    return _delete_where(
        session,
        AutoTriageCharge,
        (AutoTriageCharge.window_end < cutoff) & (AutoTriageCharge.window_end < floor),
    )


def _prune_login_attempts(session: Session) -> int:
    """Drop rate limit counters whose window closed long ago.

    Kept for a day rather than a minute so that an operator investigating a
    password guessing attempt can still see it in the table, then discarded.
    """
    return _delete_where(
        session, LoginAttempt, LoginAttempt.last_attempt_at < utcnow() - timedelta(days=1)
    )


def _prune_audit(session: Session, cutoff) -> int:
    # Delete a contiguous prefix by id, not simply ``occurred_at < cutoff``. The
    # hash chain and its single checkpoint assume the removed rows are the oldest
    # ones in a continuous block; were a row's timestamp ever backdated so its id
    # order and time order disagreed, a bare time filter could leave a gap and
    # make the verifier flag a legitimate prune as tampering. Everything up to the
    # newest row older than the cutoff goes, which keeps the chain a clean prefix.
    boundary_id = session.scalar(
        select(func.max(AuditLogEntry.id)).where(AuditLogEntry.occurred_at < cutoff)
    )
    if boundary_id is None:
        return 0
    return _delete_where(session, AuditLogEntry, AuditLogEntry.id <= boundary_id)


def _prune_ledger(session: Session, cutoff) -> int:  # type: ignore[no-untyped-def]
    """Ledger increases older than the retention window. Budget counters do
    not depend on them; an increase of an entity under a restriction still in
    force is kept, since usage after the restriction is measured from them."""
    from app.models.usage import UsageDelta

    restricted = select(EnforcementAction.target_id).where(
        EnforcementAction.status == EnforcementStatus.APPLIED
    )
    return _delete_where(
        session,
        UsageDelta,
        (UsageDelta.observed_at < cutoff)
        & (UsageDelta.entity_id.is_(None) | UsageDelta.entity_id.not_in(restricted)),
    )


def _delete_where(session: Session, model, condition) -> int:  # type: ignore[no-untyped-def]
    result = session.execute(delete(model).where(condition))
    return int(result.rowcount or 0)
