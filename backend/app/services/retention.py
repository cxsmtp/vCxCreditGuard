"""Data retention.

The audit log is append only at the application layer, and this module is the one
documented exception: pruning is the only code anywhere that deletes audit rows, it
only ever removes rows older than the configured window, and **the prune itself is
audited**, so the log always explains its own gaps.

Enforcement records are deliberately excluded from pruning while they are still
applied. An undo snapshot has to outlive any retention window, because losing it
would leave a restriction that can no longer be reversed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import AuditLogEntry, Notification
from app.models.auth import LoginAttempt
from app.models.enums import EnforcementStatus
from app.models.limits import EnforcementAction, LimitPeriodState
from app.models.usage import SchedulerRun, UsageRecord, UsageSnapshot
from app.services import auth as auth_service
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

# Never prune below this, whatever the setting says. A governance tool with a
# week of history cannot answer the question it exists to answer.
MINIMUM_RETENTION_DAYS = 7
# Always keep at least this many usage snapshots per dimension, so the trend chart
# and the period baselines survive a short retention window.
KEEP_RECENT_SNAPSHOTS = 200


@dataclass
class RetentionResult:
    usage_snapshots: int = 0
    usage_records: int = 0
    notifications: int = 0
    audit_entries: int = 0
    scheduler_runs: int = 0
    sessions: int = 0
    login_attempts: int = 0
    enforcement_actions: int = 0
    skipped: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            self.usage_snapshots
            + self.notifications
            + self.audit_entries
            + self.scheduler_runs
            + self.sessions
            + self.login_attempts
            + self.enforcement_actions
        )

    def as_stats(self) -> dict[str, object]:
        return {
            "usage_snapshots": self.usage_snapshots,
            "usage_records": self.usage_records,
            "notifications": self.notifications,
            "audit_entries": self.audit_entries,
            "scheduler_runs": self.scheduler_runs,
            "sessions": self.sessions,
            "login_attempts": self.login_attempts,
            "enforcement_actions": self.enforcement_actions,
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
    cutoff = utcnow() - timedelta(days=effective_days)

    result.usage_snapshots, result.usage_records = _prune_snapshots(session, cutoff)
    result.notifications = _prune_notifications(session, cutoff)
    result.scheduler_runs = _delete_where(session, SchedulerRun, SchedulerRun.started_at < cutoff)
    result.enforcement_actions = _prune_enforcement(session, cutoff)
    result.sessions = auth_service.purge_expired_sessions(session)
    # Rate limit counters are only meaningful for a minute, but the rows never
    # expired on their own, so every distinct username and IP pair seen at the login
    # form accumulated forever. That is an unbounded table fed by unauthenticated
    # input, which is worth closing.
    result.login_attempts = _prune_login_attempts(session)
    _prune_period_states(session, cutoff)

    # Audited last, and only if something was removed, so the entry can state the
    # counts. This is the single place that deletes audit rows.
    result.audit_entries = _prune_audit(session, cutoff)
    if result.total:
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
    session.flush()
    return result


def _prune_snapshots(session: Session, cutoff) -> tuple[int, int]:
    """Drop old snapshots, but always keep a recent tail per dimension.

    Cascades to their records through the relationship, so no orphan rows are left.
    """
    keep_ids: set[int] = set()
    for view in session.scalars(select(UsageSnapshot.view_by).distinct()):
        recent = session.scalars(
            select(UsageSnapshot.id)
            .where(UsageSnapshot.view_by == view)
            .order_by(UsageSnapshot.collected_at.desc())
            .limit(KEEP_RECENT_SNAPSHOTS)
        )
        keep_ids.update(recent)

    doomed = list(
        session.scalars(
            select(UsageSnapshot.id).where(
                UsageSnapshot.collected_at < cutoff,
                UsageSnapshot.id.notin_(keep_ids) if keep_ids else True,
            )
        )
    )
    if not doomed:
        return 0, 0

    record_count = int(
        session.scalar(
            select(func.count()).select_from(UsageRecord).where(UsageRecord.snapshot_id.in_(doomed))
        )
        or 0
    )
    session.execute(delete(UsageRecord).where(UsageRecord.snapshot_id.in_(doomed)))
    session.execute(delete(UsageSnapshot).where(UsageSnapshot.id.in_(doomed)))
    return len(doomed), record_count


def _prune_notifications(session: Session, cutoff) -> int:
    """Old notifications go, except ones attached to a live restriction.

    A restriction that is still in force must keep the notification that carries its
    Restore access button, however old it is.
    """
    live_action_ids = set(
        session.scalars(
            select(EnforcementAction.id).where(
                EnforcementAction.status == EnforcementStatus.APPLIED
            )
        )
    )
    condition = Notification.created_at < cutoff
    if live_action_ids:
        condition = condition & (
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


def _prune_period_states(session: Session, cutoff) -> int:
    """Closed period states older than the window. The current period is kept by
    virtue of its period_start being recent."""
    return _delete_where(
        session,
        LimitPeriodState,
        (LimitPeriodState.period_end.is_not(None)) & (LimitPeriodState.period_end < cutoff),
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
    return _delete_where(session, AuditLogEntry, AuditLogEntry.occurred_at < cutoff)


def _delete_where(session: Session, model, condition) -> int:  # type: ignore[no-untyped-def]
    result = session.execute(delete(model).where(condition))
    return int(result.rowcount or 0)
