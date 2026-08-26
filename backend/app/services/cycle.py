"""One governance cycle: sync, ingest, evaluate, enforce, record.

Resilience rules, all of which exist because this loop runs unattended every few
minutes against a remote API:

* **Non overlapping.** A database advisory lock, not just an in-process guard, so a
  container replaced mid cycle cannot double up with its successor. A lock whose
  heartbeat has gone quiet is reclaimed.
* **Per step isolation.** A failure in one step is recorded and the cycle
  continues into the steps that do not depend on it. The run ends as ``partial``
  rather than crashing the scheduler thread.
* **No enforcement on stale data.** If usage ingestion fails, evaluation still
  runs but only to refresh warnings from the last good snapshot; it cannot
  manufacture a breach from data it did not get. Usage that is unavailable is
  never treated as zero.
"""

from __future__ import annotations

import logging
import os
import socket
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError, NotConfiguredError
from app.db.base import utcnow
from app.db.session import session_scope
from app.models.enums import RunStatus, Severity
from app.models.usage import SchedulerLock, SchedulerRun
from app.services import connection as connection_service
from app.services import (
    delivery,
    evaluation,
    ingestion,
    notifications,
    org_sync,
    retention,
    settings_store,
)
from app.services.audit import AuditActor

logger = logging.getLogger(__name__)

LOCK_NAME = "cycle"
# A lock older than this is assumed to belong to a process that died.
LOCK_STALE_AFTER = timedelta(minutes=30)


@dataclass
class CycleResult:
    run_id: int | None = None
    status: str = RunStatus.SUCCESS
    steps: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    skipped_reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == RunStatus.SUCCESS


def holder_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


# ----------------------------------------------------------------------- locking


def acquire_lock(session: Session, *, name: str = LOCK_NAME, holder: str | None = None) -> bool:
    """Take the advisory lock, reclaiming it if the previous holder went quiet."""
    now = utcnow()
    who = holder or holder_id()
    try:
        session.execute(insert(SchedulerLock).values(name=name))
        session.commit()
    except IntegrityError:
        session.rollback()

    stale_before = now - LOCK_STALE_AFTER
    result = session.execute(
        update(SchedulerLock)
        .where(
            SchedulerLock.name == name,
            (SchedulerLock.holder.is_(None))
            | (SchedulerLock.heartbeat_at.is_(None))
            | (SchedulerLock.heartbeat_at < stale_before),
        )
        .values(holder=who, acquired_at=now, heartbeat_at=now)
    )
    session.commit()
    acquired = bool(result.rowcount)
    if not acquired:
        current = session.get(SchedulerLock, name)
        logger.info(
            "Skipping cycle: the lock is held by %s since %s",
            current.holder if current else "unknown",
            current.acquired_at if current else "unknown",
        )
    return acquired


def heartbeat(session: Session, *, name: str = LOCK_NAME, holder: str | None = None) -> None:
    session.execute(
        update(SchedulerLock)
        .where(SchedulerLock.name == name, SchedulerLock.holder == (holder or holder_id()))
        .values(heartbeat_at=utcnow())
    )
    session.commit()


def release_lock(session: Session, *, name: str = LOCK_NAME, holder: str | None = None) -> None:
    session.execute(
        update(SchedulerLock)
        .where(SchedulerLock.name == name, SchedulerLock.holder == (holder or holder_id()))
        .values(holder=None, acquired_at=None, heartbeat_at=None)
    )
    session.commit()


# ------------------------------------------------------------------- the cycle


def run_cycle(*, trigger: str = "schedule", force_org_sync: bool = False) -> CycleResult:
    """Run one full cycle. Never raises: every outcome is recorded on the run row."""
    holder = holder_id()
    result = CycleResult()

    with session_scope() as session:
        if not acquire_lock(session, holder=holder):
            result.status = RunStatus.SKIPPED
            result.skipped_reason = "a previous cycle is still running"
            run = SchedulerRun(
                kind="cycle",
                trigger=trigger,
                started_at=utcnow(),
                finished_at=utcnow(),
                status=RunStatus.SKIPPED,
                stats={"reason": result.skipped_reason},
            )
            session.add(run)
            session.flush()
            result.run_id = run.id
            return result

    try:
        with session_scope() as session:
            run = SchedulerRun(
                kind="cycle", trigger=trigger, started_at=utcnow(), status=RunStatus.RUNNING
            )
            session.add(run)
            session.flush()
            run_id = run.id
        result.run_id = run_id

        with session_scope() as session:
            _execute_steps(session, result, force_org_sync=force_org_sync)

        with session_scope() as session:
            run = session.get(SchedulerRun, run_id)
            if run is not None:
                run.finished_at = utcnow()
                run.status = result.status
                run.stats = result.steps
                run.error = "; ".join(result.errors)[:4000] if result.errors else None
    except Exception as exc:  # noqa: BLE001 - the scheduler thread must survive anything
        logger.exception("Cycle failed unexpectedly")
        result.status = RunStatus.FAILED
        result.errors.append(str(exc))
        with session_scope() as session:
            if result.run_id is not None:
                run = session.get(SchedulerRun, result.run_id)
                if run is not None:
                    run.finished_at = utcnow()
                    run.status = RunStatus.FAILED
                    run.error = str(exc)[:4000]
                    run.stats = result.steps
    finally:
        with session_scope() as session:
            release_lock(session, holder=holder)

    return result


def _execute_steps(session: Session, result: CycleResult, *, force_org_sync: bool) -> None:
    actor = AuditActor.system("scheduler")

    try:
        client: CheckmarxClient | None = connection_service.get_client(session)
    except NotConfiguredError as exc:
        result.status = RunStatus.SKIPPED
        result.skipped_reason = str(exc)
        result.steps["connection"] = {"ok": False, "reason": str(exc)}
        return

    # Step 1: organisation model, only when due.
    if force_org_sync or _org_sync_due(session):
        try:
            org_result = org_sync.sync_org_model(session, client, actor=actor)
            result.steps["org_sync"] = org_result.as_stats()
            if org_result.warnings:
                _warn(session, "org_sync", "; ".join(org_result.warnings))
                result.status = RunStatus.PARTIAL
        except CheckmarxError as exc:
            result.errors.append(f"org_sync: {exc}")
            result.status = RunStatus.PARTIAL
            result.steps["org_sync"] = {"ok": False, "error": str(exc)}
            _warn(session, "org_sync", str(exc))
    else:
        result.steps["org_sync"] = {"skipped": "not due"}

    # Step 2: usage ingestion.
    usage_ok = True
    try:
        ingest_result = ingestion.ingest_usage(
            session,
            client,
            period_param=settings_store.usage_period(session),
            page_size=settings_store.usage_page_size(session),
        )
        result.steps["ingest"] = ingest_result.as_stats()
        for warning in ingest_result.warnings:
            _warn(session, "ingest", warning)
        if ingest_result.warnings:
            result.status = RunStatus.PARTIAL
        _notify_unresolved(session)
    except CheckmarxError as exc:
        usage_ok = False
        result.errors.append(f"ingest: {exc}")
        result.status = RunStatus.PARTIAL
        result.steps["ingest"] = {"ok": False, "error": str(exc)}
        _warn(session, "ingest", str(exc))

    # Step 3: evaluation and enforcement. Runs even when ingestion failed, using
    # the last good snapshot, but a failed ingestion means no new breach can be
    # discovered from data we did not receive.
    try:
        evaluation_result = evaluation.evaluate_all(session, client=client, actor=actor)
        result.steps["evaluate"] = evaluation_result.as_stats()
        result.steps["evaluate"]["used_stale_usage"] = not usage_ok
        if evaluation_result.errors:
            result.status = RunStatus.PARTIAL
            result.errors.extend(evaluation_result.errors)
    except Exception as exc:  # noqa: BLE001 - never let evaluation kill the cycle
        logger.exception("Evaluation failed")
        result.errors.append(f"evaluate: {exc}")
        result.status = RunStatus.PARTIAL
        result.steps["evaluate"] = {"ok": False, "error": str(exc)}
        _warn(session, "evaluate", str(exc))

    # Step 4: push notifications out. A delivery failure is never allowed to affect
    # the cycle's own status: the Notification Center already has the record, and an
    # unreachable SMTP server is not a governance failure.
    try:
        delivery_result = delivery.deliver_pending(session)
        result.steps["deliver"] = delivery_result.as_stats()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Notification delivery failed")
        result.steps["deliver"] = {"ok": False, "error": str(exc)}

    # Step 5: retention, at most once a day.
    try:
        if _retention_due(session):
            retention_result = retention.prune(
                session,
                retention_days=int(
                    settings_store.get_value(session, settings_store.KEY_RETENTION_DAYS) or 365
                ),
                actor=actor,
            )
            result.steps["retention"] = retention_result.as_stats()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Retention pruning failed")
        result.steps["retention"] = {"ok": False, "error": str(exc)}


def _org_sync_due(session: Session) -> bool:
    config = settings_store.schedule_config(session)
    cutoff = utcnow() - timedelta(minutes=config.org_refresh_minutes)
    last = session.scalar(
        select(SchedulerRun.started_at)
        .where(
            SchedulerRun.kind == "cycle",
            SchedulerRun.status.in_([RunStatus.SUCCESS, RunStatus.PARTIAL]),
        )
        .order_by(SchedulerRun.started_at.desc())
        .limit(1)
    )
    if last is None:
        return True
    # Any successful run refreshed the org model at most org_refresh_minutes ago
    # only if that run actually performed the sync, so use the last sync audit.
    from app.models.audit import AuditLogEntry

    last_sync = session.scalar(
        select(AuditLogEntry.occurred_at)
        .where(AuditLogEntry.action == "org.synced")
        .order_by(AuditLogEntry.occurred_at.desc())
        .limit(1)
    )
    return last_sync is None or last_sync < cutoff


def _retention_due(session: Session) -> bool:
    """Once every 24 hours, judged by the last prune's own audit entry."""
    from app.models.audit import AuditLogEntry

    last = session.scalar(
        select(AuditLogEntry.occurred_at)
        .where(AuditLogEntry.action == "retention.pruned")
        .order_by(AuditLogEntry.occurred_at.desc())
        .limit(1)
    )
    return last is None or last < utcnow() - timedelta(hours=24)


def _warn(session: Session, step: str, message: str) -> None:
    notifications.notify(
        session,
        category=notifications.CATEGORY_SYNC_ERROR,
        severity=Severity.ERROR,
        title=f"Cycle step {step} reported a problem",
        body=message,
        dedupe_key=notifications.sync_error_key(step, utcnow().strftime("%Y-%m-%d")),
    )


def _notify_unresolved(session: Session) -> None:
    """Tell the admin about consumption that could not be attributed to a user."""
    from app.models.usage import UnresolvedSubject

    rows = list(
        session.scalars(select(UnresolvedSubject).where(UnresolvedSubject.mapped_user_id.is_(None)))
    )
    for row in rows:
        notifications.notify(
            session,
            category=notifications.CATEGORY_ATTRIBUTION,
            severity=Severity.WARNING,
            title=(
                "Credit usage could not be matched to a user: "
                f"{row.subject_name or row.subject_key}"
            ),
            body=(
                f"{row.credits_used} credits are reported against "
                f"{row.subject_name or row.subject_key}"
                f"{f' ({row.subject_email})' if row.subject_email else ''}, which does not "
                "match any synced Checkmarx user. That usage is not counted towards any "
                "user limit. Map it to a user, or check that the user's IAM email matches "
                "the address their AI actions are reported under."
            ),
            dedupe_key=notifications.attribution_key(row.subject_key),
        )
