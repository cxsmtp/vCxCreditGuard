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

from app.checkmarx import credits as credits_api
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError, NotConfiguredError
from app.db.base import utcnow
from app.db.session import session_scope
from app.models.enums import RunStatus, Severity
from app.models.usage import CreditBalanceSnapshot, SchedulerLock, SchedulerRun
from app.services import connection as connection_service
from app.services import (
    delivery,
    evaluation,
    ingestion,
    notifications,
    org_sync,
    requests_service,
    retention,
    settings_store,
)
from app.services.audit import AuditActor, record_audit

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

    # Demo mode: touch no live tenant - no sync, ingestion or enforcement. Still
    # evaluate the seeded data with no client (so demo limits get period state and
    # warnings without any Checkmarx write), and still deliver notifications and
    # prune, so demo mode can run indefinitely without undelivered mail or
    # unbounded run history.
    if settings_store.demo_mode(session):
        result.steps["demo"] = {"active": True}
        try:
            result.steps["evaluate"] = evaluation.evaluate_all(
                session, client=None, actor=actor
            ).as_stats()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Demo evaluation failed")
            result.steps["evaluate"] = {"ok": False, "error": str(exc)}
        try:
            result.steps["deliver"] = delivery.deliver_pending(session).as_stats()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Notification delivery failed")
            result.steps["deliver"] = {"ok": False, "error": str(exc)}
        try:
            if _retention_due(session):
                result.steps["retention"] = retention.prune(
                    session,
                    retention_days=int(
                        settings_store.get_value(session, settings_store.KEY_RETENTION_DAYS) or 365
                    ),
                    actor=actor,
                ).as_stats()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Retention pruning failed")
            result.steps["retention"] = {"ok": False, "error": str(exc)}
        return

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

    # Step 2b: tenant credit pool. Best-effort and never fatal - an unreachable
    # pool is unknown, so we keep the last good snapshot and record no zero. A new
    # row is written only when the balance actually changed, so a steady-state
    # tenant does not accumulate identical rows between retention prunes.
    try:
        balance = credits_api.fetch_credit_balance(client)
        if balance is not None and balance.has_values():
            latest = session.scalar(
                select(CreditBalanceSnapshot).order_by(
                    CreditBalanceSnapshot.collected_at.desc(), CreditBalanceSnapshot.id.desc()
                )
            )
            unchanged = latest is not None and (
                latest.total_credits == balance.total
                and latest.used_credits == balance.used
                and latest.available_credits == balance.available
            )
            if not unchanged:
                session.add(
                    CreditBalanceSnapshot(
                        collected_at=utcnow(),
                        total_credits=balance.total,
                        used_credits=balance.used,
                        available_credits=balance.available,
                        raw=balance.raw,
                    )
                )
            result.steps["credits"] = {
                "ok": True,
                "changed": not unchanged,
                "total": str(balance.total) if balance.total is not None else None,
                "available": str(balance.available) if balance.available is not None else None,
            }
        else:
            result.steps["credits"] = {"ok": False, "reason": "unavailable"}
    except Exception as exc:  # noqa: BLE001 - the pool read must not fail the cycle
        logger.info("Credit balance step skipped: %s", exc)
        result.steps["credits"] = {"ok": False, "error": str(exc)}

    # Step 2c: roll back temporary credit grants whose expiry has passed, before
    # evaluation so a re-tightened budget is judged against this cycle's usage. The
    # client is passed so that removing an enforced grant also lifts any
    # restriction it caused. Never fatal: a failure here must not stop enforcement.
    try:
        reverted = requests_service.revert_expired_grants(session, client=client)
        result.steps["grant_expiry"] = {"ok": True, "reverted": reverted}
    except Exception as exc:  # noqa: BLE001 - grant rollback must not fail the cycle
        logger.exception("Expired grant rollback failed")
        result.errors.append(f"grant_expiry: {exc}")
        result.status = RunStatus.PARTIAL
        result.steps["grant_expiry"] = {"ok": False, "error": str(exc)}
        _warn(session, "grant_expiry", str(exc))

    # Step 2d: expire time-boxed overrides before evaluation, so an entity whose
    # override has lapsed is enforced again this cycle. Never fatal.
    try:
        from app.services import limits_service

        expired = limits_service.expire_overrides(session)
        result.steps["override_expiry"] = {"ok": True, "expired": expired}
    except Exception as exc:  # noqa: BLE001 - override expiry must not fail the cycle
        logger.exception("Override expiry failed")
        result.errors.append(f"override_expiry: {exc}")
        result.status = RunStatus.PARTIAL
        result.steps["override_expiry"] = {"ok": False, "error": str(exc)}
        _warn(session, "override_expiry", str(exc))

    # Step 2e: hands-off automation. Auto-approve pending credit requests within
    # the configured cap before evaluation, so a granted budget is reflected in
    # this cycle (lifting a restriction straight away via the client). Never fatal.
    try:
        auto = requests_service.auto_decide_pending(session, client=client, actor=actor)
        result.steps["automation"] = auto
    except Exception as exc:  # noqa: BLE001 - automation must not fail the cycle
        logger.exception("Hands-off automation failed")
        result.errors.append(f"automation: {exc}")
        result.status = RunStatus.PARTIAL
        result.steps["automation"] = {"ok": False, "error": str(exc)}
        _warn(session, "automation", str(exc))

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

    # Step 6: weekly report email, when enabled and due. Never fatal: a mail
    # failure is an operational issue, not a governance one, and is recorded.
    try:
        if settings_store.report_email_enabled(session) and _report_email_due(session):
            sent = _send_weekly_report(session)
            result.steps["report_email"] = (
                {"ok": True, "sent": True}
                if sent
                else {"ok": True, "sent": False, "skipped": "smtp not configured"}
            )
        else:
            result.steps["report_email"] = {"skipped": "disabled or not due"}
    except Exception as exc:  # noqa: BLE001 - a mail failure must not fail the cycle
        logger.exception("Weekly report email failed")
        result.steps["report_email"] = {"ok": False, "error": str(exc)}


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


def _report_email_due(session: Session) -> bool:
    """At most once every ~7 days, judged by the last report email attempt.

    Both a successful send and a skip (SMTP not configured) count, so a report
    that is enabled but cannot be sent is attempted once a week, not every cycle.
    """
    from app.models.audit import AuditLogEntry

    last = session.scalar(
        select(AuditLogEntry.occurred_at)
        .where(AuditLogEntry.action.in_(["report.emailed", "report.email_skipped"]))
        .order_by(AuditLogEntry.occurred_at.desc())
        .limit(1)
    )
    return last is None or last < utcnow() - timedelta(days=7)


def _send_weekly_report(session: Session) -> bool:
    """Send the weekly report. Returns True if it was emailed, False if skipped
    because SMTP is not configured."""
    from app.services import delivery, reporting_service

    config = delivery.load_config(session)
    if not config.email_enabled:
        # Enabled in settings but SMTP not configured: record it so the admin sees
        # why no report arrived, and do not retry until the next due window.
        record_audit(
            session,
            action="report.email_skipped",
            actor=AuditActor.system("reporter"),
            target_type="report",
            detail="Weekly report is enabled but SMTP is not configured.",
        )
        return False
    report = reporting_service.build_report(session)
    delivery.send_report_email(
        config=config,
        subject="Weekly credit governance report",
        text_body=reporting_service.report_as_text(report),
    )
    record_audit(
        session,
        action="report.emailed",
        actor=AuditActor.system("reporter"),
        target_type="report",
        detail=f"Weekly report emailed to {len(config.smtp_recipients)} recipient(s).",
    )
    return True


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
