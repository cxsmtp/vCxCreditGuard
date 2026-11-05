"""In-app diagnostics: a quick read of whether the utility is healthy.

A handful of read-only checks an admin (or a viewer) can glance at without
leaving the app: is the tenant connection up, is the scheduler running, is the
usage data fresh, is anything stuck. Each check is OK, WARN or FAIL with a short
human-readable detail; the overall status is the worst of them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.connection import CxConnection
from app.models.enums import ConnectionStatus, EnforcementStatus, RunStatus, UsageView
from app.models.limits import EnforcementAction
from app.models.usage import DimensionState, SchedulerRun, UnresolvedSubject, UsageSnapshot
from app.services import settings_store

OK = "ok"
WARN = "warn"
FAIL = "fail"

_RANK = {OK: 0, WARN: 1, FAIL: 2}

# Usage older than this is treated as stale rather than current.
USAGE_STALE_AFTER = timedelta(hours=24)

# Guided-troubleshooting steps, keyed by (check key, status). Attached to each
# non-OK check so the UI can show a concrete "how to fix" alongside the symptom.
_REMEDIATION: dict[tuple[str, str], str] = {
    ("connection", FAIL): (
        "Open Setup and add (or re-enter) your Checkmarx One API key, then use Test "
        "connection. Confirm the tenant URL is right and that this host can reach it."
    ),
    ("connection", WARN): (
        "Open Setup and use Test connection. If it keeps failing, re-enter the API key and "
        "check the tenant URL and outbound network access."
    ),
    ("scheduler", WARN): (
        "Open Settings and enable the scheduler. If it is already enabled but stale, run a "
        "cycle now from Operations and read the run history for why it stopped."
    ),
    ("scheduler", FAIL): (
        "Read the failed run in the run history to find the cause (usually the Checkmarx "
        "connection), fix it, then run a cycle now from Operations."
    ),
    ("usage", WARN): (
        "Run a cycle now from Operations to ingest fresh usage. If it stays empty, confirm "
        "the connection is healthy and that this tenant reports consumption."
    ),
    ("attribution", WARN): (
        "Open Settings and map each unresolved consumer to a user so their usage counts "
        "towards that user's limit."
    ),
    ("enforcement", WARN): (
        "Restore the Checkmarx connection; the next healthy cycle retries the pending "
        "actions. You can also run a cycle now from Operations."
    ),
    ("dimensions", FAIL): (
        "This tenant does not report per-user consumption. Govern with project, application, "
        "or group limits instead, or ask Checkmarx to enable per-user reporting."
    ),
    ("dimensions", WARN): (
        "Set limits only at the dimensions this tenant reports; limits at unreported levels "
        "show usage as unavailable."
    ),
}


def _remediation_for(check: Check) -> str | None:
    if check.status == OK:
        return None
    return _REMEDIATION.get((check.key, check.status))


@dataclass(frozen=True, slots=True)
class Check:
    key: str
    label: str
    status: str
    detail: str
    # Guided-troubleshooting: concrete next steps shown when the check is not OK.
    remediation: str | None = None


@dataclass(slots=True)
class Diagnostics:
    generated_at: datetime
    overall: str
    checks: list[Check]


def run_diagnostics(
    session: Session, *, now: datetime | None = None, include_detail: bool = True
) -> Diagnostics:
    """Run the health checks. ``include_detail`` controls whether raw upstream
    error text (connection/scheduler failures) is included; it is withheld for
    non-admin viewers so an internal error message is not disclosed to them."""
    moment = now or utcnow()
    checks = [
        _connection_check(session, include_detail=include_detail),
        _scheduler_check(session, moment, include_detail=include_detail),
        _usage_check(session, moment),
        _attribution_check(session),
        _pending_enforcement_check(session),
        _dimensions_check(session),
    ]
    checks = [replace(c, remediation=_remediation_for(c)) for c in checks]
    overall = max((c.status for c in checks), key=lambda s: _RANK[s], default=OK)
    return Diagnostics(generated_at=moment, overall=overall, checks=checks)


def _connection_check(session: Session, *, include_detail: bool = True) -> Check:
    connection = session.scalar(select(CxConnection).limit(1))
    if connection is None:
        return Check(
            "connection",
            "Checkmarx connection",
            FAIL,
            "No Checkmarx One connection is configured. Add an API key on the Setup page.",
        )
    if connection.status == ConnectionStatus.HEALTHY:
        return Check("connection", "Checkmarx connection", OK, "Connected and healthy.")
    if connection.status == ConnectionStatus.DEGRADED:
        reason = connection.last_error if include_detail else None
        return Check(
            "connection",
            "Checkmarx connection",
            WARN,
            f"Degraded: {reason or 'intermittent failures'}.",
        )
    if connection.status == ConnectionStatus.FAILED:
        reason = connection.last_error if include_detail else None
        return Check(
            "connection",
            "Checkmarx connection",
            FAIL,
            f"Failing: {reason or 'the last call did not succeed'}.",
        )
    return Check(
        "connection",
        "Checkmarx connection",
        WARN,
        "Configured but not verified yet. Run a cycle or test the connection.",
    )


def _scheduler_check(session: Session, moment: datetime, *, include_detail: bool = True) -> Check:
    config = settings_store.schedule_config(session)
    if not config.enabled:
        return Check(
            "scheduler",
            "Scheduler",
            WARN,
            "The scheduler is disabled, so nothing is evaluated automatically.",
        )
    last_run = session.scalar(
        select(SchedulerRun).order_by(SchedulerRun.started_at.desc()).limit(1)
    )
    if last_run is None:
        return Check("scheduler", "Scheduler", WARN, "Enabled, but no cycle has run yet.")
    if last_run.status == RunStatus.FAILED:
        reason = last_run.error if include_detail else None
        return Check(
            "scheduler",
            "Scheduler",
            FAIL,
            f"The last cycle failed: {reason or 'see the run history for detail'}.",
        )
    last_success = session.scalar(
        select(SchedulerRun.finished_at)
        .where(SchedulerRun.status.in_([RunStatus.SUCCESS, RunStatus.PARTIAL]))
        .order_by(SchedulerRun.started_at.desc())
        .limit(1)
    )
    # Allow a generous few missed intervals before calling the scheduler stale.
    stale_after = timedelta(minutes=max(config.interval_minutes * 3, 60))
    if last_success is None:
        return Check(
            "scheduler", "Scheduler", WARN, "Enabled, but no cycle has finished successfully yet."
        )
    if moment - last_success > stale_after:
        return Check(
            "scheduler",
            "Scheduler",
            WARN,
            f"The last successful cycle was {_ago(moment, last_success)}; it may be stuck.",
        )
    return Check(
        "scheduler",
        "Scheduler",
        OK,
        f"Last successful cycle {_ago(moment, last_success)}.",
    )


def _usage_check(session: Session, moment: datetime) -> Check:
    latest = session.scalar(select(func.max(UsageSnapshot.collected_at)))
    if latest is None:
        return Check(
            "usage", "Usage data", WARN, "No consumption has been ingested from Checkmarx yet."
        )
    if moment - latest > USAGE_STALE_AFTER:
        return Check(
            "usage",
            "Usage data",
            WARN,
            f"The most recent usage reading is {_ago(moment, latest)}; figures may be stale.",
        )
    return Check("usage", "Usage data", OK, f"Last ingested {_ago(moment, latest)}.")


def _attribution_check(session: Session) -> Check:
    count = int(
        session.scalar(
            select(func.count())
            .select_from(UnresolvedSubject)
            .where(UnresolvedSubject.mapped_user_id.is_(None))
        )
        or 0
    )
    if count == 0:
        return Check("attribution", "Usage attribution", OK, "All usage is matched to a user.")
    return Check(
        "attribution",
        "Usage attribution",
        WARN,
        f"{count} consumer(s) could not be matched to a user, so that usage counts "
        "towards no user limit. Resolve them on the Settings page.",
    )


def _pending_enforcement_check(session: Session) -> Check:
    count = int(
        session.scalar(
            select(func.count())
            .select_from(EnforcementAction)
            .where(EnforcementAction.status == EnforcementStatus.PENDING)
        )
        or 0
    )
    if count == 0:
        return Check("enforcement", "Enforcement actions", OK, "No restrictions are stuck pending.")
    return Check(
        "enforcement",
        "Enforcement actions",
        WARN,
        f"{count} enforcement action(s) are pending, usually because the connection was down "
        "when they were due. The next healthy cycle retries them.",
    )


def _dimensions_check(session: Session) -> Check:
    rows = {row.view_by: row.supported for row in session.scalars(select(DimensionState))}
    if not rows:
        return Check(
            "dimensions",
            "Usage dimensions",
            OK,
            "Not probed yet; dimensions are checked on the first cycle.",
        )
    unsupported = sorted(view for view, ok in rows.items() if ok is False)
    if UsageView.USER in unsupported:
        return Check(
            "dimensions",
            "Usage dimensions",
            FAIL,
            "This tenant does not report per-user consumption, so user limits cannot be evaluated.",
        )
    if unsupported:
        return Check(
            "dimensions",
            "Usage dimensions",
            WARN,
            f"Not reported by this tenant: {', '.join(unsupported)}. "
            "Limits at those levels report usage as unavailable.",
        )
    return Check("dimensions", "Usage dimensions", OK, "All probed dimensions are reported.")


def _ago(now: datetime, then: datetime) -> str:
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 90:
        return "just now" if seconds < 45 else "a minute ago"
    minutes = seconds // 60
    if minutes < 90:
        return f"{minutes} minutes ago"
    hours = minutes // 60
    if hours < 36:
        return f"{hours} hours ago"
    return f"{hours // 24} days ago"
