"""In-app diagnostics: a quick read of whether the utility is healthy.

A handful of read-only checks an admin (or a viewer) can glance at without
leaving the app: is the tenant connection up, is the scheduler running, is the
usage data fresh, is anything stuck. Each check is OK, WARN or FAIL with a short
human-readable detail; the overall status is the worst of them.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.connection import CxConnection
from app.models.enums import ConnectionStatus, EnforcementStatus, RunStatus, UsageView
from app.models.limits import EnforcementAction
from app.models.usage import (
    AutoTriageProjectState,
    DimensionState,
    SchedulerRun,
    UsageSnapshot,
)
from app.services import credits_text, settings_store

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
    ("unmatched_entities", WARN): (
        "Open Settings → Attribution and map each repository name to the project (or "
        "application) it belongs to. A name that is no project at all (an SCM repository "
        "scanned outside a project) can be left: it is counted tenant wide."
    ),
    ("enforcement_coverage", WARN): (
        "Open Simulation (or Settings → Enforcement) to see who a user restriction cannot "
        "reach and why. Consider restricting through dedicated AI roles, keeping AI roles "
        "out of broad composite roles and groups, and relying on project, group and "
        "application limits, which turn AI features off on projects."
    ),
    ("group_names", WARN): (
        "Rename the groups in Checkmarx One so each name is unique, or set group limits only "
        "on groups whose name is unique."
    ),
    ("auto_triage_attribution", WARN): (
        "Map each scan initiator listed as unmatched under Settings → Attribution to the person it "
        "acts for, so their share of auto-triage credits counts. If scans could not be read, "
        "check the connection; those credits stay estimated until a later cycle reads them."
    ),
    ("activity_source", WARN): (
        "Check that the API key may read the credit activity log and that the tenant is "
        "reachable. A mismatch with the consumption summary that persists is worth raising "
        "with Checkmarx. To restrict monthly and quarterly budgets from summary totals "
        "anyway (less accurate), choose Usage source: Summary only and allow restrictions "
        "from summary totals under Settings → Schedule & data."
    ),
    ("enforcement", WARN): (
        "Restore the Checkmarx connection; the next healthy cycle retries the pending "
        "actions. You can also run a cycle now from Operations."
    ),
    ("enforcement_selftest", WARN): (
        "Open Settings → Enforcement and read the last self-test's steps and diff: it shows "
        "which step failed and what was found. Fix that (permissions, a setting the tenant "
        "does not keep) and run it again on the same target."
    ),
    ("enforcement_selftest", FAIL): (
        "A self-test could not give its target back. The restriction is tracked: the next "
        "cycle retries the restore, and Restore in the Notification Center does it now. "
        "If it keeps failing, put it back in Checkmarx One by hand from the snapshot shown "
        "on Settings → Enforcement."
    ),
    ("recount", WARN): (
        "A new restriction of a monthly or quarterly budget starts only when a direct recount "
        "of the Checkmarx activity log is also at or over the limit. Compare the budget's "
        "usage with the activity log; if the recount could not be done, check that the API "
        "key can read the log and that the activity page cap is high enough. The next cycle "
        "recounts again."
    ),
    ("readiness", WARN): (
        "Open Settings → Enforcement: the Readiness card says what each item that is not "
        "green needs and links to where to fix it."
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
        _unmatched_entities_check(session),
        _pending_enforcement_check(session),
        _dimensions_check(session),
    ]
    group_names = _group_names_check(session)
    if group_names is not None:
        checks.append(group_names)
    doubted = _doubted_falls_check(session)
    if doubted is not None:
        checks.append(doubted)
    coverage_check = _coverage_check(session)
    if coverage_check is not None:
        checks.append(coverage_check)
    selftest_check = _selftest_check(session, moment)
    if selftest_check is not None:
        checks.append(selftest_check)
    activity = _activity_check(session, moment)
    if activity is not None:
        checks.append(activity)
    checks.append(_recount_check(session, moment))
    checks.append(_readiness_check(session, moment))
    checks.append(_fast_check_check(session, moment))
    webhook = _cx_webhook_check(session, moment)
    if webhook is not None:
        checks.append(webhook)
    if settings_store.auto_triage_to_initiator(session):
        # Only while charging auto triage to scan initiators is on, so the
        # report is unchanged for everyone who has not turned it on.
        checks.append(_auto_triage_check(session))
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
    # A held read is one that was not believed, so it does not count as ingestion.
    latest = session.scalar(
        select(func.max(UsageSnapshot.collected_at)).where(UsageSnapshot.held_reason.is_(None))
    )
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
    from app.services import dashboard as dashboard_service

    summary = dashboard_service.attribution_summary(session)
    count = summary.unmatched_people
    automation = ""
    if summary.automation:
        automation = (
            f" {summary.automation} automation identit{'y' if summary.automation == 1 else 'ies'}"
            f" (Auto Triage, bots, integrations without an email) used "
            f"{_credits(summary.automation_credits)} credits; that usage is shown as "
            "automation and counts towards no user limit."
        )
    if count == 0:
        return Check(
            "attribution",
            "Usage attribution",
            OK,
            f"Every person's usage is matched to a user.{automation}",
        )
    return Check(
        "attribution",
        "Usage attribution",
        WARN,
        f"{count} consumer(s) could not be matched to a user, so that usage counts "
        f"towards no user limit. Resolve them under Settings → Attribution.{automation}",
    )


def _credits(value: Decimal | str | None) -> str:
    """A credit amount in a sentence: one decimal ("12.0", "1,365.5")."""
    if value is None or value == "":
        return "unknown"
    return credits_text.credits(value)


def _unmatched_entities_check(session: Session) -> Check:
    """Project and application usage reported under a name that is no project."""
    from app.services import dashboard as dashboard_service

    summary = dashboard_service.attribution_summary(session)
    parts: list[str] = []
    for label, found in (("project", summary.projects), ("application", summary.applications)):
        if not found.count:
            continue
        share = (
            f" ({round(float(found.credits) / float(found.total_credits) * 100)}% of "
            f"{_credits(found.total_credits)})"
            if found.total_credits > 0
            else ""
        )
        names = ", ".join(name for name, _credits_used in found.top[:3])
        parts.append(
            f"{_credits(found.credits)} {label} credits{share} under {found.count} name(s) that "
            f"match no {label}, such as {names}"
        )
    if not parts:
        return Check(
            "unmatched_entities",
            "Project and application usage",
            OK,
            "All project and application usage matches a synced project or application.",
        )
    return Check(
        "unmatched_entities",
        "Project and application usage",
        WARN,
        "Checkmarx reports usage under a repository name that matches no project in "
        f"/api/projects: {'; '.join(parts)}. That usage counts towards no project, group or "
        "application limit. Map each name under Settings → Attribution.",
    )


def _coverage_check(session: Session) -> Check | None:
    """Whether user budgets can bite, from the last coverage report (cached;
    Diagnostics never reads the tenant). Shown once user limits exist."""
    from app.models.enums import EntityType
    from app.models.limits import CreditLimit
    from app.services import coverage

    report = coverage.cached_for_key(session)
    has_user_limits = session.scalar(
        select(CreditLimit.id)
        .where(CreditLimit.entity_type == EntityType.USER, CreditLimit.is_active.is_(True))
        .limit(1)
    )
    if report is None or (has_user_limits is None and not report.get("low")):
        return None
    label = "Enforcement coverage"
    holders = report.get("ai_holders") or 0
    if report.get("low"):
        return Check("enforcement_coverage", label, WARN, str(report.get("warning")))
    return Check(
        "enforcement_coverage",
        label,
        OK,
        f"A user restriction can take AI access from {report.get('restrictable', 0)} of the "
        f"{holders} users who hold an AI role.",
    )


def _doubted_falls_check(session: Session) -> Check | None:
    """Names whose fall in a doubted reading is held (usage_missing_name, kind
    "dip"): their usage counts again once a complete reading confirms the
    fall or it recovers, at most a few readings later."""
    from app.models.usage import UsageMissingName
    from app.services import ledger

    names = list(
        session.scalars(
            select(UsageMissingName.subject_key)
            .where(UsageMissingName.kind == ledger.DIP)
            .order_by(UsageMissingName.subject_key)
        )
    )
    if not names:
        return None
    shown = ", ".join(names[:10]) + (f" and {len(names) - 10} more" if len(names) > 10 else "")
    return Check(
        "doubted_falls",
        "Doubted usage falls",
        WARN,
        f"{len(names)} name(s) reported less usage in a reading that looked incomplete "
        f"(a row repeated or missing): {shown}. The fall is not believed until a complete "
        f"reading confirms it, for at most {ledger.DIP_MAX_DOUBTS} readings or "
        f"{int(ledger.DIP_MAX_AGE.total_seconds() // 3600)} hours.",
    )


def _activity_check(session: Session, moment: datetime) -> Check | None:
    """The usage source: whether the credit activity log is the source,
    whether its sum matched the consumption summary's total over the same
    window the last time both were read in full, and whether new
    restrictions of period budgets are paused (summary-counted usage warns
    but never restricts)."""
    from app.services import activity_source

    info = activity_source.describe(session)
    label = "Usage source"
    paused = (
        " New restrictions of monthly and quarterly budgets are paused: usage the "
        "consumption summary counts warns but does not restrict (lifetime, custom and "
        "count-existing budgets, and restrictions already in force, are not affected)."
    )
    if settings_store.usage_source(session) != settings_store.USAGE_SOURCE_ACTIVITY:
        if settings_store.summary_restricts(session):
            return None
        return Check(
            "activity_source",
            label,
            WARN,
            "Usage comes from the consumption summary only (Settings → Schedule & data), "
            "and restrictions from summary totals are not allowed." + paused,
        )
    status = info.get("status")
    if status == activity_source.ACTIVE:
        detail = "The credit activity log is the source of project, user and application usage."
        failing = info.get("failing_since")
        if failing:
            return Check(
                "activity_source",
                label,
                WARN,
                f"{detail} It could not be read since {failing} ({info.get('last_error')}); "
                "nothing new is counted until it answers, and the consumption summary takes "
                f"over after {int(activity_source.OUTAGE_GRACE.total_seconds() // 60)} minutes.",
            )
        reconciliation = info.get("reconciliation") or {}
        if isinstance(reconciliation, dict) and reconciliation.get("status") == "mismatch":
            return Check(
                "activity_source",
                label,
                WARN,
                f"{detail} But over {reconciliation.get('period')} the log adds up to "
                f"{_credits(reconciliation.get('activity_credits'))} credits and the consumption "
                f"summary reports {_credits(reconciliation.get('summary_credits'))} (checked "
                f"{reconciliation.get('at')}): some usage may be missing from one of them.",
            )
        if isinstance(reconciliation, dict) and reconciliation.get("status") == "match":
            detail += (
                f" Over {reconciliation.get('period')} it adds up to the consumption summary's "
                f"total ({_credits(reconciliation.get('summary_credits'))} credits)."
            )
        return Check("activity_source", label, OK, detail)
    if status == activity_source.FALLBACK:
        return Check(
            "activity_source",
            label,
            WARN,
            "The credit activity log could not be read "
            f"({info.get('last_error')}), so usage comes from the consumption summary, "
            "matched by name. The log is tried again "
            + (f"after {info.get('retry_after')}." if info.get("retry_after") else "every cycle.")
            + paused,
        )
    if not info.get("last_error"):
        return Check(
            "activity_source",
            label,
            OK,
            "The credit activity log becomes the source of project, user and application usage "
            "at the next cycle.",
        )
    return Check(
        "activity_source",
        label,
        WARN,
        f"The credit activity log is not available: {info.get('last_error')} Usage comes "
        "from the consumption summary, matched by name." + paused,
    )


def _group_names_check(session: Session) -> Check | None:
    from app.services import org_sync

    names = settings_store.duplicate_group_names(session)
    if not names:
        return None
    return Check("group_names", "Group names", WARN, org_sync.duplicate_groups_message(names))


def _auto_triage_check(session: Session) -> Check:
    """How auto-triage credits are being charged to the people who scanned."""
    from app.services import auto_triage_attribution

    model = auto_triage_attribution.build_model(session)
    label = "Auto-triage attribution"
    if not model.available:
        return Check(
            "auto_triage_attribution",
            label,
            OK,
            "On, but there is no project consumption reading yet (or this tenant does not "
            "report consumption by project), so nothing is charged to people yet.",
        )
    total = sum((p.auto_triage_credits for p in model.projects.values()), Decimal("0"))
    observed = sum((p.observed for p in model.projects.values()), Decimal("0"))
    estimated = sum((p.estimated for p in model.projects.values()), Decimal("0"))
    unresolved = sum((p.unresolved for p in model.projects.values()), Decimal("0"))
    on_project = sum((p.unattributed for p in model.projects.values()), Decimal("0"))
    initiators = sorted(
        info.initiator
        for info in model.initiators.values()
        if info.outcome.counted_user_id is None and not info.outcome.is_bot
    )
    failing = sorted(
        row.project_id
        for row in session.scalars(
            select(AutoTriageProjectState).where(AutoTriageProjectState.last_error.is_not(None))
        )
    )
    detail = (
        f"{_credits(total)} auto-triage credits in the lookback window: {_credits(observed)} "
        f"traced to the scans that triggered them, {_credits(estimated)} estimated from earlier "
        f"scans, {_credits(unresolved)} held by initiators that are not a synced user, "
        f"{_credits(on_project)} on the project only."
    )
    problems: list[str] = []
    if initiators:
        shown = ", ".join(initiators[:5]) + ("..." if len(initiators) > 5 else "")
        problems.append(f"{len(initiators)} scan initiator(s) to map: {shown}.")
    if failing:
        problems.append(
            f"{len(failing)} project(s) with a note from the last attempt to read their scans."
        )
    if problems:
        return Check("auto_triage_attribution", label, WARN, f"{detail} {' '.join(problems)}")
    return Check("auto_triage_attribution", label, OK, detail)


def _selftest_check(session: Session, moment: datetime) -> Check | None:
    """The last enforcement self-test: passed or failed, and when. Shown once
    one has run. A target a self-test could not give back is a failure while
    its restriction is still in force."""
    from app.services import enforcement, enforcement_selftest

    row = enforcement_selftest.latest(session)
    if row is None:
        return None
    label = "Enforcement self-test"
    when = _ago(moment, row.finished_at or row.started_at)
    what = ", ".join(name for name in (row.user_label, row.project_label) if name)
    where = f" on {what}" if what else ""
    demo = " (demo tenant)" if row.demo else ""
    held = [
        action
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id.is_(None),
                EnforcementAction.period_key.like(f"{enforcement_selftest.PERIOD_PREFIX}%"),
                EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
            )
        )
        if enforcement.may_be_in_force(action)
    ]
    if held:
        targets = ", ".join(sorted({action.target_label or action.target_id for action in held}))
        return Check(
            "enforcement_selftest",
            label,
            FAIL,
            f"A self-test left {targets} restricted: its restore failed and is retried by the "
            f"next cycle. Last self-test {row.status.replace('_', ' ')}{where}, {when}.",
        )
    if row.status in ("passed", "warning"):
        words = "passed" if row.status == "passed" else "passed with warnings"
        return Check(
            "enforcement_selftest", label, OK, f"Last self-test {words}{where}{demo}, {when}."
        )
    return Check(
        "enforcement_selftest",
        label,
        WARN,
        f"Last self-test {row.status.replace('_', ' ')}{where}{demo}, {when}.",
    )


RECOUNT_RECENT = timedelta(days=7)


def _recount_check(session: Session, moment: datetime) -> Check:
    """The recounts before new restrictions that refused one: the latest, or
    "no disagreements"."""
    from app.services import recount

    label = "Recount before restricting"
    entries = recount.records(session)
    if not entries:
        return Check("recount", label, OK, "No disagreements.")
    lines = []
    for entry in entries[:3]:
        what = f"{entry.get('entity_type')} {entry.get('entity_label')}, {entry.get('period_key')}"
        if entry.get("kind") == recount.DISAGREE:
            lines.append(
                f"{what}: CreditGuard counted {_credits(entry.get('counted'))}, the activity log "
                f"{_credits(entry.get('recount'))} (limit {_credits(entry.get('credit_limit'))}); "
                "not restricted"
            )
        else:
            lines.append(
                f"{what}: no recount ({entry.get('reason')}); CreditGuard counted "
                f"{_credits(entry.get('counted'))}; not restricted"
            )
    try:
        latest = datetime.fromisoformat(str(entries[0].get("at")))
    except ValueError:
        latest = None
    recent = latest is not None and moment - latest < RECOUNT_RECENT
    when = f" Latest {_ago(moment, latest)}." if latest is not None else ""
    return Check("recount", label, WARN if recent else OK, "; ".join(lines) + "." + when)


def _readiness_check(session: Session, moment: datetime) -> Check:
    """The readiness checklist, as one line, from the same items the
    Readiness card shows: OK only while every item is green. An item that is
    pending (amber) or red warns."""
    from app.services import readiness

    current = readiness.report(session, now=moment)
    label = "Readiness"
    if current.all_green:
        return Check("readiness", label, OK, "Every readiness item is green.")
    parts = [f"{item.label}: {item.status} ({item.detail})" for item in current.not_green()]
    drifted = readiness.drifted(session, current)
    if current.gate_active:
        prefix = "Watch-only until these are green or overridden. "
    elif drifted:
        prefix = "No longer green: " + ", ".join(item.label for item in drifted) + ". "
    else:
        prefix = ""
    return Check("readiness", label, WARN, prefix + "; ".join(parts))


def _when(moment: datetime, entry: object) -> str:
    if not isinstance(entry, dict) or not isinstance(entry.get("at"), str):
        return "never"
    try:
        at = datetime.fromisoformat(entry["at"])
    except ValueError:
        return "never"
    return f"{_ago(moment, at)}: {entry.get('result') or 'no result'}"


def _fast_check_check(session: Session, moment: datetime) -> Check:
    """The fast check (app/services/fastcheck.py): last run, last action."""
    from app.services import fastcheck

    status = fastcheck.describe(session)
    label = "Fast check"
    if not status["enabled"]:
        return Check("fast_check", label, OK, "Off: budgets are checked by the full cycle only.")
    detail = (
        f"Every {status['interval_seconds']} seconds. Last run {_when(moment, status['last_run'])}."
        f" Last action {_when(moment, status['last_action'])}."
    )
    return Check("fast_check", label, WARN if status.get("error") else OK, detail)


def _cx_webhook_check(session: Session, moment: datetime) -> Check | None:
    """The Checkmarx One webhook, while it is switched on."""
    from app.services import cx_webhook

    status = cx_webhook.describe(session)
    if not status["switched_on"]:
        return None
    label = "Checkmarx One webhook"
    if not status["secret_configured"]:
        return Check("cx_webhook", label, WARN, "On, but no secret is set: deliveries are refused.")
    detail = f"Last delivery {_when(moment, status['last_delivery'])}."
    if status.get("last_rejected"):
        detail += f" Last refused {_when(moment, status['last_rejected'])}."
    return Check("cx_webhook", label, OK, detail)


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
