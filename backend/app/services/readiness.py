"""The onboarding readiness checklist, which gates turning enforcement on.

A new install starts watching only: enforcement paused, with the readiness
gate set (``readiness.gate``, written by the data migration on an empty
database only). Leaving watch-only needs every item green, or an admin's
explicit override (typing ENFORCE), which is audited with the items that were
not green. Once enforcement is on the gate is gone for good: the checklist
never turns enforcement off, and an item that turns red later raises a
WARNING and shows on Diagnose. An existing install (no gate) is never
blocked; the checklist is shown for information.

Every item is computed from what the app already has:

1. Connected to Checkmarx One: the connection check passes.
2. Activity log readable: the activity log is the usage source and its last
   read succeeded.
3. Counts match Checkmarx: the latest daily reconciliation of the log's sum
   with the consumption summary's total is within 0.5% (pending until the
   first one).
4. Self-test passed: a passed self-test on a user and one on a project in the
   last 30 days (kinds that were not applicable do not count against it).
5. Dry run reviewed: an admin marked the dry run / Simulation reviewed after
   the last budget change.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import AuditLogEntry
from app.models.connection import CxConnection
from app.models.enums import ConnectionStatus, Severity
from app.models.selftest import STATUS_PASSED, STATUS_WARNING, EnforcementSelfTest
from app.services import credits_text, notifications, settings_store
from app.services.audit import AuditActor, record_audit

GREEN = "green"
AMBER = "amber"
RED = "red"

OVERRIDE_WORD = "ENFORCE"
SELFTEST_WITHIN = timedelta(days=30)
WATCH_ONLY_REASON = (
    "Watch-only: a new install watches and warns but restricts nobody until the readiness "
    "checklist is green (Settings → Enforcement)."
)
_BUDGET_CHANGES = ("limit.created", "limit.updated", "limit.deleted", "limit.imported")


@dataclass(frozen=True, slots=True)
class Item:
    key: str
    label: str
    status: str
    detail: str
    hint: str
    link: str


@dataclass(frozen=True, slots=True)
class Report:
    items: list[Item]
    gate_active: bool
    enforcement_on: bool
    reviewed_at: str | None
    reviewed_by: str | None

    @property
    def all_green(self) -> bool:
        return all(item.status == GREEN for item in self.items)

    def not_green(self) -> list[Item]:
        return [item for item in self.items if item.status != GREEN]

    def as_dict(self) -> dict[str, Any]:
        return {
            "items": [asdict(item) for item in self.items],
            "gate_active": self.gate_active,
            "enforcement_on": self.enforcement_on,
            "all_green": self.all_green,
            "reviewed_at": self.reviewed_at,
            "reviewed_by": self.reviewed_by,
        }


class ReadinessError(ValueError):
    def __init__(self, code: str, message: str, items: list[Item] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.items = items or []


def gate_active(session: Session) -> bool:
    return settings_store.get_value(session, settings_store.KEY_READINESS_GATE, False) is True


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


# ------------------------------------------------------------------- items


def _connected(session: Session) -> Item:
    label, hint, link = (
        "Connected to Checkmarx One",
        "Add the API key on Setup and use Test connection.",
        "/setup",
    )
    connection = session.scalar(select(CxConnection).limit(1))
    if connection is None:
        return Item("connection", label, RED, "No connection is configured.", hint, link)
    if connection.status == ConnectionStatus.HEALTHY:
        return Item("connection", label, GREEN, "The connection check passes.", hint, link)
    if connection.status in (ConnectionStatus.FAILED, ConnectionStatus.DEGRADED):
        return Item("connection", label, RED, f"The connection is {connection.status}.", hint, link)
    return Item("connection", label, AMBER, "Not verified yet.", hint, link)


def _activity(session: Session) -> Item:
    from app.services import activity_source

    label, link = "Activity log readable", "/settings/general"
    hint = (
        "Let the API key read the credit activity log and keep Usage source: Activity log "
        "(Settings → Schedule & data)."
    )
    if settings_store.usage_source(session) != settings_store.USAGE_SOURCE_ACTIVITY:
        return Item("activity_log", label, RED, "The usage source is the summary only.", hint, link)
    state = session.get(activity_source.ActivitySourceState, 1)
    if state is None or state.last_fetch_at is None:
        return Item("activity_log", label, AMBER, "Not read yet: run a cycle.", hint, link)
    succeeded = (
        state.status == activity_source.ACTIVE
        and state.last_success_at is not None
        and state.last_success_at >= state.last_fetch_at
    )
    if succeeded:
        return Item("activity_log", label, GREEN, "Its last read succeeded.", hint, link)
    reason = f" ({state.last_error})" if state.last_error else ""
    return Item("activity_log", label, RED, f"Its last read failed{reason}.", hint, link)


def _counts(session: Session) -> Item:
    from app.services import activity_source

    label, link = "Counts match Checkmarx", "/"
    hint = (
        "The daily reconciliation compares the activity log's sum with the summary's total; "
        "a lasting mismatch is worth raising with Checkmarx."
    )
    state = session.get(activity_source.ActivitySourceState, 1)
    record = (state.reconciliation or {}) if state is not None else {}
    status = record.get("status") if isinstance(record, dict) else None
    if status == "match":
        return Item(
            "counts_match", label, GREEN, "Within 0.5% at the last reconciliation.", hint, link
        )
    if status == "mismatch":
        return Item(
            "counts_match",
            label,
            RED,
            f"The log counted {_credits(record.get('activity_credits'))}, the summary "
            f"{_credits(record.get('summary_credits'))} credits.",
            hint,
            link,
        )
    why = record.get("reason") if isinstance(record, dict) else None
    detail = f"Inconclusive: {why}." if status else "Pending until the first daily reconciliation."
    return Item("counts_match", label, AMBER, detail, hint, link)


def _selftest(session: Session, now: datetime) -> Item:
    label, link = "Self-test passed", "/settings/enforcement"
    hint = "Run the self-test on a user and on a project (Settings → Enforcement)."
    passed: set[str] = set()
    failed = False
    for row in session.scalars(
        select(EnforcementSelfTest).where(
            EnforcementSelfTest.started_at >= now - SELFTEST_WITHIN,
            EnforcementSelfTest.demo.is_(False),
        )
    ):
        for target in (row.result or {}).get("targets") or []:
            if not isinstance(target, dict):
                continue
            if target.get("status") in (STATUS_PASSED, STATUS_WARNING):
                passed.add(str(target.get("target_type")))
            else:
                failed = True
    missing = [noun for noun in ("user", "project") if noun not in passed]
    if not missing:
        return Item(
            "selftest",
            label,
            GREEN,
            "Passed on a user and a project in the last 30 days.",
            hint,
            link,
        )
    detail = f"No passed self-test on a {' or a '.join(missing)} in the last 30 days."
    return Item("selftest", label, RED if failed else AMBER, detail, hint, link)


def last_budget_change(session: Session) -> datetime | None:
    return session.scalar(
        select(func.max(AuditLogEntry.occurred_at)).where(AuditLogEntry.action.in_(_BUDGET_CHANGES))
    )


def _reviewed(session: Session) -> tuple[Item, str | None, str | None]:
    label, link = "Dry run reviewed", "/preview"
    hint = "Open Simulation, check what would be restricted, and click Reviewed."
    stored = settings_store.get_value(session, settings_store.KEY_READINESS_REVIEWED)
    stored = stored if isinstance(stored, dict) else {}
    at, by = _parse(stored.get("at")), stored.get("by")
    changed = last_budget_change(session)
    if at is None:
        item = Item("dry_run_reviewed", label, AMBER, "Not reviewed yet.", hint, link)
    elif changed is not None and changed > at:
        item = Item(
            "dry_run_reviewed", label, AMBER, "A budget changed since the last review.", hint, link
        )
    else:
        item = Item(
            "dry_run_reviewed", label, GREEN, f"Reviewed by {by or 'an admin'}.", hint, link
        )
    return item, stored.get("at"), by


def report(session: Session, *, now: datetime | None = None) -> Report:
    moment = now or utcnow()
    reviewed, reviewed_at, reviewed_by = _reviewed(session)
    items = [
        _connected(session),
        _activity(session),
        _counts(session),
        _selftest(session, moment),
        reviewed,
    ]
    guard = settings_store.enforcement_guard(session)
    return Report(
        items=items,
        gate_active=gate_active(session),
        enforcement_on=not guard.paused,
        reviewed_at=reviewed_at,
        reviewed_by=reviewed_by if isinstance(reviewed_by, str) else None,
    )


# ----------------------------------------------------------------- actions


def mark_reviewed(session: Session, *, actor: AuditActor) -> Report:
    now = utcnow()
    settings_store.set_value(
        session,
        settings_store.KEY_READINESS_REVIEWED,
        {"at": now.isoformat(), "by": actor.actor_name},
    )
    record_audit(
        session,
        action="readiness.dry_run_reviewed",
        actor=actor,
        target_type="settings",
        detail="The dry run / Simulation was marked reviewed.",
    )
    session.commit()
    return report(session, now=now)


def leave_watch_only(session: Session, *, actor: AuditActor, confirm: str | None) -> Report:
    """Turn enforcement on for an install still watching only. Every item
    green, or ``confirm`` the typed override word. Raises ReadinessError."""
    current = report(session)
    if not current.gate_active:
        raise ReadinessError(
            "not_watch_only", "Enforcement is not in watch-only onboarding; use Pause instead."
        )
    override = not current.all_green
    if override and (confirm or "").strip() != OVERRIDE_WORD:
        raise ReadinessError(
            "readiness_not_green",
            "Not every readiness item is green. Fix them, or type "
            f"{OVERRIDE_WORD} to turn enforcement on anyway.",
            current.not_green(),
        )
    apply_leave(session, actor=actor, current=current, override=override)
    session.commit()
    return report(session)


def apply_leave(session: Session, *, actor: AuditActor, current: Report, override: bool) -> None:
    """Enforcement on, the gate gone (flushed, committed by the caller)."""
    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_PAUSED, False)
    settings_store.set_value(session, settings_store.KEY_ENFORCEMENT_PAUSE_REASON, None)
    settings_store.set_value(session, settings_store.KEY_READINESS_GATE, False)
    remember(session, current)
    states = {item.key: item.status for item in current.items}
    if override:
        names = ", ".join(f"{item.label} ({item.status})" for item in current.not_green())
        record_audit(
            session,
            action="readiness.override",
            actor=actor,
            target_type="settings",
            after={"items": states, "not_green": [item.key for item in current.not_green()]},
            detail=f"Enforcement turned on with the readiness checklist not green: {names}.",
        )
    else:
        record_audit(
            session,
            action="readiness.enforcement_on",
            actor=actor,
            target_type="settings",
            after={"items": states},
            detail="Enforcement turned on with every readiness item green.",
        )


DRIFTED = "_drifted"


def remember(session: Session, current: Report, drifted: set[str] | None = None) -> None:
    """Each item's state now, and the items that turned red after being green
    and are not green again yet (shown on Diagnose)."""
    value: dict[str, Any] = {item.key: item.status for item in current.items}
    value[DRIFTED] = sorted(drifted or ())
    settings_store.set_value(session, settings_store.KEY_READINESS_LAST, value)


def _last(session: Session) -> dict[str, Any]:
    value = settings_store.get_value(session, settings_store.KEY_READINESS_LAST, {})
    return value if isinstance(value, dict) else {}


def drifted_items(current: Report, before: dict[str, Any]) -> list[Item]:
    """Red now, green when last recorded."""
    return [item for item in current.items if item.status == RED and before.get(item.key) == GREEN]


def drifted(session: Session, current: Report) -> list[Item]:
    """Items that turned red after being green and are not green again (none
    while a new install still watches only)."""
    if current.gate_active:
        return []
    before = _last(session)
    known = set(before.get(DRIFTED) or [])
    fresh = {item.key for item in drifted_items(current, before)}
    return [item for item in current.items if item.status != GREEN and item.key in known | fresh]


def check_drift(session: Session, *, now: datetime | None = None) -> list[str]:
    """Per cycle: an item that was green and is red now raises a WARNING once
    enforcement is on. Never changes enforcement. Returns the newly drifted keys."""
    moment = now or utcnow()
    current = report(session, now=moment)
    before = _last(session)
    fresh = drifted_items(current, before)
    if fresh and current.enforcement_on and not current.gate_active:
        for item in fresh:
            notifications.notify(
                session,
                category=notifications.CATEGORY_WARNING,
                severity=Severity.WARNING,
                title=f"Readiness: {item.label} is no longer green",
                body=(
                    f"{item.detail} {item.hint} Enforcement stays on; the readiness "
                    "checklist is on Settings → Enforcement and on Diagnose."
                ),
                dedupe_key=f"readiness.drift:{item.key}:{moment.isoformat(timespec='seconds')}",
            )
    still = {item.key for item in drifted(session, current)}
    stored = {item.key: item.status for item in current.items}
    stored[DRIFTED] = sorted(still)
    if stored != before:
        remember(session, current, still)
    session.commit()
    return [item.key for item in fresh]


def _credits(value: object) -> str:
    """A credit amount in a sentence; "unknown" when the record has none."""
    if value is None or value == "":
        return "unknown"
    return credits_text.credits(value)
