"""The fast check: count new activity and restrict within seconds.

The full cycle (app/services/cycle.py) syncs the organisation, reads usage,
evaluates every budget, verifies restrictions and does the housekeeping, every
few minutes. Between cycles the fast check, a separate scheduler job (every
``fastcheck.interval_seconds``, 15 by default), does just this:

1. reads the newest rows of the credit activity log: from where its last read
   ended (or the activity source's cursor) to the end, normally one request,
   with no database transaction open while Checkmarx is called, under the
   cycle's pacing (a time budget, and at most ``TAIL_MAX_PAGES`` pages);
2. counts the new events through the activity source's own code
   (``activity_source._reconcile`` and ``_count``: the same multiset rule, the
   same attribution lock, so a row is counted once whichever read sees it);
3. if a budget those events fed is now at or over where it restricts (its
   limit, or earlier with a headroom: app/services/headroom.py), evaluates and
   enforces just those budgets (``evaluation.evaluate_all(only=...)``), with
   every gate a cycle has: the pause and readiness state, the safety ceilings,
   ``summary_hold``, the recount, the blast-radius guard.

What it never does: run while a cycle (or another fast check) runs - it holds
the cycle's own lock, and skips the tick when that is busy; count from the
consumption summary (summary totals never start a restriction); touch the live
tenant in demo mode; move the activity source's cursor (the full cycle still
reads everything the fast check read, and is the source of truth); create a
cycle record. A tick that finds nothing new writes nothing but the lock row
(taken and released), and the status at most every ``STATUS_HEARTBEAT``.

The safety ceiling counts per cycle. So that several fast checks between two
cycles cannot together start more than one cycle may, the fast check also
counts what started restricting over the last cycle interval, and leaves
anything beyond the ceiling to the full cycle (which applies its own).

A Checkmarx One webhook (app/services/cx_webhook.py) only asks for a fast
check now (``request``): at most one is ever queued.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError, NotConfiguredError
from app.db.base import utcnow
from app.db.session import session_scope
from app.models.enums import EnforcementStatus, LimitStatus
from app.models.limits import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.usage import SchedulerLock
from app.services import activity_source, error_text, pacing, settings_store
from app.services.audit import AuditActor

logger = logging.getLogger(__name__)

DEFAULT_SECONDS = 15
MIN_SECONDS = 10
MAX_SECONDS = 300
# A tail longer than this many pages is left to the full cycle.
TAIL_MAX_PAGES = 4
# The fast check's own time budget: room for a recount before a restriction.
TIME_BUDGET_SECONDS = 120.0
# The status is written at least this often while nothing happens.
STATUS_HEARTBEAT = timedelta(minutes=5)
# A budget whose restriction the recount refused is tried again by a fast
# check at most this often (every cycle tries it anyway).
RECOUNT_RETRY = timedelta(minutes=5)
# A webhook never makes fast checks closer together than this.
MIN_SPACING_SECONDS = 5.0
HOLDER_PREFIX = "fastcheck:"
ACTOR = AuditActor.system("fast check")


# ------------------------------------------------------------------ settings


@dataclass(frozen=True, slots=True)
class FastCheckConfig:
    enabled: bool
    interval_seconds: int


def normalise_seconds(value: Any) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = DEFAULT_SECONDS
    return max(MIN_SECONDS, min(MAX_SECONDS, number))


def config(session: Session) -> FastCheckConfig:
    enabled = settings_store.get_value(session, settings_store.KEY_FAST_CHECK_ENABLED, True)
    seconds = settings_store.get_value(session, settings_store.KEY_FAST_CHECK_SECONDS)
    return FastCheckConfig(
        enabled=enabled is not False, interval_seconds=normalise_seconds(seconds)
    )


# -------------------------------------------------------------- the result


@dataclass
class FastCheckResult:
    trigger: str = "schedule"
    ran: bool = False
    skipped: str | None = None
    error: str | None = None
    requests: int = 0
    rows: int = 0
    events_counted: int = 0
    credits_counted: Decimal = Decimal("0")
    fed: list[int] = field(default_factory=list)
    candidates: list[int] = field(default_factory=list)
    evaluated: int = 0
    enforced: int = 0
    held: int = 0
    deferred: str | None = None
    wrote: bool = False
    hint: dict[str, str] | None = None
    started_at: datetime | None = None
    seconds: float = 0.0

    @property
    def acted(self) -> bool:
        return bool(self.events_counted or self.evaluated or self.deferred)

    def summary(self) -> str:
        if self.skipped:
            return f"skipped: {self.skipped}"
        if self.error:
            return f"error: {self.error}"
        if not self.events_counted:
            return "nothing new"
        text = f"counted {self.events_counted} new event(s), {self.credits_counted} credits"
        if self.deferred:
            return f"{text}; {self.deferred}"
        if self.evaluated:
            text += f"; evaluated {self.evaluated} budget(s)"
            if self.enforced:
                text += f", applied {self.enforced} restriction(s)"
            if self.held:
                text += f", {self.held} held (recount, summary totals or pause)"
        return text


# ------------------------------------------------------------- process state

_memory_lock = threading.Lock()
# Per database: where the last tail read ended (a position in the log).
_positions: dict[str, int] = {}
# Per database: the last result, for Diagnose in this process.
_last: dict[str, dict[str, Any]] = {}
# One queued request at most (a webhook): (trigger, hint).
_pending: tuple[str, dict[str, str] | None] | None = None
_last_started: float = 0.0
# Set while a full cycle waits for a fast check to let go of the lock.
cycle_waiting = threading.Event()


def _db_key() -> str:
    from app.core.config import get_settings

    return str(get_settings().database_url)


def reset_memory() -> None:
    """Forget the process state (tests)."""
    global _pending, _last_started
    with _memory_lock:
        _positions.clear()
        _last.clear()
        _pending = None
        _last_started = 0.0
    cycle_waiting.clear()


QUEUED = "queued"
MERGED = "merged"
NOT_RUNNING = "not running"


def request(trigger: str = "webhook", hint: dict[str, str] | None = None) -> str:
    """Ask for a fast check as soon as possible: ``QUEUED``, ``MERGED`` into
    the one already queued (at most one ever is), or ``NOT_RUNNING`` when no
    fast check runs in this process (turned off, or no scheduler here)."""
    global _pending
    with _memory_lock:
        if _pending is not None:
            return MERGED
        _pending = (trigger, hint)
        next_at = max(time.monotonic(), _last_started + MIN_SPACING_SECONDS)
    from app import scheduler

    if scheduler.wake_fast_check(delay=max(0.0, next_at - time.monotonic())):
        return QUEUED
    with _memory_lock:
        _pending = None
    return NOT_RUNNING


def pending() -> bool:
    with _memory_lock:
        return _pending is not None


def _take_request() -> tuple[str, dict[str, str] | None] | None:
    global _pending
    with _memory_lock:
        taken, _pending = _pending, None
        return taken


def last_status() -> dict[str, Any] | None:
    with _memory_lock:
        found = _last.get(_db_key())
        return dict(found) if found is not None else None


# --------------------------------------------------------------- locking


def _lock_busy(session: Session, now: datetime) -> str | None:
    """Why the cycle lock cannot be had right now (read only), or None."""
    from app.services import cycle

    if cycle_waiting.is_set():
        return "a cycle is waiting to start"
    row = session.get(SchedulerLock, cycle.LOCK_NAME)
    if row is None or row.holder is None or row.heartbeat_at is None:
        return None
    if row.heartbeat_at < now - cycle.LOCK_STALE_AFTER:
        return None
    if row.holder.startswith(HOLDER_PREFIX):
        return "another fast check is running"
    return "a cycle is running"


def _acquire(session: Session, holder: str, now: datetime) -> bool:
    from app.services import cycle

    if session.get(SchedulerLock, cycle.LOCK_NAME) is None:
        return cycle.acquire_lock(session, holder=holder)
    stale_before = now - cycle.LOCK_STALE_AFTER
    taken = session.execute(
        update(SchedulerLock)
        .where(
            SchedulerLock.name == cycle.LOCK_NAME,
            (SchedulerLock.holder.is_(None))
            | (SchedulerLock.heartbeat_at.is_(None))
            | (SchedulerLock.heartbeat_at < stale_before),
        )
        .values(holder=holder, acquired_at=now, heartbeat_at=now)
    )
    session.commit()
    return bool(taken.rowcount)


# --------------------------------------------------------------- the check


def run_scheduled() -> list[FastCheckResult]:
    """The scheduler job: one tick, and once more if a request arrived
    meanwhile (never more)."""
    taken = _take_request()
    trigger, hint = taken if taken is not None else ("schedule", None)
    results = [run_fast_check(trigger=trigger, hint=hint)]
    again = _take_request()
    if again is not None:
        results.append(run_fast_check(trigger=again[0], hint=again[1]))
    return results


def run_fast_check(
    *,
    trigger: str = "schedule",
    hint: dict[str, str] | None = None,
    client: CheckmarxClient | None = None,
    now: datetime | None = None,
) -> FastCheckResult:
    """One fast check. Never raises."""
    global _last_started
    result = FastCheckResult(trigger=trigger, hint=hint)
    started = time.monotonic()
    with _memory_lock:
        _last_started = started
    moment = now or utcnow()
    result.started_at = moment
    holder: str | None = None
    try:
        with session_scope() as session:
            reason = _precheck(session, moment)
            if reason is None:
                reason = _lock_busy(session, moment)
            if reason is None:
                from app.services import cycle

                candidate = f"{HOLDER_PREFIX}{cycle.new_holder_id()}"
                if _acquire(session, candidate, moment):
                    holder = candidate
                else:
                    reason = "a cycle is running"
            if reason is not None:
                result.skipped = reason
        if holder is not None:
            with pacing.cycle_deadline(TIME_BUDGET_SECONDS), session_scope() as session:
                _run(session, result, client=client, moment=moment)
                result.ran = True
    except Exception as exc:  # noqa: BLE001 - the scheduler thread must survive anything
        logger.exception("The fast check failed")
        result.error = error_text.public_error(exc)
    finally:
        if holder is not None:
            try:
                from app.services import cycle

                with session_scope() as session:
                    cycle.release_lock(session, holder=holder)
            except Exception:  # noqa: BLE001 - it goes stale and is reclaimed
                logger.exception("Could not release the cycle lock after a fast check")
    result.seconds = round(time.monotonic() - started, 3)
    _record(result, moment)
    return result


def _precheck(session: Session, moment: datetime) -> str | None:
    """Why there is nothing to do this tick (read only), or None."""
    settings = config(session)
    if not settings.enabled:
        return "turned off"
    if not settings_store.schedule_config(session).enabled:
        return "the scheduler is turned off"
    if settings_store.demo_mode(session):
        # Demo data is never read from a tenant: nothing to do.
        return "demo mode"
    if settings_store.usage_source(session) != settings_store.USAGE_SOURCE_ACTIVITY:
        return "the usage source is the consumption summary only"
    if not activity_source.source_active(session):
        return "the activity log is not the usage source right now (summary fallback)"
    return None


def _run(
    session: Session,
    result: FastCheckResult,
    *,
    client: CheckmarxClient | None,
    moment: datetime,
) -> None:
    from app.services import connection as connection_service

    if client is None:
        try:
            client = connection_service.get_client(session)
        except NotConfiguredError as exc:
            result.skipped = str(exc)
            return
    state = activity_source._state(session)
    if state is None or state.status != activity_source.ACTIVE:
        result.skipped = "the activity log is not the usage source right now"
        return
    plan = activity_source._plan(session, state, moment)
    position = None
    with _memory_lock:
        position = _positions.get(_db_key())
    if position is None:
        position = state.resume_position
    start: int | None = None
    if position is not None:
        margin = max(1, plan.size // 20)
        start = max(0, position - margin) // plan.size + 1
    plan = replace(plan, seed=False, sweep=False, start_page=start, cap=TAIL_MAX_PAGES)
    # Nothing is left open in the database while Checkmarx is called.
    session.commit()
    try:
        read = activity_source._read(client, plan)
        analysis = activity_source._analyse(read, plan)
    except CheckmarxError as exc:
        # The full cycle deals with outages; the fast check only reports.
        session.rollback()
        result.error = error_text.public_error(exc)
        return
    result.requests = read.requests
    result.rows = analysis.rows
    if read.pages:
        with _memory_lock:
            _positions[_db_key()] = analysis.end_position
    if analysis.regression or not _anything_new(session, analysis, moment, state):
        session.rollback()
        return
    _count(session, result, plan, analysis, moment)
    if not result.fed:
        return
    candidates = _candidates(session, result.fed, moment)
    result.candidates = candidates
    if not candidates:
        return
    deferred = _ceiling_defers(session, moment, len(candidates))
    if deferred is not None:
        result.deferred = deferred
        session.commit()
        return
    from app.services import evaluation

    outcome = evaluation.evaluate_all(
        session, client=client, now=moment, actor=ACTOR, only=frozenset(candidates)
    )
    session.commit()
    result.evaluated = outcome.evaluated
    result.enforced = outcome.enforced
    result.held = outcome.recount_held + outcome.summary_held + outcome.deferred
    if outcome.enforcement_paused and outcome.deferred:
        result.deferred = f"enforcement is paused: {outcome.enforcement_paused}"


def _anything_new(
    session: Session,
    analysis: Any,
    moment: datetime,
    state: Any,
) -> bool:
    """Whether the read holds a row identity seen fewer times than it shows
    (read only: a tick with nothing new writes nothing)."""
    from app.models.activity import ActivityEventCount

    cutoff = activity_source.horizon(moment)
    if state.cutoff_at is not None and state.cutoff_at > cutoff:
        cutoff = state.cutoff_at
    wanted = {
        key: count
        for key, (count, rows) in analysis.counts.items()
        if rows[0].date not in analysis.uncertain and rows[0].date >= cutoff
    }
    if not wanted:
        return False
    keys = sorted(wanted)
    seen: dict[str, int] = {}
    for start in range(0, len(keys), 500):
        for key, count in session.execute(
            select(ActivityEventCount.key_hash, ActivityEventCount.seen).where(
                ActivityEventCount.key_hash.in_(keys[start : start + 500])
            )
        ):
            seen[key] = int(count)
    return any(count > seen.get(key, 0) for key, count in wanted.items())


def _count(
    session: Session,
    result: FastCheckResult,
    plan: Any,
    analysis: Any,
    moment: datetime,
) -> None:
    """Count the new events, under the attribution lock, in one transaction,
    exactly as the activity source's write does (without moving its cursor)."""
    from app.services import ingestion

    ingestion.attribution_lock(session)
    state = activity_source._state_for_write(session)
    if (
        int(state.revision or 0) != plan.revision
        or state.status != activity_source.ACTIVE
        or settings_store.usage_source(session) != settings_store.USAGE_SOURCE_ACTIVITY
    ):
        # The state moved since the plan: nothing is written.
        session.commit()
        return
    floor = state.floor_at or moment
    cutoff = activity_source.horizon(moment)
    if state.cutoff_at is not None and state.cutoff_at > cutoff:
        cutoff = state.cutoff_at
    history = activity_source.BudgetHistory(session, moment, persist=True)
    group_floors = activity_source._observe_groups(session, state, moment)
    counted = activity_source.ActivityResult(enabled=True, status=activity_source.ACTIVE)
    new_events = activity_source._reconcile(session, analysis, plan, floor, cutoff, moment, counted)
    if new_events:
        activity_source._count(session, new_events, moment, counted, history, group_floors, state)
    # A read planned before this write is not written over it.
    state.revision = (state.revision or 0) + 1
    session.commit()
    result.wrote = True
    result.events_counted = counted.events_counted
    result.credits_counted = counted.credits_counted
    result.fed = sorted(counted.fed_limit_ids)


def _candidates(session: Session, fed: list[int], moment: datetime) -> list[int]:
    """The budgets the new events fed that are now at or over where they
    restrict, and that a fast check can do something about."""
    from app.services import evaluation, recount
    from app.services.periods import PeriodError, current_window

    index = evaluation.UsageIndex(session)
    refused = {
        (entry.get("limit_id"), entry.get("period_key")): entry.get("at")
        for entry in recount.records(session)
    }
    chosen: list[int] = []
    for limit_id in fed:
        limit = session.get(CreditLimit, limit_id)
        if limit is None or not limit.is_active:
            continue
        try:
            window = current_window(limit, moment)
        except PeriodError:
            continue
        if not window.is_active:
            continue
        used, available, _attributed = evaluation.period_usage(
            session, limit=limit, window=window, index=index, moment=moment
        )
        if not available or used < index.headroom.restrict_at(limit):
            continue
        state = session.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id,
                LimitPeriodState.period_key == window.key,
            )
        )
        already = state is not None and state.status in (
            LimitStatus.BREACHED,
            LimitStatus.RESTRICTED,
        )
        if already and (
            not limit.enforce or evaluation.restriction_started(session, limit.id, window.key)
        ):
            # Restricted already, or monitor only and already announced.
            continue
        last_refusal = refused.get((limit.id, window.key))
        if already and isinstance(last_refusal, str):
            try:
                when = datetime.fromisoformat(last_refusal)
            except ValueError:
                when = None
            if when is not None and moment - when < RECOUNT_RETRY:
                continue
        chosen.append(limit.id)
    return chosen


def _ceiling_defers(session: Session, moment: datetime, starting: int) -> str | None:
    """Leave the new restrictions to the full cycle when fast checks would,
    together, start more over one cycle interval than one cycle may."""
    guard = settings_store.enforcement_guard(session)
    if guard.ceiling_waived_once:
        # An admin's resume lets one cycle's batch through: the cycle's.
        return "left to the full cycle: the resumed batch goes through with it"
    if guard.paused:
        return None  # the evaluation's own gate says what happens
    interval = settings_store.schedule_config(session).interval_minutes
    since = moment - timedelta(minutes=max(1, interval))
    recent = (
        EnforcementAction.created_at >= since,
        EnforcementAction.status.in_((EnforcementStatus.APPLIED, EnforcementStatus.PENDING)),
    )
    limits = session.scalar(
        select(func.count(func.distinct(EnforcementAction.limit_id))).where(*recent)
    )
    targets = session.scalar(
        select(func.count(func.distinct(EnforcementAction.target_id))).where(*recent)
    )
    over_limits = 0 < guard.max_new_per_cycle < int(limits or 0) + starting
    over_targets = 0 < guard.max_new_targets_per_cycle <= int(targets or 0)
    if over_limits or over_targets:
        return (
            "left to the full cycle: restrictions started in the last "
            f"{interval} minute(s) are at the safety ceiling"
        )
    return None


# ----------------------------------------------------------------- status


def _record(result: FastCheckResult, moment: datetime) -> None:
    entry = {
        "at": moment.isoformat(),
        "trigger": result.trigger,
        "result": result.summary(),
        "requests": result.requests,
        "seconds": result.seconds,
        "hint": result.hint,
    }
    key = _db_key()
    with _memory_lock:
        previous = _last.get(key)
        stored = dict(previous or {})
        stored["last_run"] = entry
        if result.acted or result.error:
            stored["last_action"] = entry
        _last[key] = stored
    try:
        with session_scope() as session:
            persisted = settings_store.get_value(session, settings_store.KEY_FAST_CHECK_STATUS)
            persisted = persisted if isinstance(persisted, dict) else {}
            last_run = persisted.get("last_run") if isinstance(persisted, dict) else None
            last_at = _parse(last_run.get("at")) if isinstance(last_run, dict) else None
            due = last_at is None or moment - last_at >= STATUS_HEARTBEAT
            error_changed = (persisted.get("error") or None) != (result.error or None)
            if not (result.acted or error_changed or due):
                return
            updated = dict(persisted)
            updated["last_run"] = entry
            updated["error"] = result.error
            if result.acted or result.error:
                updated["last_action"] = entry
            settings_store.set_value(
                session,
                settings_store.KEY_FAST_CHECK_STATUS,
                updated,
                description="The fast check's last run and last action (bookkeeping).",
            )
    except Exception:  # noqa: BLE001 - the status is informational
        logger.warning("Could not record the fast check's status", exc_info=True)


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def describe(session: Session) -> dict[str, Any]:
    """For Diagnose and the Settings page."""
    settings = config(session)
    persisted = settings_store.get_value(session, settings_store.KEY_FAST_CHECK_STATUS)
    persisted = persisted if isinstance(persisted, dict) else {}
    live = last_status() or {}
    return {
        "enabled": settings.enabled,
        "interval_seconds": settings.interval_seconds,
        "min_seconds": MIN_SECONDS,
        "max_seconds": MAX_SECONDS,
        "last_run": live.get("last_run") or persisted.get("last_run"),
        "last_action": live.get("last_action") or persisted.get("last_action"),
        "error": persisted.get("error"),
        "queued": pending(),
        "requests_per_hour": requests_per_hour(settings.interval_seconds),
    }


def requests_per_hour(interval_seconds: int) -> int:
    """Checkmarx requests per hour while nothing is restricted: one page per
    tick (two when the tail crosses a page boundary)."""
    return 3600 // max(1, interval_seconds)
