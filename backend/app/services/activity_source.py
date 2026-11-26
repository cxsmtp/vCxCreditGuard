"""The credit activity log as the usage source of period budgets.

The consumption summary (``GET /api/credits/consumption``) reports cumulative
totals per *name*, which the ledger (app/services/ledger.py) turns into
increases matched to entities by name. On a live tenant most project and user
credits matched nothing that way. The activity log (``GET
/api/credits/activity``) reports every billed action with its date, its
project's id and its application's id, and the person's email or name, and
its sum equals the summary's total. With the setting ``usage.source`` at
"activity" (the default) it is the source of the project, user and
application views; the summary feed keeps feeding everything else (a group's
own row), and takes over whenever the log cannot be read.

Counting without row ids
------------------------
The log has no row id, and identical rows are distinct events (two triage
actions in the same second): nothing is ever deduplicated. A row's identity is
the fields that describe the action itself and are assumed never to change for
a past action - date, action, credits, project ids, scan ids, scanner
(``event_key``) - and ``usage_activity_key`` keeps how many rows of each
identity have been seen. A fetch holding ``n`` rows of one identity counts
``max(0, n - seen)`` new events and raises ``seen`` to ``n``, in the
transaction that adds them to the budget counters, under the attribution lock.
``seen`` never falls, so an event is counted at most once as long as no fetch
shows more rows of an identity than the log holds. Who (user, email) and the
application may be filled in or changed later for the same action, so they are
not part of the identity; the new events of an identity count towards a person
or an application only when every row of it in the read names the same one
(``_count``), else only towards its project and what the project belongs to.
Keys are pruned once older than the window, and nothing older than the highest
cutoff ever used is counted, even if the clock goes back.

Fetching so that no row is read twice
-------------------------------------
Pages are read in ascending page order of ``sort_by=date&sort_order=asc``
(every Checkmarx call before the write transaction opens). New rows append at
the end; rows ageing out leave from the front, which moves every row one place
earlier, so a row near a page boundary can be skipped, never read twice. Each
page is a slice of a date-sorted list as of its own request, and it follows
that a row read on page k can only be read again on a later page if every
boundary in between has the same date on both sides. So, for every pair of
adjacent pages:

* the first date of the next page is later than the last of this one: no row
  of either side can repeat across it;
* the same date: rows of that date may repeat (a tie reordered between the two
  requests, or a row inserted earlier): that date is uncertain this cycle, its
  rows are neither counted nor recorded, and the next read covers it again;
* earlier (the order went back): something other than drift happened; the
  whole fetch counts nothing.

Within a page the dates must not go back (else the log is not sorted as asked
and the answer is treated as malformed). With that, no identity is ever read
more times than the log holds, whether or not the fetch was complete, and an
over-count cannot happen. Completeness - ``totalItems`` the same on the first
and the last page, and as many rows read as it says lie from the first page
read to the end - only decides how far the read cursor moves: a skip is an
under-count, made up by the next reads, which cover the last ``OVERLAP`` again
every cycle. When the per-cycle page cap or the cycle's time budget stops a
read early, the last date read may continue on the next page: it is left out
(only complete data counts) and the next cycle starts there.

A normal cycle reads from a page before the cursor (where the last ``OVERLAP``
of the log began, one page earlier for rows that aged out meanwhile) to the
end: two or three requests on a tenant with 100k rows in 30 days. Once a day
(``SWEEP_EVERY``) the whole window is read instead (counting late rows too)
and its sum is compared with the summary's total for the same window
(``reconciliation``, shown in Diagnose).

Switching source
----------------
The same usage is never counted from both sources:

* When the log becomes the source (the setting turned on, or the log back
  after a fallback), its first fetch only records what it holds and counts
  nothing, and events dated before that moment (``floor_at``) are never
  counted from it. The summary feed stops feeding the views the log covers in
  the same cycle. Lost: what happened between the summary's last reading and
  that first fetch (one cycle).
* When the log stops being the source (the setting turned off, a 403 or 404,
  a malformed answer, or an outage - or a failure of this step itself - longer
  than ``OUTAGE_GRACE``), the summary feed's first ``SUMMARY_PAUSE_READINGS``
  (2) readings of each covered view count nothing (``summary_paused``), and
  they rebase the ledger's memory of names of those views: every name it
  remembers (missing, or holding a fall or a ceiling, present or not) becomes
  kind "rebase", and starts from what it reports in the next reading the
  completeness checks believe, never from a total from before or during the
  log's era. Lost:
  what happened between the log's last fetch and the third reading (two to
  three cycles), and the usage of a name missing across the handover until it
  returns. This assumes the summary reports an event no later than about two
  cycles after the log does (they are the same data: their sums matched
  exactly).
* During a shorter outage the log stays the source and nothing is counted;
  what happened meanwhile is counted when it answers again.

Group budgets
-------------
The summary's group view is not covered by the log: a plain group budget whose
group has a row of its own there is fed by that row, otherwise (and always with
member usage) the log feeds it through its projects and members. The log takes
a budget over from the row's reading on (``group_feeds``), and then counts
towards it only events dated from that moment: never one the row counted
before. When the row takes a budget back that the log fed, the group view's
next two readings count nothing. Lost: events dated before a takeover that the
log counts after it, and two group readings at a hand-back.

Who it counts towards
---------------------
An event counts towards the budgets of its project (by id), of the project's
groups (as the ledger feeds them: not a group budget its own summary row feeds),
of its application (its ``applicationIds[0]`` and the project's applications),
and of its person: by email, else by username (Settings → Attribution's
mappings and the matching ladder of the summary), else nobody, with the name
raised under Settings → Attribution. Each budget counts an event once, in the
month and quarter of the event's own date, and only an event dated after the
budget was created.

Integration accounts (``is_integration_account``: "[bot]" accounts, known bots,
Auto-triage, Auto-remediation, the names listed in the setting
``attribution.integration_accounts``, and handles the matcher takes for an
integration) count towards their project as any usage does. Towards a person
only when their project had no active project budget at the event's date (by
``BudgetHistory``, which records when each project budget may have been active
and never changes its answer for a past date; a budget switched off and on
between two observations counts as active throughout):
Auto-triage and Auto-remediation then through the existing auto-triage
attribution (the scan initiator, when that setting is on and it resolves one;
nobody otherwise), any other account through an admin's mapping, or towards a
user budget set on the account itself (``subject:<name>``). An event is
charged to one user budget at most.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.checkmarx import activity as activity_api
from app.checkmarx import usage as usage_api
from app.checkmarx.activity import ActivityEvent, ActivityMalformedError, ActivityPage
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import (
    CheckmarxError,
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxResponseError,
)
from app.db.base import utcnow
from app.models.activity import (
    ActivityEventCount,
    ActivitySourceState,
    is_subject_entity,
    subject_entity_id,
)
from app.models.enums import ActionType, EntityType, PeriodType, UsageView
from app.models.limits import CreditLimit
from app.models.org import (
    CxApplicationProject,
    CxGroupMembership,
    CxProjectGroup,
)
from app.models.usage import BudgetUsage, UnresolvedSubject, UsageSnapshot
from app.services import error_text, pacing, settings_store, subject_matching

logger = logging.getLogger(__name__)

ZERO = Decimal("0")

COVERED_VIEWS: tuple[str, ...] = (
    UsageView.PROJECT.value,
    UsageView.USER.value,
    UsageView.APPLICATION.value,
)

ACTIVE = "active"
INACTIVE = "inactive"
FALLBACK = "fallback"
OFF = "off"

# Every cycle reads the log again from this long before its newest row, so a
# row skipped by drift (or arriving late) is read again by the next cycles.
OVERLAP = timedelta(hours=2)
# An outage (5xx, timeout, rate limit) shorter than this keeps the log as the
# source: nothing is counted meanwhile, and it is counted when the log answers.
OUTAGE_GRACE = timedelta(hours=1)
# After a 403, a 404 or a malformed answer, the log is asked again after this.
REPROBE_AFTER = timedelta(hours=6)
# How often the whole window is read and its sum compared with the summary.
SWEEP_EVERY = timedelta(hours=24)
SWEEP_MAX_PAGES = 400
# Keys are kept this long beyond the log's window, and an event older than
# the window plus this is never counted.
PRUNE_MARGIN = timedelta(days=1)
# A reconciliation difference above both of these is a mismatch.
MISMATCH_RATIO = Decimal("0.005")
MISMATCH_FLOOR = Decimal("1")

_AUTO_TRIAGE = frozenset({"auto-triage", "auto triage", "autotriage", "auto_triage"})
_GRANULARITIES = (PeriodType.MONTHLY, PeriodType.QUARTERLY)
FUSION_MODEL = "fusion_model:"


# ------------------------------------------------------------------ results


@dataclass
class ActivityResult:
    enabled: bool = False
    status: str = INACTIVE
    # The log is the source of the covered views after this cycle.
    source_active: bool = False
    seeded: bool = False
    sweep: bool = False
    read_failed: bool = False
    pages: int = 0
    rows: int = 0
    bad_rows: int = 0
    events_counted: int = 0
    credits_counted: Decimal = ZERO
    # Rows left for a later cycle: a date repeated across a page boundary, or
    # the last date of a read the cap or time budget stopped.
    uncertain_rows: int = 0
    # The page size asked for this cycle.
    page_size: int = 0
    partial: bool = False
    complete: bool = False
    issues: list[str] = field(default_factory=list)
    # Of the counted events, by where the user dimension went.
    user_outcomes: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)

    def as_stats(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "status": self.status,
            "source_active": self.source_active,
            "seeded": self.seeded,
            "sweep": self.sweep,
            "read_failed": self.read_failed,
            "pages": self.pages,
            "rows": self.rows,
            "bad_rows": self.bad_rows,
            "events_counted": self.events_counted,
            "credits_counted": str(self.credits_counted),
            "uncertain_rows": self.uncertain_rows,
            "page_size": self.page_size,
            "partial": self.partial,
            "complete": self.complete,
            "issues": list(self.issues),
            "user_outcomes": dict(self.user_outcomes),
            "error": self.error,
        }


# --------------------------------------------------------------- the state


def _state(session: Session) -> ActivitySourceState | None:
    return session.get(ActivitySourceState, 1)


def _state_for_write(session: Session) -> ActivitySourceState:
    """The state row, created if missing. Call under the attribution lock."""
    state = _state(session)
    if state is None:
        state = ActivitySourceState(id=1, status=INACTIVE, revision=0)
        session.add(state)
        session.flush()
    return state


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


def _parse(value: object) -> datetime | None:
    return activity_api.parse_date(value) if isinstance(value, str) else None


def source_active(session: Session) -> bool:
    """True while the log is the source of the project, user and application
    views (the summary feed does not feed their budgets)."""
    state = _state(session)
    return state is not None and state.status == ACTIVE


# After the log stops being a view's source (or stops feeding a group budget
# through its projects), this many summary readings of the view count
# nothing: a summary that reports an event up to about two cycles after the
# log did cannot count it again.
SUMMARY_PAUSE_READINGS = 2


def summary_feeds(session: Session, view: str, snapshot: UsageSnapshot) -> bool:
    """Whether a summary reading of ``view`` feeds budget counters. Call
    under the attribution lock, with the new reading stored.

    Not while the log is the source of the view, nor in the first
    ``SUMMARY_PAUSE_READINGS`` readings after it stopped being the source
    (their increases span usage the log may have counted). The same pause
    applies to the group view after the log stopped feeding a group budget
    through its projects (``group_feeds``)."""
    view = str(view)
    state = _state(session)
    if state is None:
        return True
    if view in COVERED_VIEWS and state.status == ACTIVE:
        return False
    if view == UsageView.GROUP.value and _groups_taken_back(session, state, snapshot):
        # A group's own row is back for a budget the log fed through its
        # projects: this reading and the next count nothing.
        from app.services import ingestion

        previous = ingestion.latest_live_snapshot(session, view, excluding=snapshot.id)
        paused_views = dict(state.summary_paused or {})
        paused_views[view] = previous.id if previous is not None else 0
        state.summary_paused = paused_views
    paused = (state.summary_paused or {}).get(view)
    if not isinstance(paused, int):
        return True
    return _readings_since(session, view, paused, snapshot.id) >= SUMMARY_PAUSE_READINGS


def _own_rows(session: Session, snapshot: UsageSnapshot) -> set[str]:
    from app.models.usage import UsageRecord

    return {
        str(entity_id)
        for entity_id in session.scalars(
            select(UsageRecord.entity_id).where(
                UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.is_not(None)
            )
        )
    }


def _plain_group_entries(
    session: Session, state: ActivitySourceState, own: set[str]
) -> list[tuple[str, dict]]:
    """The log's group-feed entries of plain group budgets whose group has a
    row of its own in ``own``: the group view feeds them from now on."""
    feeds = state.group_feeds or {}
    if not feeds or not own:
        return []
    found = []
    for limit in session.scalars(
        select(CreditLimit).where(
            CreditLimit.entity_type == EntityType.GROUP.value,
            CreditLimit.include_member_usage.is_(False),
        )
    ):
        entry = _entry_of(feeds, limit)
        if entry is not None and str(limit.entity_id) in own:
            found.append((str(limit.id), entry))
    return found


def _group_identity(limit: CreditLimit) -> dict[str, object]:
    return {"entity": str(limit.entity_id), "created": _iso(limit.created_at)}


def _entry_of(feeds: dict, limit: CreditLimit) -> dict | None:  # type: ignore[type-arg]
    """The log's group-feed entry of this budget: keyed by id, and only if it
    names the budget's group and creation time (a deleted budget's id can be
    handed to a new one, which must not inherit its floor or its "fed")."""
    entry = feeds.get(str(limit.id))
    if not isinstance(entry, dict):
        return None
    identity = _group_identity(limit)
    if "entity" in entry and any(entry.get(key) != value for key, value in identity.items()):
        return None
    return entry


def _groups_taken_back(session: Session, state: ActivitySourceState, snapshot) -> bool:  # type: ignore[no-untyped-def]
    entries = _plain_group_entries(session, state, _own_rows(session, snapshot))
    return any(entry.get("fed") for _key, entry in entries)


def _readings_since(session: Session, view: str, paused: int, current: int) -> int:
    """Live readings of the view after ``paused``, the current one aside."""
    from sqlalchemy import func

    return int(
        session.scalar(
            select(func.count())
            .select_from(UsageSnapshot)
            .where(
                UsageSnapshot.view_by == view,
                UsageSnapshot.id > paused,
                UsageSnapshot.id != current,
                UsageSnapshot.held_reason.is_(None),
                UsageSnapshot.period_param.is_distinct_from(settings_store.DEMO_PERIOD_PARAM),
            )
        )
        or 0
    )


def after_summary_reading(
    session: Session, view: str, snapshot: UsageSnapshot, records: list, *, fed: bool
) -> None:
    """After the ledger read a summary reading. Call under the attribution
    lock, in its transaction.

    While the log is the source of a covered view, remember the reading: the
    summary's next readings count nothing once the log stops. A reading
    paused for a handover is also a rebase for the ledger's per-name memory
    of the view: every name it remembers (missing, a held dip, or any other
    kind) last reported a total from before or during the log's era, so a
    name present now continues from what it reports now (its memory is
    dropped), and a name still missing starts, when it returns, from what it
    reports then (kind "rebase"), as after a reading in another lookback
    window. Otherwise its return would count, as one increase, usage the log
    already counted."""
    view = str(view)
    state = _state(session)
    if state is None:
        return
    if view == UsageView.GROUP.value:
        # A group with a row of its own in this reading is fed by the group
        # view from now on: the log stops feeding it, and takes it over again
        # (from a later date) only if the row leaves.
        taken = _plain_group_entries(session, state, _own_rows(session, snapshot))
        if taken:
            feeds = dict(state.group_feeds or {})
            for key, _entry in taken:
                feeds.pop(key, None)
            state.group_feeds = feeds
    if view in COVERED_VIEWS and state.status == ACTIVE:
        paused = dict(state.summary_paused or {})
        paused[view] = snapshot.id
        state.summary_paused = paused
        return
    if fed or not isinstance((state.summary_paused or {}).get(view), int):
        return
    _rebase_names(session, view, snapshot, records)


def _rebase_names(session: Session, view: str, snapshot: UsageSnapshot, records: list) -> None:
    from app.models.usage import UsageMissingName
    from app.services import ledger

    for row in list(
        session.scalars(select(UsageMissingName).where(UsageMissingName.view_by == view))
    ):
        # Every kind, the name present or not: a held fall (or ceiling) of a
        # name present now may be a glitch of this very reading, and dropping
        # it would count the recovery. As "rebase", the name counts nothing
        # until it is read again in a reading the checks believe.
        row.kind = ledger.REBASE
        row.period_param = snapshot.period_param
    session.flush()


def _start_era(state: ActivitySourceState, now: datetime) -> None:
    eras = [list(era) for era in (state.eras or []) if isinstance(era, list) and len(era) == 2]
    eras.append([_iso(now), None])
    # Kept for as long as any charge it covers can still count.
    horizon = now - timedelta(days=400)
    state.eras = [era for era in eras if era[1] is None or (_parse(era[1]) or now) >= horizon]


def _end_era(state: ActivitySourceState, now: datetime) -> None:
    eras = [list(era) for era in (state.eras or []) if isinstance(era, list) and len(era) == 2]
    for era in eras:
        if era[1] is None:
            era[1] = _iso(now)
    state.eras = eras


def _stop(state: ActivitySourceState, status: str, now: datetime) -> None:
    if state.status == ACTIVE:
        _end_era(state, now)
    # The summary feeds the group budgets the log fed through their
    # projects again, after its pause of the covered views.
    state.group_feeds = None
    state.status = status
    state.resume_at = None
    state.resume_position = None
    state.failing_since = None
    state.revision = (state.revision or 0) + 1


# ------------------------------------------------------- integration rule


def is_integration_account(name: str | None, email: str | None, extras: frozenset[str]) -> bool:
    """A bot or an automation account, by its name alone: "[bot]" accounts and
    known bots, Auto-triage and Auto-remediation (``is_synthetic_subject``),
    and the names an admin listed (``attribution.integration_accounts``)."""
    from app.services.ingestion import is_synthetic_subject

    for value in (name, email):
        if not value or not value.strip():
            continue
        low = value.strip().lower()
        if is_synthetic_subject(low) or low in extras or subject_matching.is_bot_subject(low):
            return True
    return False


def listed_extras(session: Session) -> frozenset[str]:
    return frozenset(name.lower() for name in settings_store.integration_accounts(session))


def initiator_skip(session: Session) -> Callable[[object], bool] | None:
    """For evaluation: the auto-triage charges to scan initiators that the
    integration-account rule keeps off user budgets - those observed while
    the log was the source, on a project that may have had an active project
    budget then (``ProjectBudgetInterval``, observed by ``observe_budgets``:
    the answer for a past charge never changes). None when there are none
    (the log was never the source)."""
    state = _state(session)
    eras: list[tuple[datetime, datetime | None]] = []
    for era in (state.eras or []) if state is not None else []:
        if isinstance(era, list) and len(era) == 2 and _parse(era[0]) is not None:
            eras.append((_parse(era[0]), _parse(era[1])))  # type: ignore[arg-type]
    if not eras:
        return None
    governed = BudgetHistory(session, utcnow(), persist=False)
    if not governed.intervals:
        return None

    def skip(part: object) -> bool:
        when = getattr(part, "observed_at", None)
        project_id = getattr(part, "project_id", None)
        if when is None or project_id is None:
            return False
        if not any(start <= when and (end is None or when < end) for start, end in eras):
            return False
        return governed.covers(str(project_id), when)

    return skip


class BudgetHistory:
    """When each project's budgets may have been active (``usage_budget_interval``),
    brought up to date with what is true at ``now``.

    An interval starts when its budget was created (or, for a budget seen
    active again, when it was last seen inactive) and ends when it is first
    seen inactive or gone. Every observation is made before any decision
    that uses it, so a date found outside every interval of a project is
    never inside one later: a decision about a past event never changes. It
    can only err towards a project budget having been active (a budget off
    and on again between two observations), which keeps usage off user
    budgets: an under-count, never an over-count."""

    def __init__(self, session: Session, now: datetime, *, persist: bool) -> None:
        from app.models.activity import ProjectBudgetInterval

        self.intervals: dict[str, list[tuple[datetime, datetime | None]]] = defaultdict(list)
        limits = {
            limit.id: limit
            for limit in session.scalars(
                select(CreditLimit).where(CreditLimit.entity_type == EntityType.PROJECT.value)
            )
        }
        rows = list(
            session.scalars(select(ProjectBudgetInterval).order_by(ProjectBudgetInterval.id))
        )

        def close(index: int, row: ProjectBudgetInterval) -> None:
            if persist:
                row.end_at = now
                row.checked_at = now
            else:
                rows[index] = ProjectBudgetInterval(
                    limit_id=row.limit_id,
                    project_id=row.project_id,
                    budget_created_at=row.budget_created_at,
                    start_at=row.start_at,
                    end_at=now,
                    checked_at=now,
                )

        # The latest row of each budget. A row is a budget's only if it names
        # the budget's project and creation time too: a deleted budget's id
        # can be handed to a new one (SQLite reuses the highest id), and the
        # new one must not take over the old one's history.
        latest: dict[int, int] = {}
        for index, row in enumerate(rows):
            limit = limits.get(row.limit_id)
            if limit is None or _same_budget(row, limit):
                latest[row.limit_id] = index
            elif row.end_at is None:
                # Another budget's (now gone) open interval: it ends now.
                close(index, row)
        made: list[ProjectBudgetInterval] = []
        for limit_id, limit in limits.items():
            index = latest.get(limit_id)
            row = rows[index] if index is not None else None
            created = limit.created_at or now
            if limit.is_active:
                if row is None:
                    made.append(_interval(limit, created, None, now))
                elif row.end_at is not None:
                    # Seen inactive until row.checked_at: active again since.
                    made.append(_interval(limit, row.checked_at, None, now))
            elif row is None:
                made.append(_interval(limit, created, created, now))
            elif row.end_at is None:
                close(index, row)  # type: ignore[arg-type]
            elif persist:
                row.checked_at = now
        for limit_id, index in latest.items():
            if limit_id not in limits and rows[index].end_at is None:
                close(index, rows[index])  # deleted: it ends now
        if persist:
            for row in made:
                session.add(row)
            session.flush()
        for row in [*rows, *made]:
            if row.end_at is None or row.end_at > row.start_at:
                self.intervals[row.project_id].append((row.start_at, row.end_at))

    def covers(self, project_id: str | None, when: datetime) -> bool:
        if not project_id:
            return False
        return any(
            start <= when and (end is None or when < end)
            for start, end in self.intervals.get(project_id, ())
        )


def _same_budget(row, limit: CreditLimit) -> bool:  # type: ignore[no-untyped-def]
    return row.project_id == str(limit.entity_id)[:64] and (
        row.budget_created_at is None
        or limit.created_at is None
        or row.budget_created_at == limit.created_at
    )


def _interval(limit: CreditLimit, start: datetime, end: datetime | None, now: datetime):  # type: ignore[no-untyped-def]
    from app.models.activity import ProjectBudgetInterval

    return ProjectBudgetInterval(
        limit_id=limit.id,
        project_id=str(limit.entity_id)[:64],
        budget_created_at=limit.created_at,
        start_at=start,
        end_at=end,
        checked_at=now,
    )


def observe_budgets(session: Session, now: datetime | None = None) -> None:
    """Record what the project budgets are now (evaluation calls this before
    it judges any limit; every activity-log write does too)."""
    BudgetHistory(session, now or utcnow(), persist=True)


# ----------------------------------------------------------------- reading


@dataclass
class _Plan:
    now: datetime
    seed: bool
    sweep: bool
    start_page: int | None
    size: int
    cap: int | None
    resume_at: datetime | None
    resume_position: int | None
    floor_at: datetime | None
    revision: int
    reconcile_view: str


@dataclass
class _Read:
    pages: list[ActivityPage]
    start_page: int
    size: int
    partial: bool = False
    stopped_by: str | None = None
    requests: int = 0
    summary_total: Decimal | None = None
    summary_error: str | None = None


def _alternate(size: int) -> int:
    return max(1, size - max(1, size // 37))


def _plan(session: Session, state: ActivitySourceState | None, now: datetime) -> _Plan:
    seed = state is None or state.status != ACTIVE
    requested = activity_api.ACTIVITY_PAGE_SIZE
    stats = (state.last_stats or {}) if state is not None else {}
    if "uncertain_dates" in (stats.get("issues") or []) and stats.get("page_size") == requested:
        # Rows of one date met at a page boundary last time: another page size
        # moves the boundaries, so they can be read whole this time.
        requested = _alternate(requested)
    # Positions are in the server's own page size when it serves fewer rows
    # than asked (``page_size`` is only set then).
    server = state.page_size if state is not None else None
    size = min(requested, server) if server else requested
    # A sweep the cycle's time budget stopped is tried again, every other
    # cycle: the cycles between read the tail as usual.
    timed_out = bool(stats.get("sweep")) and "stopped_by_time_budget" in (stats.get("issues") or [])
    sweep = (
        not seed
        and state is not None
        and not timed_out
        and (state.last_sweep_at is None or now - state.last_sweep_at >= SWEEP_EVERY)
    )
    cap = settings_store.activity_max_pages(session) or None
    if sweep:
        cap = max(cap or 0, SWEEP_MAX_PAGES)
    start: int | None
    if seed or state is None:
        start = None
    elif sweep:
        start = 1
    elif state.resume_position is None:
        start = None
    else:
        # A little earlier than the cursor: rows that aged out of the window
        # since moved every row that many places towards the front.
        margin = max(1, size // 10)
        start = max(0, state.resume_position - margin) // size + 1
    from app.services import ingestion

    reconcile_view = (
        UsageView.ACTION.value
        if ingestion.dimension_supported(session, UsageView.ACTION)
        else UsageView.USER.value
    )
    return _Plan(
        now=now,
        seed=seed,
        sweep=sweep,
        start_page=start,
        size=requested,
        cap=cap,
        resume_at=(now if seed else (state.resume_at if state is not None else None)),
        resume_position=None if seed or state is None else state.resume_position,
        floor_at=(now if seed else (state.floor_at if state is not None else now)),
        revision=0 if state is None else int(state.revision or 0),
        reconcile_view=reconcile_view,
    )


def _is_last(page: ActivityPage, number: int, size: int) -> bool:
    if page.rows == 0:
        return True
    if page.total_pages is not None:
        return number >= page.total_pages
    return page.rows < size


def _read(client: CheckmarxClient, plan: _Plan) -> _Read:
    """Read the log from the planned page to its end. Touches no database."""
    requests = 0

    def get(number: int) -> ActivityPage:
        nonlocal requests
        requests += 1
        return activity_api.fetch_page(client, number, size=plan.size)

    pages: list[ActivityPage] = []
    start = plan.start_page
    restarted = False
    done = False
    if start is None:
        # No cursor: page 1 says how many pages there are; read the tail.
        first = get(1)
        if (first.total_pages or 1) > 2:
            start = (first.total_pages or 1) - 1
            restarted = True
        else:
            start = 1
            pages.append(first)
            done = _is_last(first, 1, plan.size)
    number = start + len(pages)
    partial = False
    stopped_by: str | None = None
    while not done:
        if plan.cap is not None and requests >= plan.cap:
            partial, stopped_by = True, "page cap"
            break
        if pacing.out_of_time():
            partial, stopped_by = True, "time budget"
            break
        page = get(number)
        if (
            not pages
            and page.rows == 0
            and (page.total_pages or 0) > 0
            and number > (page.total_pages or 0)
            and not restarted
        ):
            # The log is shorter than the cursor thought: start at its tail.
            restarted = True
            start = number = max(1, (page.total_pages or 1) - 1)
            continue
        pages.append(page)
        done = _is_last(page, number, plan.size)
        number += 1
    read = _Read(
        pages=pages,
        start_page=start,
        size=plan.size,
        partial=partial,
        stopped_by=stopped_by,
        requests=requests,
    )
    if plan.sweep and not partial:
        try:
            read.summary_total = _summary_total(client, plan.reconcile_view)
        except CheckmarxError as exc:
            read.summary_error = error_text.public_error(exc)
    return read


def _summary_total(client: CheckmarxClient, view: str) -> Decimal:
    """The consumption summary's total over the log's window."""
    total = ZERO
    for page in usage_api.fetch_usage(
        client, view_by=view, period=activity_api.ACTIVITY_PERIOD, page_size=100
    ):
        total += sum((item.credits_used for item in page.items), ZERO)
    return total


# ---------------------------------------------------------------- analysis


@dataclass
class _Analysis:
    # key -> (rows of it in this read, those rows)
    counts: dict[str, tuple[int, list[ActivityEvent]]]
    uncertain: set[datetime]
    # Of those, dates met at a page boundary (the others: the last date of a
    # read the cap or time budget stopped).
    ties: set[datetime]
    regression: bool
    newest: datetime | None
    stable: bool
    rows_match: bool
    coverage_gap: bool
    rows: int
    bad_rows: int
    credits: Decimal
    size: int
    # (position in the log, date), in read order.
    positions: list[tuple[int, datetime]]
    end_position: int


def _analyse(read: _Read, plan: _Plan) -> _Analysis:
    pages = read.pages
    # The server's own page size, if smaller than asked: positions use it.
    size = read.size
    for page in pages[:-1]:
        if 0 < page.rows < size:
            size = page.rows
    for page in pages:
        dates = [event.date for event in page.events]
        if any(later < earlier for earlier, later in zip(dates, dates[1:], strict=False)):
            raise ActivityMalformedError(
                "The credit activity log is not sorted by date as asked, so new rows cannot "
                "be told from rows read before."
            )
    uncertain: set[datetime] = set()
    regression = False
    filled = [page for page in pages if page.events]
    for before, after in zip(filled, filled[1:], strict=False):
        last, first = before.events[-1].date, after.events[0].date
        if first < last:
            regression = True
        elif first == last:
            uncertain.add(first)
    ties = set(uncertain)
    if read.partial and filled:
        # The last date read may continue on the page not read.
        uncertain.add(filled[-1].events[-1].date)
    counts: dict[str, tuple[int, list[ActivityEvent]]] = {}
    positions: list[tuple[int, datetime]] = []
    credits = ZERO
    for page in pages:
        for event in page.events:
            key = event.key
            seen, rows_of = counts.get(key, (0, []))
            rows_of.append(event)
            counts[key] = (seen + 1, rows_of)
            positions.append(((page.number - 1) * size + event.index, event.date))
            credits += event.credits
    rows = sum(page.rows for page in pages)
    totals = [page.total_items for page in pages if page.total_items is not None]
    stable = bool(totals) and totals[0] == totals[-1]
    rows_match = stable and not read.partial and rows == totals[-1] - (read.start_page - 1) * size
    first_date = filled[0].events[0].date if filled else None
    coverage_gap = (
        read.start_page > 1
        and plan.resume_at is not None
        and first_date is not None
        and first_date >= plan.resume_at
    )
    end_position = (pages[-1].number - 1) * size + pages[-1].rows if pages else 0
    return _Analysis(
        counts=counts,
        uncertain=uncertain,
        ties=ties,
        regression=regression,
        newest=max((date for _pos, date in positions), default=None),
        stable=stable,
        rows_match=rows_match,
        coverage_gap=coverage_gap,
        rows=rows,
        bad_rows=sum(page.bad_rows for page in pages),
        credits=credits,
        size=size,
        positions=positions,
        end_position=end_position,
    )


def horizon(now: datetime) -> datetime:
    """Events older than this are never counted, and their keys are pruned."""
    return now - timedelta(days=activity_api.ACTIVITY_PERIOD_DAYS) - PRUNE_MARGIN


# ------------------------------------------------------------------ targets


class _Targets:
    """Which budgets an event counts towards, read once per write."""

    def __init__(
        self,
        session: Session,
        now: datetime,
        history: BudgetHistory,
        group_floors: dict[int, datetime],
    ) -> None:
        from app.services import ingestion

        self.session = session
        self.now = now
        self.by_target: dict[tuple[str, str], list[CreditLimit]] = defaultdict(list)
        for limit in session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))):
            self.by_target[(str(limit.entity_type), str(limit.entity_id))].append(limit)
        self.history = history
        # The group budgets the log feeds through their projects (and members),
        # and the date from which (``_observe_groups``).
        self.group_floors = group_floors
        self.fed_groups: set[int] = set()
        self.index = ingestion.build_user_index(session)
        # One matching per reported name and fetch.
        self._outcomes: dict[tuple[str, str, str], object] = {}
        self.extras = listed_extras(session)
        self.project_groups: dict[str, list[str]] = defaultdict(list)
        self.project_apps: dict[str, list[str]] = defaultdict(list)
        self.user_groups: dict[str, list[str]] = defaultdict(list)
        self.raised: set[str] = set()

    def load_links(self, project_ids: set[str], user_ids: set[str]) -> None:
        for owner, member, ids, into in (
            (CxProjectGroup.group_id, CxProjectGroup.project_id, project_ids, self.project_groups),
            (
                CxApplicationProject.application_id,
                CxApplicationProject.project_id,
                project_ids,
                self.project_apps,
            ),
            (CxGroupMembership.group_id, CxGroupMembership.user_id, user_ids, self.user_groups),
        ):
            ordered = sorted(ids)
            for start in range(0, len(ordered), 500):
                for owner_id, member_id in self.session.execute(
                    select(owner, member).where(member.in_(ordered[start : start + 500]))
                ):
                    into[str(member_id)].append(str(owner_id))

    def user_entity(self, event: ActivityEvent) -> tuple[str | None, str]:
        """(the user-budget entity this event's person counts towards, why)."""
        from app.services.ingestion import is_synthetic_subject

        key = event.subject_key
        if not key:
            return None, "no_user"
        cache = (key, event.user, event.user_email)
        outcome = self._outcomes.get(cache)
        if outcome is None:
            outcome = self.index.resolve_detailed(
                subject_key=key,
                name=event.user or None,
                email=event.user_email or None,
                integrations=True,
            )
            self._outcomes[cache] = outcome
        integration = is_integration_account(event.user, event.user_email, self.extras) or (
            outcome.is_bot and outcome.counted_user_id is None
        )
        if integration:
            if self.history.covers(event.project_id, event.date):
                # Its project had (or may have had) an active project budget at
                # the event's date: that is where it counts, never also
                # against a person.
                return None, "project_budget"
            if is_synthetic_subject(event.user) or is_synthetic_subject(key):
                # Auto-triage and Auto-remediation: the scan initiator, through
                # auto-triage attribution (app/services/auto_triage_attribution.py).
                return None, "initiator"
            if outcome.counted_user_id:
                return outcome.counted_user_id, "user"
            self._raise(event, outcome, bot=True)
            return subject_entity_id(key), "subject"
        if outcome.counted_user_id:
            return outcome.counted_user_id, "user"
        self._raise(event, outcome, bot=False)
        return None, "unmatched"

    def _raise(self, event: ActivityEvent, outcome, *, bot: bool) -> None:  # type: ignore[no-untyped-def]
        """Raise the name under Settings → Attribution, the existing way, when
        the summary has not already."""
        key = event.subject_key
        if key in self.raised:
            return
        self.raised.add(key)
        row = self.session.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == key)
        )
        if row is not None:
            row.last_seen_at = self.now
            if bot and not row.is_bot and row.mapped_user_id is None:
                row.is_bot = True
            return
        top = outcome.candidates[0] if outcome.candidates else None
        self.session.add(
            UnresolvedSubject(
                subject_key=key,
                subject_name=(event.user or None),
                subject_email=(event.user_email or None),
                view_by=UsageView.USER.value,
                credits_used=ZERO,
                first_seen_at=self.now,
                last_seen_at=self.now,
                times_seen=1,
                status=outcome.method,
                is_bot=bot or outcome.is_bot,
                suggested_user_id=top.user_id if top else None,
                match_score=top.score if top else None,
                suggestions=[candidate.as_dict() for candidate in outcome.candidates] or None,
            )
        )

    def budgets(
        self, event: ActivityEvent, user_id: str | None, application_id: str | None
    ) -> list[CreditLimit]:
        found: dict[int, CreditLimit] = {}
        floors = self.group_floors

        def via_log(limit: CreditLimit) -> bool:
            since = floors.get(limit.id)
            return since is not None and event.date >= since

        def add(entity_type: str, entity_id: str, keep=lambda _limit: True) -> None:  # type: ignore[no-untyped-def]
            for limit in self.by_target.get((entity_type, entity_id), []):
                if keep(limit):
                    found[limit.id] = limit

        project = event.project_id
        apps: set[str] = set()
        if project:
            add(EntityType.PROJECT.value, project)
            for group_id in self.project_groups.get(project, []):
                add(EntityType.GROUP.value, group_id, via_log)
            apps.update(self.project_apps.get(project, []))
        if application_id:
            apps.add(application_id)
        for app_id in sorted(apps):
            add(EntityType.APPLICATION.value, app_id)
        if user_id:
            add(EntityType.USER.value, user_id)
            if not is_subject_entity(user_id):
                for group_id in self.user_groups.get(user_id, []):
                    add(
                        EntityType.GROUP.value,
                        group_id,
                        lambda limit: limit.include_member_usage and via_log(limit),
                    )
        chosen = [
            limit
            for limit in found.values()
            if limit.created_at is None or limit.created_at <= event.date
        ]
        self.fed_groups.update(
            limit.id for limit in chosen if limit.entity_type == EntityType.GROUP.value
        )
        return chosen


def _observe_groups(
    session: Session, state: ActivitySourceState, now: datetime
) -> dict[int, datetime]:
    """The group budgets the log feeds through their projects, and from when.

    A plain group budget with a row of its own in the summary's group view is
    fed by that row (the group view is not covered by the log); otherwise,
    and always with member usage, the log feeds it through its projects (and
    members). Which one is decided from the latest group reading, here, at
    every write. When the log takes a budget over, it feeds it only events
    dated from that moment on: what the group's row counted before is never
    counted again by the log, whenever its events reach the log (a backlog
    after an outage, a row of an uncertain date, a late row found by the
    daily sweep). Lost: events dated before the takeover that the log counts
    after it. When the group's row takes a budget back from the log, and the
    log fed it anything, the group view's next ``SUMMARY_PAUSE_READINGS``
    readings feed nothing (for every group: the pause is per view)."""
    from app.services import ingestion, ledger

    own = ledger.own_figures(session).get(UsageView.GROUP.value, set())
    previous = dict(state.group_feeds or {})
    current: dict[str, dict[str, object]] = {}
    handed_back = False
    for limit in session.scalars(
        select(CreditLimit).where(CreditLimit.entity_type == EntityType.GROUP.value)
    ):
        key = str(limit.id)
        entry = _entry_of(previous, limit)
        if not limit.is_active:
            if entry is not None:
                current[key] = entry
            continue
        if limit.include_member_usage or str(limit.entity_id) not in own:
            current[key] = (
                entry
                if entry is not None
                else {"since": _iso(now), "fed": False, **_group_identity(limit)}
            )
        elif entry is not None and entry.get("fed"):
            handed_back = True
    if handed_back:
        snapshot = ingestion.latest_live_snapshot(session, UsageView.GROUP.value)
        paused = dict(state.summary_paused or {})
        paused[UsageView.GROUP.value] = snapshot.id if snapshot is not None else 0
        state.summary_paused = paused
    state.group_feeds = current
    floors: dict[int, datetime] = {}
    for key, entry in current.items():
        since = _parse(entry.get("since")) if isinstance(entry, dict) else None
        if since is not None:
            floors[int(key)] = since
    return floors


def _actions(event: ActivityEvent, count: int) -> dict[str, int]:
    from app.services.ingestion import is_synthetic_subject

    action = usage_api.normalise_action_type(event.action)
    automatic = event.user.strip().lower() in _AUTO_TRIAGE
    unnamed = action == ActionType.UNKNOWN and is_synthetic_subject(event.user)
    if (action == ActionType.TRIAGE and automatic) or unnamed:
        # Triage the Auto-triage account did is Auto Triage.
        action = ActionType.AUTO_TRIAGE.value
    counts = {str(action): count}
    if action == ActionType.FUSION:
        counts[FUSION_MODEL + usage_api.action_key(event.action)] = count
    return counts


def _add_counts(into: dict[str, int], more: dict[str, int]) -> dict[str, int]:
    for key, value in more.items():
        into[key] = into.get(key, 0) + value
    return into


# ------------------------------------------------------------------ the step


def ingest_activity(session: Session, client: CheckmarxClient) -> ActivityResult:
    """One cycle of the activity source: read (no transaction open), then
    count and record under the attribution lock, in one transaction."""
    try:
        result = _ingest(session, client)
    except Exception as exc:  # noqa: BLE001 - never stops the summary feed
        session.rollback()
        logger.exception("The credit activity step failed")
        # A failure like an outage: while the log is the source it counts
        # nothing (and neither does the summary for its views), and once it
        # has lasted OUTAGE_GRACE the summary takes over. A bug that persists
        # thus falls back instead of counting nothing for ever.
        result = ActivityResult(enabled=True)
        try:
            return _failed(
                session,
                result,
                utcnow(),
                RuntimeError(f"The credit activity step failed: {exc}"),
                structural=False,
            )
        except Exception:  # noqa: BLE001 - the database itself is failing
            session.rollback()
            logger.exception("The credit activity step could not record its failure")
            active = source_active(session)
            result.status = ACTIVE if active else INACTIVE
            result.source_active = active
            result.read_failed = active
            result.error = f"The credit activity step failed: {exc}"
            return result
    try:
        _notice_once(session, result)
    except Exception:  # noqa: BLE001 - a notice never fails the step
        session.rollback()
        logger.exception("The usage source notice could not be raised")
    return result


NOTICE_KEY = "usage.source.activity_log"


def _notice_once(session: Session, result: ActivityResult) -> None:
    """Once per install, at the first cycle with the activity log as the
    chosen source (an upgrade moves there without being asked): say so, and
    what it means for restrictions; when the log is not available, how to
    restrict from summary totals as before."""
    from app.models.enums import Severity
    from app.services import notifications

    if not result.enabled:
        return
    state = _state(session)
    if state is None or state.noticed_at is not None:
        return
    rule = (
        "Monthly and quarterly budgets of projects, users and applications now restrict only "
        "on usage the activity log counted: usage the consumption summary counts (while the "
        "log is unavailable, or from a group's own summary row) and auto-triage charged to "
        "the person who started a scan still count and warn, but do not start a "
        "restriction. Lifetime, custom and count-existing budgets, and restrictions already "
        "in force, are unchanged."
    )
    opt_back = (
        "To go back to the consumption summary as before: Settings → Schedule & data → "
        "Usage source: Summary only, and turn on Allow restrictions from summary totals "
        "(less accurate)."
    )
    if result.source_active:
        title = "Usage now comes from the credit activity log"
        body = (
            "CreditGuard now counts each billed action from Checkmarx One's credit activity "
            "log, by project and application id, in the period it happened in. "
            f"{rule} {opt_back}"
        )
        severity = Severity.INFO
    else:
        title = "Restrictions paused for period budgets: the activity log is not available"
        body = (
            "CreditGuard now uses Checkmarx One's credit activity log as the usage source, "
            "but it could not be read"
            + (f" ({result.error})" if result.error else "")
            + f". Usage comes from the consumption summary meanwhile. {rule} {opt_back}"
        )
        severity = Severity.WARNING
    notifications.notify(
        session,
        category=notifications.CATEGORY_WARNING,
        severity=severity,
        title=title,
        body=body,
        dedupe_key=NOTICE_KEY,
    )
    state.noticed_at = utcnow()
    session.commit()


def _ingest(session: Session, client: CheckmarxClient) -> ActivityResult:
    from app.services import ingestion

    now = utcnow()
    if settings_store.usage_source(session) != settings_store.USAGE_SOURCE_ACTIVITY:
        state = _state(session)
        if state is not None and state.status != OFF:
            ingestion.attribution_lock(session)
            state = _state_for_write(session)
            _stop(state, OFF, now)
            # Turned on again later, the log is asked at once.
            state.retry_after = None
            session.commit()
        return ActivityResult(enabled=False, status=OFF)

    state = _state(session)
    result = ActivityResult(enabled=True, status=state.status if state else INACTIVE)
    if (
        state is not None
        and state.status != ACTIVE
        and state.retry_after is not None
        and now < state.retry_after
    ):
        result.error = state.last_error
        return result
    plan = _plan(session, state, now)
    result.sweep = plan.sweep
    # Nothing is left open in the database while Checkmarx is called.
    session.commit()
    try:
        read = _read(client, plan)
        analysis = _analyse(read, plan)
    except (CheckmarxNotFoundError, CheckmarxPermissionError, CheckmarxResponseError) as exc:
        # Refused, absent or not the log: the summary takes over at once.
        session.rollback()
        return _failed(session, result, plan.now, exc, structural=True)
    except CheckmarxError as exc:
        # An outage, a rate limit, a token problem: expected to pass.
        session.rollback()
        return _failed(session, result, plan.now, exc, structural=False)

    ingestion.attribution_lock(session)
    state = _state_for_write(session)
    if (
        int(state.revision or 0) != plan.revision
        or settings_store.usage_source(session) != settings_store.USAGE_SOURCE_ACTIVITY
        or (state.status == ACTIVE) == plan.seed
    ):
        # The state moved while the log was read: this read is not written.
        session.commit()
        result.status = state.status
        result.source_active = state.status == ACTIVE
        result.issues.append("state_changed")
        return result
    _write(session, state, plan, read, analysis, result)
    session.commit()
    return result


def _failed(
    session: Session,
    result: ActivityResult,
    now: datetime,
    exc: Exception,
    *,
    structural: bool,
) -> ActivityResult:
    from app.services import ingestion

    message = error_text.public_error(exc)[:2000]
    ingestion.attribution_lock(session)
    state = _state_for_write(session)
    state.last_error = message
    state.last_fetch_at = now
    was_active = state.status == ACTIVE
    result.error = message
    if was_active:
        if state.failing_since is None:
            state.failing_since = now
        if structural or now - state.failing_since >= OUTAGE_GRACE:
            _stop(state, FALLBACK, now)
            state.retry_after = now + REPROBE_AFTER if structural else None
            result.warnings.append(
                "The credit activity log could not be read "
                f"({message}). Usage of projects, users and applications comes from the "
                "consumption summary again; its first reading counts nothing, so the usage "
                "of the last cycle or two is not counted."
            )
        else:
            state.revision = (state.revision or 0) + 1
            result.read_failed = True
            result.warnings.append(
                "The credit activity log could not be read this cycle "
                f"({message}). Nothing new is counted for projects, users and applications "
                "until it answers; what happened meanwhile is counted then. After "
                f"{int(OUTAGE_GRACE.total_seconds() // 60)} minutes the consumption summary "
                "takes over."
            )
    else:
        state.retry_after = now + REPROBE_AFTER if structural else None
        if state.status != FALLBACK:
            state.status = INACTIVE
        logger.info("The credit activity log is not used this cycle: %s", message)
    result.status = state.status
    result.source_active = state.status == ACTIVE
    session.commit()
    return result


def _write(
    session: Session,
    state: ActivitySourceState,
    plan: _Plan,
    read: _Read,
    analysis: _Analysis,
    result: ActivityResult,
) -> None:
    now = plan.now
    if plan.seed:
        state.status = ACTIVE
        state.floor_at = now
        state.active_since = now
        state.summary_paused = {
            view: value
            for view, value in (state.summary_paused or {}).items()
            if view == UsageView.GROUP.value
        } or None
        _start_era(state, now)
        result.seeded = True
        result.warnings.append(
            "The credit activity log is now the source of project, user and application "
            "usage. This first read only records what it holds and counts nothing: usage "
            "since the consumption summary's last reading is not counted."
        )
    floor = state.floor_at or now
    # Never below a cutoff already used: keys older than it may be gone.
    cutoff = horizon(now)
    if state.cutoff_at is not None and state.cutoff_at > cutoff:
        cutoff = state.cutoff_at
    state.cutoff_at = cutoff
    # Observed before anything is decided with them (see BudgetHistory).
    history = BudgetHistory(session, now, persist=True)
    group_floors = _observe_groups(session, state, now)
    result.status = ACTIVE
    result.source_active = True
    result.pages = len(read.pages)
    result.page_size = plan.size
    result.rows = analysis.rows
    result.bad_rows = analysis.bad_rows
    result.partial = read.partial
    if analysis.regression:
        result.issues.append("order_went_back")
    if not analysis.stable:
        result.issues.append("total_changed")
    elif not analysis.rows_match and not read.partial:
        result.issues.append("rows_mismatch")
    if analysis.coverage_gap:
        result.issues.append("coverage_gap")
    if analysis.ties:
        result.issues.append("uncertain_dates")
    if read.partial:
        result.issues.append(f"stopped_by_{(read.stopped_by or 'cap').replace(' ', '_')}")
        result.warnings.append(
            f"The credit activity log was not read to its end this cycle ({read.stopped_by}, "
            f"{len(read.pages)} page(s)). What was read completely is counted; the rest is "
            "counted in the next cycles."
        )
    result.complete = (
        analysis.stable
        and analysis.rows_match
        and not analysis.coverage_gap
        and not analysis.uncertain
        and not analysis.regression
    )

    new_events: list[tuple[ActivityEvent, int]] = []
    if not analysis.regression:
        new_events = _reconcile(session, analysis, plan, floor, cutoff, now, result)
    if new_events:
        _count(session, new_events, now, result, history, group_floors, state)

    session.execute(delete(ActivityEventCount).where(ActivityEventCount.event_at < cutoff))
    _prune_log_counters(session)

    _move_cursor(state, plan, read, analysis, cutoff)
    result.sweep = plan.sweep
    if plan.sweep and not (read.partial and read.stopped_by == "time budget"):
        # A sweep the page cap stopped (a log too large to read in a cycle)
        # is not tried again until the next day.
        state.last_sweep_at = now
        state.reconciliation = _reconciliation(read, analysis, now)
    state.page_size = analysis.size if analysis.size < plan.size else None
    state.last_total = next(
        (page.total_items for page in reversed(read.pages) if page.total_items is not None),
        state.last_total,
    )
    state.last_fetch_at = now
    state.last_success_at = now
    state.failing_since = None
    state.retry_after = None
    state.last_error = None
    state.revision = (state.revision or 0) + 1
    state.last_stats = result.as_stats()
    session.flush()


def _reconcile(
    session: Session,
    analysis: _Analysis,
    plan: _Plan,
    floor: datetime,
    cutoff: datetime,
    now: datetime,
    result: ActivityResult,
) -> list[tuple[list[ActivityEvent], int]]:
    """Raise each identity's seen count to what this read holds; the rise is
    the new events (none in a seed, none dated before the floor), with every
    row of the identity in this read (``_count`` decides what of them is
    certain)."""
    wanted: dict[str, tuple[int, list[ActivityEvent]]] = {}
    for key, (count, rows) in analysis.counts.items():
        event = rows[0]
        if event.date in analysis.uncertain:
            result.uncertain_rows += count
            continue
        if event.date < cutoff:
            continue
        wanted[key] = (count, rows)
    keys = sorted(wanted)
    stored: dict[str, ActivityEventCount] = {}
    for start in range(0, len(keys), 500):
        for row in session.scalars(
            select(ActivityEventCount).where(
                ActivityEventCount.key_hash.in_(keys[start : start + 500])
            )
        ):
            stored[row.key_hash] = row
    new_events: list[tuple[list[ActivityEvent], int]] = []
    for key in keys:
        count, rows = wanted[key]
        event = rows[0]
        row = stored.get(key)
        before = row.seen if row is not None else 0
        if count <= before:
            continue
        if row is None:
            session.add(
                ActivityEventCount(key_hash=key, event_at=event.date, seen=count, updated_at=now)
            )
        else:
            row.seen = count
            row.updated_at = now
        if not plan.seed and event.date >= floor:
            new_events.append((rows, count - before))
    return new_events


def _count(
    session: Session,
    new_events: list[tuple[list[ActivityEvent], int]],
    now: datetime,
    result: ActivityResult,
    history: BudgetHistory,
    group_floors: dict[int, datetime],
    state: ActivitySourceState,
) -> None:
    """Add the new events to the month's and the quarter's counter, of the
    period each happened in, of every budget it counts towards.

    The rows of one identity (same date, action, credits, project, scans and
    scanner) can differ in the fields that may change later (who, the
    application). Which of them are the new ones cannot be told, so the new
    events of an identity count towards a person or an application only when
    every row of it in this read names the same one; otherwise only towards
    what the identity itself fixes (its project, the project's groups and
    applications). A budget is then charged at most as many events of the
    identity as rows naming it were read at once: never more than there
    are."""
    from app.services.periods import current_window

    targets = _Targets(session, now, history, group_floors)
    resolved: list[tuple[ActivityEvent, int, str | None, str | None]] = []
    for rows, count in new_events:
        event = rows[0]
        if all(row.variant == event.variant for row in rows):
            user_id, outcome = targets.user_entity(event)
            application_id = event.application_id
        else:
            user_id, outcome, application_id = None, "ambiguous", None
        result.user_outcomes[outcome] = result.user_outcomes.get(outcome, 0) + count
        resolved.append((event, count, user_id, application_id))
    targets.load_links(
        {event.project_id for event, _c, _u, _a in resolved if event.project_id},
        {user_id for _e, _c, user_id, _a in resolved if user_id and not is_subject_entity(user_id)},
    )
    adds: dict[tuple[int, str], tuple[Decimal, dict[str, int]]] = {}
    for event, count, user_id, application_id in resolved:
        credits = event.credits * count
        result.events_counted += count
        result.credits_counted += credits
        actions = _actions(event, count)
        for limit in targets.budgets(event, user_id, application_id):
            for granularity in _GRANULARITIES:
                period = current_window(
                    SimpleNamespace(period_type=granularity, created_at=limit.created_at),  # type: ignore[arg-type]
                    event.date,
                )
                total, counts = adds.get((limit.id, period.key), (ZERO, {}))
                adds[(limit.id, period.key)] = (total + credits, _add_counts(counts, actions))
    if targets.fed_groups:
        feeds = {key: dict(value) for key, value in (state.group_feeds or {}).items()}
        for limit_id in targets.fed_groups:
            if str(limit_id) in feeds:
                feeds[str(limit_id)]["fed"] = True
        state.group_feeds = feeds
    if not adds:
        return
    limit_ids = sorted({limit_id for limit_id, _key in adds})
    period_keys = sorted({key for _limit_id, key in adds})
    existing = {
        (row.limit_id, row.period_key): row
        for row in session.scalars(
            select(BudgetUsage).where(
                BudgetUsage.limit_id.in_(limit_ids), BudgetUsage.period_key.in_(period_keys)
            )
        )
    }
    for (limit_id, period_key), (credits, counts) in adds.items():
        row = existing.get((limit_id, period_key))
        if row is None:
            row = BudgetUsage(limit_id=limit_id, period_key=period_key, credits=ZERO, actions={})
            session.add(row)
        row.credits = Decimal(row.credits or 0) + credits
        row.actions = _add_counts(dict(row.actions or {}), counts)
        # When it was observed: a closed period is reconciled with what
        # arrived after it was last evaluated.
        row.updated_at = max(row.updated_at, now) if row.updated_at else now
    # The log's own part of each counter: only it can start a restriction.
    from app.models.activity import ActivityBudgetCounter

    mine = {
        (row.limit_id, row.period_key): row
        for row in session.scalars(
            select(ActivityBudgetCounter).where(
                ActivityBudgetCounter.limit_id.in_(limit_ids),
                ActivityBudgetCounter.period_key.in_(period_keys),
            )
        )
    }
    for (limit_id, period_key), (credits, _counts) in adds.items():
        part = mine.get((limit_id, period_key))
        if part is None:
            part = ActivityBudgetCounter(limit_id=limit_id, period_key=period_key, credits=ZERO)
            session.add(part)
        part.credits = Decimal(part.credits or 0) + credits


def _move_cursor(
    state: ActivitySourceState,
    plan: _Plan,
    read: _Read,
    analysis: _Analysis,
    cutoff: datetime,
) -> None:
    """Where the next read starts: the last ``OVERLAP`` of what was read, and
    no later than a date left uncertain (or the gap a read did not cover)."""
    if plan.sweep and read.partial:
        # A sweep the cap stopped never moves the normal cursor back.
        return
    current = plan.resume_at
    if analysis.newest is None:
        if read.pages:
            state.resume_position = analysis.end_position
        state.resume_at = current
        return
    candidates = [analysis.newest - OVERLAP]
    if read.partial and analysis.uncertain:
        # Stopped early: carry on from where it stopped (the overlap would
        # read the same pages again and never reach the end).
        candidates = [min(analysis.uncertain)]
    elif analysis.uncertain:
        candidates.append(min(analysis.uncertain))
    if analysis.regression and current is not None:
        candidates.append(current)
    if analysis.coverage_gap and current is not None:
        candidates.append(current)
    target = max(min(candidates), cutoff)
    state.resume_at = target
    position = next((pos for pos, date in analysis.positions if date >= target), None)
    if analysis.coverage_gap:
        position = max(0, (read.start_page - 3) * analysis.size)
    state.resume_position = position if position is not None else analysis.end_position


def _reconciliation(read: _Read, analysis: _Analysis, now: datetime) -> dict[str, object]:
    record: dict[str, object] = {
        "at": _iso(now),
        "period": activity_api.ACTIVITY_PERIOD,
        "activity_credits": str(analysis.credits),
        "rows": analysis.rows,
        "summary_credits": None,
        "difference": None,
    }
    if read.partial:
        record["status"] = "inconclusive"
        record["reason"] = f"the whole log could not be read in one cycle ({read.stopped_by})"
        return record
    if read.summary_total is None:
        record["status"] = "inconclusive"
        record["reason"] = f"the consumption summary could not be read ({read.summary_error})"
        return record
    summary = read.summary_total
    difference = analysis.credits - summary
    record["summary_credits"] = str(summary)
    record["difference"] = str(difference)
    tolerance = max(MISMATCH_FLOOR, max(abs(summary), abs(analysis.credits)) * MISMATCH_RATIO)
    if abs(difference) > tolerance:
        record["status"] = "mismatch"
    elif not analysis.stable:
        record["status"] = "match"
        record["reason"] = "the log changed while it was read; compared as read"
    else:
        record["status"] = "match"
    return record


# ------------------------------------------------------------------ reading


def _prune_log_counters(session: Session) -> None:
    """The log's part of a counter goes with the counter (retention prunes
    those with their period)."""
    from sqlalchemy import exists

    from app.models.activity import ActivityBudgetCounter

    session.execute(
        delete(ActivityBudgetCounter).where(
            ~exists().where(
                BudgetUsage.limit_id == ActivityBudgetCounter.limit_id,
                BudgetUsage.period_key == ActivityBudgetCounter.period_key,
            )
        )
    )


def log_counted(session: Session, period_key: str) -> dict[int, Decimal]:
    """limit id -> what the activity log counted towards it in the period."""
    from app.models.activity import ActivityBudgetCounter

    return {
        row.limit_id: Decimal(row.credits or 0)
        for row in session.scalars(
            select(ActivityBudgetCounter).where(ActivityBudgetCounter.period_key == period_key)
        )
    }


def restriction_hold(session: Session) -> dict[str, object] | None:
    """Why new restrictions of period budgets rest on the activity log's
    counts only right now (None: they do not, the log is the source or the
    admin let summary totals restrict). ``reason`` is a sentence; ``since``
    when the log stopped being the source, if known."""
    setting = settings_store.usage_source(session)
    if setting == settings_store.USAGE_SOURCE_SUMMARY:
        if settings_store.summary_restricts(session):
            return None
        return {
            "reason": (
                "the usage source is the consumption summary only, and restrictions from "
                "summary totals are not allowed (Settings → Schedule & data)"
            ),
            "since": None,
            "summary_only": True,
        }
    state = _state(session)
    if state is not None and state.status == ACTIVE:
        return None
    since: str | None = None
    for era in (state.eras or []) if state is not None else []:
        if isinstance(era, list) and len(era) == 2 and era[1]:
            since = str(era[1])
    if since is None and state is not None and state.last_fetch_at is not None:
        since = _iso(state.last_fetch_at)
    return {
        "reason": "the activity log is unavailable"
        + (f" since {since}" if since else "")
        + (f" ({state.last_error})" if state is not None and state.last_error else ""),
        "since": since,
        "summary_only": False,
    }


def describe(session: Session) -> dict[str, object]:
    """The source's state, for Diagnose and the Settings page."""
    state = _state(session)
    setting = settings_store.usage_source(session)
    hold = restriction_hold(session)
    if state is None:
        return {"setting": setting, "status": INACTIVE, "restrictions_held": hold}
    return {
        "setting": setting,
        "restrictions_held": hold,
        "status": state.status,
        "active_since": _iso(state.active_since),
        "floor_at": _iso(state.floor_at),
        "last_success_at": _iso(state.last_success_at),
        "last_fetch_at": _iso(state.last_fetch_at),
        "failing_since": _iso(state.failing_since),
        "retry_after": _iso(state.retry_after),
        "last_error": state.last_error,
        "reconciliation": state.reconciliation,
        "last_stats": state.last_stats,
    }
