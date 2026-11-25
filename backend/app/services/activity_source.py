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
every identifying field (``event_key``), and ``usage_activity_key`` keeps how
many rows of each identity have been seen. A fetch holding ``n`` rows of one
identity counts ``max(0, n - seen)`` new events and raises ``seen`` to ``n``,
in the transaction that adds them to the budget counters, under the
attribution lock. ``seen`` never falls, so an event is counted at most once as
long as no fetch shows more rows of an identity than the log holds.

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
  a malformed answer, or an outage longer than ``OUTAGE_GRACE``), the summary
  feed's first reading of each covered view counts nothing (``summary_paused``)
  and the next ones count increases as before. Lost: what happened between the
  log's last fetch and that second reading (one to two cycles). This assumes
  the summary reports an event no later than a cycle after the log does (they
  are the same data: their sums matched exactly).
* During a shorter outage the log stays the source and nothing is counted;
  what happened meanwhile is counted when it answers again.

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
only when their project had no active project budget at the event's date:
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
from app.services import pacing, settings_store, subject_matching

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


def summary_feeds(session: Session, view: str, snapshot: UsageSnapshot) -> bool:
    """Whether a summary reading of ``view`` feeds budget counters. Call
    under the attribution lock, with the new reading stored.

    Not while the log is the source of the view, nor in the first reading
    after it stopped being the source (its increase spans usage the log may
    have counted)."""
    view = str(view)
    if view not in COVERED_VIEWS:
        return True
    state = _state(session)
    if state is None:
        return True
    if state.status == ACTIVE:
        return False
    paused = (state.summary_paused or {}).get(view)
    if not isinstance(paused, int):
        return True
    from app.services import ingestion

    previous = ingestion.latest_live_snapshot(session, view, excluding=snapshot.id)
    return previous is not None and previous.id > paused


def note_summary_reading(session: Session, view: str, snapshot: UsageSnapshot) -> None:
    """Remember a summary reading taken while the log was the source."""
    view = str(view)
    if view not in COVERED_VIEWS:
        return
    state = _state(session)
    if state is None or state.status != ACTIVE:
        return
    paused = dict(state.summary_paused or {})
    paused[view] = snapshot.id
    state.summary_paused = paused


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
    the log was the source, on a project that had an active project budget
    then. None when there are none (the log was never the source)."""
    state = _state(session)
    eras: list[tuple[datetime, datetime | None]] = []
    for era in (state.eras or []) if state is not None else []:
        if isinstance(era, list) and len(era) == 2 and _parse(era[0]) is not None:
            eras.append((_parse(era[0]), _parse(era[1])))  # type: ignore[arg-type]
    if not eras:
        return None
    since = _project_budget_since(session)
    if not since:
        return None

    def skip(part: object) -> bool:
        when = getattr(part, "observed_at", None)
        project_id = getattr(part, "project_id", None)
        if when is None or project_id is None:
            return False
        if not any(start <= when and (end is None or when < end) for start, end in eras):
            return False
        created = since.get(str(project_id))
        return created is not None and created <= when

    return skip


def _project_budget_since(session: Session) -> dict[str, datetime]:
    """project id -> when its earliest active project budget was created."""
    found: dict[str, datetime] = {}
    for entity_id, created_at in session.execute(
        select(CreditLimit.entity_id, CreditLimit.created_at).where(
            CreditLimit.entity_type == EntityType.PROJECT.value,
            CreditLimit.is_active.is_(True),
        )
    ):
        if created_at is None:
            continue
        key = str(entity_id)
        if key not in found or created_at < found[key]:
            found[key] = created_at
    return found


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
    sweep = (
        not seed
        and state is not None
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
            read.summary_error = str(exc)
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
    # key -> (rows of it in this read, one of them)
    counts: dict[str, tuple[int, ActivityEvent]]
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
    counts: dict[str, tuple[int, ActivityEvent]] = {}
    positions: list[tuple[int, datetime]] = []
    credits = ZERO
    for page in pages:
        for event in page.events:
            key = event.key
            seen, sample = counts.get(key, (0, event))
            counts[key] = (seen + 1, sample)
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

    def __init__(self, session: Session, now: datetime) -> None:
        from app.services import ingestion, ledger

        self.session = session
        self.now = now
        self.by_target: dict[tuple[str, str], list[CreditLimit]] = defaultdict(list)
        for limit in session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))):
            self.by_target[(str(limit.entity_type), str(limit.entity_id))].append(limit)
        self.project_budget_since = _project_budget_since(session)
        # A group budget its own summary row feeds is not fed by its projects
        # (the summary's group view is not covered by the log).
        self.groups_own = ledger.own_figures(session).get(UsageView.GROUP.value, set())
        self.index = ingestion.build_user_index(session)
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
        outcome = self.index.resolve_detailed(
            subject_key=key,
            name=event.user or None,
            email=event.user_email or None,
            integrations=True,
        )
        integration = is_integration_account(event.user, event.user_email, self.extras) or (
            outcome.is_bot and outcome.counted_user_id is None
        )
        if integration:
            project = event.project_id
            since = self.project_budget_since.get(project) if project else None
            if since is not None and since <= event.date:
                # Its project had an active project budget: that is where it
                # counts, never also against a person.
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

    def budgets(self, event: ActivityEvent, user_id: str | None) -> list[CreditLimit]:
        found: dict[int, CreditLimit] = {}

        def add(entity_type: str, entity_id: str, keep=lambda _limit: True) -> None:  # type: ignore[no-untyped-def]
            for limit in self.by_target.get((entity_type, entity_id), []):
                if keep(limit):
                    found[limit.id] = limit

        project = event.project_id
        apps: set[str] = set()
        if project:
            add(EntityType.PROJECT.value, project)
            for group_id in self.project_groups.get(project, []):
                add(
                    EntityType.GROUP.value,
                    group_id,
                    lambda limit, g=group_id: (
                        limit.include_member_usage or g not in self.groups_own
                    ),
                )
            apps.update(self.project_apps.get(project, []))
        if event.application_id:
            apps.add(event.application_id)
        for app_id in sorted(apps):
            add(EntityType.APPLICATION.value, app_id)
        if user_id:
            add(EntityType.USER.value, user_id)
            if not is_subject_entity(user_id):
                for group_id in self.user_groups.get(user_id, []):
                    add(EntityType.GROUP.value, group_id, lambda limit: limit.include_member_usage)
        return [
            limit
            for limit in found.values()
            if limit.created_at is None or limit.created_at <= event.date
        ]


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
        return _ingest(session, client)
    except Exception as exc:  # noqa: BLE001 - never stops the summary feed
        session.rollback()
        logger.exception("The credit activity step failed")
        return ActivityResult(
            enabled=True,
            status=INACTIVE,
            source_active=source_active(session),
            read_failed=source_active(session),
            error=f"The credit activity step failed: {exc}",
        )


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
        return _failed(session, result, plan, exc, structural=True)
    except CheckmarxError as exc:
        # An outage, a rate limit, a token problem: expected to pass.
        session.rollback()
        return _failed(session, result, plan, exc, structural=False)

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
    plan: _Plan,
    exc: Exception,
    *,
    structural: bool,
) -> ActivityResult:
    from app.services import ingestion

    now = plan.now
    message = str(exc)[:2000]
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
        state.summary_paused = None
        _start_era(state, now)
        result.seeded = True
        result.warnings.append(
            "The credit activity log is now the source of project, user and application "
            "usage. This first read only records what it holds and counts nothing: usage "
            "since the consumption summary's last reading is not counted."
        )
    floor = state.floor_at or now
    cutoff = horizon(now)
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
        _count(session, new_events, now, result)

    session.execute(delete(ActivityEventCount).where(ActivityEventCount.event_at < cutoff))

    _move_cursor(state, plan, read, analysis, cutoff)
    if plan.sweep:
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
) -> list[tuple[ActivityEvent, int]]:
    """Raise each identity's seen count to what this read holds; the rise is
    the new events (none in a seed, none dated before the floor)."""
    wanted: dict[str, tuple[int, ActivityEvent]] = {}
    for key, (count, event) in analysis.counts.items():
        if event.date in analysis.uncertain:
            result.uncertain_rows += count
            continue
        if event.date < cutoff:
            continue
        wanted[key] = (count, event)
    keys = sorted(wanted)
    stored: dict[str, ActivityEventCount] = {}
    for start in range(0, len(keys), 500):
        for row in session.scalars(
            select(ActivityEventCount).where(
                ActivityEventCount.key_hash.in_(keys[start : start + 500])
            )
        ):
            stored[row.key_hash] = row
    new_events: list[tuple[ActivityEvent, int]] = []
    for key in keys:
        count, event = wanted[key]
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
            new_events.append((event, count - before))
    return new_events


def _count(
    session: Session,
    new_events: list[tuple[ActivityEvent, int]],
    now: datetime,
    result: ActivityResult,
) -> None:
    """Add the new events to the month's and the quarter's counter, of the
    period each happened in, of every budget it counts towards."""
    from app.services.periods import current_window

    targets = _Targets(session, now)
    resolved: list[tuple[ActivityEvent, int, str | None]] = []
    for event, count in new_events:
        user_id, outcome = targets.user_entity(event)
        result.user_outcomes[outcome] = result.user_outcomes.get(outcome, 0) + count
        resolved.append((event, count, user_id))
    targets.load_links(
        {event.project_id for event, _c, _u in resolved if event.project_id},
        {user_id for _e, _c, user_id in resolved if user_id and not is_subject_entity(user_id)},
    )
    adds: dict[tuple[int, str], tuple[Decimal, dict[str, int]]] = {}
    for event, count, user_id in resolved:
        credits = event.credits * count
        result.events_counted += count
        result.credits_counted += credits
        actions = _actions(event, count)
        for limit in targets.budgets(event, user_id):
            for granularity in _GRANULARITIES:
                period = current_window(
                    SimpleNamespace(period_type=granularity, created_at=limit.created_at),  # type: ignore[arg-type]
                    event.date,
                )
                total, counts = adds.get((limit.id, period.key), (ZERO, {}))
                adds[(limit.id, period.key)] = (total + credits, _add_counts(counts, actions))
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


def describe(session: Session) -> dict[str, object]:
    """The source's state, for Diagnose and the Settings page."""
    state = _state(session)
    setting = settings_store.usage_source(session)
    if state is None:
        return {"setting": setting, "status": INACTIVE}
    return {
        "setting": setting,
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
