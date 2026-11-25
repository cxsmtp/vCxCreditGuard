"""Charge a project's Auto Triage credits to the person who started the scan.

Checkmarx reports Auto Triage spend under a synthetic "Auto-triage" user, so by
default it counts against the project (and tenant wide) and against nobody's
user limit. With the admin setting ``attribution.auto_triage_to_scan_initiator``
on, each project's Auto Triage credits are *additionally* split across the
people whose scans triggered the auto triage. Project, application and tenant
totals never change: this only decides which people a share of a project's
figure is also counted against, and the shares for a project never add up to
more than that project's Auto Triage credits.

Where the number comes from
---------------------------
``A_p`` is the project's Auto Triage credits in the newest believed project
snapshot. The consumption feed gives per action *transaction counts*, not per
action credits, so ``A_p`` is the project's credits when Auto Triage is all it
did, and otherwise its Auto Triage transactions priced at the tenant wide
credits-per-transaction the action dimension reports for Auto Triage, capped at
the project's transaction-mix share so that credits of other actions (human
triage, already counted against the person who did it) never become ``A_p``.
Without that tenant price, a project row that also did other actions has no
``A_p`` at all: the mix share alone could hand a person's own credits to a
scan initiator.

Who triggered it
----------------
* **Observed.** Each cycle, a project whose Auto Triage *transaction count*
  went up since the last reading that was dealt with has its scans listed for
  that interval (less a small lag, because auto triage runs after a scan
  completes). The new transactions, priced at the project's current credits
  per Auto Triage transaction, are split equally across the completed scans on
  the project's auto-triage branches, so per initiator by scan count; scans
  without an initiator keep their share on the project, and so do scans an
  earlier charge already named (they are not charged twice, and their share
  does not move onto the other scans). A scan whose ``updatedAt`` (all the
  listing gives for completion) is more than ``MAX_SCAN_RUNTIME`` after its
  creation was edited later and is not taken. With no scan in the interval,
  the latest one before it (since observation began, inside the window, after
  the previous charged interval ended, and not already charged) is used; with
  none at all, or with more scans than a listing reads, the increase is
  recorded as ``unattributed`` and stays on the project. The cursor is the
  transaction count, never a credit figure: a price change is not new auto
  triage. A project missing from a reading, or a row that cannot say how much
  Auto Triage it did (no per action breakdown, an unreadable count, a
  breakdown without Auto Triage that no total confirms complete), is no
  reading at all and leaves the cursor alone (a row that may be a 0 is taken
  only while the cursor already stands at 0).
* **Observation (re)starts** at the current reading whenever the setting is
  turned on (``attribution.auto_triage_observation_epoch``), the lookback
  window changes, or a project is first seen with consumption it already had
  (also under a row that matched no project yet): whatever arrived before is
  history and estimated, never observed.
* **Estimated.** Credits from before observation began are split by the
  number of completed scans each person ran on the auto-triage branches inside
  the consumption window, before observation began. Never more than what is
  left of that history: ``history_ceiling`` (the reading observation began
  at, less every fall since, at the current credits per transaction), scaled
  by the share of the sampled history scans still inside the window. A fall
  only shows when more ages out than arrives; the scans' dates show the
  history ageing out either way. Whatever else no recorded charge explains
  (an interval that could not be read, new transactions netted against older
  ones ageing out) stays on the project.
* An initiator that does not resolve to a synced user (a webhook bot, an
  unknown address) is raised as an unresolved subject of kind
  ``scan_initiator`` for an admin to map; until then its share stays on the
  project only.

Dates and periods
-----------------
Observed charges are dated (the snapshot that showed the increase), estimated
shares are not. A charge older than the consumption window drops out, exactly
as the reported figures do. How much counts towards a limit's period follows
the rule its own credits follow (``evaluation.counts_existing_usage``): a
lifetime, custom or count-existing limit counts everything attributed inside
the window; a monthly or quarterly limit counts only charges observed after its
baseline was taken.

Crash safety
------------
No write transaction is open while Checkmarx is called: state is committed
before every call. A project's cursor only advances once its increase has been
recorded, so a failed or deferred listing is caught up by the next cycle and
stays on the project meanwhile. Any failure in one project (the tenant, a
payload, the database) is rolled back and recorded on that project; the others
carry on.
Listing is bounded per project and per cycle.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import ROUND_DOWN, Decimal

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.checkmarx import platform
from app.checkmarx import scans as scans_api
from app.checkmarx import usage as usage_api
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import (
    CheckmarxError,
    CheckmarxRateLimitError,
    CheckmarxUnavailableError,
)
from app.db.base import utcnow
from app.models.enums import ActionType, ActorType, Severity, UsageView
from app.models.org import CxProject
from app.models.usage import (
    AutoTriageCharge,
    AutoTriageProjectState,
    UnresolvedSubject,
    UsageEntityOffset,
    UsageRecord,
    UsageSnapshot,
)
from app.services import error_text, ingestion, notifications, pacing, settings_store
from app.services.audit import AuditActor, record_audit
from app.services.subject_matching import MatchMethod, MatchOutcome

logger = logging.getLogger(__name__)

BASIS_OBSERVED = "observed"
BASIS_ESTIMATED = "estimated"
BASIS_UNATTRIBUTED = "unattributed"

# ``unresolved_subject.view_by`` for an initiator seen on a scan rather than a
# subject of the consumption feed. The mapping flow is the same.
SOURCE_SCAN_INITIATOR = "scan_initiator"

# Auto triage runs shortly after a scan completes, so the credits for a scan
# that finished just before the previous snapshot can show up in the next one.
OBSERVATION_LAG = timedelta(minutes=30)
# A scan is filtered by creation time on the server, but what matters is when it
# completed: a scan created this long before a window can still finish inside it.
# Four hours covers a full SAST scan of a large repository with room to spare
# (most scans finish in minutes). It also bounds how much has to be read: an
# interval is about the cycle interval plus the lag, so the listing covers about
# 4h45m of scans, and only a project with more than ~100 scans an hour on its
# auto-triage branches reaches the per-project cap. A scan that runs longer
# than this and finishes inside an interval is seen only if the listing happened
# to read it on its last page; otherwise its share goes to the scans that are
# (or the increase stays on the project).
SCAN_RUNTIME_ALLOWANCE = timedelta(hours=4)
# The longest a listed scan may have run (creation to ``updatedAt``) and still
# be taken. ``completed_at`` is the scan's ``updatedAt``, which also moves when
# the scan is edited later (a tag, say): without a bound, a scan created weeks
# ago that was on the last page read (or inside a widen listing, which can
# reach back to when observation began) and was touched in the interval would
# be taken for one that just finished. A day is far beyond any real scan (the
# allowance above already covers a long one); a scan that genuinely ran longer
# is not charged, and its share stays on the project.
MAX_SCAN_RUNTIME = timedelta(hours=24)

# Bounds, so one busy project or a huge tenant never makes a cycle unbounded.
# Whatever does not fit is caught up on the next cycle and stays on the project
# meanwhile.
MAX_PROJECTS_PER_CYCLE = 50
MAX_REQUESTS_PER_CYCLE = 300
MAX_PAGES_PER_LISTING = 5
SCAN_PAGE_SIZE = 100
WIDEN_PAGE_SIZE = 50
HISTORY_MAX_PAGES = 5
# More configured branches than this are listed together and filtered here.
MAX_BRANCH_LISTINGS = 5

# Errors that mean the tenant is unreachable or throttling, rather than that one
# project's data is unreadable.
OUTAGE_ERRORS = (CheckmarxUnavailableError, CheckmarxRateLimitError)

QUANTUM = Decimal("0.0001")
ZERO = Decimal("0")


def _q(value: Decimal) -> Decimal:
    """Round down to the stored precision, so shares never add up to more."""
    return value.quantize(QUANTUM, rounding=ROUND_DOWN)


def lookback_days(period_param: str | None) -> int:
    return usage_api.PERIOD_DAYS.get(period_param or "", 365)


# Width of the ``initiator`` and ``initiator_key`` columns.
INITIATOR_WIDTH = 320


def initiator_key(initiator: str) -> str:
    return initiator.strip().lower()[:INITIATOR_WIDTH]


def initiator_name(initiator: str) -> str:
    return initiator.strip()[:INITIATOR_WIDTH]


# --------------------------------------------------------------- the number A_p


def auto_triage_price(session: Session) -> Decimal | None:
    """Credits per Auto Triage transaction, tenant wide, from the action dimension."""
    snapshot = ingestion.latest_snapshot(session, UsageView.ACTION)
    if snapshot is None:
        return None
    for record in session.scalars(
        select(UsageRecord).where(UsageRecord.snapshot_id == snapshot.id)
    ):
        actions = record.actions or {}
        named = usage_api.normalise_action_type(record.subject_key) == ActionType.AUTO_TRIAGE
        only = bool(actions) and set(actions) == {ActionType.AUTO_TRIAGE.value}
        if not (named or only):
            continue
        transactions = record.transactions or sum(
            count for count in actions.values() if isinstance(count, int) and count > 0
        )
        if transactions and transactions > 0 and record.credits_used > 0:
            return Decimal(record.credits_used) / Decimal(transactions)
    return None


def _valid_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _raw_auto_triage_counts(record: UsageRecord) -> list[object]:
    """Every ``transactionCount`` the raw row gives for Auto Triage, as sent.

    The parser turns a value that is not an integer into 0, so whether the feed
    sent a real 0 or something unreadable is only visible in the raw row.
    """
    raw = record.raw if isinstance(record.raw, dict) else {}
    performed = raw.get("actionsPerformed")
    entries = performed.get("actions") if isinstance(performed, dict) else None
    if not isinstance(entries, list):
        return []
    return [
        entry.get("transactionCount")
        for entry in entries
        if isinstance(entry, dict)
        and usage_api.normalise_action_type(entry.get("actionType")) == ActionType.AUTO_TRIAGE
    ]


def auto_triage_transactions(record: UsageRecord) -> int | None:
    """The row's Auto Triage transaction count, or None when it cannot say.

    None ("no reading") for:

    * a row without the per action breakdown, whatever its credits: a row that
      briefly comes back with no breakdown (or 0 credits and no breakdown) is
      a dip in the feed, not the project's auto triage falling to nothing;
    * an Auto Triage count that is not a non-negative integer;
    * a breakdown without Auto Triage that is not confirmed complete. Without
      the entry the row is a real 0 only when other actions account for it:
      at least one other action with transactions, every count readable, and
      the counts adding up to the reported total. Anything less (an empty or
      zero breakdown, a total the counts do not reach, no total at all) could
      be a partial breakdown that left Auto Triage out. Without a total it is
      only a possible 0 (``_may_be_zero``).
    """
    actions = record.actions or {}
    if not actions:
        return None
    raw_counts = _raw_auto_triage_counts(record)
    if any(not _valid_count(value) for value in raw_counts):
        return None
    count = actions.get(ActionType.AUTO_TRIAGE.value)
    if count is not None or raw_counts:
        return count if _valid_count(count) else None
    others = list(actions.values())
    if not all(_valid_count(value) for value in others) or sum(others) <= 0:
        return None
    if record.transactions is None or record.transactions != sum(others):
        return None
    return 0


def _may_be_zero(record: UsageRecord) -> bool:
    """A row that says nothing about Auto Triage, yet may be a real 0.

    Either it reports no credits, or its other actions look complete but no
    total confirms that the breakdown left nothing out. Read as 0 only while
    the project's cursor already stands at 0 (so a dip of a project with auto
    triage never resets its cursor, and is not re-charged in full when the
    entry comes back); otherwise no reading.
    """
    if any(not _valid_count(value) for value in _raw_auto_triage_counts(record)):
        return False
    actions = record.actions or {}
    if ActionType.AUTO_TRIAGE.value in actions:
        return False
    if Decimal(record.credits_used or 0) <= 0:
        return True
    others = list(actions.values())
    return (
        record.transactions is None
        and bool(others)
        and all(_valid_count(value) for value in others)
        and sum(others) > 0
    )


def auto_triage_share(record: UsageRecord, price: Decimal | None) -> Decimal:
    """The Auto Triage part of one project row's credits.

    Priced at the tenant-wide credits per Auto Triage transaction, but never
    more than the row's transaction-mix share (its credits less what the mix
    attributes to the other actions): when the tenant average says Auto Triage
    is dearer than this project's own credits allow, the difference would be
    other actions' credits (a person's own triage, already counted against
    them), and those must never be charged to a scan initiator as well.

    Without a tenant price, a row that also did other actions has no Auto
    Triage part anyone can be charged for: the mix share alone can hand a
    person's own (dearer) remediation credits to a scan initiator. Only a row
    whose breakdown is Auto Triage alone then takes its credits.
    """
    actions = record.actions or {}
    count = actions.get(ActionType.AUTO_TRIAGE.value)
    credits = Decimal(record.credits_used or 0)
    if not isinstance(count, int) or count <= 0 or credits <= 0:
        return ZERO
    total = sum(value for value in actions.values() if isinstance(value, int) and value > 0)
    if total <= count:
        return _q(credits)
    if price is None or price <= 0:
        return ZERO
    return _q(min(credits * count / total, price * count))


@dataclass(frozen=True, slots=True)
class ProjectReading:
    """One project's Auto Triage in one snapshot: what the cursor follows."""

    transactions: int
    credits: Decimal
    # False when a row of it said nothing about Auto Triage and nothing confirms
    # that is a 0 (no credits, or a breakdown without a total): read as 0 only
    # while the cursor is already 0.
    certain: bool = True

    @property
    def unit(self) -> Decimal:
        """Credits per Auto Triage transaction for this project, now."""
        if self.transactions <= 0:
            return ZERO
        return self.credits / Decimal(self.transactions)


def project_readings(
    session: Session, snapshot: UsageSnapshot, *, price: Decimal | None
) -> dict[str, ProjectReading | None]:
    """Every synced project's reading in a project snapshot.

    None for a project whose row cannot say how much Auto Triage it did (see
    ``auto_triage_transactions``); a project absent from the snapshot is absent
    here. Both mean "no reading": the collector leaves that project's cursor
    alone. A row that says nothing about Auto Triage and may still be a 0 (see
    ``_may_be_zero``) gives an uncertain 0 (``certain`` false), which the
    collector only takes while the cursor already stands at 0.
    """
    readings: dict[str, ProjectReading | None] = {}
    for record in session.scalars(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.is_not(None)
        )
    ):
        if not record.entity_id:
            continue
        if record.entity_id in readings and readings[record.entity_id] is None:
            continue
        count = auto_triage_transactions(record)
        certain = True
        if count is None:
            if not _may_be_zero(record):
                readings[record.entity_id] = None
                continue
            count, certain = 0, False
        known = readings.get(record.entity_id) or ProjectReading(0, ZERO)
        readings[record.entity_id] = ProjectReading(
            transactions=known.transactions + count,
            credits=known.credits + auto_triage_share(record, price),
            certain=known.certain and certain,
        )
    # A name that joined or left a project (a mapping, a rename, a move, a
    # name missing from a reading and back) shifts the project's figure by
    # its whole Auto Triage history. The usage ledger keeps that shift per
    # project (``UsageEntityOffset``), so the reading moves only by Auto Triage
    # observed while a name counted towards the project: no history is ever
    # charged to whoever scanned (app/services/ledger.py).
    offsets = {
        row.entity_id: row
        for row in session.scalars(
            select(UsageEntityOffset).where(UsageEntityOffset.view_by == UsageView.PROJECT.value)
        )
    }
    for project_id, reading in list(readings.items()):
        offset = offsets.get(project_id)
        if reading is None or offset is None:
            continue
        readings[project_id] = ProjectReading(
            transactions=max(0, reading.transactions - int(offset.auto_triage_transactions or 0)),
            credits=max(ZERO, reading.credits - Decimal(offset.auto_triage_credits or 0)),
            certain=reading.certain,
        )
    return readings


def project_auto_triage_credits(
    session: Session, snapshot: UsageSnapshot, *, price: Decimal | None = None
) -> dict[str, tuple[Decimal, int]]:
    """``A_p`` and its Auto Triage transactions, per synced project that has any."""
    result: dict[str, tuple[Decimal, int]] = {}
    for record in session.scalars(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id.is_not(None)
        )
    ):
        if not record.entity_id:
            continue
        share = auto_triage_share(record, price)
        if share > 0:
            count = (record.actions or {}).get(ActionType.AUTO_TRIAGE.value)
            credits, transactions = result.get(record.entity_id, (ZERO, 0))
            result[record.entity_id] = (
                credits + share,
                transactions + (count if _valid_count(count) else 0),
            )
    return result


# ------------------------------------------------------------------ read model


@dataclass(frozen=True, slots=True)
class AttributedPart:
    """One person's share of one project's Auto Triage credits."""

    user_id: str
    project_id: str
    basis: str
    credits: Decimal
    initiator: str
    # When the increase was observed (the snapshot that showed it). None for an
    # estimated share, which has no date.
    observed_at: datetime | None = None


@dataclass
class ProjectAttribution:
    project_id: str
    auto_triage_credits: Decimal = ZERO
    observed: Decimal = ZERO
    estimated: Decimal = ZERO
    # Recorded as unattributable, or left over with nobody to estimate against.
    unattributed: Decimal = ZERO
    # Shares whose initiator is not a synced user (yet): on the project only.
    unresolved: Decimal = ZERO
    # < 1 when the charges recorded inside the window add up to more than the
    # project now reports (older usage aged out), and were scaled down to fit.
    scale: Decimal = Decimal("1")
    history_status: str | None = None
    observing_since: datetime | None = None

    @property
    def charged_to_people(self) -> Decimal:
        return self.observed + self.estimated


@dataclass
class InitiatorInfo:
    initiator: str
    outcome: MatchOutcome
    credits: Decimal = ZERO


@dataclass
class AttributionModel:
    """Who is charged what, computed from stored data only (no network)."""

    enabled: bool
    available: bool = False
    reference_at: datetime | None = None
    window_start: datetime | None = None
    parts_by_user: dict[str, list[AttributedPart]] = field(default_factory=dict)
    projects: dict[str, ProjectAttribution] = field(default_factory=dict)
    # Keyed by initiator key: every initiator holding a share in the window.
    initiators: dict[str, InitiatorInfo] = field(default_factory=dict)

    def parts_for(self, user_id: str) -> list[AttributedPart]:
        return self.parts_by_user.get(user_id, [])

    def window_total(self, user_id: str) -> Decimal:
        return sum((part.credits for part in self.parts_for(user_id)), ZERO)


def _history_counts(
    state: AutoTriageProjectState | None, *, window_start: datetime
) -> tuple[dict[str | None, tuple[str | None, int]], int]:
    """Completed scans per initiator key in the sample inside the window, and
    how many scans the sample held in all (inside the window or not).

    Scans with no initiator are counted under the key None: they are part of
    the split (their share stays on the project), so the people who did start
    scans are not charged for them.
    """
    counts: dict[str | None, tuple[str | None, int]] = {}
    sampled = 0
    if state is None or not isinstance(state.history, list):
        return counts, sampled
    floor = window_start.date().isoformat()
    for entry in state.history:
        if not isinstance(entry, list | tuple) or len(entry) != 3:
            continue
        initiator, day, count = entry
        if initiator is not None and not isinstance(initiator, str):
            continue
        if not isinstance(day, str) or not isinstance(count, int) or count <= 0:
            continue
        sampled += count
        if day < floor:
            continue
        key = initiator_key(initiator) if initiator and initiator.strip() else None
        name, total = counts.get(key, (initiator if key is not None else None, 0))
        counts[key] = (name, total + count)
    return counts, sampled


def _estimate_cap(
    state: AutoTriageProjectState | None,
    snapshot: UsageSnapshot,
    available: Decimal,
    transactions_now: int,
) -> Decimal:
    """The most of ``A_p`` the history from before observation can explain.

    The history ceiling (in transactions) at the project's current credits per
    Auto Triage transaction. Without a ceiling (no state yet, a state from
    another lookback window, or one from before the ceiling existed) the
    current reading is the ceiling, which bounds nothing beyond ``A_p``.
    """
    if transactions_now <= 0 or available <= 0:
        return ZERO
    ceiling = transactions_now
    if (
        state is not None
        and state.history_ceiling is not None
        and state.period_param == snapshot.period_param
    ):
        ceiling = max(0, min(int(state.history_ceiling), transactions_now))
    if ceiling >= transactions_now:
        return available
    return _q(available * ceiling / transactions_now)


def build_model(
    session: Session, *, user_index: ingestion.UserIndex | None = None
) -> AttributionModel:
    """Split every project's Auto Triage credits across the people who scanned.

    Pure read: safe for the dashboard, the simulation and evaluation alike.
    """
    if not settings_store.auto_triage_to_initiator(session):
        return AttributionModel(enabled=False)
    if not ingestion.dimension_supported(session, UsageView.PROJECT):
        return AttributionModel(enabled=True)
    snapshot = ingestion.latest_snapshot(session, UsageView.PROJECT)
    if snapshot is None:
        return AttributionModel(enabled=True)

    reference = snapshot.collected_at
    window_start = reference - timedelta(days=lookback_days(snapshot.period_param))
    model = AttributionModel(
        enabled=True, available=True, reference_at=reference, window_start=window_start
    )
    totals = project_auto_triage_credits(session, snapshot, price=auto_triage_price(session))

    charges: dict[str, list[tuple[str, str | None, Decimal, datetime]]] = defaultdict(list)
    for project_id, basis, initiator, credits, window_end in session.execute(
        select(
            AutoTriageCharge.project_id,
            AutoTriageCharge.basis,
            AutoTriageCharge.initiator,
            AutoTriageCharge.credits,
            AutoTriageCharge.window_end,
        )
        .where(
            AutoTriageCharge.window_end > window_start,
            AutoTriageCharge.window_end <= reference,
        )
        .order_by(AutoTriageCharge.id)
    ):
        charges[project_id].append((basis, initiator, Decimal(credits or 0), window_end))
    states = {row.project_id: row for row in session.scalars(select(AutoTriageProjectState))}

    index = user_index or ingestion.build_user_index(session)
    resolved: dict[str, MatchOutcome] = {}

    def outcome_for(initiator: str) -> MatchOutcome:
        key = initiator_key(initiator)
        if key not in resolved:
            resolved[key] = resolve_initiator(index, initiator)
        return resolved[key]

    def assign(project: ProjectAttribution, initiator: str, credits: Decimal, basis: str, when):
        if credits <= 0:
            return
        if ingestion.is_synthetic_subject(initiator):
            project.unattributed += credits
            return
        outcome = outcome_for(initiator)
        info = model.initiators.setdefault(
            initiator_key(initiator), InitiatorInfo(initiator=initiator, outcome=outcome)
        )
        info.credits += credits
        user_id = outcome.counted_user_id
        if user_id is None:
            project.unresolved += credits
            return
        if basis == BASIS_OBSERVED:
            project.observed += credits
        else:
            project.estimated += credits
        model.parts_by_user.setdefault(user_id, []).append(
            AttributedPart(
                user_id=user_id,
                project_id=project.project_id,
                basis=basis,
                credits=credits,
                initiator=initiator,
                observed_at=when,
            )
        )

    for project_id in sorted(set(totals) | set(charges)):
        available, transactions_now = totals.get(project_id, (ZERO, 0))
        state = states.get(project_id)
        project = ProjectAttribution(
            project_id=project_id,
            auto_triage_credits=available,
            history_status=state.history_status if state else None,
            observing_since=state.observing_since if state else None,
        )
        model.projects[project_id] = project
        rows = charges.get(project_id, [])
        covered = sum((credits for _b, _i, credits, _w in rows), ZERO)
        if covered > available:
            # Usage that was charged has since aged out of what the project
            # reports. Never charge people more than the project shows.
            project.scale = (available / covered) if covered > 0 else ZERO
        for basis, initiator, credits, window_end in rows:
            share = _q(credits * project.scale) if project.scale != 1 else credits
            if basis == BASIS_OBSERVED and initiator:
                assign(project, initiator, share, BASIS_OBSERVED, window_end)
            else:
                project.unattributed += share

        remainder = available - covered if available > covered else ZERO
        counts, sampled = _history_counts(state, window_start=window_start)
        scans = sum(count for _name, count in counts.values())
        cap = _estimate_cap(state, snapshot, available, transactions_now)
        if sampled and scans < sampled:
            # Part of the sampled history has aged out of the window by date.
            # The transaction ceiling only drops on a net fall, so history
            # ageing out while as many new transactions arrive never lowers
            # it; the scans' own dates do. Only the share of the sample still
            # inside the window can be left of the history.
            cap = _q(cap * scans / sampled)
        if remainder > cap:
            # More than what is left of the history: newer auto triage that no
            # recorded charge explains (an interval that could not be read or
            # was too busy to read, or new transactions netted against older
            # ones ageing out). It is not the history's, so it stays on the
            # project.
            project.unattributed += remainder - cap
            remainder = cap
        if remainder <= 0:
            continue
        if not scans:
            project.unattributed += remainder
            continue
        spent = ZERO
        for key, (name, count) in sorted(counts.items(), key=lambda item: item[0] or ""):
            if key is None or name is None:
                # Scans nobody started (a scheduler): their share stays on
                # the project, below with the rounding remainder.
                continue
            share = _q(remainder * count / scans)
            spent += share
            assign(project, name, share, BASIS_ESTIMATED, None)
        project.unattributed += remainder - spent
    return model


def resolve_initiator(index: ingestion.UserIndex, initiator: str) -> MatchOutcome:
    """The same matching the consumption subjects get: pin, exact ladder, fuzzy."""
    email = initiator if usage_api.looks_like_email(initiator) else None
    return index.resolve_detailed(
        subject_key=initiator_key(initiator), name=initiator.strip(), email=email
    )


# ---------------------------------------------------------- per limit counting


@dataclass(frozen=True, slots=True)
class CountedPart:
    user_id: str
    project_id: str
    basis: str
    credits: Decimal
    counted: Decimal


@dataclass
class AttributedUsage:
    """The attributed auto-triage credits behind one limit's figure."""

    # Included in the period's credits_used.
    counted: Decimal
    # Everything attributed to these people inside the consumption window.
    window_total: Decimal
    # True when the limit counts usage already reported (lifetime, custom,
    # count_existing_usage); otherwise only charges observed after ``since``.
    counts_existing: bool
    since: datetime | None
    parts: list[CountedPart] = field(default_factory=list)

    @property
    def not_counted(self) -> Decimal:
        return self.window_total - self.counted


def attributed_usage(
    model: AttributionModel,
    *,
    user_ids: list[str],
    exclude_projects: set[str] | frozenset[str] = frozenset(),
    counts_existing: bool,
    since: datetime | None,
    skip: Callable[[AttributedPart], bool] | None = None,
) -> AttributedUsage:
    """Sum the parts for these people, under the limit's period rule.

    ``skip``: parts no user budget counts (the integration-account rule of the
    activity source, app/services/activity_source.py ``initiator_skip``)."""
    grouped: dict[tuple[str, str, str], list[Decimal]] = {}
    counted_total = ZERO
    window_total = ZERO
    for user_id in user_ids:
        for part in model.parts_for(user_id):
            if part.project_id in exclude_projects:
                continue
            if skip is not None and skip(part):
                continue
            counts = counts_existing or (
                part.basis == BASIS_OBSERVED
                and part.observed_at is not None
                and (since is None or part.observed_at > since)
            )
            counted = part.credits if counts else ZERO
            bucket = grouped.setdefault((part.user_id, part.project_id, part.basis), [ZERO, ZERO])
            bucket[0] += part.credits
            bucket[1] += counted
            window_total += part.credits
            counted_total += counted
    parts = [
        CountedPart(user_id=user, project_id=project, basis=basis, credits=v[0], counted=v[1])
        for (user, project, basis), v in sorted(grouped.items())
    ]
    return AttributedUsage(
        counted=counted_total,
        window_total=window_total,
        counts_existing=counts_existing,
        since=None if counts_existing else since,
        parts=parts,
    )


# ------------------------------------------------------------------ collection


@dataclass
class CollectResult:
    skipped: str | None = None
    projects: int = 0
    increases: int = 0
    observed_charges: int = 0
    unattributed_charges: int = 0
    histories: int = 0
    requests: int = 0
    # Increases left for the next cycle because the per-cycle cap was reached.
    deferred: int = 0
    # Listings that hit the per-project cap: that increase stays on the project.
    capped: int = 0
    # Projects whose observation (re)started at this reading: setting turned on,
    # lookback window changed, or first seen with consumption it already had.
    restarted: int = 0
    # Of those, projects restarted only because an earlier project row without
    # an id, that matched nothing, could have been theirs (logged as a warning).
    restarted_unidentified: int = 0
    # Projects with no usable reading this cycle (missing from the snapshot, or
    # a row without the per action breakdown): their cursor stayed where it was.
    no_reading: int = 0
    unresolved_initiators: int = 0
    warnings: list[str] = field(default_factory=list)
    # Coverage: projects worked through per cycle at most, the projects left
    # waiting for a later cycle, how long the longest-waiting one has waited,
    # and at this backlog within how many cycles each one is reached.
    per_cycle: int = 0
    backlog: int = 0
    oldest_waiting_minutes: int | None = None
    each_within_cycles: int = 0

    def as_stats(self) -> dict[str, object]:
        return {
            "skipped": self.skipped,
            "projects": self.projects,
            "increases": self.increases,
            "observed_charges": self.observed_charges,
            "unattributed_charges": self.unattributed_charges,
            "histories": self.histories,
            "requests": self.requests,
            "deferred": self.deferred,
            "capped": self.capped,
            "restarted": self.restarted,
            "restarted_unidentified": self.restarted_unidentified,
            "no_reading": self.no_reading,
            "unresolved_initiators": self.unresolved_initiators,
            "per_cycle": self.per_cycle,
            "backlog": self.backlog,
            "oldest_waiting_minutes": self.oldest_waiting_minutes,
            "each_within_cycles": self.each_within_cycles,
            "warnings": self.warnings,
        }


@dataclass(frozen=True, slots=True)
class _Increase:
    project_id: str
    # New Auto Triage transactions, and what they are worth at the project's
    # current credits per transaction.
    delta_transactions: int
    delta: Decimal
    transactions_after: int
    credits_after: Decimal
    window_start: datetime
    window_end: datetime
    snapshot_id: int
    # How far back the "latest scan before the interval" fallback may look.
    widen_floor: datetime
    # The start of the lookback window: charges before it no longer count.
    lookback_start: datetime


@dataclass(frozen=True, slots=True)
class _History:
    project_id: str
    since: datetime
    until: datetime


class _Budget:
    def __init__(self, *, max_projects: int | None = None, max_requests: int | None = None) -> None:
        self.requests = 0
        self.projects = 0
        # 0 in the settings: no cap.
        self.max_projects = MAX_PROJECTS_PER_CYCLE if max_projects is None else max_projects
        self.max_requests = MAX_REQUESTS_PER_CYCLE if max_requests is None else max_requests

    @property
    def exhausted(self) -> bool:
        return bool(
            (self.max_requests and self.requests >= self.max_requests)
            or (self.max_projects and self.projects >= self.max_projects)
        )


def _waiting_since(task: _Increase | _History) -> datetime:
    """Since when this project's work has been waiting to be done."""
    return task.window_start if isinstance(task, _Increase) else task.until


def collect(
    session: Session, client: CheckmarxClient, *, now: datetime | None = None
) -> CollectResult:
    """The cycle step: record who triggered each new increase in Auto Triage credits."""
    result = CollectResult()
    if not settings_store.auto_triage_to_initiator(session):
        result.skipped = "off"
        return result
    if not ingestion.dimension_supported(session, UsageView.PROJECT):
        result.skipped = "this tenant does not report consumption by project"
        return result
    snapshot = ingestion.latest_snapshot(session, UsageView.PROJECT)
    if snapshot is None:
        result.skipped = "no project consumption has been read yet"
        return result

    moment = now or utcnow()
    # The enablement this run observes under. Missing only when the setting was
    # turned on before the stamp existed: start an epoch now, which restarts
    # every project at this reading (nothing before it is observed).
    epoch = settings_store.auto_triage_observation_epoch(
        session
    ) or settings_store.start_auto_triage_observation_epoch(session)
    readings = project_readings(session, snapshot, price=auto_triage_price(session))
    increases, histories = _plan(session, snapshot, readings, epoch=epoch, result=result)
    result.projects = sum(
        1 for reading in readings.values() if reading is not None and reading.credits > 0
    )
    result.increases = len(increases)
    # Nothing is left open in the database while Checkmarx is being called.
    session.commit()

    config = pacing.pacing(session)
    budget = _Budget(
        max_projects=config.attribution_projects_per_cycle,
        max_requests=config.attribution_requests_per_cycle,
    )
    window_start = snapshot.collected_at - timedelta(days=lookback_days(snapshot.period_param))
    # The longest waiting first, increases and histories alike, so a cycle that
    # reaches its cap leaves the newest work and nothing waits for ever: a
    # deferred project keeps its place (its cursor did not move) and comes
    # first next cycle.
    pending: list[_Increase | _History] = sorted(
        [*increases, *histories], key=lambda task: (_waiting_since(task), task.project_id)
    )
    result.per_cycle = budget.max_projects or len(pending)
    result.each_within_cycles = math.ceil(len(pending) / max(1, result.per_cycle)) if pending else 0
    for position, task in enumerate(pending):
        if budget.exhausted or pacing.out_of_time():
            left = pending[position:]
            result.deferred = sum(1 for item in left if isinstance(item, _Increase))
            result.backlog = len(left)
            result.oldest_waiting_minutes = int(
                (moment - min(_waiting_since(item) for item in left)).total_seconds() // 60
            )
            why = (
                "its time budget for this cycle"
                if not budget.exhausted
                else f"its per-cycle cap ({budget.max_projects or 'no'} projects, "
                f"{budget.max_requests or 'no'} requests)"
            )
            message = (
                f"Auto-triage attribution reached {why}; {len(left)} project(s) are left on the "
                "project for now and caught up on the next cycle (the longest waiting first)."
            )
            result.warnings.append(message)
            logger.warning(message)
            break
        budget.projects += 1
        try:
            if isinstance(task, _Increase):
                _observe(session, client, task, budget, result)
            else:
                _collect_history(session, client, task, window_start, budget, result)
        except Exception as exc:  # noqa: BLE001 - one project must never block the others
            # Whatever went wrong (the tenant, an unexpected payload, the
            # database refusing a value), this project's cursor did not move:
            # the next cycle tries the interval again, and until then the
            # increase stays on the project. The other projects go on.
            session.rollback()
            if isinstance(exc, CheckmarxError):
                # Shown in the Notification Center (viewers too) and sent by
                # mail and webhook: redacted like every other error shown there.
                message = (
                    f"Scans of project {task.project_id} could not be read: "
                    f"{error_text.public_error(exc)}"
                )
                logger.warning("Auto-triage attribution: %s", message)
            else:
                message = (
                    f"Auto triage of project {task.project_id} could not be attributed: "
                    f"{error_text.public_error(exc)}"
                )
                logger.exception("Auto-triage attribution: %s", message)
            result.warnings.append(message)
            _record_error(session, task.project_id, message)
            if isinstance(exc, OUTAGE_ERRORS):
                # The tenant is down or throttling us: every further project
                # would only wait through the same retries. Leave the rest for
                # the next cycle (on the project meanwhile).
                left = pending[position + 1 :]
                result.deferred += sum(1 for item in left if isinstance(item, _Increase))
                if left:
                    result.warnings.append(
                        f"Checkmarx did not answer, so {len(left)} more project(s) are left "
                        "for the next cycle."
                    )
                break
    result.requests = budget.requests

    model = build_model(session)
    result.unresolved_initiators = _sync_initiator_subjects(session, model, moment)
    if result.warnings:
        notifications.notify(
            session,
            category=notifications.CATEGORY_SYNC_ERROR,
            severity=Severity.WARNING,
            title="Auto-triage credits could not all be traced to a scan this cycle",
            body=(
                "; ".join(result.warnings[:10])
                + "\n\nThe credits concerned count against the project only until a later "
                "cycle reads them. Nothing else in the cycle was affected."
            ),
            dedupe_key=notifications.sync_error_key(
                "auto_triage_attribution", moment.strftime("%Y-%m-%d")
            ),
        )
    session.commit()
    return result


def _record_error(session: Session, project_id: str, message: str) -> None:
    """Note the failure on the project's state; never let that fail the step."""
    try:
        state = session.get(AutoTriageProjectState, project_id)
        if state is not None:
            state.last_error = message[:2000]
            state.updated_at = utcnow()
        session.commit()
    except Exception:  # noqa: BLE001 - the warning is already in the result
        session.rollback()
        logger.exception("Could not record the auto-triage error of project %s", project_id)


def _is_current(state: AutoTriageProjectState, snapshot: UsageSnapshot, epoch: str) -> bool:
    """Whether the state's cursor belongs to this enablement and lookback window."""
    return (
        state.observation_epoch == epoch
        and state.period_param == snapshot.period_param
        and state.last_transactions is not None
    )


def _earlier_rows(snapshot: UsageSnapshot, *, since: datetime) -> Select:
    """Project rows with consumption in earlier readings inside the window."""
    return (
        select(UsageRecord.id)
        .join(UsageSnapshot, UsageRecord.snapshot_id == UsageSnapshot.id)
        .where(
            UsageRecord.view_by == str(UsageView.PROJECT),
            (UsageRecord.credits_used > 0) | (UsageRecord.transactions > 0),
            UsageSnapshot.period_param == snapshot.period_param,
            UsageSnapshot.collected_at < snapshot.collected_at,
            UsageSnapshot.collected_at > since,
        )
    )


@dataclass(frozen=True, slots=True)
class _UnmatchedRow:
    """An earlier project row that matched no project in the local catalogue."""

    reported_id: str | None
    name: str


def _unmatched_rows(
    session: Session, snapshot: UsageSnapshot, *, since: datetime
) -> list[_UnmatchedRow]:
    """Each distinct unmatched project row with consumption, earlier in the window.

    Ingestion stores a project row it cannot match to the catalogue (a project
    created since the last organisation sync, a failed sync, a name or id
    mismatch) with no entity. One query for the distinct subjects, then the
    newest row of each for the id the feed reported.
    """
    newest = session.execute(
        _earlier_rows(snapshot, since=since)
        .with_only_columns(UsageRecord.subject_key, func.max(UsageRecord.id))
        .where(UsageRecord.entity_id.is_(None))
        .group_by(UsageRecord.subject_key)
    ).all()
    rows: list[_UnmatchedRow] = []
    for subject_key, record_id in newest:
        record = session.get(UsageRecord, record_id)
        if record is None:
            continue
        parsed = usage_api.parse_usage_item(record.raw) if isinstance(record.raw, dict) else None
        name = (record.subject_name or subject_key or "").strip().lower()
        rows.append(_UnmatchedRow(reported_id=parsed.reported_id if parsed else None, name=name))
    return rows


def _identities(
    session: Session, project_id: str, snapshot: UsageSnapshot
) -> tuple[set[str], set[str]]:
    """The ids and lowercased names a project is known by, here and in the feed."""
    ids = {project_id}
    names: set[str] = set()
    project = session.get(CxProject, project_id)
    if project is not None and project.name:
        names.add(project.name.strip().lower())
    for record in session.scalars(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.entity_id == project_id
        )
    ):
        if record.subject_name:
            names.add(record.subject_name.strip().lower())
        if record.subject_key:
            names.add(record.subject_key.strip().lower())
        parsed = usage_api.parse_usage_item(record.raw) if isinstance(record.raw, dict) else None
        if parsed is not None and parsed.reported_id:
            ids.add(parsed.reported_id)
    return ids, names


REPORTED_AS_ITSELF = "itself"
REPORTED_UNIDENTIFIED = "unidentified"


def _reported_before(
    session: Session,
    project_id: str,
    snapshot: UsageSnapshot,
    *,
    since: datetime,
    unmatched: list[_UnmatchedRow],
) -> str | None:
    """Whether an earlier project reading (inside the window) showed consumption.

    ``REPORTED_AS_ITSELF`` when a row of this project (by entity, reported id or
    name) did; ``REPORTED_UNIDENTIFIED`` when only an unmatched row without an
    id could have been it; None when nothing earlier was.

    Tells a project that is genuinely new (its first consumption arrived since
    the last reading) from one that was missing from a reading or two and comes
    back with consumption it already had. Earlier rows that matched no project
    count too when they are this project's: the same reported id, or the same
    name. An unmatched row with no reported id cannot be told apart from this
    project, so it counts as well: restarting estimates the history, observing
    could charge all of it to whoever scanned last.
    """
    matched = session.scalar(
        _earlier_rows(snapshot, since=since).where(UsageRecord.entity_id == project_id).limit(1)
    )
    if matched is not None:
        return REPORTED_AS_ITSELF
    if not unmatched:
        return None
    ids, names = _identities(session, project_id, snapshot)
    if any(row.reported_id in ids or row.name in names for row in unmatched):
        return REPORTED_AS_ITSELF
    if any(row.reported_id is None for row in unmatched):
        return REPORTED_UNIDENTIFIED
    return None


def _plan(
    session: Session,
    snapshot: UsageSnapshot,
    readings: dict[str, ProjectReading | None],
    *,
    epoch: str,
    result: CollectResult,
) -> tuple[list[_Increase], list[_History]]:
    """Move cursors that need no Checkmarx call, and list the work that does."""
    states = {row.project_id: row for row in session.scalars(select(AutoTriageProjectState))}
    # The last reading observation already dealt with, in this enablement and
    # lookback window. A cursor from an earlier enablement says nothing about
    # what happened while the setting was off.
    previous = max(
        (row.last_collected_at for row in states.values() if _is_current(row, snapshot, epoch)),
        default=None,
    )
    lookback = timedelta(days=lookback_days(snapshot.period_param))
    window_start = snapshot.collected_at - lookback
    # Where the previous charged interval ended: a scan that completed before
    # that was dealt with then (charged, or part of an interval without a rise).
    latest_charge = dict(
        session.execute(
            select(AutoTriageCharge.project_id, func.max(AutoTriageCharge.window_end)).group_by(
                AutoTriageCharge.project_id
            )
        ).all()
    )
    unmatched: list[_UnmatchedRow] | None = None
    increases: list[_Increase] = []
    histories: list[_History] = []
    for project_id in sorted(set(readings) | set(states)):
        reading = readings.get(project_id)
        state = states.get(project_id)
        if (
            reading is not None
            and not reading.certain
            and not (
                state is not None
                and _is_current(state, snapshot, epoch)
                and int(state.last_transactions or 0) == 0
                and reading.transactions == 0
            )
        ):
            # A row with no credits that says nothing about Auto Triage: a 0
            # only for a project whose cursor already stands at 0. Otherwise it
            # is a dip in the feed, and taking it would re-charge the whole
            # count as new when the row comes back.
            reading = None
        if reading is None:
            # Missing from this reading, or a row without the breakdown: no
            # reading at all. The cursor stays, so the next real reading is
            # measured from the last one, and a dip is never re-charged.
            if state is not None:
                result.no_reading += 1
                if state.history_status == "pending" and _is_current(state, snapshot, epoch):
                    histories.append(
                        _History(
                            project_id=project_id,
                            since=window_start,
                            until=state.observing_since,
                        )
                    )
            continue
        if state is None and previous is not None and previous < snapshot.collected_at:
            if unmatched is None:
                unmatched = _unmatched_rows(session, snapshot, since=window_start)
            reported = _reported_before(
                session, project_id, snapshot, since=window_start, unmatched=unmatched
            )
            if reported == REPORTED_UNIDENTIFIED:
                # Only once per project: the state made below is current from
                # now on, so this project is never asked again.
                result.restarted_unidentified += 1
                logger.warning(
                    "Auto-triage attribution: project %s is new, but an earlier project row "
                    "without an id matched nothing in the catalogue and could have been it; "
                    "its consumption so far is estimated from its scans, not observed.",
                    project_id,
                )
            if reported is None:
                # A project with no consumption at all in the readings before:
                # all of it arrived since the last reading dealt with, so it is
                # observed. It has no history.
                state = AutoTriageProjectState(
                    project_id=project_id,
                    period_param=snapshot.period_param,
                    observation_epoch=epoch,
                    observing_since=previous,
                    history_status="none",
                    history_ceiling=0,
                    last_snapshot_id=None,
                    last_collected_at=previous,
                    last_transactions=0,
                    last_credits=ZERO,
                    updated_at=utcnow(),
                )
                session.add(state)
        if state is None or not _is_current(state, snapshot, epoch):
            # Observation (re)starts now: the setting was turned on, the
            # lookback window changed, or the project was first seen with
            # consumption it already had. What it reports so far is history,
            # estimated from the scans before this moment, never observed.
            if state is None:
                state = AutoTriageProjectState(project_id=project_id)
                session.add(state)
            state.period_param = snapshot.period_param
            state.observation_epoch = epoch
            state.observing_since = snapshot.collected_at
            state.history_status = "pending" if reading.transactions > 0 else "none"
            state.history = None
            state.history_collected_at = None
            state.history_ceiling = reading.transactions
            state.last_error = None
            _advance(state, snapshot, reading)
            result.restarted += 1
        elif (
            state.last_snapshot_id != snapshot.id
            and snapshot.collected_at > state.last_collected_at
        ):
            delta_transactions = reading.transactions - int(state.last_transactions or 0)
            delta = _q(reading.unit * delta_transactions) if delta_transactions > 0 else ZERO
            if delta > 0:
                floors = [
                    window_start,
                    state.observing_since - OBSERVATION_LAG,
                ]
                if latest_charge.get(project_id) is not None:
                    floors.append(latest_charge[project_id])
                increases.append(
                    _Increase(
                        project_id=project_id,
                        delta_transactions=delta_transactions,
                        delta=delta,
                        transactions_after=reading.transactions,
                        credits_after=reading.credits,
                        window_start=state.last_collected_at - OBSERVATION_LAG,
                        window_end=snapshot.collected_at,
                        snapshot_id=snapshot.id,
                        widen_floor=max(floors),
                        lookback_start=window_start,
                    )
                )
            else:
                # No new transactions, or fewer (older ones aged out of the
                # lookback window): the cursor follows, nothing is charged.
                # What ages out is the oldest first, so a fall comes out of the
                # history before anything observed: its ceiling drops with it.
                if delta_transactions < 0:
                    base = state.history_ceiling
                    if base is None:
                        base = int(state.last_transactions or 0)
                    state.history_ceiling = max(
                        0, min(base + delta_transactions, reading.transactions)
                    )
                _advance(state, snapshot, reading)
        if state.history_status == "pending":
            histories.append(
                _History(project_id=project_id, since=window_start, until=state.observing_since)
            )
    session.flush()
    # The longest waiting first, so a capped cycle cannot starve a project.
    increases.sort(key=lambda item: (item.window_start, item.project_id))
    histories.sort(key=lambda item: (item.until, item.project_id))
    return increases, histories


def _charged_scans(session: Session, task: _Increase) -> set[str]:
    """The scans this project's recent charges already name.

    The interval opens a lag before the previous reading, so without this a
    scan that completed just before that reading would take a full share of
    the next rise too. A scan in an interval that showed no rise is in no
    charge, so auto triage that genuinely landed late is still placed. Read
    only for a project being observed, through the (project, window_end) index.

    Only charges that could name a scan this interval (or its widen fallback)
    can take are read, not every charge in the lookback window: ``_list`` keeps
    a scan only if it completed at most ``MAX_SCAN_RUNTIME`` after its
    creation, and a scan only qualifies if it completed after the interval's
    start (or the widen floor), so every scan that can qualify was created
    after the floor below. A charge ends no
    earlier than the completion it saw for each scan it names, which is no
    earlier than that scan's creation; a charge that ended before the floor
    cannot name a scan seen now, however far its ``updatedAt`` has moved.
    """
    floor = min(task.window_start, task.widen_floor) - MAX_SCAN_RUNTIME
    charged: set[str] = set()
    for scan_ids in session.scalars(
        select(AutoTriageCharge.scan_ids).where(
            AutoTriageCharge.project_id == task.project_id,
            AutoTriageCharge.window_end > floor,
            AutoTriageCharge.scan_count > 0,
        )
    ):
        if isinstance(scan_ids, list):
            charged.update(str(scan_id) for scan_id in scan_ids)
    return charged


def _advance(
    state: AutoTriageProjectState, snapshot: UsageSnapshot, reading: ProjectReading
) -> None:
    state.last_snapshot_id = snapshot.id
    state.last_collected_at = snapshot.collected_at
    state.last_transactions = reading.transactions
    state.last_credits = reading.credits
    state.updated_at = utcnow()


def _read_branches(
    session: Session, client: CheckmarxClient, project_id: str, budget: _Budget
) -> list[str] | None:
    """The auto-triage branches, or None for "all branches".

    Read whether or not auto triage is enabled now: a project where it ran and
    was later switched off still has the branches it ran on. A configuration
    whose ``branches`` is not a list is read as naming none.
    """
    session.commit()
    budget.requests += 1
    try:
        state = platform.get_auto_triage(client, project_id=project_id)
    except OUTAGE_ERRORS:
        # An outage says nothing about the configuration; the listing would fail
        # too. Let the caller treat the whole project as unreadable this cycle.
        raise
    except CheckmarxError as exc:
        logger.info(
            "Auto-triage configuration of %s unreadable (%s); all branches", project_id, exc
        )
        return None
    raw = state.config.get("branches") if isinstance(state.config, dict) else None
    if raw is None:
        return None
    if not isinstance(raw, list):
        logger.info(
            "Auto-triage configuration of %s has branches of type %s; all branches",
            project_id,
            type(raw).__name__,
        )
        return None
    branches = [entry.strip() for entry in raw if isinstance(entry, str) and entry.strip()]
    return branches or None


@dataclass
class _Listed:
    # Completed scans on the auto-triage branches, newest completion first.
    scans: list[scans_api.ScanSummary]
    # True when a page cap stopped a listing before it reached ``since``: older
    # scans exist that were not read.
    truncated: bool


def _list(
    session: Session,
    client: CheckmarxClient,
    *,
    project_id: str,
    branches: list[str] | None,
    since: datetime | None,
    max_pages: int,
    page_size: int,
    budget: _Budget,
) -> _Listed:
    """Completed scans on the given branches, newest first, and whether capped.

    Scans without an initiator are kept: they are part of the split, and their
    share stays on the project. Scans created before ``since`` that were on the
    last page read are kept too (no extra request): a long scan can complete
    well after it was created. Any scan whose ``updatedAt`` is more than
    ``MAX_SCAN_RUNTIME`` after its creation is dropped: that is a later edit of
    an old scan, not its completion. Callers filter by completion time.
    """
    if (
        branches
        and len(branches) <= MAX_BRANCH_LISTINGS
        and not any(scans_api.has_wildcard(branch) for branch in branches)
    ):
        targets: list[str | None] = list(branches)
    else:
        targets = [None]
    found: dict[str, scans_api.ScanSummary] = {}
    truncated = False

    def plausible(scan: scans_api.ScanSummary) -> bool:
        # ``completed_at`` is the scan's ``updatedAt``. A scan without a
        # creation time, or "completed" before it was created, cannot be
        # placed; one "completed" more than ``MAX_SCAN_RUNTIME`` after it was
        # created was edited later, and its ``updatedAt`` is not a completion.
        # That matters most for the scans created before ``since`` on the last
        # page, and for the widen listing, which can reach weeks back.
        if scan.created_at is None or scan.completed_at is None:
            return False
        return timedelta(0) <= scan.completed_at - scan.created_at <= MAX_SCAN_RUNTIME

    for branch in targets:
        session.commit()
        listing = scans_api.list_project_scans(
            client,
            project_id=project_id,
            branch=branch,
            since=since,
            page_size=page_size,
            max_pages=max_pages,
        )
        budget.requests += listing.requests
        truncated = truncated or listing.truncated
        for scan in (*listing.scans, *listing.older):
            if (
                scan.completed
                and plausible(scan)
                and scans_api.branch_matches(scan.branch, branches)
            ):
                found.setdefault(scan.id, scan)
    ordered = sorted(found.values(), key=lambda scan: scan.completed_at, reverse=True)  # type: ignore[arg-type, return-value]
    return _Listed(scans=ordered, truncated=truncated)


def _observe(
    session: Session,
    client: CheckmarxClient,
    task: _Increase,
    budget: _Budget,
    result: CollectResult,
) -> None:
    charged = _charged_scans(session, task)
    branches = _read_branches(session, client, task.project_id, budget)
    # Listed back to the window start less the runtime allowance: a scan
    # created before that is only seen if it was on the last page read. The
    # listing is newest first by creation, so "truncated" means exactly that the
    # unread tail still holds scans created after that point, which could have
    # completed inside the interval.
    listed = _list(
        session,
        client,
        project_id=task.project_id,
        branches=branches,
        since=task.window_start - SCAN_RUNTIME_ALLOWANCE,
        max_pages=MAX_PAGES_PER_LISTING,
        page_size=SCAN_PAGE_SIZE,
        budget=budget,
    )
    in_window = [
        scan
        for scan in listed.scans
        if scan.completed_at is not None
        and task.window_start < scan.completed_at <= task.window_end
    ]
    # A scan an earlier charge already took a share for is not charged again:
    # the interval opens a lag before the previous reading, and a scan that
    # completed in that lag was part of the previous rise. It still counts in
    # the split, its share stays on the project: auto triage of it that landed
    # late is not moved onto the other scans of the interval.
    qualifying = [scan for scan in in_window if scan.id not in charged]
    already = [scan for scan in in_window if scan.id in charged]
    detail: str | None = None
    if listed.truncated:
        # Too many scans to see them all: a split over the ones we happened to
        # read would be biased, so this increase stays on the project,
        # recorded as such so that it is never estimated to the history.
        result.capped += 1
        message = (
            f"Project {task.project_id} had more scans in one interval than the "
            f"{MAX_PAGES_PER_LISTING * SCAN_PAGE_SIZE} read per project; that increase is "
            "left on the project instead."
        )
        result.warnings.append(message)
        logger.warning("Auto-triage attribution: %s", message)
        result.unattributed_charges += 1
        _finish(
            session,
            task,
            branches,
            charges=[_unattributed(task, utcnow(), detail=message)],
            note=message,
        )
        return
    if not in_window:
        # Widen once: the latest qualifying scan that completed before the
        # window opened (an auto triage that ran late, or a long lag). Never
        # further back than the lookback window, the start of observation, or
        # the end of the previous charged interval, and never a scan a charge
        # already names: a scan before that was either already charged for its
        # own auto triage or belongs to the estimate.
        earlier = _list(
            session,
            client,
            project_id=task.project_id,
            branches=branches,
            since=task.widen_floor - SCAN_RUNTIME_ALLOWANCE,
            max_pages=1,
            page_size=WIDEN_PAGE_SIZE,
            budget=budget,
        )
        before = [
            scan
            for scan in earlier.scans
            if scan.completed_at is not None
            and task.widen_floor < scan.completed_at <= task.window_end
            and scan.id not in charged
        ]
        if before:
            qualifying = [before[0]]
            detail = "No scan completed in the window; charged to the latest one before it."

    now = utcnow()
    charges: list[AutoTriageCharge] = []
    if not qualifying and not already:
        charges.append(
            _unattributed(
                task,
                now,
                detail="No completed scan on the auto-triage branches explains this increase.",
            )
        )
        result.unattributed_charges += 1
    else:
        # Scans without an initiator, and scans already charged, stay in the
        # denominator: their share is recorded as unattributed, so the people
        # who did start the other scans are only charged for theirs.
        total = len(qualifying) + len(already)
        if already:
            charges.append(
                _unattributed(
                    task,
                    now,
                    credits=_q(task.delta * len(already) / total),
                    scans=already,
                    detail="Scans an earlier charge already named: their share stays on the "
                    "project.",
                )
            )
            result.unattributed_charges += 1
        by_initiator: dict[str | None, list[scans_api.ScanSummary]] = defaultdict(list)
        names: dict[str, str] = {}
        for scan in qualifying:
            if scan.initiator and scan.initiator.strip():
                key: str | None = initiator_key(scan.initiator)
                names.setdefault(key, initiator_name(scan.initiator))  # type: ignore[arg-type]
            else:
                key = None
            by_initiator[key].append(scan)
        for key, group in sorted(by_initiator.items(), key=lambda item: item[0] or ""):
            credits = _q(task.delta * len(group) / total)
            if key is None:
                charges.append(
                    _unattributed(
                        task,
                        now,
                        credits=credits,
                        scans=group,
                        detail="Scans with no initiator: their share stays on the project.",
                    )
                )
                result.unattributed_charges += 1
                continue
            charges.append(
                AutoTriageCharge(
                    project_id=task.project_id,
                    basis=BASIS_OBSERVED,
                    initiator=names[key],
                    initiator_key=key,
                    scan_ids=[scan.id for scan in group],
                    scan_count=len(group),
                    credits=credits,
                    window_start=task.window_start,
                    window_end=task.window_end,
                    snapshot_id=task.snapshot_id,
                    created_at=now,
                    detail=detail,
                )
            )
            result.observed_charges += 1
    _finish(session, task, branches, charges=charges, note=None)


def _unattributed(
    task: _Increase,
    now: datetime,
    *,
    detail: str,
    credits: Decimal | None = None,
    scans: list[scans_api.ScanSummary] | None = None,
) -> AutoTriageCharge:
    """A charge that keeps (part of) an increase on the project, on record."""
    return AutoTriageCharge(
        project_id=task.project_id,
        basis=BASIS_UNATTRIBUTED,
        initiator=None,
        initiator_key=None,
        scan_ids=[scan.id for scan in scans or []],
        scan_count=len(scans or []),
        credits=task.delta if credits is None else credits,
        window_start=task.window_start,
        window_end=task.window_end,
        snapshot_id=task.snapshot_id,
        created_at=now,
        detail=detail,
    )


def _finish(
    session: Session,
    task: _Increase,
    branches: list[str] | None,
    *,
    charges: list[AutoTriageCharge],
    note: str | None,
) -> None:
    """Record the charges and move the cursor, in one short transaction."""
    state = session.get(AutoTriageProjectState, task.project_id)
    for charge in charges:
        session.add(charge)
    if state is not None:
        state.last_snapshot_id = task.snapshot_id
        state.last_collected_at = task.window_end
        state.last_transactions = task.transactions_after
        state.last_credits = task.credits_after
        state.branches = branches
        state.last_error = note
        state.updated_at = utcnow()
    session.commit()


def _collect_history(
    session: Session,
    client: CheckmarxClient,
    task: _History,
    window_start: datetime,
    budget: _Budget,
    result: CollectResult,
) -> None:
    """Sample the scans that credits from before observation are estimated against."""
    branches = _read_branches(session, client, task.project_id, budget)
    listed = _list(
        session,
        client,
        project_id=task.project_id,
        branches=branches,
        since=task.since - SCAN_RUNTIME_ALLOWANCE,
        max_pages=HISTORY_MAX_PAGES,
        page_size=SCAN_PAGE_SIZE,
        budget=budget,
    )
    # Scans with no initiator are counted too (as null): they take their share
    # of the estimate, which then stays on the project.
    counts: dict[tuple[str | None, str], int] = defaultdict(int)
    for scan in listed.scans:
        if scan.completed_at is None:
            continue
        if not (task.since <= scan.completed_at <= task.until):
            continue
        name = initiator_name(scan.initiator) if scan.initiator and scan.initiator.strip() else None
        counts[(name, scan.completed_at.date().isoformat())] += 1
    state = session.get(AutoTriageProjectState, task.project_id)
    if state is not None:
        state.history = [
            [name, day, count]
            for (name, day), count in sorted(
                counts.items(), key=lambda item: (item[0][0] or "", item[0][1])
            )
        ]
        state.history_status = "truncated" if listed.truncated else "done"
        state.history_collected_at = utcnow()
        state.branches = branches
        state.last_error = (
            f"Only the newest {HISTORY_MAX_PAGES * SCAN_PAGE_SIZE} scans were sampled."
            if listed.truncated
            else None
        )
        state.updated_at = utcnow()
    if listed.truncated:
        logger.info(
            "Auto-triage history for project %s sampled from the newest scans only", task.project_id
        )
    result.histories += 1
    session.commit()


# ---------------------------------------------------------- unresolved initiators


def _sync_initiator_subjects(session: Session, model: AttributionModel, now: datetime) -> int:
    """Raise every initiator that is not a synced user, so an admin can map it.

    Uses the same review row (``unresolved_subject``) and the same mapping flow as
    a consumption subject, marked with ``view_by = "scan_initiator"``. A row the
    consumption feed already owns (same key) is left to it: mapping it covers both.
    """
    unresolved = 0
    for key, info in sorted(model.initiators.items()):
        outcome = info.outcome
        row = session.scalar(select(UnresolvedSubject).where(UnresolvedSubject.subject_key == key))
        if outcome.method in (MatchMethod.PINNED, MatchMethod.EXACT):
            if (
                row is not None
                and row.mapped_user_id is None
                and row.view_by == SOURCE_SCAN_INITIATOR
            ):
                session.delete(row)
            continue
        if row is not None and row.view_by != SOURCE_SCAN_INITIATOR:
            continue
        top = outcome.candidates[0] if outcome.candidates else None
        suggestions = [candidate.as_dict() for candidate in outcome.candidates] or None
        newly_auto = (
            outcome.method == MatchMethod.FUZZY_AUTO
            and top is not None
            and (
                row is None
                or row.status != MatchMethod.FUZZY_AUTO
                or row.suggested_user_id != top.user_id
            )
        )
        email = info.initiator if usage_api.looks_like_email(info.initiator) else None
        if row is None:
            row = UnresolvedSubject(
                subject_key=key,
                subject_name=info.initiator,
                subject_email=email,
                view_by=SOURCE_SCAN_INITIATOR,
                credits_used=info.credits,
                first_seen_at=now,
                last_seen_at=now,
                times_seen=1,
                status=outcome.method,
                is_bot=outcome.is_bot,
                suggested_user_id=top.user_id if top else None,
                match_score=top.score if top else None,
                suggestions=suggestions,
            )
            session.add(row)
        else:
            row.last_seen_at = now
            row.times_seen += 1
            row.credits_used = info.credits
            row.status = outcome.method
            row.is_bot = outcome.is_bot
            row.suggested_user_id = top.user_id if top else None
            row.match_score = top.score if top else None
            row.suggestions = suggestions
        if outcome.counted_user_id is None:
            unresolved += 1
            if not outcome.is_bot:
                notifications.notify(
                    session,
                    category=notifications.CATEGORY_ATTRIBUTION,
                    severity=Severity.WARNING,
                    title=f"Auto-triage credits could not be charged to a person: {info.initiator}",
                    body=(
                        f"Scans started by {info.initiator} triggered auto triage worth "
                        f"{_q(info.credits)} credits, but {info.initiator} does not match any "
                        "synced Checkmarx user, so those credits count against the project only. "
                        "If they belong to a person (a bot or integration acting for someone), "
                        "map it to that user under Settings → Attribution."
                    ),
                    dedupe_key=notifications.attribution_key(key),
                )
        if newly_auto and top is not None:
            record_audit(
                session,
                action="usage.subject_auto_matched",
                actor=AuditActor(actor_type=ActorType.SYSTEM, actor_name="matcher"),
                target_type="unresolved_subject",
                target_id=key[:64],
                target_label=info.initiator,
                after={"suggested_user_id": top.user_id, "score": round(top.score, 4)},
                detail=(
                    f"Scans started by {info.initiator} were automatically matched to "
                    f"{top.label} at {round(top.score * 100)}% confidence for auto-triage "
                    "attribution. Override it under Settings → Attribution if this is wrong."
                ),
            )
    session.flush()
    return unresolved
