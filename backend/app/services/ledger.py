"""The usage ledger: period budgets count increases, never totals.

The consumption feed reports, per name, a cumulative total over a lookback
window. A budget period that took "the current total of the names that count
towards it, minus one baseline taken when the period opened" broke whenever
the set of names changed (a mapping, a rename, a deletion and return, a group
membership, demo mode): history came in, or usage already counted went out.

So every live reading is turned into increases instead (``record_reading``),
in the same transaction that stores the reading:

* For each name, the increase is its total now minus its total in the previous
  live reading of the same view. A name missing from that reading is compared
  with the total it last had (``UsageMissingName``, kind "missing"; forgotten
  once older than the lookback window), so a return adds only what it reported
  since. A fall adds nothing: in a believed reading the name continues from its
  new total (the window rolled past old usage); in one the completeness checks
  doubt (``suspect``), the fall is held (kind "dip") until the name recovers or
  a believed reading confirms it; past DIP_MAX_DOUBTS readings or DIP_MAX_AGE
  it is no longer reported but stays a ceiling (kind "ceiling"), as does every
  fall in a collapse of the whole feed accepted only because it persisted
  (kind "collapse"): only usage above it counts. A remembered name is
  forgotten once its total last rose, or fell to a non-zero total
  (``last_rise_at``), before the lookback window (plus HORIZON_MARGIN) began. A name back after
  missing readings starts from the highest of its own last total and those of
  the names it may have been meanwhile (a rename and a rename back).
* A name never seen before counts in full: a name absent from the previous
  reading reported nothing then. Unless it may be a rename: a name of an entity
  starts from the highest last total of that entity's remembered names and of
  unmatched names that left within the window; a name of nothing from the
  highest of any names that left within the window (per action type too). That
  can under-count, never over-count. The very first reading, and a reading in
  another lookback window, are history: nothing is counted from them, and a
  name missing then starts from what it reports when it returns (kind
  "rebase").
* A group's or application's own row that is new, or back, counts nothing,
  in that reading and the next (kind "fresh"): its
  projects fed its budget while it was not there (``own_figures``, decided once
  per ingest, says which feeds a group or application budget).
* Each increase is attributed to the entity the name counts towards at that
  moment (``UsageDelta``), and added to the counter of every active budget that
  entity feeds at that moment, per month and per quarter of the observation;
  none of it when its interval (``since`` to ``observed_at``) spans that
  period's start. A period budget's usage is its counter. Every active budget
  is fed, whatever its type; one that counts usage already reported reads
  totals instead.
* An increase observed while a name counted towards nothing is kept. It is
  claimed by the entity the name comes to match by its own name, for what was
  observed within the window before that entity was first synced (a project
  created and used before the sync brought it). A mapping settles it
  (``settle_waiting``): never claimed.

Mappings, renames, deletions and returns, and membership changes therefore
only ever move usage observed from then on. What is lost, by construction:
usage a name reported between its last reading under one name and its first
under a new one that could not be paired; what a new name adds in its first
reading when it may be a rename; increases hidden by the lookback window
rolling past older usage in the same interval, or by a real fall first
reported in a doubted reading; an interval spanning a period start; the
reading in which an aggregate row leaves its view; and usage observed while a
name counted towards nothing that no new entity claims.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType, UsageView
from app.models.limits import CreditLimit
from app.models.org import (
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.usage import (
    BudgetUsage,
    UsageDelta,
    UsageEntityOffset,
    UsageMissingName,
    UsageRecord,
    UsageSnapshot,
)

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
MISSING = "missing"
DIP = "dip"
REBASE = "rebase"
# A held fall that outlasted its doubt bound: the name's usage counts again
# only above the total it had before the fall. Cleared by a believed reading
# that confirms a lower total, by rising above it, or at the lookback horizon.
CEILING = "ceiling"
# The same after a collapse of the whole feed that was accepted only because
# it persisted (ingestion._hold_reason): cleared only by rising above it or at
# the lookback horizon, never by a reading of the same collapse.
COLLAPSE = "collapse"
# A group's or application's own row in its second reading: counts nothing
# either (the overlap between the reads of one ingest).
FRESH = "fresh"
HELD_KINDS = (DIP, CEILING, COLLAPSE)
# A couple of days beyond the lookback window before a total is forgotten:
# calendar-year and day-granular windows reach that far.
HORIZON_MARGIN = timedelta(days=2)
# A doubted fall is believed after this many doubted readings in a row, or
# once it has been doubted this long, whichever comes first.
DIP_MAX_DOUBTS = 3
DIP_MAX_AGE = timedelta(hours=2)
AGGREGATE_VIEWS = (UsageView.GROUP.value, UsageView.APPLICATION.value)
FUSION_MODEL = "fusion_model:"
SLID = "_slid"

_VIEW_MODEL = {
    UsageView.USER.value: CxUser,
    UsageView.PROJECT.value: CxProject,
    UsageView.APPLICATION.value: CxApplication,
    UsageView.GROUP.value: CxGroup,
}
_VIEW_ENTITY = {
    UsageView.USER.value: EntityType.USER,
    UsageView.PROJECT.value: EntityType.PROJECT,
    UsageView.APPLICATION.value: EntityType.APPLICATION,
    UsageView.GROUP.value: EntityType.GROUP,
}


# ------------------------------------------------------------------- counts


def counts_of(record) -> dict[str, int]:  # type: ignore[no-untyped-def]
    """A row's per action transaction counts, with one ``fusion_model:`` entry
    per Fusion model from the raw row (what a Fusion price needs)."""
    from app.checkmarx import usage as usage_api

    counts: dict[str, int] = {}
    for action, count in (record.actions or {}).items():
        if isinstance(count, int) and not isinstance(count, bool):
            counts[str(action)] = counts.get(str(action), 0) + count
    raw = record.raw if isinstance(getattr(record, "raw", None), dict) else {}
    performed = raw.get("actionsPerformed") if isinstance(raw, dict) else None
    entries = performed.get("actions") if isinstance(performed, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        action, count = entry.get("actionType"), entry.get("transactionCount")
        if (
            isinstance(action, str)
            and usage_api.normalise_action_type(action) == "fusion"
            and isinstance(count, int)
            and not isinstance(count, bool)
        ):
            key = FUSION_MODEL + usage_api.action_key(action)
            counts[key] = counts.get(key, 0) + count
    return counts


def plain_actions(counts: dict | None) -> dict[str, int]:
    """The per action counts without the Fusion model entries and markers."""
    return {
        key: value
        for key, value in (counts or {}).items()
        if not str(key).startswith((FUSION_MODEL, "_")) and isinstance(value, int)
    }


def slid(counts: dict | None) -> bool:
    """True when an increase came with another action of the same name that
    did not rise (it may have slid out of the window as many new ones
    arrived, or fallen): which action the credits were spent on cannot be told
    from the counts alone."""
    return bool((counts or {}).get(SLID))


def fusion_models(counts: dict | None) -> dict[str, int]:
    """The Fusion model entries, keyed like ``usage_mix._fusion_models``."""
    return {
        str(key)[len(FUSION_MODEL) :]: value
        for key, value in (counts or {}).items()
        if str(key).startswith(FUSION_MODEL) and isinstance(value, int)
    }


def _drop(session: Session, row) -> None:  # type: ignore[no-untyped-def]
    if row in session.new:
        session.expunge(row)
    else:
        session.delete(row)


def _increase(now: dict[str, int], before: dict[str, int]) -> dict[str, int]:
    return {
        key: count - before.get(key, 0)
        for key, count in now.items()
        if count - before.get(key, 0) > 0
    }


def _add(into: dict[str, int], more: dict[str, int] | None) -> dict[str, int]:
    for key, count in (more or {}).items():
        if isinstance(count, int):
            into[key] = into.get(key, 0) + count
    return into


# ------------------------------------------------------------------- feeding


def counts_existing(limit: CreditLimit) -> bool:
    """A budget that counts usage already reported reads current totals, not
    its counter (which is still fed, so switching back loses nothing)."""
    from app.models.enums import PeriodType

    return limit.period_type in {PeriodType.LIFETIME, PeriodType.CUSTOM} or bool(
        limit.count_existing_usage
    )


def own_figures(session: Session, excluding: int | None = None) -> dict[str, set[str]]:
    """Groups and applications with a row of their own in their view's latest
    live reading (``view``), and in the one before it too (``view:steady``).
    Taken once per ingest, before any view is read, so a group or application
    budget is fed either by its own row or by its projects in a given cycle,
    whichever order the views are read in. An own row feeds its budget only
    once it is steady: in the ingest its entity first has one, its projects
    have fed the budget up to their own read, after the application's."""
    from app.services.settings_store import DEMO_PERIOD_PARAM

    found: dict[str, set[str]] = {}
    for view in AGGREGATE_VIEWS:
        query = (
            select(UsageSnapshot.id)
            .where(
                UsageSnapshot.view_by == view,
                UsageSnapshot.held_reason.is_(None),
                UsageSnapshot.period_param.is_distinct_from(DEMO_PERIOD_PARAM),
            )
            .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
            .limit(2)
        )
        if excluding is not None:
            query = query.where(UsageSnapshot.id != excluding)
        ids = list(session.scalars(query))
        sets = [
            {
                str(entity_id)
                for entity_id in session.scalars(
                    select(UsageRecord.entity_id).where(
                        UsageRecord.snapshot_id == snapshot_id,
                        UsageRecord.entity_id.is_not(None),
                    )
                )
            }
            for snapshot_id in ids
        ]
        found[view] = sets[0] if sets else set()
        found[f"{view}:steady"] = sets[0] & sets[1] if len(sets) == 2 else set()
        # The latest reading of the view before this ingest (its id).
        found[f"{view}:upto"] = {str(ids[0])} if ids else set()
    return found


class _Feeds:
    """Which budgets an entity of one view feeds, now."""

    def __init__(self, session: Session, view: str, own: dict[str, set[str]] | None = None) -> None:
        self.session = session
        self.view = view
        self.by_target: dict[tuple[str, str], list[CreditLimit]] = defaultdict(list)
        for limit in session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))):
            self.by_target[(str(limit.entity_type), limit.entity_id)].append(limit)
        self._own = own if own is not None else None
        self._last_own: dict[str, dict[str, datetime]] = {}

    def _with_own_figure(self, view: str) -> set[str]:
        if self._own is None:
            self._own = own_figures(self.session)
        return self._own.get(view, set())

    def own_row_until(self, limit: CreditLimit) -> datetime | None:
        """For a group or application budget fed by its projects: when a
        reading of its view last had its own row (which fed it then). A
        project's increase whose interval began before that may hold usage the
        own row already counted, so it does not feed the budget. None for any
        other budget."""
        kind = str(limit.entity_type)
        if self.view != UsageView.PROJECT.value or kind not in (
            EntityType.GROUP.value,
            EntityType.APPLICATION.value,
        ):
            return None
        if kind == EntityType.GROUP.value and limit.include_member_usage:
            return None  # fed by its members' rows whatever its own row does
        view = (
            UsageView.GROUP.value if kind == EntityType.GROUP.value else UsageView.APPLICATION.value
        )
        if view not in self._last_own:
            from app.services.settings_store import DEMO_PERIOD_PARAM

            # Readings up to the latest before this ingest: this ingest's own
            # application reading (read before the projects) is no own-row
            # feeding yet.
            upto = self._with_own_figure(f"{view}:upto")
            if not upto:
                self._last_own[view] = {}
                return None

            self._last_own[view] = {
                str(entity_id): when
                for entity_id, when in self.session.execute(
                    select(UsageRecord.entity_id, func.max(UsageSnapshot.collected_at))
                    .join(UsageSnapshot, UsageSnapshot.id == UsageRecord.snapshot_id)
                    .where(
                        UsageSnapshot.view_by == view,
                        UsageSnapshot.held_reason.is_(None),
                        UsageSnapshot.period_param.is_distinct_from(DEMO_PERIOD_PARAM),
                        UsageRecord.entity_id.is_not(None),
                        UsageSnapshot.id <= int(next(iter(upto))),
                    )
                    .group_by(UsageRecord.entity_id)
                )
            }
        return self._last_own[view].get(str(limit.entity_id))

    def budgets(self, entity_ids: set[str]) -> dict[str, list[CreditLimit]]:
        """entity id -> the budgets it feeds."""
        found: dict[str, list[CreditLimit]] = {entity_id: [] for entity_id in entity_ids}
        if not self.by_target or not entity_ids:
            return found
        ids = sorted(entity_ids)
        if self.view == UsageView.USER.value:
            for user_id in ids:
                found[user_id].extend(self.by_target.get((EntityType.USER.value, user_id), []))
            for group_id, user_id in self._links(
                CxGroupMembership.group_id, CxGroupMembership.user_id, ids
            ):
                found[user_id].extend(
                    limit
                    for limit in self.by_target.get((EntityType.GROUP.value, group_id), [])
                    if limit.include_member_usage
                )
        elif self.view == UsageView.PROJECT.value:
            groups_own = self._with_own_figure(UsageView.GROUP.value)
            apps_own = self._with_own_figure(UsageView.APPLICATION.value)
            for project_id in ids:
                found[project_id].extend(
                    self.by_target.get((EntityType.PROJECT.value, project_id), [])
                )
            for group_id, project_id in self._links(
                CxProjectGroup.group_id, CxProjectGroup.project_id, ids
            ):
                found[project_id].extend(
                    limit
                    for limit in self.by_target.get((EntityType.GROUP.value, group_id), [])
                    if limit.include_member_usage or group_id not in groups_own
                )
            for app_id, project_id in self._links(
                CxApplicationProject.application_id, CxApplicationProject.project_id, ids
            ):
                if app_id not in apps_own:
                    found[project_id].extend(
                        self.by_target.get((EntityType.APPLICATION.value, app_id), [])
                    )
        elif self.view == UsageView.APPLICATION.value:
            steady = self._with_own_figure(f"{UsageView.APPLICATION.value}:steady")
            for app_id in ids:
                if app_id in steady:
                    found[app_id].extend(
                        self.by_target.get((EntityType.APPLICATION.value, app_id), [])
                    )
        elif self.view == UsageView.GROUP.value:
            steady = self._with_own_figure(f"{UsageView.GROUP.value}:steady")
            for group_id in ids:
                if group_id not in steady:
                    continue
                found[group_id].extend(
                    limit
                    for limit in self.by_target.get((EntityType.GROUP.value, group_id), [])
                    if not limit.include_member_usage
                )
        return found

    def _links(self, owner, member, ids: list[str]) -> list[tuple[str, str]]:  # type: ignore[no-untyped-def]
        links: list[tuple[str, str]] = []
        for start in range(0, len(ids), 500):
            links.extend(
                (str(a), str(b))
                for a, b in self.session.execute(
                    select(owner, member).where(member.in_(ids[start : start + 500]))
                )
            )
        return links


# --------------------------------------------------------------- recording


@dataclass
class LedgerResult:
    deltas: int = 0
    credits: Decimal = ZERO
    unattributed_credits: Decimal = ZERO
    claimed: int = 0
    history: bool = False
    # Increases held back: a fall in a doubted reading, or a new aggregate row.
    held: int = 0
    # Names whose fall is held as doubted after this reading.
    dips: list[str] = field(default_factory=list)
    # Doubted falls accepted because they persisted past the bound.
    dips_accepted: int = 0
    # (limit id, period key) -> credits added.
    counted: dict[tuple[int, str], Decimal] = field(default_factory=dict)
    # Credits not counted towards a budget because their interval spans its
    # month's start.
    dropped: Decimal = ZERO


def _window(session: Session) -> timedelta:
    """How long a name may wait for its entity (or a rename for its new
    name): one org refresh, plus an hour."""
    from app.services import settings_store

    value = settings_store.get_value(session, settings_store.KEY_ORG_REFRESH_MINUTES)
    try:
        minutes = max(1, int(value))
    except (TypeError, ValueError):
        minutes = 30
    return timedelta(minutes=minutes) + timedelta(hours=1)


# How long usage can stay in a window after it was spent, where that is longer
# than the window's nominal length: "last_month" is the previous calendar
# month, so usage on the 1st of a month is in it until the end of the next.
_FORGET_DAYS = {"last_month": 62}


def _lookback(period_param: str) -> timedelta:
    """How long after its last rise a name's total may still be in the
    window (rolling windows by their length; calendar ones by the longest
    stretch they can cover)."""
    from app.checkmarx import usage as usage_api

    days = _FORGET_DAYS.get(period_param, usage_api.PERIOD_DAYS.get(period_param, 365))
    return timedelta(days=days)


def _highest(rows: list[UsageMissingName]) -> tuple[Decimal, dict[str, int], datetime]:
    """Where a name that may be any of ``rows`` renamed starts from: the
    highest total, per action type too, read at the earliest time."""
    counts: dict[str, int] = {}
    for row in rows:
        for action, count in (row.last_actions or {}).items():
            if isinstance(count, int) and count > counts.get(action, 0):
                counts[action] = count
    return (
        max(Decimal(row.last_total or 0) for row in rows),
        counts,
        min(row.last_seen_at for row in rows),
    )


def _raise_to(
    start: tuple[Decimal, dict[str, int]], other: tuple[Decimal, dict[str, int]]
) -> tuple[Decimal, dict[str, int]]:
    counts = dict(start[1])
    for action, count in other[1].items():
        if count > counts.get(action, 0):
            counts[action] = count
    return max(start[0], other[0]), counts


def record_reading(
    session: Session,
    view: UsageView | str,
    snapshot: UsageSnapshot,
    records: list[UsageRecord],
    *,
    suspect: bool = False,
    own: dict[str, set[str]] | None = None,
    collapse: bool = False,
) -> LedgerResult:
    """Turn one stored live reading into ledger increases and budget counters.

    Called by the ingest, under the attribution lock, in the transaction that
    stores the reading, so a reading is counted exactly once (a failed one
    leaves nothing behind, and the next one is measured from the last one that
    was stored). ``suspect``: the completeness checks doubt the listing (a
    short or repeated page), so a fall in it is not believed yet. ``own``: the
    groups and applications with a row of their own (``own_figures``), taken
    once per ingest. ``collapse``: the whole feed fell and the fall is
    accepted only because it persisted; a fall in it keeps a ceiling.
    """
    from app.services import ingestion

    view = str(view)
    result = LedgerResult()
    now = snapshot.collected_at
    if own is None:
        own = own_figures(session, excluding=snapshot.id)
    previous = ingestion.latest_live_snapshot(session, view, excluding=snapshot.id)
    kept = {
        row.subject_key: row
        for row in session.scalars(select(UsageMissingName).where(UsageMissingName.view_by == view))
    }
    if previous is None or previous.period_param != snapshot.period_param:
        # The first reading, or one taken over another lookback window: every
        # total is history. Nothing is counted; every name starts from here. A
        # name remembered as missing has no total in this window: when it
        # returns, it starts from whatever it reports then. When each name last
        # rose is unknown: taken as now, so nothing is forgotten too early.
        present = {record.subject_key for record in records}
        for record in records:
            record.last_rise_at = now
        for row in kept.values():
            if row.kind != MISSING or row.subject_key in present:
                _drop(session, row)
            else:
                row.kind = REBASE
                row.period_param = snapshot.period_param
        result.history = True
        return result

    then = previous.collected_at
    # A name whose total last rose before the lookback window began has
    # nothing left in it: forgotten, it counts in full when it reports again.
    horizon = now - _lookback(snapshot.period_param) - HORIZON_MARGIN
    for key, row in list(kept.items()):
        rose = row.last_rise_at or row.last_seen_at
        if rose is None or rose < horizon:
            _drop(session, row)
            del kept[key]
    # Gone before anything below adds a row for the same name (a flush
    # inserts before it deletes).
    session.flush()

    previous_rows = {
        record.subject_key: record
        for record in session.scalars(
            select(UsageRecord).where(UsageRecord.snapshot_id == previous.id)
        )
    }
    before = {
        key: (Decimal(record.credits_used or 0), counts_of(record))
        for key, record in previous_rows.items()
    }
    shifts = _Shifts(session, view)
    reported = {record.subject_key for record in records}
    window = _window(session)
    aggregate = view in AGGREGATE_VIEWS

    # Names that left the feed: remembered, so a return adds only the increase.
    for key, (credits, counts) in before.items():
        if key in reported:
            continue
        earlier = previous_rows[key]
        shifts.leave(earlier.entity_id, earlier)
        row = kept.get(key)
        if row is None:
            row = UsageMissingName(view_by=view, subject_key=key)
            session.add(row)
            kept[key] = row
        ceiling = row.kind in HELD_KINDS or (row.kind == FRESH and row.doubts == 1)
        if not ceiling:
            row.last_total = credits
            row.last_actions = counts
            row.last_seen_at = then
            row.last_rise_at = earlier.last_rise_at or then
        if ceiling or collapse:
            # A held fall keeps the higher total it was held at, and keeps
            # it while the name is missing; a name missing from a collapse
            # accepted because it persisted fell in it too.
            row.kind = COLLAPSE if (collapse or row.kind in (COLLAPSE, FRESH)) else CEILING
        else:
            row.kind = MISSING
        row.doubts = 0
        row.missing_since = now
        row.period_param = snapshot.period_param
        row.entity_id = earlier.entity_id

    # Rename partners: remembered names, and names held under a ceiling that
    # the feed does not report.
    missing = {
        key: row
        for key, row in kept.items()
        if row.kind == MISSING or (row.kind in HELD_KINDS and key not in reported)
    }

    def partners(entity_id: str | None, exclude: str | None = None) -> list[UsageMissingName]:
        """What a name new to the feed, or back in it, may be a rename of: any
        name that left the feed just now (within the window), and, for a name
        of an entity, that entity's remembered names however long ago they
        left. A name that left just now may have counted towards another
        entity when it left (the sync gave its old name to a new project), so
        it is a candidate whatever it counted towards."""
        found = []
        for key, row in missing.items():
            if key == exclude or key in reported or row.period_param != snapshot.period_param:
                continue
            recent = row.missing_since >= now - window
            if recent or (entity_id is not None and row.entity_id == entity_id):
                found.append(row)
        return found

    deltas: list[UsageDelta] = []
    for record in records:
        key = record.subject_key
        credits_now = Decimal(record.credits_used or 0)
        counts_now = counts_of(record)
        since = then
        row = kept.get(key)
        returning: UsageMissingName | None = None
        # The name's own previous total, when it has one: only a fall below it
        # is a fall of this name (a start raised to a possible rename's total
        # is not).
        own_start: Decimal | None = None
        # Whether a possible rename's start is held under a ceiling.
        under_ceiling = False
        # When the name last rose, carried forward; set to now if it rises.
        if key in before:
            record.last_rise_at = previous_rows[key].last_rise_at or then
        elif row is not None:
            record.last_rise_at = row.last_rise_at or row.last_seen_at
        else:
            record.last_rise_at = now
        if aggregate and key not in before:
            # A group's or application's own row, new or back: its projects fed
            # the budget while it was not there, so its total is not new usage;
            # nor is what it adds by its next reading (the projects fed the
            # budget up to their own read of this ingest, after this one).
            fresh = row or UsageMissingName(view_by=view, subject_key=key)
            if row is None:
                session.add(fresh)
            held = (
                row is not None
                and row.kind in HELD_KINDS
                and Decimal(row.last_total or 0) > credits_now
            )
            fresh.kind = FRESH
            # 1: back under a ceiling it keeps (``last_total``) after this.
            fresh.doubts = 1 if held else 0
            if not held:
                fresh.last_total = credits_now
                fresh.last_actions = counts_now
            fresh.last_seen_at = now
            fresh.last_rise_at = now
            fresh.missing_since = now
            fresh.period_param = snapshot.period_param
            fresh.entity_id = record.entity_id
            record.last_rise_at = now
            result.held += 1
            continue
        if row is not None and row.kind == FRESH:
            if row.doubts == 1 and credits_now < Decimal(row.last_total or 0):
                # Its second reading counts nothing either; it is still under
                # the ceiling it came back with, which it keeps.
                row.kind = COLLAPSE
                row.doubts = 0
                row.last_seen_at = now
            else:
                _drop(session, row)
            record.last_rise_at = now
            result.held += 1
            continue
        if row is not None and row.kind == REBASE:
            # Missing when the lookback window changed: its old total is in
            # another window, so it starts from what it reports now.
            _drop(session, row)
            record.last_rise_at = now
            continue
        if row is not None and row.kind in HELD_KINDS:
            start_credits, start_counts = Decimal(row.last_total or 0), dict(row.last_actions or {})
            since = row.last_seen_at
            if credits_now >= start_credits:
                # Back at (or above) the total before the fall: what is above
                # it is new.
                _drop(session, row)
            elif collapse:
                # The whole feed's collapse, accepted because it persisted, is
                # no confirmation of a held fall: the ceiling stays.
                row.kind = COLLAPSE
                result.held += 1
                continue
            elif row.kind == DIP and suspect:
                if (row.doubts or 0) + 1 < DIP_MAX_DOUBTS and now - row.missing_since < DIP_MAX_AGE:
                    row.doubts = (row.doubts or 0) + 1
                    result.dips.append(key)
                else:
                    # The doubt outlasted its bound: no longer reported, but
                    # the total before the fall stays the ceiling.
                    row.kind = CEILING
                    result.dips_accepted += 1
                result.held += 1
                continue
            elif row.kind in (DIP, CEILING) and not suspect:
                # A believed reading confirms the lower total: the name
                # continues from it, and its usage may still be in the window.
                _drop(session, row)
                if credits_now > 0:
                    record.last_rise_at = now
                continue
            else:
                # Still under the ceiling (a doubted reading, or the collapse
                # it was taken in): nothing counts.
                result.held += 1
                continue
        elif key in before:
            start_credits, start_counts = before[key]
            own_start = start_credits
            was = previous_rows[key].display_rows
            if was is not None and record.display_rows is not None and was != record.display_rows:
                # Two people who share a display name were split across pages
                # (read as one repeated row) or joined on one page (added up):
                # the totals are not comparable. The name starts from what it
                # reports now; what was spent in this interval is not counted.
                record.last_rise_at = now
                result.held += 1
                continue
        elif row is not None:
            # A name back after missing readings. It may have been renamed and
            # renamed back: what its other names counted from its total is
            # never counted again (it starts from the highest of them).
            start_credits, start_counts = Decimal(row.last_total or 0), dict(row.last_actions or {})
            own_start = start_credits
            since = row.last_seen_at
            others = partners(record.entity_id, exclude=key)
            under_ceiling = any(other.kind in HELD_KINDS for other in others)
            if others:
                high, high_counts, seen = _highest(others)
                start_credits, start_counts = _raise_to(
                    (start_credits, start_counts), (high, high_counts)
                )
                since = min(since, seen)
            returning = row
        else:
            found = partners(record.entity_id)
            under_ceiling = any(other.kind in HELD_KINDS for other in found)
            start_credits, start_counts = ZERO, {}
            if found:
                start_credits, start_counts, partner_seen = _highest(found)
                since = min(since, partner_seen)
                shifts.join(record.entity_id, _as_row(start_credits, start_counts))
        if key in before:
            earlier = previous_rows[key]
            if earlier.entity_id != record.entity_id:
                shifts.leave(earlier.entity_id, earlier)
                if earlier.entity_id is not None or not shifts.new_entity(
                    record.entity_id, now, window
                ):
                    # A new project the name was waiting for keeps the name's
                    # figure: its history is handled as a new project's.
                    shifts.join(record.entity_id, earlier)
        credits = credits_now - start_credits
        falls = own_start is not None and credits_now < own_start
        if credits < 0 and (collapse and falls or under_ceiling):
            # The whole feed collapsed and the collapse was accepted only
            # because it persisted: the total before it stays the ceiling.
            # So does the ceiling of a name this one may be a rename of.
            hold = returning or UsageMissingName(view_by=view, subject_key=key)
            if returning is None:
                session.add(hold)
            hold.kind = COLLAPSE
            hold.doubts = 0
            hold.last_total = start_credits
            hold.last_actions = start_counts
            hold.last_seen_at = since
            hold.last_rise_at = record.last_rise_at
            hold.missing_since = now
            hold.period_param = snapshot.period_param
            hold.entity_id = record.entity_id
            result.held += 1
            continue
        if credits < 0 and suspect and falls:
            # A fall in a listing the completeness checks doubt: not believed
            # yet. The name continues from the higher total until it recovers,
            # a believed reading confirms the fall, or the doubt outlasts its
            # bound (DIP_MAX_DOUBTS readings, DIP_MAX_AGE).
            hold = returning or UsageMissingName(view_by=view, subject_key=key)
            if returning is None:
                session.add(hold)
            hold.kind = DIP
            hold.doubts = 1
            hold.last_total = start_credits
            hold.last_actions = start_counts
            hold.last_seen_at = since
            hold.last_rise_at = record.last_rise_at
            hold.missing_since = now
            hold.period_param = snapshot.period_param
            hold.entity_id = record.entity_id
            result.held += 1
            result.dips.append(key)
            continue
        if returning is not None:
            shifts.join(record.entity_id, _as_row(start_credits, start_counts))
            _drop(session, returning)
        if credits < 0:
            # The window rolled past older usage: nothing can be told apart,
            # nothing is added, and the name continues from its new total.
            # Usage spent meanwhile may be in that total: the name is
            # remembered from now, as if it had just risen.
            credits = ZERO
            increase: dict[str, int] = {}
            if credits_now > 0:
                record.last_rise_at = now
        else:
            increase = _increase(counts_now, start_counts)
            plain_now, plain_start = plain_actions(counts_now), plain_actions(start_counts)
            if increase and any(
                action not in increase
                for action in set(plain_now) | set(plain_start)
                if plain_now.get(action, 0) or plain_start.get(action, 0)
            ):
                increase[SLID] = 1
        if credits > 0:
            record.last_rise_at = now
        if credits <= 0 and not increase:
            continue
        deltas.append(
            UsageDelta(
                snapshot_id=snapshot.id,
                view_by=view,
                subject_key=key,
                entity_type=record.entity_type if record.entity_id else None,
                entity_id=record.entity_id,
                credits=credits,
                actions=increase or None,
                observed_at=now,
                since=since,
            )
        )
    for delta in deltas:
        session.add(delta)
    result.deltas = len(deltas)
    result.credits = sum((d.credits for d in deltas), ZERO)
    result.unattributed_credits = sum((d.credits for d in deltas if d.entity_id is None), ZERO)

    claimed = _claims(session, view, records, window, now)
    result.claimed = len(claimed)
    attributed = [d for d in deltas if d.entity_id is not None]
    _feed(session, view, attributed, result, own)
    _feed(session, view, claimed, result, own, claimed=True)
    shifts.save(now)
    session.flush()
    return result


def _claims(
    session: Session,
    view: str,
    records: list[UsageRecord],
    window: timedelta,
    now: datetime,
) -> list[UsageDelta]:
    """Increases observed while a name counted towards nothing, claimed by the
    entity it now counts towards (by its own name, never by a mapping, which
    settles them: ``settle_waiting``) when they were observed shortly before
    that entity was first synced (within ``window``): a project created and
    used before the sync brought it keeps its first usage. Everything else
    observed while the name counted towards nothing stays there."""
    candidates = {record.subject_key: record for record in records if record.entity_id is not None}
    if not candidates:
        return []
    keys = sorted(candidates)
    waiting: dict[str, list[UsageDelta]] = defaultdict(list)
    for start in range(0, len(keys), 500):
        for delta in session.scalars(
            select(UsageDelta)
            .where(
                UsageDelta.view_by == view,
                UsageDelta.entity_id.is_(None),
                UsageDelta.claimed_at.is_(None),
                UsageDelta.subject_key.in_(keys[start : start + 500]),
            )
            .order_by(UsageDelta.observed_at)
        ):
            waiting[delta.subject_key].append(delta)
    if not waiting:
        return []
    created = _created(session, view, {candidates[key].entity_id for key in waiting})
    claimed: list[UsageDelta] = []
    for key, rows in waiting.items():
        record = candidates[key]
        first_synced = created.get(str(record.entity_id))
        for delta in rows:
            # Settled either way: claimed now, or left counting towards nothing.
            delta.claimed_at = now
            if (
                first_synced is not None
                and first_synced - window <= delta.observed_at <= first_synced
            ):
                delta.entity_id = record.entity_id
                delta.entity_type = record.entity_type
                claimed.append(delta)
    return claimed


def _created(session: Session, view: str, entity_ids: set) -> dict[str, datetime]:  # type: ignore[type-arg]
    """When each entity was first synced, in one query per 500."""
    model = _VIEW_MODEL.get(view)
    ids = sorted(str(entity_id) for entity_id in entity_ids if entity_id is not None)
    found: dict[str, datetime] = {}
    if model is None:
        return found
    for start in range(0, len(ids), 500):
        for entity_id, created_at in session.execute(
            select(model.id, model.created_at).where(model.id.in_(ids[start : start + 500]))
        ):
            found[str(entity_id)] = created_at
    return found


def settle_waiting(session: Session, view: str, subject_key: str) -> int:
    """A name an admin maps (or whose disputed match is resolved) counts from
    then on: what it was observed using while it counted towards nothing is
    never claimed."""
    rows = list(
        session.scalars(
            select(UsageDelta).where(
                UsageDelta.view_by == str(view),
                UsageDelta.subject_key == subject_key,
                UsageDelta.entity_id.is_(None),
                UsageDelta.claimed_at.is_(None),
            )
        )
    )
    stamp = utcnow()
    for row in rows:
        row.claimed_at = stamp
    return len(rows)


def _by_entity(deltas: list[UsageDelta]) -> dict[str, list[UsageDelta]]:
    found: dict[str, list[UsageDelta]] = defaultdict(list)
    for delta in deltas:
        if delta.entity_id is not None:
            found[delta.entity_id].append(delta)
    return found


# Every budget is fed per month and per quarter, whatever its period type, so
# that switching its type (to lifetime and back, monthly to quarterly) never
# loses what was observed meanwhile.
_GRANULARITIES = (PeriodType.MONTHLY, PeriodType.QUARTERLY)


def _feed(
    session: Session,
    view: str,
    deltas: list[UsageDelta],
    result: LedgerResult,
    own: dict[str, set[str]] | None = None,
    *,
    claimed: bool = False,
) -> None:
    """Add each increase to the month's and the quarter's counter, of the
    period it was observed in, of every budget its entity feeds now. An
    increase whose interval spans the period's start (a reading after downtime,
    demo mode or a skipped cycle across a rollover) cannot be split: that
    period counts none of it. A claimed increase does not feed a budget created
    after it was observed."""
    from app.services.periods import current_window

    if not deltas:
        return
    feeds = _Feeds(session, view, own)
    if not feeds.by_target:
        return
    by_entity = _by_entity(deltas)
    budgets = feeds.budgets(set(by_entity))
    adds: dict[tuple[int, str], tuple[Decimal, dict[str, int], datetime]] = {}
    for entity_id, rows in by_entity.items():
        seen: set[int] = set()
        for limit in budgets.get(entity_id, []):
            if limit.id in seen:
                continue
            seen.add(limit.id)
            for delta in rows:
                if (
                    claimed
                    and limit.created_at is not None
                    and limit.created_at > delta.observed_at
                ):
                    continue
                own_until = feeds.own_row_until(limit)
                if own_until is not None and delta.since < own_until:
                    # The budget was fed by its own row during this interval:
                    # what the project added may be counted there already.
                    result.dropped += Decimal(delta.credits or 0)
                    continue
                for granularity in _GRANULARITIES:
                    period = current_window(
                        SimpleNamespace(period_type=granularity, created_at=limit.created_at),
                        delta.observed_at,
                    )
                    if delta.since < period.start:
                        if granularity == PeriodType.MONTHLY:
                            result.dropped += Decimal(delta.credits or 0)
                        continue
                    credits, counts, latest = adds.get(
                        (limit.id, period.key), (ZERO, {}, delta.observed_at)
                    )
                    adds[(limit.id, period.key)] = (
                        credits + Decimal(delta.credits or 0),
                        _add(counts, delta.actions),
                        max(latest, delta.observed_at),
                    )
    if not adds:
        return
    limit_ids = sorted({limit_id for limit_id, _key in adds})
    keys = sorted({key for _limit_id, key in adds})
    existing = {
        (row.limit_id, row.period_key): row
        for row in session.scalars(
            select(BudgetUsage).where(
                BudgetUsage.limit_id.in_(limit_ids), BudgetUsage.period_key.in_(keys)
            )
        )
    }
    for (limit_id, key), (credits, counts, latest) in adds.items():
        row = existing.get((limit_id, key))
        if row is None:
            row = BudgetUsage(limit_id=limit_id, period_key=key, credits=ZERO, actions={})
            session.add(row)
        row.credits = Decimal(row.credits or 0) + credits
        row.actions = _add(dict(row.actions or {}), counts)
        # When the newest increase in it was observed: a closed period is
        # reconciled only with what arrived after it was last evaluated.
        row.updated_at = max(row.updated_at, latest) if row.updated_at else latest
        result.counted[(limit_id, key)] = credits
    # Sessions do not autoflush: the next feed of this reading (claims) must
    # find these counters.
    session.flush()


def _as_row(credits: Decimal, counts: dict[str, int]) -> SimpleNamespace:
    return SimpleNamespace(actions=plain_actions(counts), credits_used=credits, raw=None)


class _Shifts:
    """What names joining and leaving projects did to each project's reported
    Auto Triage figure (``UsageEntityOffset``): Auto Triage attribution
    subtracts it, so only Auto Triage observed while a name counted towards a
    project reads as an increase there."""

    def __init__(self, session: Session, view: str) -> None:
        from app.services import auto_triage_attribution

        self.session = session
        self.active = view == UsageView.PROJECT.value
        self.module = auto_triage_attribution
        self.price = auto_triage_attribution.auto_triage_price(session) if self.active else None
        self.changes: dict[str, list] = {}
        self._created: dict[str, datetime] | None = None

    def new_entity(self, entity_id: str | None, now: datetime, window: timedelta) -> bool:
        if not self.active or entity_id is None:
            return False
        if self._created is None:
            # Every project's first sync, in one query (asked per changed name).
            self._created = {
                str(project_id): created_at
                for project_id, created_at in self.session.execute(
                    select(CxProject.id, CxProject.created_at)
                )
            }
        created = self._created.get(str(entity_id))
        return created is not None and created >= now - window

    def _value(self, record) -> tuple[int, Decimal]:  # type: ignore[no-untyped-def]
        count = self.module.auto_triage_transactions(record)
        share = self.module.auto_triage_share(record, self.price)
        return int(count or 0), Decimal(share or 0)

    def join(self, entity_id: str | None, record) -> None:  # type: ignore[no-untyped-def]
        self._shift(entity_id, record, 1)

    def leave(self, entity_id: str | None, record) -> None:  # type: ignore[no-untyped-def]
        self._shift(entity_id, record, -1)

    def _shift(self, entity_id: str | None, record, sign: int) -> None:  # type: ignore[no-untyped-def]
        if not self.active or entity_id is None:
            return
        count, share = self._value(record)
        if not count and not share:
            return
        change = self.changes.setdefault(entity_id, [0, ZERO])
        change[0] += sign * count
        change[1] += sign * share

    def save(self, now: datetime) -> None:
        if not self.changes:
            return
        ids = sorted(self.changes)
        rows = {
            row.entity_id: row
            for row in self.session.scalars(
                select(UsageEntityOffset).where(
                    UsageEntityOffset.view_by == UsageView.PROJECT.value,
                    UsageEntityOffset.entity_id.in_(ids),
                )
            )
        }
        for entity_id in ids:
            count, share = self.changes[entity_id]
            row = rows.get(entity_id)
            if row is None:
                row = UsageEntityOffset(
                    view_by=UsageView.PROJECT.value,
                    entity_id=entity_id,
                    auto_triage_transactions=0,
                    auto_triage_credits=ZERO,
                )
                self.session.add(row)
            row.auto_triage_transactions = int(row.auto_triage_transactions or 0) + count
            row.auto_triage_credits = Decimal(row.auto_triage_credits or 0) + share
            row.updated_at = now


def shift_for_move(
    session: Session, view: str, record: UsageRecord, old: str | None, new: str | None
) -> None:
    """A mapping re-points the latest reading's row at once: shift the Auto
    Triage figures as a reading would have, so the name's history is no
    increase at its new project (and no fall at its old one)."""
    shifts = _Shifts(session, str(view))
    shifts.leave(old, record)
    shifts.join(new, record)
    shifts.save(utcnow())


# --------------------------------------------------------------- reading


def period_usage(session: Session, limit_id: int, period_key: str):  # type: ignore[no-untyped-def]
    """(credits, per action counts) a budget counted in a period."""
    row = session.scalar(
        select(BudgetUsage).where(
            BudgetUsage.limit_id == limit_id, BudgetUsage.period_key == period_key
        )
    )
    if row is None:
        return ZERO, {}
    return Decimal(row.credits or 0), dict(row.actions or {})


def ensure_counter(session: Session, limit_id: int, period_key: str, moment: datetime):  # type: ignore[no-untyped-def]
    """(credits, per action counts) of a period's counter, which is created
    at zero when it does not exist yet. In a
    savepoint: an ingest adding the same counter at the same moment wins, and
    an ingest that loses to it fails whole and is read again next cycle."""
    from sqlalchemy.exc import IntegrityError

    row = session.scalar(
        select(BudgetUsage).where(
            BudgetUsage.limit_id == limit_id, BudgetUsage.period_key == period_key
        )
    )
    if row is not None:
        return Decimal(row.credits or 0), dict(row.actions or {})
    try:
        with session.begin_nested():
            session.add(
                BudgetUsage(
                    limit_id=limit_id,
                    period_key=period_key,
                    credits=ZERO,
                    actions={},
                    # Nothing observed yet: older than any evaluation of it.
                    updated_at=moment,
                )
            )
    except IntegrityError:
        return period_usage(session, limit_id, period_key)
    return ZERO, {}


def entity_increases(
    session: Session, view: str, entity_id: str, since: datetime
) -> list[UsageDelta]:
    """The increases attributed to an entity observed after ``since``.

    An increase is read between two readings and cannot be split: one whose
    interval began before ``since`` (normally the seconds between the cycle's
    reading and a restriction applied in the same cycle) is included."""
    return list(
        session.scalars(
            select(UsageDelta)
            .where(
                UsageDelta.view_by == view,
                UsageDelta.entity_id == entity_id,
                UsageDelta.observed_at > since,
            )
            .order_by(UsageDelta.observed_at, UsageDelta.id)
        )
    )
