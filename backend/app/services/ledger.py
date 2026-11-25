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
  with the total it last had (``UsageMissingName``), so a return adds only what
  it reported since. A negative difference (the lookback window rolled past old
  usage) adds nothing, and the name continues from its new total.
* A name never seen before counts in full: a name absent from the previous
  reading reported nothing then, so all of its total is new usage. Except when
  names left the feed as it appeared (a rename the feed reported first, maybe
  with its total rolled down meanwhile): it then starts from the highest of
  their last totals, per action type too, since it may be any of them. That
  can under-count (a really new name, or several renames at once), never
  over-count. The very first reading, and a reading in another lookback
  window, are history: nothing is counted from them.
* Each increase is attributed to the entity the name counts towards at that
  moment (``UsageDelta``), and added to the pending counter of every budget
  that entity feeds at that moment: the user's, its groups' (members' usage),
  the project's, its groups' and its applications' (when they have no figure
  of their own). The next evaluation moves pending counters into the period it
  evaluates (``consume_pending``). A period budget's usage is its counter.
* An increase observed while a name counted towards nothing is kept; when the
  name first counts towards an entity that was synced after (or shortly
  before) that usage, it is claimed for it: a project created and used before
  the sync brought it keeps its first usage.

Budgets that count usage already reported (lifetime, custom, or "count
existing usage") are not ledger budgets: they count the current totals of the
names that count towards them, by definition.

Mappings, renames, deletions and returns, and membership changes therefore
only ever move usage observed from then on. What is lost, by construction:
usage a name reported between its last reading under one name and its first
under a new one that could not be paired, what a new name adds in its first
reading when other names left the feed just before (it starts from the highest
of them), increases hidden by the lookback window rolling past older usage in
the same interval, and usage observed while a name counted towards nothing that
no new entity claims.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType, UsageView
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
PENDING = ""
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
    """A budget that counts usage already reported is no ledger budget."""
    from app.models.enums import PeriodType

    return limit.period_type in {PeriodType.LIFETIME, PeriodType.CUSTOM} or bool(
        limit.count_existing_usage
    )


class _Feeds:
    """Which ledger budgets an entity of one view feeds, now."""

    def __init__(self, session: Session, view: str) -> None:
        self.session = session
        self.view = view
        self.by_target: dict[tuple[str, str], list[CreditLimit]] = defaultdict(list)
        for limit in session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))):
            if not counts_existing(limit):
                self.by_target[(str(limit.entity_type), limit.entity_id)].append(limit)
        self._own_figure: dict[str, set[str]] = {}

    def _with_own_figure(self, view: str) -> set[str]:
        """Entities that have a row of their own in the latest ``view`` reading
        (their budgets are fed from it, not rolled up from their projects)."""
        if view not in self._own_figure:
            from app.services import ingestion

            snapshot = ingestion.latest_snapshot(self.session, view)
            self._own_figure[view] = (
                set(
                    self.session.scalars(
                        select(UsageRecord.entity_id).where(
                            UsageRecord.snapshot_id == snapshot.id,
                            UsageRecord.entity_id.is_not(None),
                        )
                    )
                )
                if snapshot is not None
                else set()
            )
        return self._own_figure[view]

    def budgets(self, entity_ids: set[str]) -> dict[str, list[CreditLimit]]:
        """entity id -> the ledger budgets it feeds."""
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
            for app_id in ids:
                found[app_id].extend(self.by_target.get((EntityType.APPLICATION.value, app_id), []))
        elif self.view == UsageView.GROUP.value:
            for group_id in ids:
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
    pending: dict[int, Decimal] = field(default_factory=dict)


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


def record_reading(
    session: Session, view: UsageView | str, snapshot: UsageSnapshot, records: list[UsageRecord]
) -> LedgerResult:
    """Turn one stored live reading into ledger increases and budget counters.

    Called by the ingest, under the attribution lock, in the transaction that
    stores the reading, so a reading is counted exactly once (a failed one
    leaves nothing behind, and the next one is measured from the last one that
    was stored).
    """
    from app.services import ingestion

    view = str(view)
    result = LedgerResult()
    now = snapshot.collected_at
    previous = ingestion.latest_live_snapshot(session, view, excluding=snapshot.id)
    missing = {
        row.subject_key: row
        for row in session.scalars(select(UsageMissingName).where(UsageMissingName.view_by == view))
    }
    if previous is None or previous.period_param != snapshot.period_param:
        # The first reading, or one taken over another lookback window: every
        # total is history. Nothing is counted; every name starts from here.
        for row in missing.values():
            _drop(session, row)
        result.history = True
        return result

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

    # Names that left the feed: remembered, so a return adds only the increase.
    left_now: dict[str, tuple[Decimal, dict[str, int]]] = {}
    for key, (credits, counts) in before.items():
        if key in reported:
            continue
        left_now[key] = (credits, counts)
        shifts.leave(previous_rows[key].entity_id, previous_rows[key])
        row = missing.get(key)
        if row is None:
            row = UsageMissingName(view_by=view, subject_key=key)
            session.add(row)
            missing[key] = row
        row.last_total = credits
        row.last_actions = counts
        row.missing_since = now
        row.period_param = snapshot.period_param

    # Rename partners for names never seen before: names that left the feed in
    # this reading, or not long before. A new name may be any of them renamed
    # (its total possibly rolled down meanwhile) or a name that is really new;
    # nothing tells them apart, so it starts from the highest of them, per
    # action type too: whichever it is, that never counts more than it added.
    # Partners are not used up (several renames may land in one reading) and
    # stay remembered, so an old name that returns still adds only its own
    # increase.
    partner_rows = [
        row
        for key, row in missing.items()
        if key not in reported
        and row.period_param == snapshot.period_param
        and row.missing_since is not None
        and row.missing_since >= now - window
    ]
    partner_start: tuple[Decimal, dict[str, int]] | None = None
    if partner_rows:
        highest: dict[str, int] = {}
        for row in partner_rows:
            for action, count in (row.last_actions or {}).items():
                if isinstance(count, int) and count > highest.get(action, 0):
                    highest[action] = count
        partner_start = (max(Decimal(row.last_total or 0) for row in partner_rows), highest)

    deltas: list[UsageDelta] = []
    for record in records:
        key = record.subject_key
        credits_now = Decimal(record.credits_used or 0)
        counts_now = counts_of(record)
        if key in before:
            start_credits, start_counts = before[key]
            earlier = previous_rows[key]
            if earlier.entity_id != record.entity_id:
                shifts.leave(earlier.entity_id, earlier)
                if earlier.entity_id is not None or not shifts.new_entity(
                    record.entity_id, now, window
                ):
                    # A new project the name was waiting for keeps the name's
                    # figure: its history is handled as a new project's.
                    shifts.join(record.entity_id, earlier)
        elif key in missing:
            row = missing.pop(key)
            start_credits, start_counts = Decimal(row.last_total or 0), dict(row.last_actions or {})
            shifts.join(record.entity_id, _as_row(start_credits, start_counts))
            _drop(session, row)
        else:
            start_credits, start_counts = partner_start or (ZERO, {})
            if start_credits or start_counts:
                shifts.join(record.entity_id, _as_row(start_credits, start_counts))
        credits = credits_now - start_credits
        if credits < 0:
            # The window rolled past older usage: nothing can be told apart,
            # nothing is added, and the name continues from its new total.
            credits = ZERO
            increase: dict[str, int] = {}
        else:
            increase = _increase(counts_now, start_counts)
            plain_now, plain_start = plain_actions(counts_now), plain_actions(start_counts)
            if increase and any(
                key not in increase
                for key in set(plain_now) | set(plain_start)
                if plain_now.get(key, 0) or plain_start.get(key, 0)
            ):
                increase[SLID] = 1
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
            )
        )
    for delta in deltas:
        session.add(delta)
    result.deltas = len(deltas)
    result.credits = sum((d.credits for d in deltas), ZERO)
    result.unattributed_credits = sum((d.credits for d in deltas if d.entity_id is None), ZERO)

    claimed = _claims(session, view, records, before, window, now)
    result.claimed = len(claimed)
    attributed = [d for d in deltas if d.entity_id is not None] + claimed
    _feed(session, view, attributed, result)
    shifts.save(now)
    session.flush()
    return result


def _claims(
    session: Session,
    view: str,
    records: list[UsageRecord],
    before: dict[str, tuple[Decimal, dict[str, int]]],
    window: timedelta,
    now: datetime,
) -> list[UsageDelta]:
    """Increases observed while a name counted towards nothing, claimed by the
    entity it now counts towards, when that entity was first synced after the
    first of them: the entity the name was waiting for (only those observed
    within ``window`` before it was synced).
    An entity that existed all along claims nothing: a name mapped or matched
    to it counts from then on."""
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
    model = _VIEW_MODEL.get(view)
    claimed: list[UsageDelta] = []
    for key, rows in waiting.items():
        record = candidates[key]
        created = session.scalar(select(model.created_at).where(model.id == record.entity_id))
        claimable = created is not None and created > rows[0].observed_at
        for delta in rows:
            # Settled either way: claimed now, or left counting towards nothing.
            delta.claimed_at = now
            if claimable and delta.observed_at >= created - window:
                delta.entity_id = record.entity_id
                delta.entity_type = record.entity_type
                claimed.append(delta)
    return claimed


def _by_entity(deltas: list[UsageDelta]) -> dict[str, list[UsageDelta]]:
    found: dict[str, list[UsageDelta]] = defaultdict(list)
    for delta in deltas:
        if delta.entity_id is not None:
            found[delta.entity_id].append(delta)
    return found


def _feed(session: Session, view: str, deltas: list[UsageDelta], result: LedgerResult) -> None:
    """Add the increases to the pending counter of every budget fed now."""
    if not deltas:
        return
    feeds = _Feeds(session, view)
    if not feeds.by_target:
        return
    by_entity = _by_entity(deltas)
    budgets = feeds.budgets(set(by_entity))
    adds: dict[int, tuple[Decimal, dict[str, int]]] = {}
    for entity_id, rows in by_entity.items():
        seen: set[int] = set()
        for limit in budgets.get(entity_id, []):
            if limit.id in seen:
                continue
            seen.add(limit.id)
            credits, counts = adds.get(limit.id, (ZERO, {}))
            for delta in rows:
                credits += Decimal(delta.credits or 0)
                _add(counts, delta.actions)
            adds[limit.id] = (credits, counts)
    if not adds:
        return
    existing = {
        row.limit_id: row
        for row in session.scalars(
            select(BudgetUsage).where(
                BudgetUsage.limit_id.in_(sorted(adds)), BudgetUsage.period_key == PENDING
            )
        )
    }
    stamp = utcnow()
    for limit_id, (credits, counts) in adds.items():
        row = existing.get(limit_id)
        if row is None:
            row = BudgetUsage(limit_id=limit_id, period_key=PENDING, credits=ZERO, actions={})
            session.add(row)
        row.credits = Decimal(row.credits or 0) + credits
        row.actions = _add(dict(row.actions or {}), counts)
        row.updated_at = stamp
        result.pending[limit_id] = credits


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

    def new_entity(self, entity_id: str | None, now: datetime, window: timedelta) -> bool:
        if not self.active or entity_id is None:
            return False
        created = self.session.scalar(select(CxProject.created_at).where(CxProject.id == entity_id))
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


def consume_pending(session: Session, moment: datetime) -> int:
    """Move every pending counter into the period its budget is in at
    ``moment``. Its own short transaction, under the attribution lock, so an
    ingest cannot add to a counter while it is being moved."""
    from app.services import ingestion
    from app.services.periods import PeriodError, current_window

    ingestion.attribution_lock(session)
    pending = list(session.scalars(select(BudgetUsage).where(BudgetUsage.period_key == PENDING)))
    moved = 0
    for row in pending:
        limit = session.get(CreditLimit, row.limit_id)
        if limit is None:
            session.delete(row)
            continue
        try:
            key = current_window(limit, moment).key
        except PeriodError:
            continue
        target = session.scalar(
            select(BudgetUsage).where(
                BudgetUsage.limit_id == row.limit_id, BudgetUsage.period_key == key
            )
        )
        if target is None:
            target = BudgetUsage(limit_id=row.limit_id, period_key=key, credits=ZERO, actions={})
            session.add(target)
        target.credits = Decimal(target.credits or 0) + Decimal(row.credits or 0)
        target.actions = _add(dict(target.actions or {}), row.actions)
        target.updated_at = utcnow()
        session.delete(row)
        moved += 1
    session.commit()
    return moved


def period_usage(session: Session, limit_id: int, period_key: str, *, pending: bool = False):  # type: ignore[no-untyped-def]
    """(credits, per action counts) a budget counted in a period; with
    ``pending``, plus what the next evaluation will add (for previews)."""
    keys = [period_key, PENDING] if pending else [period_key]
    credits = ZERO
    counts: dict[str, int] = {}
    for row in session.scalars(
        select(BudgetUsage).where(
            BudgetUsage.limit_id == limit_id, BudgetUsage.period_key.in_(keys)
        )
    ):
        credits += Decimal(row.credits or 0)
        _add(counts, row.actions)
    return credits, counts


def entity_increases(
    session: Session, view: str, entity_id: str, since: datetime
) -> list[UsageDelta]:
    """The increases attributed to an entity observed after ``since``."""
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
