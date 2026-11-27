"""An independent recount before every new restriction of a period budget.

The fail-safe. Just before the evaluation would apply a **new** restriction
for a monthly or quarterly budget, the budget's usage in the period is
counted again, independently of the ledger: straight from the raw rows of
the credit activity log (``GET /api/credits/activity``), never from the
budget counters (``budget_usage``), ``usage_delta`` or the log's own counter.
The restriction is applied only when the recount is also at or over the
limit (the same threshold the evaluation uses). Otherwise nothing is
restricted, the budget stays BREACHED, a WARNING says the counts disagree
(once per budget and period), and the disagreement is recorded for Diagnose.
When the recount cannot be done (the log cannot be read, the page cap or the
cycle's time budget stops the read, anything fails), nothing new is
restricted either: the rule is fail-safe towards not restricting.

Where the rows come from: the app does not keep raw rows (only how many rows
of each identity it has seen), so the log is read afresh, at most once per
cycle and window - ``last_30_days`` for a month that started within the last
30 days, ``last_90_days`` otherwise and for a quarter - from page 1 to the
end, with no database transaction open, capped by the activity page cap
(``activity.max_pages_per_cycle``) and the cycle's time budget. A read that
does not reach the end is no recount.

Who a row counts towards is decided by the activity source's own mapping
(``activity_source._Targets``): a project by id, an application by id and
through the project's synced applications, a person by email or username
through the existing resolver and the integration-account rule, a group
through all its projects (and members, with member usage), whichever feed the
ledger used for it.
Nothing here matches names itself. A row is counted towards a person or an
application only when every row of its identity in the read names the same
one, as the ledger does. Rows met twice across a page boundary (the same
date on both sides) are counted at most as often as one page shows them:
the recount can fall short, never count a row twice.

Not affected: a restriction already in force (or started) is re-asserted and
lifted exactly as before; lifts and credit-increase restores; lifetime,
custom and count-existing budgets (they keep today's rule). Always on: there
is no setting.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from sqlalchemy.orm import Session

from app.checkmarx import activity as activity_api
from app.checkmarx.activity import ActivityEvent
from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.activity import is_subject_entity
from app.models.enums import EntityType, PeriodType, Severity
from app.models.limits import CreditLimit
from app.services import (
    activity_source,
    credits_text,
    error_text,
    notifications,
    pacing,
    settings_store,
)
from app.services.periods import PeriodError, PeriodWindow, current_window

logger = logging.getLogger(__name__)

ZERO = Decimal("0")
EARLIEST = datetime(1970, 1, 1, tzinfo=UTC)
PERIOD_30 = "last_30_days"
PERIOD_90 = "last_90_days"
# The page cap when the activity page cap setting is 0 (no cap).
DEFAULT_MAX_PAGES = 400
# How many refusals Diagnose keeps.
KEEP_RECORDS = 50
DISAGREE = "disagree"
UNAVAILABLE = "unavailable"

PREVIEW_NOTE = (
    "Would restrict if the recount agrees: a new restriction of a monthly or quarterly "
    "budget starts only when a direct recount of the Checkmarx activity log is also at or "
    "over the limit."
)


class RecountUnavailable(RuntimeError):
    """The log could not be read completely: no recount."""


def applies(session: Session, limit: CreditLimit, window: PeriodWindow) -> bool:
    """Whether starting a restriction of this budget in this period needs the
    recount: a monthly or quarterly budget that counts usage from the ledger
    (not lifetime, custom, count-existing or a demo budget), with no
    restriction of the period in force or started yet."""
    from app.services import evaluation

    if window.period_type not in (PeriodType.MONTHLY, PeriodType.QUARTERLY):
        return False
    if evaluation.counts_from_totals(session, limit, window):
        return False
    return not evaluation.restriction_started(session, limit.id, window.key)


def period_for(window: PeriodWindow, now: datetime) -> str:
    """The activity log window a recount of this period reads."""
    if window.period_type == PeriodType.MONTHLY and window.start >= now - timedelta(days=30):
        return PERIOD_30
    return PERIOD_90


@dataclass
class Verdict:
    """The recount of one budget's period: ``agrees`` None when it could not
    be done (``reason`` says why)."""

    agrees: bool | None
    recount: Decimal | None = None
    reason: str | None = None


@dataclass
class _Fetch:
    events: list[ActivityEvent] | None = None
    error: str | None = None
    # limit id -> credits in its current period, computed once per fetch.
    totals: dict[int, Decimal] | None = None


# ------------------------------------------------------------------ reading


def read_log(client: CheckmarxClient, period: str, max_pages: int) -> list[ActivityEvent]:
    """Every row of the log's window, oldest first. Touches no database.
    RecountUnavailable when the read cannot be completed."""
    size = activity_api.ACTIVITY_PAGE_SIZE
    pages: list[activity_api.ActivityPage] = []
    number = 1
    while True:
        if len(pages) >= max_pages:
            raise RecountUnavailable(f"the page cap of {max_pages} pages was reached")
        if pacing.out_of_time():
            raise RecountUnavailable("the cycle's time budget ran out")
        page = activity_api.fetch_page(client, number, size=size, period=period)
        pages.append(page)
        if page.rows == 0:
            break
        if page.total_pages is not None:
            if number >= page.total_pages:
                break
        elif page.rows < size:
            break
        number += 1
    for page in pages:
        dates = [event.date for event in page.events]
        if any(later < earlier for earlier, later in zip(dates, dates[1:], strict=False)):
            raise RecountUnavailable("the activity log was not sorted by date as asked")
    filled = [page for page in pages if page.events]
    ties: set[datetime] = set()
    for before, after in zip(filled, filled[1:], strict=False):
        last, first = before.events[-1].date, after.events[0].date
        if first < last:
            raise RecountUnavailable("the activity log changed order while it was read")
        if first == last:
            ties.add(first)
    events: list[ActivityEvent] = []
    # A date on both sides of a page boundary: a row may have been read twice.
    # Each identity of such a date counts as often as one page shows it, at most.
    tied: dict[str, list[ActivityEvent]] = {}
    most: dict[str, int] = defaultdict(int)
    for page in pages:
        on_page: dict[str, int] = defaultdict(int)
        for event in page.events:
            if event.date in ties:
                on_page[event.key] += 1
                tied.setdefault(event.key, []).append(event)
            else:
                events.append(event)
        for key, count in on_page.items():
            most[key] = max(most[key], count)
    for key, rows in tied.items():
        events.extend(rows[: most[key]])
    return events


# ---------------------------------------------------------------- counting


def _totals(session: Session, events: list[ActivityEvent], now: datetime) -> dict[int, Decimal]:
    """limit id -> what the rows count towards it in its current period, by the
    activity source's own mapping (no counters, no deltas)."""
    history = activity_source.BudgetHistory(session, now, persist=False)
    # No handover floors: a group budget is recounted through all its projects
    # (and members, with member usage) in the period, whichever feed the
    # ledger used for it.
    targets = _QuietTargets(session, now, history, {})
    windows: dict[int, PeriodWindow] = {}
    for limits in targets.by_target.values():
        for limit in limits:
            if limit.entity_type == EntityType.GROUP.value:
                targets.group_floors[limit.id] = EARLIEST
            try:
                windows[limit.id] = current_window(limit, now)
            except PeriodError:
                continue
    by_key: dict[str, list[ActivityEvent]] = defaultdict(list)
    for event in events:
        by_key[event.key].append(event)
    resolved: list[tuple[ActivityEvent, str | None, str | None]] = []
    for rows in by_key.values():
        first = rows[0]
        if all(row.variant == first.variant for row in rows):
            user_id, _why = targets.user_entity(first)
            application_id = first.application_id
        else:
            user_id, application_id = None, None
        resolved.extend((row, user_id, application_id) for row in rows)
    targets.load_links(
        {event.project_id for event, _u, _a in resolved if event.project_id},
        {user_id for _e, user_id, _a in resolved if user_id and not is_subject_entity(user_id)},
    )
    totals: dict[int, Decimal] = defaultdict(lambda: ZERO)
    for event, user_id, application_id in resolved:
        for limit in targets.budgets(event, user_id, application_id):
            window = windows.get(limit.id)
            if window is not None and window.contains(event.date):
                totals[limit.id] += event.credits
    return dict(totals)


class _QuietTargets(activity_source._Targets):
    """The activity source's mapping, raising nothing under Settings →
    Attribution (a recount writes nothing but its own record)."""

    def _raise(self, event, outcome, *, bot: bool) -> None:  # type: ignore[no-untyped-def]
        return None


# ------------------------------------------------------------- per cycle


@dataclass
class Recounter:
    """The recounts of one cycle: the log is read at most once per window."""

    client: CheckmarxClient | None
    now: datetime = field(default_factory=utcnow)
    _fetches: dict[str, _Fetch] = field(default_factory=dict)

    def prepare(self, session: Session, periods: set[str]) -> None:
        """Read the windows not read yet. Ends the session's transaction
        first: nothing is held open in the database across the HTTP calls."""
        missing = sorted(period for period in periods if period not in self._fetches)
        if not missing:
            return
        max_pages = settings_store.activity_max_pages(session) or DEFAULT_MAX_PAGES
        session.commit()
        for period in missing:
            fetch = _Fetch()
            if self.client is None:
                fetch.error = "there is no Checkmarx connection"
            else:
                try:
                    fetch.events = read_log(self.client, period, max_pages)
                except RecountUnavailable as exc:
                    # Our own reason (a cap reached, a log out of order): safe to show.
                    fetch.error = str(exc)[:500]
                except Exception as exc:  # noqa: BLE001 - no recount, never a restriction
                    logger.warning("The recount could not read the activity log: %s", exc)
                    fetch.error = error_text.public_error(exc)[:500]
            self._fetches[period] = fetch

    def check(self, session: Session, limit: CreditLimit, window: PeriodWindow) -> Verdict:
        period = period_for(window, self.now)
        if period not in self._fetches:
            self.prepare(session, {period})
        fetch = self._fetches[period]
        if fetch.events is None:
            return Verdict(agrees=None, reason=fetch.error or "the activity log was not read")
        try:
            if fetch.totals is None:
                fetch.totals = _totals(session, fetch.events, self.now)
        except Exception as exc:  # noqa: BLE001 - no recount, never a restriction
            session.rollback()
            logger.exception("The recount failed")
            return Verdict(agrees=None, reason=f"the recount failed ({exc})"[:500])
        recount = fetch.totals.get(limit.id, ZERO)
        return Verdict(agrees=recount >= Decimal(limit.credit_limit), recount=recount)


# ------------------------------------------------------------- the gate


def _credits(value: Decimal | None) -> str:
    if value is None:
        return "unknown"
    return credits_text.credits(value)


def _stored(value: Decimal | None) -> str | None:
    """The amount kept in the refusal record (read back by Diagnose, which words it)."""
    return None if value is None else f"{value.quantize(Decimal('0.01')).normalize():f}"


def gate(
    session: Session,
    recounter: Recounter,
    *,
    limit: CreditLimit,
    window: PeriodWindow,
    counted: Decimal,
    moment: datetime,
) -> str | None:
    """None when the new restriction may go ahead (the recount agrees, or the
    recount does not apply). Otherwise why not, after warning and recording
    it. Call with no transaction that must survive: the log may be read."""
    if not applies(session, limit, window):
        return None
    verdict = recounter.check(session, limit, window)
    if verdict.agrees:
        return None
    entity = limit.entity_label or limit.entity_id
    if verdict.agrees is None:
        kind = UNAVAILABLE
        message = (
            f"Not restricted: a direct recount of the Checkmarx activity log could not be "
            f"done ({verdict.reason}). CreditGuard's count is {_credits(counted)}. The "
            "restriction starts once a recount confirms it. See Diagnose."
        )
        title = f"{limit.entity_type.capitalize()} {entity}: not restricted, recount unavailable"
    else:
        kind = DISAGREE
        message = (
            f"Counts disagree: CreditGuard's count is {_credits(counted)}, a direct recount "
            f"of the Checkmarx activity log is {_credits(verdict.recount)}; not restricted. "
            "See Diagnose."
        )
        title = f"{limit.entity_type.capitalize()} {entity}: counts disagree, not restricted"
    notifications.notify(
        session,
        category=notifications.CATEGORY_WARNING,
        severity=Severity.WARNING,
        title=title,
        body=message,
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        dedupe_key=f"recount.{kind}:{limit.id}:{window.key}",
    )
    _record(
        session,
        {
            "kind": kind,
            "limit_id": limit.id,
            "entity_type": str(limit.entity_type),
            "entity_label": str(entity),
            "period_key": window.key,
            "credit_limit": limit.credit_limit,
            "counted": _stored(counted),
            "recount": _stored(verdict.recount),
            "reason": verdict.reason,
            "at": moment.isoformat(),
        },
    )
    return message


def _record(session: Session, entry: dict[str, Any]) -> None:
    """Keep the newest refusals; the same budget, period and kind again
    updates its entry instead of adding one every cycle."""
    entries = [item for item in records(session) if isinstance(item, dict) and item.get("limit_id")]
    same = (entry["limit_id"], entry["period_key"], entry["kind"])
    kept = [
        item
        for item in entries
        if (item.get("limit_id"), item.get("period_key"), item.get("kind")) != same
    ]
    earlier = next(
        (
            item
            for item in entries
            if (item.get("limit_id"), item.get("period_key"), item.get("kind")) == same
        ),
        None,
    )
    entry["first_at"] = (earlier or {}).get("first_at") or entry["at"]
    entry["times"] = int((earlier or {}).get("times") or 0) + 1
    settings_store.set_value(
        session, settings_store.KEY_RECOUNT_RECORDS, [entry, *kept][:KEEP_RECORDS]
    )


def records(session: Session) -> list[dict[str, Any]]:
    """The recorded refusals, newest first."""
    value = settings_store.get_value(session, settings_store.KEY_RECOUNT_RECORDS, [])
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
