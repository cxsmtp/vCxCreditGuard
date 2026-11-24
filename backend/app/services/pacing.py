"""How much one cycle may do, so a large tenant is worked through over several.

A tenant of a few thousand projects cannot be read back, restricted and
checked in full every few minutes: at a realistic 50 ms per Checkmarx call,
verifying every restriction in force alone would take longer than the cycle
interval. Instead each kind of per-target work has a per-cycle budget and is
rotated fairly, oldest first, so that everything is covered within a bounded
number of cycles and the cycle itself finishes well within its interval:

* **Verification** of restrictions in force: each is read back at most every
  ``verify_interval_minutes`` (default 60), spread evenly over the cycles,
  oldest-verified first, at most ``max_verifications_per_cycle`` per cycle. A
  restriction is read back straight after it is applied, so a new one is
  always verified at once.
* **Restriction writes** (applying or lifting a restriction): at most
  ``max_writes_per_cycle`` per cycle. A limit with more targets than that is
  restricted over several cycles, resuming where it stopped, with its progress
  on the limit ("Restricting 1,240 of 2,000 projects"). Small limits go first,
  so one large rollout never holds up a single user's restriction.
* **Policy violation scan checks** and **auto-triage attribution**: a number of
  projects per cycle, the longest-waiting first.
* **A time budget** for the whole cycle (``time_budget_pct`` of the interval):
  once it is spent, the steps stop starting new per-target work and leave the
  rest to the next cycle, rather than overrun into it.
* **Read concurrency**: read-only Checkmarx calls that do not depend on each
  other (verification read-backs, scan listings) are made ``read_concurrency``
  at a time. Writes are never parallel.

Each budget set to 0 means "no budget": the behaviour before pacing existed.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, TypeVar

from sqlalchemy.orm import Session

from app.services import settings_store

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


@dataclass(frozen=True, slots=True)
class Pacing:
    verify_interval_minutes: int
    max_verifications_per_cycle: int
    max_writes_per_cycle: int
    violation_projects_per_cycle: int
    attribution_projects_per_cycle: int
    attribution_requests_per_cycle: int
    read_concurrency: int
    time_budget_pct: int
    interval_minutes: int

    def verifications_per_cycle(self, in_force: int, due: int) -> int | None:
        """How many restrictions to read back this cycle; None: all of them."""
        if self.verify_interval_minutes <= 0:
            return None
        # Spread evenly: every restriction once per interval, plus whatever is
        # overdue (a backlog after an upgrade, or after cycles that ran short).
        even = math.ceil(in_force * self.interval_minutes / self.verify_interval_minutes)
        wanted = max(due, even)
        if self.max_verifications_per_cycle > 0:
            wanted = min(wanted, self.max_verifications_per_cycle)
        return wanted

    def coverage_minutes(self, in_force: int) -> int | None:
        """At most how long a restriction in force goes unverified, at this size."""
        if self.verify_interval_minutes <= 0:
            return self.interval_minutes
        per_cycle = self.verifications_per_cycle(in_force, 0) or 1
        cycles = math.ceil(in_force / max(1, per_cycle)) if in_force else 1
        return max(self.verify_interval_minutes, cycles * self.interval_minutes)


def _int(session: Session, key: str, *, low: int = 0, high: int = 1_000_000) -> int:
    value = settings_store.get_value(session, key, settings_store.DEFAULTS.get(key))
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = int(settings_store.DEFAULTS[key])
    return max(low, min(high, number))


def pacing(session: Session) -> Pacing:
    """The pacing settings, normalised to safe values."""
    return Pacing(
        verify_interval_minutes=_int(session, settings_store.KEY_VERIFY_INTERVAL_MINUTES),
        max_verifications_per_cycle=_int(session, settings_store.KEY_MAX_VERIFICATIONS),
        max_writes_per_cycle=_int(session, settings_store.KEY_MAX_WRITES),
        violation_projects_per_cycle=_int(session, settings_store.KEY_VIOLATION_PROJECTS),
        attribution_projects_per_cycle=_int(session, settings_store.KEY_ATTRIBUTION_PROJECTS),
        attribution_requests_per_cycle=_int(session, settings_store.KEY_ATTRIBUTION_REQUESTS),
        read_concurrency=_int(session, settings_store.KEY_READ_CONCURRENCY, low=1, high=16),
        time_budget_pct=_int(session, settings_store.KEY_CYCLE_TIME_BUDGET_PCT, high=100),
        interval_minutes=settings_store.schedule_config(session).interval_minutes,
    )


# ------------------------------------------------------------- time budget

# The monotonic moment by which the running cycle should stop starting new
# per-target work. One cycle runs at a time (the cycle lock), so one value.
_deadline: float | None = None
_deadline_guard = threading.Lock()


@contextmanager
def cycle_deadline(seconds: float | None) -> Iterator[None]:
    """Give the steps inside a time budget; None or 0: no budget."""
    global _deadline
    with _deadline_guard:
        previous = _deadline
        _deadline = time.monotonic() + seconds if seconds else None
    try:
        yield
    finally:
        with _deadline_guard:
            _deadline = previous


def seconds_left() -> float | None:
    """Time left in the cycle's budget, or None when there is no budget."""
    deadline = _deadline
    return None if deadline is None else deadline - time.monotonic()


def out_of_time() -> bool:
    left = seconds_left()
    return left is not None and left <= 0


def cycle_budget_seconds(config: Pacing) -> float | None:
    """The cycle's time budget: a share of its interval, at least a minute."""
    if config.time_budget_pct <= 0:
        return None
    return max(60.0, config.interval_minutes * 60 * config.time_budget_pct / 100)


# ------------------------------------------------------------- parallel reads


def parallel_map(
    work: Callable[[T], R], items: Iterable[T], *, workers: int
) -> list[tuple[T, R | None, Exception | None]]:
    """Run ``work`` on each item, ``workers`` at a time, in the input order.

    For read-only Checkmarx calls only: ``work`` must not touch the database
    (the session is not shared between threads). Each item's exception is
    returned with it, never raised, so one failure stops nothing else.
    """
    items = list(items)

    def run(item: T) -> tuple[T, R | None, Exception | None]:
        try:
            return item, work(item), None
        except Exception as exc:  # noqa: BLE001 - returned to the caller with its item
            return item, None, exc

    if workers <= 1 or len(items) <= 1:
        return [run(item) for item in items]
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cx-read") as pool:
        return list(pool.map(run, items))


def describe(config: Pacing, **extra: Any) -> dict[str, Any]:
    """The pacing in force, for a cycle's record."""
    return {
        "verify_interval_minutes": config.verify_interval_minutes,
        "max_verifications_per_cycle": config.max_verifications_per_cycle,
        "max_writes_per_cycle": config.max_writes_per_cycle,
        "read_concurrency": config.read_concurrency,
        "time_budget_seconds": cycle_budget_seconds(config),
        **extra,
    }
