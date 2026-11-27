"""The fast check (app/services/fastcheck.py). Synthetic data only (example.com)."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from decimal import Decimal

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.db.session import get_engine, session_scope
from app.models import BudgetUsage, SchedulerRun
from app.models.enums import LimitStatus
from app.services import (
    cx_webhook,
    cycle,
    diagnostics,
    fastcheck,
    recount,
    settings_store,
)
from tests.test_summary_hold import ALICE, World

ACTIVITY_PAGE = "page"


@pytest.fixture(autouse=True)
def fresh_memory() -> Iterator[None]:
    fastcheck.reset_memory()
    cx_webhook.reset_memory()
    yield
    fastcheck.reset_memory()
    cx_webhook.reset_memory()


def tick(world: World) -> fastcheck.FastCheckResult:
    world.db.commit()
    result = fastcheck.run_fast_check(client=world.client, now=world.clock.value)
    world.db.expire_all()
    return result


def counted(world: World, limit_id: int) -> Decimal:
    world.db.expire_all()
    row = world.db.scalar(
        select(BudgetUsage).where(
            BudgetUsage.limit_id == limit_id, BudgetUsage.period_key == "2026-08"
        )
    )
    return Decimal(row.credits) if row is not None else Decimal("0")


def ready(world: World, **fields) -> object:  # type: ignore[no-untyped-def]
    limit = world.budget(**fields)
    world.evaluate()
    world.tick(1)
    return limit


def test_a_new_event_over_the_budget_restricts_within_one_tick_through_the_recount(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = ready(world)
    world.spend(6)
    before = len(world.tenant.activity_requests)
    result = tick(world)
    assert result.ran and result.skipped is None and result.error is None
    assert result.events_counted == 1 and result.fed == [limit.id]
    assert result.candidates == [limit.id] and result.enforced == 1
    assert world.restricted()
    assert world.state(limit).status == LimitStatus.RESTRICTED
    # The recount read the log's month (an explicit window, from page 1).
    asked = world.tenant.activity_requests[before:]
    assert any(request.get("period") == [recount.PERIOD_30] for request in asked)
    # The tail itself: one request with no explicit window.
    assert result.requests == 1
    # No cycle record for a fast check.
    assert db.scalars(select(SchedulerRun)).all() == []


def test_under_the_budget_it_counts_and_does_not_evaluate(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = ready(world)
    world.spend(3)
    result = tick(world)
    assert result.events_counted == 1 and result.candidates == [] and result.evaluated == 0
    assert counted(world, limit.id) == Decimal("3")
    assert not world.restricted()


def test_skips_while_the_cycle_lock_is_held(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    ready(world)
    world.spend(6)
    with session_scope() as session:
        assert cycle.acquire_lock(session, holder="another-host:cycle")
    before = len(world.tenant.activity_requests)
    result = tick(world)
    assert not result.ran and result.skipped == "a cycle is running"
    assert len(world.tenant.activity_requests) == before
    assert not world.restricted()
    with session_scope() as session:
        cycle.release_lock(session, holder="another-host:cycle")
    assert tick(world).enforced == 1


def test_a_cycle_waits_for_a_fast_check_instead_of_skipping(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cycle, "FAST_CHECK_POLL_SECONDS", 0.05)
    holder = f"{fastcheck.HOLDER_PREFIX}test"
    with session_scope() as session:
        assert cycle.acquire_lock(session, holder=holder)

    def let_go() -> None:
        time.sleep(0.3)
        with session_scope() as session:
            cycle.release_lock(session, holder=holder)

    releaser = threading.Thread(target=let_go)
    releaser.start()
    with session_scope() as session:
        assert cycle._acquire_for_cycle(session, "cycle-holder")
    releaser.join()
    assert not fastcheck.cycle_waiting.is_set()
    with session_scope() as session:
        cycle.release_lock(session, holder="cycle-holder")
        # Held by a cycle: skipped at once, as before.
        assert cycle.acquire_lock(session, holder="other-cycle")
        assert not cycle._acquire_for_cycle(session, "cycle-holder")


def test_summary_totals_never_restrict(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=False)  # the log answers 404: summary fallback
    ready(world)
    world.spend(9, log=False)
    world.ingest()
    result = tick(world)
    assert result.skipped is not None and "not the usage source" in result.skipped
    assert not world.restricted()
    # Summary only, by choice: nothing either.
    settings_store.set_value(
        db, settings_store.KEY_USAGE_SOURCE, settings_store.USAGE_SOURCE_SUMMARY
    )
    db.commit()
    result = tick(world)
    assert result.skipped == "the usage source is the consumption summary only"


def test_paused_enforcement_is_respected(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    limit = ready(world)
    settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, True)
    settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSE_REASON, "Watch-only (test).")
    world.spend(6)
    result = tick(world)
    assert result.events_counted == 1 and result.evaluated == 1
    assert result.enforced == 0 and result.held >= 1
    assert not world.restricted()
    assert world.state(limit).status == LimitStatus.BREACHED


def test_a_monitor_only_budget_is_not_restricted(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = ready(world, warning_threshold_pct=80)
    db.get(type(limit), limit.id).enforce = False  # type: ignore[union-attr]
    db.commit()
    world.spend(6)
    result = tick(world)
    assert result.evaluated == 1 and result.enforced == 0
    assert not world.restricted()
    # Announced once: the next new event does not evaluate it again.
    world.spend(1)
    world.tick(1)
    assert tick(world).candidates == []


def test_idempotent_across_ticks_and_with_the_full_cycle(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = ready(world)
    world.spend(2)
    world.spend(2)  # two identical rows: two events
    first = tick(world)
    assert first.events_counted == 2
    for _ in range(3):
        world.tick(1)
        again = tick(world)
        assert again.events_counted == 0 and not again.wrote
    assert counted(world, limit.id) == Decimal("4")
    # The full cycle reads the same rows: nothing new either.
    world.ingest()
    assert counted(world, limit.id) == Decimal("4")
    # And what the cycle counted first, the fast check does not count again.
    world.tick(1)
    world.spend(1)
    world.ingest()
    assert tick(world).events_counted == 0
    assert counted(world, limit.id) == Decimal("5")


def test_no_database_writes_when_nothing_changed(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    ready(world)
    world.spend(2)
    assert tick(world).events_counted == 1
    writes: list[str] = []

    def watch(_conn, _cursor, statement, _params, _context, _many) -> None:  # type: ignore[no-untyped-def]
        verb = statement.lstrip().split(" ", 1)[0].upper()
        if verb in {"INSERT", "UPDATE", "DELETE"}:
            writes.append(statement)

    engine = get_engine()
    event.listen(engine, "before_cursor_execute", watch)
    try:
        for _ in range(3):
            world.tick(1)
            result = tick(world)
            assert result.ran and result.events_counted == 0
    finally:
        event.remove(engine, "before_cursor_execute", watch)
    # Only the lock row: taken and released, each tick.
    assert writes and all("scheduler_lock" in statement for statement in writes), writes
    assert len(writes) == 6


def test_demo_mode_never_touches_the_live_tenant(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    ready(world)
    world.spend(6)
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
    db.commit()
    before = len(world.tenant.activity_requests)
    result = tick(world)
    assert result.skipped == "demo mode" and not result.ran
    assert len(world.tenant.activity_requests) == before
    assert not world.restricted()


def test_turned_off_does_nothing(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    ready(world)
    settings_store.set_value(db, settings_store.KEY_FAST_CHECK_ENABLED, False)
    db.commit()
    world.spend(6)
    assert tick(world).skipped == "turned off"
    assert not world.restricted()


def test_a_restriction_held_by_the_recount_is_not_retried_every_tick(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = ready(world)
    world.spend(6)
    world.tenant.activity_status = None
    # The recount cannot be done: held, warned, recorded.
    original = recount.read_log

    def refuse(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise recount.RecountUnavailable("test: the log could not be read")

    monkeypatch.setattr(recount, "read_log", refuse)
    first = tick(world)
    assert first.enforced == 0 and first.held == 1
    assert world.state(limit).status == LimitStatus.BREACHED
    monkeypatch.setattr(recount, "read_log", original)
    world.tick(1)
    world.spend(1)
    # Within RECOUNT_RETRY: the next new event does not trigger another recount.
    assert tick(world).candidates == []
    world.tick(10)
    world.spend(1)
    again = tick(world)
    assert again.candidates == [limit.id] and again.enforced == 1
    assert world.restricted()


def test_the_ceiling_counts_what_fast_checks_started_recently(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    ready(world)
    settings_store.set_value(db, settings_store.KEY_MAX_NEW_ENFORCEMENTS, 1)
    db.commit()
    with session_scope() as session:
        assert fastcheck._ceiling_defers(session, world.clock.value, 1) is None
    world.spend(6)
    assert tick(world).enforced == 1
    # One restriction started within the cycle interval: another one now
    # would make two, over the ceiling of 1: left to the full cycle.
    with session_scope() as session:
        deferred = fastcheck._ceiling_defers(session, world.clock.value, 1)
    assert deferred is not None and "left to the full cycle" in deferred
    # An interval later it no longer counts.
    world.tick(16)
    with session_scope() as session:
        assert fastcheck._ceiling_defers(session, world.clock.value, 1) is None


def test_status_on_diagnose(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    ready(world)
    world.spend(6)
    tick(world)
    db.expire_all()
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "fast_check")
    assert check.status == diagnostics.OK
    assert "Last run just now: counted 1 new event(s)" in check.detail
    assert "applied 1 restriction(s)" in check.detail
    stored = settings_store.get_value(db, settings_store.KEY_FAST_CHECK_STATUS)
    assert stored["last_action"]["trigger"] == "schedule"
    assert fastcheck.describe(db)["requests_per_hour"] == 240


def test_scheduled_runs_take_one_queued_request(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app import scheduler

    woken: list[float] = []
    monkeypatch.setattr(scheduler, "wake_fast_check", lambda delay=0.0: woken.append(delay))
    world = World(db, monkeypatch, log=True)
    ready(world)
    db.commit()
    assert fastcheck.request(hint={"project_id": "proj-api"})
    assert not fastcheck.request(hint={"project_id": "proj-web"})  # merged
    assert len(woken) == 1
    monkeypatch.setattr(
        fastcheck, "run_fast_check", lambda **kwargs: fastcheck.FastCheckResult(**kwargs)
    )
    results = fastcheck.run_scheduled()
    assert [r.trigger for r in results] == ["webhook"]
    assert results[0].hint == {"project_id": "proj-api"}
    assert not fastcheck.pending()
    assert ALICE  # the world's person, synthetic
