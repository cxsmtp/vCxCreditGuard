"""Core enforcement under the real defaults (review): the usage that takes a
monthly budget over its limit comes from the credit activity log, and the
same scenario fed by the summary with restrictions from summary totals
allowed (the old behaviour) must end the same way. Rollover, hold until
released, the pause switch and the safety ceiling. Synthetic data only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.models.enums import LimitStatus
from app.services import settings_store
from tests.activity_world import iso
from tests.test_summary_hold import World

SOURCES = ["log", "summary_opt_in"]
PEOPLE = {
    "user-alice": ("Alice Archer", "alice.archer@example.com"),
    "user-bob": ("Bob Baker", "bob.baker@example.com"),
}


def _world(db: Session, monkeypatch: pytest.MonkeyPatch, source: str) -> World:
    if source == "summary_opt_in":
        settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, "summary")
        settings_store.set_value(db, settings_store.KEY_SUMMARY_RESTRICTS, True)
        db.commit()
    world = World(db, monkeypatch, log=source == "log")
    if source == "summary_opt_in":
        # The summary is the usage source, but the recount before a new
        # restriction reads the activity log directly (app/services/recount.py):
        # it holds the same spending (``spend``).
        world.tenant.activity = []
    world.totals = {"user-alice": 3, "user-bob": 5}  # type: ignore[attr-defined]
    return world


def spend(world: World, user_id: str, credits: int) -> None:
    name, email = PEOPLE[user_id]
    world.totals[user_id] += credits  # type: ignore[attr-defined]
    world.tenant.set_user_credits(name=name, email=email, credits=world.totals[user_id])  # type: ignore[attr-defined]
    if world.tenant.activity is not None:
        world.tenant.add_activity(
            date=iso(world.clock.value - timedelta(minutes=1)),
            credits=str(credits),
            project_id="proj-api",
            user=name,
            email=email,
        )


def restricted(world: World, user_id: str) -> bool:
    return not any(role in world.tenant.role_mappings[user_id] for role in AI_ROLE_NAMES)


def over_the_limit(world: World, *users: str) -> None:
    world.evaluate()
    for _ in range(2):  # the summary's first reading after the budget is history
        world.tick()
        world.ingest()
    world.tick()
    for extra, user_id in enumerate(users):
        # Different amounts: two rows alike in every field that cannot change
        # are one identity, whose people cannot be told apart.
        spend(world, user_id, 6 + extra)
    world.ingest()


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("hold", [False, True], ids=["lifted", "held"])
def test_rollover(db: Session, monkeypatch: pytest.MonkeyPatch, source: str, hold: bool) -> None:
    world = _world(db, monkeypatch, source)
    limit = world.budget(hold_until_released=hold)
    over_the_limit(world, "user-alice")
    assert world.evaluate().enforced == 1 and restricted(world, "user-alice")
    # The next month: a new period, nothing used in it.
    world.clock.value = datetime(2026, 9, 1, 0, 30, tzinfo=UTC)
    world.ingest()
    world.evaluate()
    assert restricted(world, "user-alice") is hold
    world.db.expire_all()
    if not hold:
        assert world.state(limit).status in (LimitStatus.RESTRICTED, LimitStatus.RESTORED)


@pytest.mark.parametrize("source", SOURCES)
def test_the_pause_switch(db: Session, monkeypatch: pytest.MonkeyPatch, source: str) -> None:
    world = _world(db, monkeypatch, source)
    world.budget()
    settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, True)
    db.commit()
    over_the_limit(world, "user-alice")
    paused = world.evaluate()
    assert paused.enforced == 0 and paused.deferred == 1 and not restricted(world, "user-alice")
    settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, False)
    db.commit()
    assert world.evaluate().enforced == 1 and restricted(world, "user-alice")


@pytest.mark.parametrize("source", SOURCES)
def test_the_safety_ceiling(db: Session, monkeypatch: pytest.MonkeyPatch, source: str) -> None:
    from app.models import CreditLimit
    from app.models.enums import EntityType, PeriodType

    world = _world(db, monkeypatch, source)
    world.budget()
    db.add(
        CreditLimit(
            entity_type=EntityType.USER,
            entity_id="user-bob",
            entity_label="Bob Baker",
            credit_limit=5,
            period_type=PeriodType.MONTHLY,
            enforce=True,
            created_at=world.clock.value - timedelta(days=1),
        )
    )
    settings_store.set_value(db, settings_store.KEY_MAX_NEW_ENFORCEMENTS, 1)
    db.commit()
    over_the_limit(world, "user-alice", "user-bob")
    result = world.evaluate()
    assert result.enforced == 0
    assert not restricted(world, "user-alice") and not restricted(world, "user-bob")
    assert settings_store.enforcement_guard(db).paused
