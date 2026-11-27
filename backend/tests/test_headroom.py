"""Headroom: restrict before the budget runs out (app/services/headroom.py).
Synthetic data only (example.com)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CreditLimit, FusionScanCost, Notification
from app.models.enums import LimitStatus
from app.services import fastcheck, headroom, preview_service, recount
from tests.activity_world import iso
from tests.test_summary_hold import ALICE, EMAIL, World


@pytest.fixture(autouse=True)
def fresh_memory() -> Iterator[None]:
    fastcheck.reset_memory()
    yield
    fastcheck.reset_memory()


def spend_and_count(world: World, credits: int) -> None:
    world.tick(1)
    world.spend(credits)
    world.ingest()


def budget(world: World, **fields) -> CreditLimit:  # type: ignore[no-untyped-def]
    limit = world.budget(**fields)
    limit.credit_limit = 10
    world.db.commit()
    world.evaluate()
    return limit


def breach_notice(db: Session) -> Notification | None:
    db.expire_all()
    return db.scalar(
        select(Notification).where(
            Notification.entity_id == ALICE, Notification.dedupe_key.like("breach%")
        )
    )


def fusion_costs(db: Session, world: World, values: list[str], *, user: str | None) -> None:
    for number, value in enumerate(values):
        db.add(
            FusionScanCost(
                scan_key=f"scan-{user}-{number}",
                event_at=world.clock.value - timedelta(days=2),
                project_id="proj-api",
                user_id=user,
                credits=Decimal(value),
            )
        )
    db.commit()


# ------------------------------------------------------------------ fixed


def test_fixed_headroom_restricts_early_with_its_own_message(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world, headroom_credits=3)
    spend_and_count(world, 6)
    assert world.evaluate().enforced == 0  # 4 left: more than the headroom
    assert not world.restricted()
    spend_and_count(world, 1)
    result = world.evaluate()  # 3 left: inside the headroom of 3
    assert result.enforced == 1 and world.restricted()
    state = world.state(limit)
    assert state.status == LimitStatus.RESTRICTED and state.headroom_credits == Decimal("3")
    notice = breach_notice(db)
    assert notice is not None
    assert notice.title == "User Alice Archer is nearly out of credits"
    assert "Restricted early: 3 credits left, at the headroom of 3." in (notice.body or "")
    evaluated = next(e for e in result.evaluations if e.limit.id == limit.id)
    assert evaluated.note == "Restricted early: 3 credits left, at the headroom of 3."


def test_off_is_unchanged(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world)
    assert not headroom.configured(limit)
    spend_and_count(world, 9)
    assert world.evaluate().enforced == 0 and not world.restricted()
    assert world.state(limit).headroom_credits is None
    spend_and_count(world, 1)  # exactly at the limit: restricted, as before
    assert world.evaluate().enforced == 1 and world.restricted()
    notice = breach_notice(db)
    assert notice is not None and notice.title.endswith("reached its credit limit")
    assert "Restricted early" not in (notice.body or "")


def test_raising_the_budget_above_the_headroom_lifts(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world, headroom_credits=3)
    spend_and_count(world, 8)
    assert world.evaluate().enforced == 1 and world.restricted()
    stored = db.get(CreditLimit, limit.id)
    assert stored is not None
    stored.credit_limit = 11  # 3 left: still inside the headroom
    db.commit()
    world.tick(1)
    assert world.evaluate().restored == 0 and world.restricted()
    stored.credit_limit = 12  # 4 left: more than the headroom
    db.commit()
    world.tick(1)
    assert world.evaluate().restored >= 1
    assert not world.restricted()
    assert world.state(limit).status == LimitStatus.RESTORED


def test_the_recount_uses_the_limit_less_the_headroom(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world, headroom_credits=3)
    spend_and_count(world, 7)
    # The log now says 6.5 for the same row: under 10 - 3 = 7.
    assert world.tenant.activity is not None
    world.tenant.activity[-1]["creditsUsed"] = "6.5"
    result = world.evaluate()
    assert result.enforced == 0 and result.recount_held == 1
    assert not world.restricted()
    entry = recount.records(db)[0]
    assert entry["recount"] == "6.5" and entry["counted"] == "7"
    world.tenant.activity[-1]["creditsUsed"] = "7"
    world.tick(1)
    assert world.evaluate().enforced == 1 and world.restricted()
    assert world.state(limit).status == LimitStatus.RESTRICTED


def test_simulation_and_dry_run_use_the_same_rule(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world, headroom_credits=3)
    spend_and_count(world, 7)
    row = next(r for r in preview_service.dry_run(db).rows if r.limit_id == limit.id)
    assert row.projected_status == LimitStatus.BREACHED and row.would_enforce
    assert row.note is not None and row.note.startswith(
        "Would restrict early: 3 credits left, at the headroom of 3."
    )


def test_a_headroom_never_restricts_an_unused_budget(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world, headroom_credits=50)  # more than the limit itself
    found = headroom.for_limit(db, limit)
    assert found.credits == Decimal("9")  # at most limit - 1
    assert world.evaluate().enforced == 0 and not world.restricted()


# -------------------------------------------------------------- automatic


def test_automatic_headroom_from_the_budgets_own_fusion_scans(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    fusion_costs(db, world, ["2", "3", "4"], user=ALICE)
    fusion_costs(db, world, ["1", "1", "1", "1"], user=None)
    limit = budget(world, headroom_auto=True)
    found = headroom.for_limit(db, limit)
    assert found.source == headroom.AUTO_ENTITY and found.credits == Decimal("3")
    assert "median cost of this budget's 3 Fusion scan(s)" in found.describe()
    spend_and_count(world, 7)
    assert world.evaluate().enforced == 1 and world.restricted()


def test_automatic_headroom_falls_back_to_the_tenant_and_to_none(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = budget(world, headroom_auto=True)
    nothing = headroom.for_limit(db, limit)
    assert nothing.source == headroom.AUTO_NONE and not nothing.active
    fusion_costs(db, world, ["2", "2", "8"], user="user-someone-else")
    tenant = headroom.for_limit(db, limit)
    assert tenant.source == headroom.AUTO_TENANT and tenant.credits == Decimal("2")
    # Held to half the limit.
    fusion_costs(db, world, ["40", "40", "40", "40"], user=None)
    capped = headroom.for_limit(db, limit)
    assert capped.credits == Decimal("5") and "held to half the limit" in capped.describe()


def test_fusion_scan_costs_come_from_the_activity_log_once(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    budget(world)
    world.tick(1)
    moment = iso(world.clock.value - timedelta(minutes=1))
    for model in ("Fusion Scan - Opus 5.5", "Fusion Scan - Sonnet 5"):
        world.tenant.add_activity(
            date=moment,
            credits="2.5",
            project_id="proj-api",
            user="Alice Archer",
            email=EMAIL,
            action=model,
            scan_id="scan-1",
        )
    world.ingest()
    world.ingest()  # read again: nothing added twice
    db.expire_all()
    rows = db.scalars(select(FusionScanCost)).all()
    assert [(row.scan_key, row.credits, row.user_id) for row in rows] == [
        ("scan-1", Decimal("5"), ALICE)
    ]


# --------------------------------------------------------------------- API


def test_the_budget_api_takes_and_shows_a_headroom(admin_client, db: Session) -> None:  # type: ignore[no-untyped-def]
    refused = admin_client.post(
        "/api/limits",
        json={
            "entity_type": "project",
            "entity_id": "proj-headroom",
            "credit_limit": 10,
            "headroom_credits": 10,
        },
    )
    assert refused.status_code == 400
    assert "smaller than the credit limit" in refused.json()["detail"]["message"]
    created = admin_client.post(
        "/api/limits",
        json={
            "entity_type": "project",
            "entity_id": "proj-headroom",
            "credit_limit": 10,
            "headroom_credits": 4,
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["headroom_credits"] == 4 and body["headroom_auto"] is False
    assert Decimal(str(body["headroom_effective"])) == Decimal("4")
    assert body["headroom_description"] == "4 credits (fixed)."
    changed = admin_client.patch(
        f"/api/limits/{body['id']}", json={"headroom_credits": None, "headroom_auto": True}
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["headroom_auto"] is True
    assert changed.json()["headroom_description"].startswith("Automatic: not enough")
