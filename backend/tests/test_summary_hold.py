"""Summary-counted usage never starts a restriction of a period budget
(app/services/evaluation.py ``summary_hold``). Synthetic data only."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.checkmarx.iam import AI_ROLE_NAMES
from app.db.migrate import alembic_config
from app.models import CreditLimit, EnforcementAction, LimitPeriodState, Notification
from app.models.enums import EnforcementStatus, EntityType, LimitStatus, PeriodType
from app.services import (
    activity_source,
    diagnostics,
    evaluation,
    ingestion,
    org_sync,
    preview_service,
    settings_store,
)
from app.services.audit import AuditActor
from tests.activity_world import install_clock, iso
from tests.conftest import TEST_DATABASE_URL, USING_SQLITE
from tests.fake_tenant import populated_tenant

ACTOR = AuditActor.system("test")
START = datetime(2026, 8, 11, 11, 0, tzinfo=UTC)
ALICE = "user-alice"
EMAIL = "alice.archer@example.com"


class World:
    def __init__(self, db: Session, monkeypatch: pytest.MonkeyPatch, *, log: bool) -> None:
        self.db = db
        self.clock = install_clock(monkeypatch, START)
        self.tenant = populated_tenant()
        self.tenant.activity = [] if log else None
        self.client = self.tenant.client()
        org_sync.sync_org_model(db, self.client)
        db.commit()
        self.alice = 3
        self.ingest()

    def tick(self, minutes: int = 15) -> None:
        self.clock.value = self.clock.value + timedelta(minutes=minutes)

    def ingest(self) -> ingestion.IngestResult:
        result = ingestion.ingest_usage(self.db, self.client)
        self.db.commit()
        return result

    def evaluate(self) -> evaluation.EvaluationResult:
        result = evaluation.evaluate_all(
            self.db, client=self.client, now=self.clock.value, actor=ACTOR
        )
        self.db.commit()
        return result

    def spend(self, credits: int, *, log: bool = True) -> None:
        """Alice spends: in the summary always, and in the log when it has one."""
        self.alice += credits
        self.tenant.set_user_credits(name="Alice Archer", email=EMAIL, credits=self.alice)
        if log and self.tenant.activity is not None:
            self.tenant.add_activity(
                date=iso(self.clock.value - timedelta(minutes=1)),
                credits=str(credits),
                project_id="proj-api",
                user="Alice Archer",
                email=EMAIL,
            )

    def budget(self, **fields) -> CreditLimit:  # type: ignore[no-untyped-def]
        limit = CreditLimit(
            entity_type=EntityType.USER,
            entity_id=ALICE,
            entity_label="Alice Archer",
            credit_limit=5,
            period_type=fields.pop("period_type", PeriodType.MONTHLY),
            enforce=True,
            created_at=START - timedelta(days=1),
            **fields,
        )
        self.db.add(limit)
        self.db.commit()
        return limit

    def restricted(self) -> bool:
        return not any(role in self.tenant.role_mappings[ALICE] for role in AI_ROLE_NAMES)

    def state(self, limit: CreditLimit) -> LimitPeriodState:
        self.db.expire_all()
        found = self.db.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
            )
        )
        assert found is not None
        return found


def over_on_summary(world: World) -> evaluation.EvaluationResult:
    """Alice goes over her limit on what the summary counted."""
    world.evaluate()
    for _ in range(3):
        world.tick()
        world.spend(4, log=False)
        world.ingest()
    return world.evaluate()


def test_a_fallback_over_the_limit_warns_and_does_not_restrict(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=False)  # the log answers 404
    limit = world.budget()
    result = over_on_summary(world)
    assert world.state(limit).credits_used >= 5
    assert result.enforced == 0 and result.summary_held == 1
    assert world.state(limit).status == LimitStatus.BREACHED
    assert not world.restricted()
    assert not db.scalars(select(EnforcementAction)).all()
    note = db.scalar(select(Notification).where(Notification.entity_id == ALICE))
    assert note is not None and "summary totals" in note.body and "not restricted" in note.body
    # The simulation says the same, and so do the banner and Diagnose.
    row = next(r for r in preview_service.dry_run(db).rows if r.limit_id == limit.id)
    assert not row.would_enforce and "summary totals" in (row.note or "")
    held = activity_source.restriction_hold(db)
    assert held is not None and "unavailable" in str(held["reason"])
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "activity_source")
    assert check.status == diagnostics.WARN and "paused" in check.detail


def test_a_restriction_from_the_log_stays_in_force_after_a_fallback(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    world.evaluate()
    world.tick()
    world.spend(6)
    world.ingest()
    assert world.evaluate().enforced == 1 and world.restricted()
    # The log is gone: the summary takes over and counts more.
    world.tenant.activity_status = 404
    for _ in range(4):
        world.tick()
        world.spend(3, log=False)
        world.ingest()
        world.evaluate()
    assert not activity_source.source_active(db)
    assert world.state(limit).status == LimitStatus.RESTRICTED
    assert world.restricted()
    assert not [
        action
        for action in db.scalars(select(EnforcementAction))
        if action.status == EnforcementStatus.REVERSED
    ]


def test_the_log_back_restricts_on_what_it_counts(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=False)
    limit = world.budget()
    assert over_on_summary(world).enforced == 0
    # The log answers again (asked after the re-probe delay): it seeds, then
    # counts what Alice spends; that alone takes her over: restricted.
    world.tenant.activity = []
    world.tick(7 * 60)
    assert world.ingest().activity.seeded  # type: ignore[union-attr]
    world.tick()
    world.spend(4)
    world.ingest()
    assert world.evaluate().enforced == 0  # 4 of 5 from the log
    world.tick()
    world.spend(2)
    world.ingest()
    assert world.evaluate().enforced == 1
    assert world.restricted() and world.state(limit).status == LimitStatus.RESTRICTED


def test_the_opt_in_restores_restrictions_from_summary_totals(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=False)
    settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, "summary")
    db.commit()
    limit = world.budget()
    held = over_on_summary(world)
    assert held.enforced == 0 and held.summary_held == 1  # summary only, opt-in off
    settings_store.set_value(db, settings_store.KEY_SUMMARY_RESTRICTS, True)
    db.commit()
    assert world.evaluate().enforced == 1
    assert world.restricted() and world.state(limit).status == LimitStatus.RESTRICTED
    assert activity_source.restriction_hold(db) is None


@pytest.mark.parametrize(
    "fields",
    [{"period_type": PeriodType.LIFETIME}, {"count_existing_usage": True}],
    ids=["lifetime", "count_existing"],
)
def test_budgets_that_count_totals_still_restrict_on_the_summary(
    db: Session, monkeypatch: pytest.MonkeyPatch, fields: dict
) -> None:
    world = World(db, monkeypatch, log=False)
    world.budget(**fields)
    assert over_on_summary(world).enforced == 1
    assert world.restricted()


def _migration_url(tmp_path: Path) -> str:
    if USING_SQLITE:
        return f"sqlite:///{(tmp_path / 'summary-restricts.db').as_posix()}"
    engine = create_engine(TEST_DATABASE_URL)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    return TEST_DATABASE_URL


@pytest.mark.parametrize(
    ("stored", "expected"), [("summary", True), ("activity", None), (None, None)]
)
def test_the_migration_keeps_restrictions_for_an_explicit_summary_choice(
    tmp_path: Path, stored: str | None, expected: bool | None
) -> None:
    url = _migration_url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, "c9f2b6d4e8a1")
    engine = create_engine(url)
    now = datetime.now(UTC)
    if stored is not None:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO app_setting (key, value, is_secret, created_at, updated_at) "
                    "VALUES ('usage.source', :v, :no, :now, :now)"
                ),
                {"v": json.dumps(stored), "no": False, "now": now},
            )
    command.upgrade(config, "head")
    with engine.begin() as connection:
        value = connection.execute(
            text("SELECT value FROM app_setting WHERE key = 'usage.summary_restricts'")
        ).scalar()
    assert (json.loads(value) if value is not None else None) == expected
    command.downgrade(config, "c9f2b6d4e8a1")
    with engine.begin() as connection:
        gone = connection.execute(
            text("SELECT value FROM app_setting WHERE key = 'usage.summary_restricts'")
        ).scalar()
    assert gone is None
    engine.dispose()


def test_the_banner_endpoint_says_restrictions_are_paused(
    db: Session, monkeypatch: pytest.MonkeyPatch, admin_client
) -> None:
    World(db, monkeypatch, log=False)
    response = admin_client.get("/api/usage/source")
    assert response.status_code == 200, response.text
    held = response.json()["restrictions_held"]
    assert held is not None and held["summary_only"] is False


def test_auto_triage_charged_to_the_person_never_starts_a_restriction(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It always derives from the summary's project readings (owner's
    decision): only the log's part of the counter may start a restriction."""
    from decimal import Decimal

    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    index = evaluation.UsageIndex(db)
    window = evaluation.current_window(limit, world.clock.value)
    reason = evaluation.summary_hold(
        db,
        limit=limit,
        window=window,
        index=index,
        credits_used=Decimal(9),
        attributed=Decimal(9),
    )
    assert reason is not None
    world.tick()
    world.spend(6)
    world.ingest()
    index = evaluation.UsageIndex(db)
    assert (
        evaluation.summary_hold(
            db,
            limit=limit,
            window=window,
            index=index,
            credits_used=Decimal(15),
            attributed=Decimal(9),
        )
        is None
    )


def test_a_restriction_after_a_summary_held_breach_is_announced(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=False)
    world.budget()
    assert over_on_summary(world).enforced == 0
    world.tenant.activity = []
    world.tick(7 * 60)
    world.ingest()  # the log is back (seeded)
    world.tick()
    world.spend(6)
    world.ingest()
    assert world.evaluate().enforced == 1
    titles = [
        note.body or ""
        for note in db.scalars(select(Notification).where(Notification.entity_id == ALICE))
    ]
    assert any("summary totals" in body for body in titles)
    assert any("being restricted now" in body for body in titles)
