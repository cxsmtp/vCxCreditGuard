"""The usage ledger after the sixth review of realfix: doubted falls, aggregate
rows of their own, count-existing switches, rollovers with late, skipped or
no evaluation, mappings that settle what waited, and remembered names that
age out of the lookback window. Synthetic data only."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import LimitPeriodState, UsageDelta, UsageMissingName
from app.models.enums import EntityType, PeriodType
from app.services import connection as connection_service
from app.services import cycle, evaluation, ingestion, limits_service, org_sync
from app.services.periods import current_window
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _limit, _state


def _doubted_reading(monkeypatch: pytest.MonkeyPatch, *, name: str, credits: int) -> None:
    """One project reading the completeness checks doubt (it says it has one
    row more than it serves), reporting ``name`` lower than it is."""
    real = FakeTenant._consumption_response

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "project":
            return real(self, params)
        rows = [
            dict(row, creditsUsed=str(credits)) if row["name"] == name else row
            for row in self.consumption["project"]
        ]
        return httpx.Response(
            200,
            json={"items": rows, "totalItems": len(rows) + 1, "totalPages": 1, "currentPage": 1},
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)


def _states(db: Session, limit) -> dict[str, Decimal]:  # type: ignore[no-untyped-def]
    db.expire_all()
    return {
        s.period_key: s.credits_used
        for s in db.scalars(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
    }


class TestDoubtedFalls:
    def test_a_dip_in_a_doubted_reading_and_its_recovery_count_nothing(
        self,
        db: Session,
        connected,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
        # Enough other usage that the dip is not a collapse of the whole feed.
        tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        web = _limit(db, EntityType.PROJECT, "proj-web")
        cycle.run_cycle(trigger="manual")
        _doubted_reading(monkeypatch, name="payments/web", credits=400)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 0
        held = db.scalar(select(UsageMissingName).where(UsageMissingName.kind == "dip"))
        assert held is not None and held.last_total == 1000
        monkeypatch.undo()
        connected(tenant)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 0
        # From then on, only what it adds.
        tenant.set_entity_credits(view="project", name="payments/web", credits=1012)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 12

    def test_usage_during_a_dip_counts_once_it_recovers(
        self,
        db: Session,
        connected,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
        # Enough other usage that the dip is not a collapse of the whole feed.
        tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        web = _limit(db, EntityType.PROJECT, "proj-web")
        cycle.run_cycle(trigger="manual")
        _doubted_reading(monkeypatch, name="payments/web", credits=10)
        cycle.run_cycle(trigger="manual")
        cycle.run_cycle(trigger="manual")  # doubted again: still held
        monkeypatch.undo()
        connected(tenant)
        tenant.set_entity_credits(view="project", name="payments/web", credits=1025)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 25

    def test_a_believed_fall_rebases_and_the_rise_after_it_counts(
        self,
        db: Session,
        connected,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A fall confirmed by a complete reading is the window rolling past
        old usage: the name continues from its new total."""
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
        # Enough other usage that the dip is not a collapse of the whole feed.
        tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        web = _limit(db, EntityType.PROJECT, "proj-web")
        cycle.run_cycle(trigger="manual")
        _doubted_reading(monkeypatch, name="payments/web", credits=900)
        cycle.run_cycle(trigger="manual")
        monkeypatch.undo()
        connected(tenant)
        tenant.set_entity_credits(view="project", name="payments/web", credits=900)
        cycle.run_cycle(trigger="manual")
        assert db.scalar(select(UsageMissingName)) is None
        tenant.set_entity_credits(view="project", name="payments/web", credits=930)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 30


class TestAggregateRows:
    def test_an_applications_first_own_row_counts_no_history_and_no_double(
        self,
        db: Session,
        connected,
    ) -> None:
        tenant = live_tenant()
        tenant.consumption["application"] = []  # a real, idle application dimension
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        app_limit = _limit(db, EntityType.APPLICATION, "app-payments")
        cycle.run_cycle(trigger="manual")
        assert _state(db, app_limit).credits_used == 0
        # payments/web goes from 4 to 40 (36 new); the application dimension
        # reports the application for the first time, history included.
        tenant.set_entity_credits(view="project", name="payments/web", credits=40)
        tenant.set_entity_credits(
            view="application", name="Payments", credits=48, entity_id="app-payments"
        )
        cycle.run_cycle(trigger="manual")
        assert _state(db, app_limit).credits_used == 36
        # From then on its own row feeds it, and its projects do not.
        tenant.set_entity_credits(view="project", name="payments/web", credits=45)
        tenant.set_entity_credits(
            view="application", name="Payments", credits=53, entity_id="app-payments"
        )
        cycle.run_cycle(trigger="manual")
        assert _state(db, app_limit).credits_used == 41

    def test_a_group_row_that_returns_counts_none_of_its_absence(
        self,
        db: Session,
        connected,
    ) -> None:
        tenant = live_tenant()
        tenant.consumption["group"] = []
        tenant.set_entity_credits(view="group", name="AA-Platform", credits=2)
        # Enough other usage that the group view is not a collapse when it goes.
        tenant.set_entity_credits(view="group", name="Payments", credits=5000)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        limit = limits_service.create_limit(
            db,
            data=limits_service.LimitInput(
                entity_type=EntityType.GROUP,
                entity_id="grp-platform",
                credit_limit=100,
                period_type=PeriodType.MONTHLY,
                enforce=False,
                include_member_usage=False,
            ),
            actor=ACTOR,
        )
        db.commit()
        cycle.run_cycle(trigger="manual")
        # The group's row leaves the group view. The reading it leaves in is
        # lost (the group was fed by its own row, which is not there); from
        # the next one its project feeds it.
        tenant.consumption["group"] = [
            r for r in tenant.consumption["group"] if r["name"] != "AA-Platform"
        ]
        tenant.set_entity_credits(view="project", name="platform/tools", credits=12)
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(view="project", name="platform/tools", credits=22)
        cycle.run_cycle(trigger="manual")
        # Back, with everything since it left: counted once, by the project.
        tenant.set_entity_credits(view="group", name="AA-Platform", credits=22)
        cycle.run_cycle(trigger="manual")
        assert _state(db, limit).credits_used == 10


class TestCountExistingSwitches:
    def test_a_budget_that_counts_existing_usage_switched_to_its_period(
        self,
        db: Session,
        connected,
    ) -> None:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        web = _limit(db, EntityType.PROJECT, "proj-web", existing=True)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 1000
        tenant.set_entity_credits(view="project", name="payments/web", credits=1020)
        cycle.run_cycle(trigger="manual")
        assert _state(db, web).credits_used == 1020
        limits_service.update_limit(
            db, limit=web, changes={"count_existing_usage": False}, actor=ACTOR
        )
        db.commit()
        cycle.run_cycle(trigger="manual")
        # The 20 observed this period while it counted existing usage.
        assert _state(db, web).credits_used == 20


def _drive(db: Session, client, clock: list) -> None:  # type: ignore[no-untyped-def]
    org_sync.sync_org_model(db, client)
    db.commit()
    ingestion.ingest_usage(db, client)
    db.commit()


class TestRollovers:
    def _setup(self, db: Session, connected, monkeypatch):  # type: ignore[no-untyped-def]
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
        connected(tenant)
        client = connection_service.get_client(db)
        month_start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        clock = [month_start + timedelta(days=27)]
        monkeypatch.setattr(ingestion, "utcnow", lambda: clock[0])
        _drive(db, client, clock)
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()
        web = _limit(db, EntityType.PROJECT, "proj-web")
        clock[0] += timedelta(minutes=30)
        _drive(db, client, clock)
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()
        return tenant, client, clock, web

    def test_a_skipped_evaluation_across_a_rollover(
        self,
        db: Session,
        connected,
        monkeypatch,
    ) -> None:
        tenant, client, clock, web = self._setup(db, connected, monkeypatch)
        old = current_window(web, clock[0]).key
        # Read (not evaluated) late in the month ...
        tenant.set_entity_credits(view="project", name="payments/web", credits=1030)
        clock[0] = clock[0].replace(day=28, hour=23)
        _drive(db, client, clock)
        # ... and read again after the rollover, with more usage meanwhile.
        tenant.set_entity_credits(view="project", name="payments/web", credits=1050)
        clock[0] = (clock[0].replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=30)
        _drive(db, client, clock)
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()
        new = current_window(web, clock[0]).key
        states = _states(db, web)
        # The 30 in the old month; the 20 spans the rollover and counts nowhere.
        assert states[old] == 30 and states.get(new, Decimal(0)) == 0, states
        tenant.set_entity_credits(view="project", name="payments/web", credits=1055)
        clock[0] += timedelta(minutes=30)
        _drive(db, client, clock)
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()
        assert _states(db, web)[new] == 5

    def test_demo_mode_across_a_rollover_brings_nothing_into_the_new_period(
        self,
        db: Session,
        connected,
        monkeypatch,
        admin_client: TestClient,
    ) -> None:
        tenant, client, clock, web = self._setup(db, connected, monkeypatch)
        assert admin_client.post("/api/ops/demo/seed").status_code == 200
        tenant.set_entity_credits(view="project", name="payments/web", credits=1080)
        assert admin_client.post("/api/ops/demo/clear").status_code == 200
        clock[0] = (clock[0].replace(day=1) + timedelta(days=32)).replace(day=2)
        _drive(db, client, clock)
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()
        assert _states(db, web).get(current_window(web, clock[0]).key, Decimal(0)) == 0


class TestSettledWaits:
    def test_mapping_a_person_never_claims_what_waited(
        self,
        db: Session,
        connected,
        admin_client: TestClient,
    ) -> None:
        """The user view: usage under a handle that matched nobody stays
        uncounted when an admin maps it, even to a user synced meanwhile."""
        tenant = live_tenant()
        tenant.set_user_credits(name="Erin Example", credits=100)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        cycle.run_cycle(trigger="manual")
        tenant.set_user_credits(name="Erin Example", credits=140)
        cycle.run_cycle(trigger="manual")
        waiting = db.scalar(select(UsageDelta).where(UsageDelta.subject_key == "erin example"))
        assert waiting is not None and waiting.entity_id is None
        tenant.add_user(
            user_id="user-erin",
            username="erin.e@example.org",
            email="erin.e@example.org",
            first_name="Erin",
            last_name="Other",
        )
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        erin = _limit(db, EntityType.USER, "user-erin")
        subject = admin_client.get("/api/usage/unresolved").json()
        target = next(s for s in subject if s["subject_key"] == "erin example")
        response = admin_client.post(
            f"/api/usage/unresolved/{target['id']}/map", json={"user_id": "user-erin"}
        )
        assert response.status_code == 200, response.text
        cycle.run_cycle(trigger="manual")
        assert _state(db, erin).credits_used == 0
        db.expire_all()
        assert db.get(UsageDelta, waiting.id).claimed_at is not None


class TestRememberedNamesAge:
    def test_a_name_back_after_the_lookback_window_counts_in_full(
        self,
        db: Session,
        connected,
        monkeypatch,
    ) -> None:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
        tenant.set_entity_credits(view="project", name="payments/web", credits=50)
        connected(tenant)
        client = connection_service.get_client(db)
        clock = [utcnow().replace(day=1, hour=1)]
        monkeypatch.setattr(ingestion, "utcnow", lambda: clock[0])
        _drive(db, client, clock)
        web = _limit(db, EntityType.PROJECT, "proj-web")
        clock[0] += timedelta(minutes=5)
        _drive(db, client, clock)
        tenant.consumption["project"] = [
            r for r in tenant.consumption["project"] if r["name"] != "payments/web"
        ]
        clock[0] += timedelta(minutes=5)
        _drive(db, client, clock)
        assert db.scalar(select(UsageMissingName)) is not None
        # Back after more than the lookback window (a year): nothing of its old
        # total can be left in the window, so everything it reports is new.
        tenant.set_entity_credits(view="project", name="payments/web", credits=7)
        clock[0] += timedelta(days=366)
        _drive(db, client, clock)
        db.expire_all()
        assert db.scalar(select(UsageMissingName)) is None
        back = db.scalar(select(UsageDelta).where(UsageDelta.subject_key == "payments/web"))
        assert back is not None and back.credits == 7
        # The interval spans the budget's period start: no period counts it.
        evaluation.evaluate_all(db, now=clock[0])
        db.commit()
        assert _states(db, web).get(current_window(web, clock[0]).key, Decimal(0)) == 0
