"""Demo <-> live data toggle: seeding, clearing, and cycle suppression."""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import RunStatus, UsageView
from app.models.org import CxUser
from app.services import connection as connection_service
from app.services import cycle, demo_service, ingestion, org_sync, settings_store
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")


@pytest.fixture
def tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    client = fake.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: fake.client())
    return fake


class TestSeedAndClear:
    def test_seed_populates_org_and_usage(self, db: Session) -> None:
        demo_service.seed(db)
        # Demo usage is only visible in demo mode (the endpoint turns it on).
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()
        assert demo_service.is_seeded(db) is True
        user_totals = ingestion.latest_totals(db, UsageView.USER)
        assert user_totals.get("demo-user-alan") == Decimal("1180")
        assert any(k.startswith("demo-") for k in user_totals)

    def test_clear_removes_only_demo_rows(self, tenant: FakeTenant, db: Session) -> None:
        real_users_before = set(db.scalars(select(CxUser.id).where(CxUser.id.not_like("demo-%"))))
        assert real_users_before  # the tenant fixture synced real users

        demo_service.seed(db)
        db.commit()
        assert demo_service.is_seeded(db) is True

        demo_service.clear(db)
        db.commit()
        assert demo_service.is_seeded(db) is False
        # Real users survive; no demo users remain.
        real_users_after = set(db.scalars(select(CxUser.id).where(CxUser.id.not_like("demo-%"))))
        assert real_users_after == real_users_before
        assert (
            db.scalar(select(func.count()).select_from(CxUser).where(CxUser.id.like("demo-%"))) == 0
        )

    def test_seed_is_idempotent(self, db: Session) -> None:
        demo_service.seed(db)
        db.commit()
        demo_service.seed(db)
        db.commit()
        # Not doubled.
        assert (
            db.scalar(select(func.count()).select_from(CxUser).where(CxUser.id.like("demo-%"))) == 3
        )


class TestDemoSnapshotIsolation:
    def test_demo_usage_is_hidden_outside_demo_mode(self, tenant: FakeTenant, db: Session) -> None:
        # With real usage already ingested by the fixture, seeding demo data must
        # NOT shadow it while demo mode is off.
        demo_service.seed(db)
        db.commit()
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, False)
        db.commit()
        totals_live = ingestion.latest_totals(db, UsageView.USER)
        assert not any(k.startswith("demo-") for k in totals_live)
        assert "user-harsh" in totals_live  # the real entity is still visible

        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()
        totals_demo = ingestion.latest_totals(db, UsageView.USER)
        assert "demo-user-alan" in totals_demo


class TestCycleSuppression:
    def test_demo_mode_runs_a_reduced_cycle_without_touching_checkmarx(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        demo_service.seed(db)
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        # Not a dead skip: it evaluates demo data and delivers, but runs no
        # Checkmarx-touching step (no org_sync / ingest / credits).
        assert result.status != RunStatus.FAILED
        assert result.steps.get("demo") == {"active": True}
        assert "evaluate" in result.steps
        assert "org_sync" not in result.steps
        assert "ingest" not in result.steps


class TestEndpoints:
    def test_seed_and_clear_endpoints(self, admin_client: TestClient, db: Session) -> None:
        seeded = admin_client.post("/api/ops/demo/seed")
        assert seeded.status_code == httpx.codes.OK, seeded.text
        assert seeded.json() == {"seeded": True, "demo_mode": True}
        # Seeding enters demo mode so the live cycle won't read the demo snapshots.
        status = admin_client.get("/api/ops/demo").json()
        assert status["seeded"] is True and status["demo_mode"] is True

        cleared = admin_client.post("/api/ops/demo/clear")
        assert cleared.status_code == httpx.codes.OK
        assert cleared.json() == {"seeded": False, "demo_mode": False}

    def test_seed_requires_admin(self, viewer_client: TestClient) -> None:
        assert viewer_client.post("/api/ops/demo/seed").status_code == httpx.codes.FORBIDDEN

    def test_demo_mode_flows_through_settings_and_me(self, admin_client: TestClient) -> None:
        updated = admin_client.put("/api/settings", json={"demo_mode": True})
        assert updated.status_code == httpx.codes.OK
        assert updated.json()["demo_mode"] is True
        assert admin_client.get("/api/me").json()["demo_mode"] is True
