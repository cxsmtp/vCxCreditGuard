"""Business-unit chargeback and time-boxed override (expiring exemption)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType
from app.models.limits import CreditLimit, Exemption
from app.services import connection as connection_service
from app.services import (
    cycle,
    evaluation,
    ingestion,
    limits_service,
    org_sync,
    reporting_service,
    settings_store,
)
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUG_02 = datetime(2026, 8, 2, tzinfo=UTC)
AUG_16 = datetime(2026, 8, 16, tzinfo=UTC)


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


class TestChargeback:
    def test_groups_by_business_unit_with_cost(self, tenant: FakeTenant, db: Session) -> None:
        client = tenant.client()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=1)
        ingestion.ingest_usage(db, client)
        db.commit()
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                entity_label="Harsh Gokani",
                credit_limit=100,
                period_type=PeriodType.MONTHLY,
                business_unit="Platform",
            )
        )
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-akash",
                entity_label="Akash",
                credit_limit=50,
                period_type=PeriodType.MONTHLY,
            )  # no business unit -> unassigned
        )
        db.commit()
        evaluation.evaluate_all(db, client=None, now=AUG_02, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=21)
        ingestion.ingest_usage(db, client)
        db.commit()
        settings_store.set_value(db, settings_store.KEY_CREDIT_UNIT_COST, 0.5)
        db.commit()

        result = reporting_service.chargeback(db, now=AUG_16)
        assert result.currency_known is True
        assert result.unassigned_limits == 1
        platform = next(r for r in result.rows if r.business_unit == "Platform")
        assert platform.credits_used == Decimal("20")
        assert platform.estimated_cost == Decimal("10.0")

    def test_no_cost_means_no_currency(self, tenant: FakeTenant, db: Session) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                credit_limit=100,
                period_type=PeriodType.MONTHLY,
                business_unit="Platform",
            )
        )
        db.commit()
        result = reporting_service.chargeback(db, now=AUG_16)
        assert result.currency_known is False
        assert all(r.estimated_cost is None for r in result.rows)

    def test_endpoint(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        assert admin_client.get("/api/reports/chargeback").status_code == httpx.codes.OK


class TestOverride:
    def test_a_future_override_is_stored(self, tenant: FakeTenant, db: Session) -> None:
        exemption = limits_service.add_exemption(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            reason="incident bridge",
            expires_at=utcnow() + timedelta(hours=4),
            actor=ACTOR,
        )
        db.commit()
        assert exemption.expires_at is not None

    def test_re_scoping_an_override_is_audited(self, tenant: FakeTenant, db: Session) -> None:
        from app.models.audit import AuditLogEntry

        limits_service.add_exemption(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            reason="initial",
            expires_at=utcnow() + timedelta(hours=2),
            actor=ACTOR,
        )
        db.commit()
        limits_service.add_exemption(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            reason="extended",
            expires_at=utcnow() + timedelta(days=5),
            actor=ACTOR,
        )
        db.commit()
        updated = db.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "exemption.updated")
        )
        assert updated is not None

    def test_a_past_expiry_is_rejected(self, tenant: FakeTenant, db: Session) -> None:
        with pytest.raises(limits_service.LimitError):
            limits_service.add_exemption(
                db,
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                reason="oops",
                expires_at=utcnow() - timedelta(hours=1),
                actor=ACTOR,
            )

    def test_expire_overrides_removes_lapsed_ones(self, tenant: FakeTenant, db: Session) -> None:
        db.add(
            Exemption(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                entity_label="Harsh Gokani",
                reason="temporary",
                expires_at=utcnow() - timedelta(minutes=1),
            )
        )
        # A permanent exemption must survive the sweep.
        db.add(Exemption(entity_type=EntityType.USER, entity_id="user-akash", reason="permanent"))
        db.commit()

        removed = limits_service.expire_overrides(db)
        db.commit()
        assert removed == 1
        remaining = {e.entity_id for e in db.scalars(select(Exemption))}
        assert remaining == {"user-akash"}

    def test_cycle_expires_overrides(self, tenant: FakeTenant, db: Session) -> None:
        db.add(
            Exemption(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                reason="temporary",
                expires_at=utcnow() - timedelta(minutes=1),
            )
        )
        db.commit()
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.steps.get("override_expiry", {}).get("expired") == 1
        assert db.scalar(select(func.count()).select_from(Exemption)) == 0

    def test_endpoint_creates_and_rejects(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        future = (utcnow() + timedelta(hours=2)).isoformat()
        ok = admin_client.post(
            "/api/exemptions",
            json={
                "entity_type": "user",
                "entity_id": "user-harsh",
                "reason": "x",
                "expires_at": future,
            },
        )
        assert ok.status_code == httpx.codes.CREATED, ok.text
        assert ok.json()["expires_at"] is not None

        past = (utcnow() - timedelta(hours=2)).isoformat()
        bad = admin_client.post(
            "/api/exemptions",
            json={
                "entity_type": "user",
                "entity_id": "user-sean",
                "reason": "x",
                "expires_at": past,
            },
        )
        assert bad.status_code == httpx.codes.BAD_REQUEST
        assert bad.json()["detail"]["code"] == "invalid_override"
