"""Forward projection, impact, and the exportable/emailable report."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditLogEntry
from app.models.enums import EntityType, PeriodType
from app.models.limits import CreditLimit
from app.services import connection as connection_service
from app.services import (
    cycle,
    delivery,
    evaluation,
    ingestion,
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


def _mid_period_burn(db: Session, tenant: FakeTenant) -> CreditLimit:
    """A user that spends steadily through the month, baselined early."""
    client = tenant.client()
    tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=1)
    ingestion.ingest_usage(db, client)
    db.commit()
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-harsh",
        entity_label="Harsh Gokani",
        credit_limit=100,
        period_type=PeriodType.MONTHLY,
        enforce=True,
    )
    db.add(limit)
    db.commit()
    evaluation.evaluate_all(db, client=None, now=AUG_02, actor=ACTOR)  # baseline ~1
    db.commit()
    tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=51)
    ingestion.ingest_usage(db, client)
    db.commit()
    return limit


class TestProjection:
    def test_a_steady_burn_projects_a_breach(self, tenant: FakeTenant, db: Session) -> None:
        self._seed_and_check(db, tenant)

    def _seed_and_check(self, db: Session, tenant: FakeTenant) -> None:
        _mid_period_burn(db, tenant)
        projections = reporting_service.forward_projection(db, now=AUG_16)
        row = next(p for p in projections if p.entity_id == "user-harsh")
        # ~50 credits over ~15 days -> ~3.3/day -> ~103 by end of a 31-day month.
        assert row.credits_used == Decimal("50")
        assert row.burn_per_day > Decimal("3")
        assert row.projected_period_end > Decimal("100")
        assert row.will_breach is True
        assert row.days_to_exhaustion is not None and row.days_to_exhaustion < 20
        assert row.exhaustion_at is not None

    def test_an_idle_limit_is_not_projected(self, tenant: FakeTenant, db: Session) -> None:
        # No usage delta -> nothing to project.
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-akash",
                entity_label="Akash",
                credit_limit=100,
                period_type=PeriodType.MONTHLY,
            )
        )
        db.commit()
        projections = reporting_service.forward_projection(db, now=AUG_16)
        assert all(p.entity_id != "user-akash" for p in projections)


class TestImpact:
    def test_impact_counts_over_budget_on_enforced_limits(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        _mid_period_burn(db, tenant)
        impact = reporting_service.impact_summary(db, now=AUG_16)
        assert impact.enforced_limits >= 1
        # 50 used against a 100 limit: not yet over budget mid-period.
        assert impact.credits_over_budget == Decimal("0")

    def test_over_budget_is_summed(self, tenant: FakeTenant, db: Session) -> None:
        client = tenant.client()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=1)
        ingestion.ingest_usage(db, client)
        db.commit()
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                entity_label="Harsh Gokani",
                credit_limit=10,
                period_type=PeriodType.MONTHLY,
                enforce=True,
            )
        )
        db.commit()
        evaluation.evaluate_all(db, client=None, now=AUG_02, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=35)
        ingestion.ingest_usage(db, client)
        db.commit()
        impact = reporting_service.impact_summary(db, now=AUG_16)
        # 34 used - 10 limit = 24 over budget.
        assert impact.credits_over_budget == Decimal("24")

    def test_an_exempt_entity_is_not_counted_over_budget(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        from app.models.enums import EntityType as ET
        from app.services import limits_service

        client = tenant.client()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=1)
        ingestion.ingest_usage(db, client)
        db.commit()
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                entity_label="Harsh Gokani",
                credit_limit=10,
                period_type=PeriodType.MONTHLY,
                enforce=True,
            )
        )
        db.commit()
        evaluation.evaluate_all(db, client=None, now=AUG_02, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=35)
        ingestion.ingest_usage(db, client)
        db.commit()
        limits_service.add_exemption(
            db, entity_type=ET.USER, entity_id="user-harsh", reason="break glass", actor=ACTOR
        )
        db.commit()
        impact = reporting_service.impact_summary(db, now=AUG_16)
        # Exempt: it will never be restricted, so it is not "held back".
        assert impact.credits_over_budget == Decimal("0")


class TestReportEndpoints:
    def test_summary_endpoint(
        self, admin_client: TestClient, tenant: FakeTenant, db: Session
    ) -> None:
        _mid_period_burn(db, tenant)
        body = admin_client.get("/api/reports/summary").json()
        assert "impact" in body and "projections" in body
        assert body["limits_enforcing"] >= 1

    def test_a_viewer_may_read_the_report(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert viewer_client.get("/api/reports/summary").status_code == httpx.codes.OK

    def test_email_requires_smtp(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        response = admin_client.post("/api/reports/email")
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "email_not_configured"

    def test_email_sends_when_configured(
        self,
        admin_client: TestClient,
        tenant: FakeTenant,
        db: Session,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _configure_smtp(db)
        sent: list[str] = []
        monkeypatch.setattr(
            delivery, "send_report_email", lambda **kwargs: sent.append(kwargs["subject"])
        )
        response = admin_client.post("/api/reports/email")
        assert response.status_code == httpx.codes.OK, response.text
        assert response.json()["sent"] is True
        assert len(sent) == 1


class TestScheduledReport:
    def test_cycle_emails_the_weekly_report_when_enabled_and_due(
        self, tenant: FakeTenant, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_smtp(db)
        settings_store.set_value(db, settings_store.KEY_REPORT_EMAIL_ENABLED, True)
        db.commit()
        sent: list[str] = []
        monkeypatch.setattr(
            delivery, "send_report_email", lambda **kwargs: sent.append(kwargs["subject"])
        )
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.steps.get("report_email", {}).get("sent") is True
        assert len(sent) == 1
        # Audited, so a second cycle the same week does not re-send.
        assert (
            db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "report.emailed"))
            is not None
        )

    def test_cycle_skips_the_report_when_disabled(
        self, tenant: FakeTenant, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_smtp(db)
        sent: list[str] = []
        monkeypatch.setattr(
            delivery, "send_report_email", lambda **kwargs: sent.append(kwargs["subject"])
        )
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert sent == []


def _configure_smtp(db: Session) -> None:
    settings_store.set_value(db, settings_store.KEY_SMTP_HOST, "smtp.example.com")
    settings_store.set_value(db, settings_store.KEY_SMTP_FROM, "cxcg@example.com")
    settings_store.set_value(db, settings_store.KEY_SMTP_RECIPIENTS, "ops@example.com")
    db.commit()
