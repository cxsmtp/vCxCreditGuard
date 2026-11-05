"""Read-only enforcement previews: blast radius and the next-cycle dry run."""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import EntityType, LimitStatus, PeriodType
from app.models.limits import CreditLimit, LimitPeriodState
from app.services import connection as connection_service
from app.services import evaluation, ingestion, org_sync, preview_service
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


def _add_limit(db: Session, **kwargs) -> CreditLimit:
    kwargs.setdefault("period_type", PeriodType.MONTHLY)
    limit = CreditLimit(**kwargs)
    db.add(limit)
    db.commit()
    return limit


class TestBlastRadius:
    def test_a_user_limit_restricts_only_that_user(self, tenant: FakeTenant, db: Session) -> None:
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="user-harsh"
        )
        assert blast.remove_user_roles == 1
        assert blast.affected_users == 1
        assert blast.affected_projects == 0
        assert blast.total_actions == 1

    def test_an_application_limit_fans_out_to_its_projects(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.APPLICATION, entity_id="app-payments"
        )
        # app-payments has proj-api (with a repo) and proj-web (without).
        assert blast.affected_projects == 2
        assert blast.disable_auto_triage == 2
        assert blast.disable_pr_remediation == 1
        assert blast.total_actions == 3

    def test_an_exempt_user_has_an_empty_blast_radius(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        from app.services import limits_service

        limits_service.add_exemption(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            reason="break glass",
            actor=ACTOR,
        )
        db.commit()
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="user-harsh"
        )
        assert blast.exempt is True
        assert blast.total_actions == 0

    def test_the_endpoint_returns_the_blast_radius(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.get(
            "/api/preview/blast-radius",
            params={"entity_type": "application", "entity_id": "app-payments"},
        )
        assert response.status_code == httpx.codes.OK, response.text
        body = response.json()
        assert body["affected_projects"] == 2
        assert body["disable_pr_remediation"] == 1

    def test_a_viewer_may_read_the_blast_radius(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = viewer_client.get(
            "/api/preview/blast-radius",
            params={"entity_type": "user", "entity_id": "user-harsh"},
        )
        assert response.status_code == httpx.codes.OK

    def test_an_unknown_entity_type_is_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.get(
            "/api/preview/blast-radius",
            params={"entity_type": "nonsense", "entity_id": "x"},
        )
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY


class TestDryRun:
    def _breaching_user_limit(
        self, db: Session, tenant: FakeTenant, *, enforce: bool
    ) -> CreditLimit:
        client = tenant.client()
        # Baseline at a low reading so the delta, not history, drives the breach.
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=1)
        ingestion.ingest_usage(db, client)
        db.commit()
        limit = _add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            entity_label="Harsh Gokani",
            credit_limit=5,
            enforce=enforce,
        )
        evaluation.evaluate_all(db, client=None, actor=ACTOR)  # baseline only, no enforcement
        db.commit()
        # Now blow past the limit.
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()
        return limit

    def test_a_limit_within_budget_is_not_flagged(
        self, admin_client: TestClient, tenant: FakeTenant, db: Session
    ) -> None:
        _add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            entity_label="Harsh Gokani",
            credit_limit=1_000_000,
            enforce=True,
        )
        body = admin_client.get("/api/preview/dry-run").json()
        row = next(r for r in body["rows"] if r["entity_id"] == "user-harsh")
        assert row["would_enforce"] is False
        assert row["projected_status"] in {"ok", "warned"}

    def test_a_breaching_enforced_limit_would_enforce_with_a_blast_radius(
        self, admin_client: TestClient, tenant: FakeTenant, db: Session
    ) -> None:
        self._breaching_user_limit(db, tenant, enforce=True)
        body = admin_client.get("/api/preview/dry-run").json()
        assert body["would_enforce_count"] >= 1
        assert body["affected_users"] >= 1
        row = next(r for r in body["rows"] if r["entity_id"] == "user-harsh")
        assert row["projected_status"] == "breached"
        assert row["would_enforce"] is True
        assert row["blast"]["remove_user_roles"] == 1

    def test_a_breaching_monitor_only_limit_would_not_enforce(
        self, admin_client: TestClient, tenant: FakeTenant, db: Session
    ) -> None:
        self._breaching_user_limit(db, tenant, enforce=False)
        body = admin_client.get("/api/preview/dry-run").json()
        row = next(r for r in body["rows"] if r["entity_id"] == "user-harsh")
        assert row["projected_status"] == "breached"
        assert row["would_enforce"] is False
        assert row["blast"] is None
        assert "monitor only" in (row["note"] or "")

    def test_the_dry_run_stages_no_inserts_or_mutations(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        # Run the service directly on the fixture session so the ORM unit-of-work
        # is visible: this proves no entity was mutated or inserted, which a
        # commit/expire check (with autoflush off) cannot.
        limit = self._breaching_user_limit(db, tenant, enforce=True)
        status_before = db.scalar(
            select(LimitPeriodState.status).where(LimitPeriodState.limit_id == limit.id)
        )

        db.flush()  # clear any pending work from setup
        result = preview_service.dry_run(db)

        assert not db.new, f"dry_run staged inserts: {db.new}"
        assert not db.dirty, f"dry_run mutated entities: {db.dirty}"
        assert not db.deleted, f"dry_run staged deletes: {db.deleted}"
        # Sanity: the projection still saw the breach even though it wrote nothing.
        assert status_before == LimitStatus.OK
        row = next(r for r in result.rows if r.entity_id == "user-harsh")
        assert row.projected_status == LimitStatus.BREACHED
        assert row.would_enforce is True

    def test_a_brand_new_lifetime_limit_is_projected_against_full_usage(
        self, tenant: FakeTenant, db: Session
    ) -> None:
        # A lifetime (or count_existing) limit baselines to 0 on its first cycle,
        # so the preview must count the whole reported total - not assume zero -
        # or it would claim an over-budget limit is fine right up until it bites.
        client = tenant.client()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=40)
        ingestion.ingest_usage(db, client)
        db.commit()
        _add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            entity_label="Harsh Gokani",
            credit_limit=5,
            enforce=True,
            period_type=PeriodType.LIFETIME,
        )
        # No evaluation has run, so there is no LimitPeriodState yet.
        assert db.scalar(select(func.count()).select_from(LimitPeriodState)) == 0
        result = preview_service.dry_run(db)
        row = next(r for r in result.rows if r.entity_id == "user-harsh")
        assert row.projected_status == LimitStatus.BREACHED
        assert row.would_enforce is True
        assert row.credits_used == Decimal("40")
