"""Limits, exemptions, notifications and ops endpoints."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.models import AuditLogEntry, CreditLimit, EnforcementAction
from app.models.enums import EnforcementStatus, EntityType
from app.services import connection as connection_service
from app.services import enforcement, evaluation, ingestion, org_sync
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


class TestLimitCrud:
    def test_admin_creates_a_monitor_only_limit_by_default(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 100},
        )
        assert response.status_code == httpx.codes.CREATED
        body = response.json()
        assert body["enforce"] is False
        assert body["warning_threshold_pct"] == 80
        assert body["entity_label"] == "Harsh Gokani"

    def test_entity_labels_are_resolved_from_the_synced_model(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits",
            json={"entity_type": "application", "entity_id": "app-payments", "credit_limit": 50},
        )
        assert response.json()["entity_label"] == "Payments"

    def test_a_duplicate_limit_is_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        payload = {"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 100}
        admin_client.post("/api/limits", json=payload)
        response = admin_client.post("/api/limits", json=payload)
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert "already exists" in response.json()["detail"]["message"]

    def test_a_custom_period_without_a_start_is_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits",
            json={
                "entity_type": "user",
                "entity_id": "user-harsh",
                "credit_limit": 10,
                "period_type": "custom",
            },
        )
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_member_usage_is_only_valid_for_groups(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits",
            json={
                "entity_type": "user",
                "entity_id": "user-harsh",
                "credit_limit": 10,
                "include_member_usage": True,
            },
        )
        assert response.status_code == httpx.codes.BAD_REQUEST

    def test_thresholds_outside_the_range_are_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        for threshold in (0, 101, -5):
            response = admin_client.post(
                "/api/limits",
                json={
                    "entity_type": "user",
                    "entity_id": f"user-{threshold}",
                    "credit_limit": 10,
                    "warning_threshold_pct": threshold,
                },
            )
            assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_negative_limits_are_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": -1},
        )
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_unknown_fields_are_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits",
            json={
                "entity_type": "user",
                "entity_id": "user-harsh",
                "credit_limit": 10,
                "sneaky": "value",
            },
        )
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_limits_can_be_listed_and_filtered(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        admin_client.post(
            "/api/limits",
            json={"entity_type": "project", "entity_id": "proj-api", "credit_limit": 10},
        )
        assert len(admin_client.get("/api/limits").json()) == 2
        assert len(admin_client.get("/api/limits?entity_type=project").json()) == 1

    def test_a_limit_can_be_updated(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        limit_id = admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        ).json()["id"]
        response = admin_client.patch(
            f"/api/limits/{limit_id}", json={"credit_limit": 25, "enforce": True}
        )
        assert response.status_code == httpx.codes.OK
        assert response.json()["credit_limit"] == 25
        assert response.json()["enforce"] is True

    def test_updates_record_before_and_after(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        limit_id = admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        ).json()["id"]
        admin_client.patch(f"/api/limits/{limit_id}", json={"credit_limit": 40})

        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "limit.updated"))
        assert entry is not None
        assert entry.before["credit_limit"] == 10
        assert entry.after["credit_limit"] == 40

    def test_deleting_a_missing_limit_is_a_404(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert admin_client.delete("/api/limits/9999").status_code == httpx.codes.NOT_FOUND

    def test_viewer_can_read_but_not_write(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert viewer_client.get("/api/limits").status_code == httpx.codes.OK
        response = viewer_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        assert response.status_code == httpx.codes.FORBIDDEN

    def test_authentication_is_required(self, client: TestClient) -> None:
        assert client.get("/api/limits").status_code == httpx.codes.UNAUTHORIZED


class TestLimitStateInResponses:
    def test_current_period_usage_is_reported(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        limit_id = admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-sean", "credit_limit": 10},
        ).json()["id"]

        client = connection_service.get_client(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=13, actions={"triage": 13})
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()

        body = next(
            item for item in admin_client.get("/api/limits").json() if item["id"] == limit_id
        )
        period = body["current_period"]
        assert period is not None
        assert float(period["credits_used"]) == 8.0
        assert period["status"] == "warned"
        assert period["percent_used"] == pytest.approx(80.0)

    def test_only_breached_filter_works(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-sean", "credit_limit": 1},
        )
        client = connection_service.get_client(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=50, actions={"triage": 50})
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()

        assert len(admin_client.get("/api/limits?only_breached=true").json()) == 1


class TestExemptions:
    def test_an_exemption_can_be_added_and_removed(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        created = admin_client.post(
            "/api/exemptions",
            json={"entity_type": "user", "entity_id": "user-harsh", "reason": "on call"},
        )
        assert created.status_code == httpx.codes.CREATED
        assert created.json()["entity_label"] == "Harsh Gokani"

        assert len(admin_client.get("/api/exemptions").json()) == 1
        assert (
            admin_client.delete(f"/api/exemptions/{created.json()['id']}").status_code
            == httpx.codes.OK
        )
        assert admin_client.get("/api/exemptions").json() == []

    def test_adding_an_exemption_lifts_an_active_restriction(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        """An exemption that left someone restricted would be a trap."""
        limit = CreditLimit(
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            entity_label="Harsh Gokani",
            credit_limit=1,
            period_type="monthly",
            enforce=True,
        )
        db.add(limit)
        db.commit()
        client = connection_service.get_client(db)
        enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-08", actor=ACTOR)
        db.commit()
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

        admin_client.post(
            "/api/exemptions", json={"entity_type": "user", "entity_id": "user-harsh"}
        )
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    def test_removing_an_exemption_lets_the_next_cycle_restrict_again(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        """Regression: lifting a restriction for an exemption is not permanent.
        Removing the exemption allows enforcement to restrict again."""
        limit = CreditLimit(
            entity_type=EntityType.PROJECT,
            entity_id="proj-api",
            entity_label="payments/api",
            credit_limit=1,
            period_type="monthly",
            enforce=True,
        )
        db.add(limit)
        db.commit()
        client = connection_service.get_client(db)
        enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-08", actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-api"]["enabled"] is False

        exemption_id = admin_client.post(
            "/api/exemptions",
            json={"entity_type": "project", "entity_id": "proj-api"},
        ).json()["id"]
        db.commit()
        assert tenant.auto_triage["proj-api"]["enabled"] is True

        admin_client.delete(f"/api/exemptions/{exemption_id}")
        db.commit()
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key="2026-08", actor=ACTOR
        )
        db.commit()
        assert outcome.applied
        assert tenant.auto_triage["proj-api"]["enabled"] is False

    def test_viewer_cannot_create_exemptions(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = viewer_client.post(
            "/api/exemptions", json={"entity_type": "user", "entity_id": "user-harsh"}
        )
        assert response.status_code == httpx.codes.FORBIDDEN


class TestNotificationsApi:
    def _restrict(self, db: Session, tenant: FakeTenant) -> EnforcementAction:
        limit = CreditLimit(
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            entity_label="payments/web",
            credit_limit=1,
            period_type="monthly",
            enforce=True,
        )
        db.add(limit)
        db.commit()
        client = connection_service.get_client(db)
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key="2026-08", actor=ACTOR
        )
        db.commit()
        return outcome.applied[0]

    def test_notifications_are_listed_with_an_unread_count(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        self._restrict(db, tenant)
        body = admin_client.get("/api/notifications").json()
        assert body["total"] >= 1
        assert body["unread"] >= 1
        assert body["items"][0]["title"]

    def test_enforcement_notifications_offer_a_restore(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        self._restrict(db, tenant)
        items = admin_client.get("/api/notifications?category=enforcement").json()["items"]
        assert items
        assert items[0]["can_restore"] is True

    def test_restore_reverses_the_change_in_the_tenant(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        action = self._restrict(db, tenant)
        assert tenant.auto_triage["proj-web"]["enabled"] is False

        response = admin_client.post(f"/api/notifications/enforcements/{action.id}/restore")
        assert response.status_code == httpx.codes.OK
        assert response.json()["restored"] is True
        assert tenant.auto_triage["proj-web"]["enabled"] is True

    def test_restoring_twice_reports_nothing_to_do(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        action = self._restrict(db, tenant)
        admin_client.post(f"/api/notifications/enforcements/{action.id}/restore")
        second = admin_client.post(f"/api/notifications/enforcements/{action.id}/restore")
        assert second.json()["restored"] is False

    def test_restore_requires_admin(
        self, viewer_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        action = self._restrict(db, tenant)
        response = viewer_client.post(f"/api/notifications/enforcements/{action.id}/restore")
        assert response.status_code == httpx.codes.FORBIDDEN

    def test_restore_of_an_unknown_action_is_a_404(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post("/api/notifications/enforcements/4242/restore")
        assert response.status_code == httpx.codes.NOT_FOUND

    def test_active_enforcements_are_listed(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        self._restrict(db, tenant)
        rows = admin_client.get("/api/notifications/enforcements").json()
        assert len(rows) == 1
        assert rows[0]["status"] == EnforcementStatus.APPLIED
        assert rows[0]["target_label"] == "payments/web"

    def test_notifications_can_be_marked_read(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        self._restrict(db, tenant)
        assert admin_client.post("/api/notifications/read", json={}).json()["marked_read"] >= 1
        assert admin_client.get("/api/notifications").json()["unread"] == 0

    def test_filters_narrow_the_feed(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        self._restrict(db, tenant)
        assert admin_client.get("/api/notifications?severity=critical").json()["items"]
        assert admin_client.get("/api/notifications?severity=info").json()["items"] == []


class TestOpsApi:
    def test_a_manual_cycle_can_be_run(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        response = admin_client.post("/api/ops/run-cycle?force_org_sync=true")
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["status"] in {"success", "partial"}
        assert body["steps"]["org_sync"]["users"] == 3

    def test_a_manual_cycle_is_audited(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        admin_client.post("/api/ops/run-cycle")
        assert db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "ops.cycle_triggered"))

    def test_org_sync_can_be_triggered(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        response = admin_client.post("/api/ops/sync-org")
        assert response.status_code == httpx.codes.OK
        assert response.json()["steps"]["org_sync"]["users"] == 3

    def test_viewer_cannot_trigger_a_cycle(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert viewer_client.post("/api/ops/run-cycle").status_code == httpx.codes.FORBIDDEN

    def test_status_reports_the_schedule_and_tiles(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        admin_client.post("/api/ops/run-cycle?force_org_sync=true")
        body = admin_client.get("/api/ops/status").json()
        assert body["schedule"] == "every 15 minute(s)"
        assert body["enabled"] is True
        assert body["last_run_status"] in {"success", "partial"}
        assert body["unresolved_subjects"] == 1

    def test_viewer_can_read_status(self, viewer_client: TestClient, tenant: FakeTenant) -> None:
        assert viewer_client.get("/api/ops/status").status_code == httpx.codes.OK
