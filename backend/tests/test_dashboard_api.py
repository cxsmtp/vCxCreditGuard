"""Dashboard, entity search, audit, settings, bulk edit and CSV endpoints."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLogEntry, CreditLimit
from app.models.enums import EntityType
from app.services import connection as connection_service
from app.services import evaluation, ingestion, limits_csv, org_sync
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


class TestMe:
    def test_reports_identity_and_setup_state(self, admin_client: TestClient) -> None:
        body = admin_client.get("/api/me").json()
        assert body["username"] == "admin"
        assert body["role"] == "admin"
        assert body["connection_configured"] is False
        assert body["setup_required"] is True

    def test_setup_is_not_required_once_connected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        body = admin_client.get("/api/me").json()
        assert body["setup_required"] is False
        assert body["tenant_name"] == "acme-corp"

    def test_requires_authentication(self, client: TestClient) -> None:
        assert client.get("/api/me").status_code == httpx.codes.UNAUTHORIZED


class TestDashboard:
    def test_empty_tenant_reports_null_rather_than_zero(self, admin_client: TestClient) -> None:
        """No snapshot must not look identical to no consumption."""
        body = admin_client.get("/api/dashboard").json()
        assert body["tenant_total_credits"] is None
        assert body["collected_at"] is None
        assert body["top_users"] == []

    def test_totals_and_breakdown(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        body = admin_client.get("/api/dashboard").json()
        assert float(body["tenant_total_credits"]) == 15.0
        actions = {item["action_type"]: item for item in body["breakdown"]}
        assert set(actions) == {"triage", "remediation"}
        assert float(actions["triage"]["credits"]) == 9.0

    def test_top_consumers_per_dimension(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        body = admin_client.get("/api/dashboard").json()
        assert [item["label"] for item in body["top_users"]][0] == "departed.person@checkmarx.com"
        assert float(body["top_users"][0]["credits"]) == 7.0
        assert {item["label"] for item in body["top_projects"]} == {
            "payments/api",
            "payments/web",
            "platform/tools",
        }
        assert [item["label"] for item in body["top_applications"]] == ["Payments"]

    def test_unresolved_consumers_are_flagged_not_hidden(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        body = admin_client.get("/api/dashboard").json()
        departed = next(
            item for item in body["top_users"] if item["label"] == "departed.person@checkmarx.com"
        )
        assert departed["resolved"] is False
        assert departed["entity_id"] is None

    def test_groups_are_rolled_up_from_projects(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        body = admin_client.get("/api/dashboard").json()
        groups = {item["label"]: float(item["credits"]) for item in body["top_groups"]}
        assert groups["Payments"] == 12.0
        assert groups["AA-Platform"] == 2.0

    def test_limits_are_annotated_onto_consumers(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "project", "entity_id": "proj-api", "credit_limit": 40},
        )
        client = connection_service.get_client(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()

        body = admin_client.get("/api/dashboard").json()
        project = next(item for item in body["top_projects"] if item["entity_id"] == "proj-api")
        assert project["limit"] == 40
        assert project["status"] == "ok"

    def test_trend_reports_deltas_between_polls(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        client = connection_service.get_client(db)
        tenant.consumption["action"][0]["creditsUsed"] = 20
        ingestion.ingest_usage(db, client)
        db.commit()

        trend = admin_client.get("/api/dashboard").json()["trend"]
        assert len(trend) == 2
        assert trend[0]["delta_credits"] is None
        assert float(trend[1]["delta_credits"]) == 11.0

    def test_tiles_summarise_state(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        tiles = admin_client.get("/api/dashboard").json()["tiles"]
        assert tiles["unresolved_subjects"] == 1
        assert tiles["schedule"] == "every 15 minute(s)"
        assert tiles["limits_configured"] == 0

    def test_unavailable_dimensions_are_surfaced(
        self, db: Session, admin_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = populated_tenant()
        fake.unsupported_views.add("project")
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        client = fake.client()
        org_sync.sync_org_model(db, client)
        ingestion.ingest_usage(db, client)
        db.commit()

        body = admin_client.get("/api/dashboard").json()
        assert "project" in body["unavailable_dimensions"]

    def test_viewer_can_read_the_dashboard(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert viewer_client.get("/api/dashboard").status_code == httpx.codes.OK


class TestEntitySearch:
    def test_lists_users_with_secondary_detail(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        rows = admin_client.get("/api/org/entities?entity_type=user").json()
        assert len(rows) == 3
        harsh = next(row for row in rows if row["entity_id"] == "user-harsh")
        assert harsh["label"] == "Harsh Gokani"
        assert harsh["secondary"] == "harsh.gokani@checkmarx.com"

    def test_search_matches_name_and_email(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert len(admin_client.get("/api/org/entities?entity_type=user&q=gokani").json()) == 1
        assert len(admin_client.get("/api/org/entities?entity_type=user&q=Sean").json()) == 1

    def test_search_matches_project_names(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        rows = admin_client.get("/api/org/entities?entity_type=project&q=payments").json()
        assert {row["label"] for row in rows} == {"payments/api", "payments/web"}

    def test_existing_limits_and_exemptions_are_flagged(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        admin_client.post("/api/exemptions", json={"entity_type": "user", "entity_id": "user-sean"})
        rows = {
            row["entity_id"]: row
            for row in admin_client.get("/api/org/entities?entity_type=user").json()
        }
        assert rows["user-harsh"]["has_limit"] is True
        assert rows["user-sean"]["is_exempt"] is True
        assert rows["user-akash"]["has_limit"] is False

    def test_deleted_entities_are_hidden_by_default(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.projects = [row for row in tenant.projects if row["id"] != "proj-web"]
        org_sync.sync_org_model(db, tenant.client())
        db.commit()

        assert len(admin_client.get("/api/org/entities?entity_type=project").json()) == 2
        assert (
            len(
                admin_client.get(
                    "/api/org/entities?entity_type=project&include_deleted=true"
                ).json()
            )
            == 3
        )

    def test_groups_report_their_path(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        rows = admin_client.get("/api/org/entities?entity_type=group").json()
        assert next(row for row in rows if row["label"] == "Payments")["secondary"] == "/Payments"


class TestAuditApi:
    def test_lists_entries_newest_first(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        body = admin_client.get("/api/audit").json()
        assert body["total"] >= 2
        assert body["items"][0]["action"] == "limit.created"
        assert "org.synced" in body["actions"]

    def test_filters_by_action(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        body = admin_client.get("/api/audit?action=limit.created").json()
        assert body["total"] == 1
        assert body["items"][0]["after"]["credit_limit"] == 10

    def test_free_text_search(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        assert admin_client.get("/api/audit?q=Harsh").json()["total"] >= 1

    def test_pagination(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        first = admin_client.get("/api/audit?limit=1&offset=0").json()
        second = admin_client.get("/api/audit?limit=1&offset=1").json()
        assert first["items"][0]["id"] != second["items"][0]["id"]

    def test_viewer_can_read_the_audit_log(
        self, viewer_client: TestClient, tenant: FakeTenant
    ) -> None:
        assert viewer_client.get("/api/audit").status_code == httpx.codes.OK


class TestUnresolvedSubjects:
    def test_they_are_listed(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        rows = admin_client.get("/api/usage/unresolved").json()
        assert len(rows) == 1
        assert rows[0]["subject_key"] == "departed.person@checkmarx.com"
        assert float(rows[0]["credits_used"]) == 7.0

    def test_mapping_attributes_future_usage(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        subject_id = admin_client.get("/api/usage/unresolved").json()[0]["id"]
        response = admin_client.post(
            f"/api/usage/unresolved/{subject_id}/map", json={"user_id": "user-akash"}
        )
        assert response.status_code == httpx.codes.OK
        assert response.json()["mapped_user_label"] == "Akash Singh"

        client = connection_service.get_client(db)
        ingestion.ingest_usage(db, client)
        db.commit()
        from app.models.enums import UsageView

        assert float(ingestion.latest_totals(db, UsageView.USER)["user-akash"]) == 7.0

    def test_mapping_attributes_immediately(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        """The latest snapshot is re-pointed on the spot, without a fresh cycle."""
        subject_id = admin_client.get("/api/usage/unresolved").json()[0]["id"]
        body = admin_client.post(
            f"/api/usage/unresolved/{subject_id}/map", json={"user_id": "user-akash"}
        ).json()
        # The response reflects the new attribution for the GUI to render at once.
        assert body["counts_towards_user_id"] == "user-akash"
        assert body["counts_towards_label"] == "Akash Singh"

        from app.models.enums import UsageView

        # No new ingest has run, yet the credits already count towards the user.
        assert float(ingestion.latest_totals(db, UsageView.USER)["user-akash"]) == 7.0

    def test_clearing_a_mapping_reverts_the_snapshot(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        subject_id = admin_client.get("/api/usage/unresolved").json()[0]["id"]
        admin_client.post(f"/api/usage/unresolved/{subject_id}/map", json={"user_id": "user-akash"})
        admin_client.post(f"/api/usage/unresolved/{subject_id}/map", json={"user_id": None})

        from app.models.enums import UsageView

        assert "user-akash" not in ingestion.latest_totals(db, UsageView.USER)

    def test_mapping_is_audited(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        subject_id = admin_client.get("/api/usage/unresolved").json()[0]["id"]
        admin_client.post(f"/api/usage/unresolved/{subject_id}/map", json={"user_id": "user-akash"})
        assert db.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "usage.subject_mapped")
        )

    def test_mapping_to_an_unknown_user_is_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        subject_id = admin_client.get("/api/usage/unresolved").json()[0]["id"]
        response = admin_client.post(
            f"/api/usage/unresolved/{subject_id}/map", json={"user_id": "nobody"}
        )
        assert response.status_code == httpx.codes.BAD_REQUEST

    def test_mapping_can_be_cleared(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        subject_id = admin_client.get("/api/usage/unresolved").json()[0]["id"]
        admin_client.post(f"/api/usage/unresolved/{subject_id}/map", json={"user_id": "user-akash"})
        response = admin_client.post(
            f"/api/usage/unresolved/{subject_id}/map", json={"user_id": None}
        )
        assert response.json()["mapped_user_id"] is None

    def test_viewer_cannot_map(self, viewer_client: TestClient, tenant: FakeTenant) -> None:
        rows = viewer_client.get("/api/usage/unresolved").json()
        response = viewer_client.post(
            f"/api/usage/unresolved/{rows[0]['id']}/map", json={"user_id": "user-akash"}
        )
        assert response.status_code == httpx.codes.FORBIDDEN


class TestSettingsApi:
    def test_defaults_are_reported(self, admin_client: TestClient) -> None:
        body = admin_client.get("/api/settings").json()
        assert body["schedule_interval_minutes"] == 15
        assert body["scheduler_enabled"] is True
        assert body["usage_period_param"] == "last_year"
        assert body["allowed_interval_minutes"] == [2, 5, 15, 60]

    def test_interval_can_be_changed(self, admin_client: TestClient) -> None:
        response = admin_client.put("/api/settings", json={"schedule_interval_minutes": 5})
        assert response.status_code == httpx.codes.OK
        assert response.json()["schedule_interval_minutes"] == 5
        assert response.json()["current_schedule_description"] == "every 5 minute(s)"

    def test_cron_mode_requires_an_expression(self, admin_client: TestClient) -> None:
        response = admin_client.put("/api/settings", json={"schedule_mode": "cron"})
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "cron_required"

    def test_a_valid_cron_is_accepted(self, admin_client: TestClient) -> None:
        response = admin_client.put(
            "/api/settings", json={"schedule_mode": "cron", "schedule_cron": "*/10 * * * *"}
        )
        assert response.status_code == httpx.codes.OK
        assert "cron */10 * * * *" in response.json()["current_schedule_description"]

    def test_an_invalid_cron_is_rejected(self, admin_client: TestClient) -> None:
        response = admin_client.put(
            "/api/settings", json={"schedule_mode": "cron", "schedule_cron": "nonsense"}
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "invalid_cron"

    def test_secrets_are_write_only(self, admin_client: TestClient) -> None:
        admin_client.put("/api/settings", json={"smtp_password": "hunter2-and-more"})
        body = admin_client.get("/api/settings").json()
        assert body["smtp_password_configured"] is True
        assert "hunter2-and-more" not in admin_client.get("/api/settings").text

    def test_secrets_are_encrypted_at_rest(self, admin_client: TestClient, db: Session) -> None:
        admin_client.put("/api/settings", json={"smtp_password": "hunter2-and-more"})
        from app.models.connection import AppSetting
        from app.services import settings_store

        row = db.get(AppSetting, settings_store.KEY_SMTP_PASSWORD)
        assert row is not None
        assert row.value is not None
        assert "hunter2-and-more" not in row.value
        assert settings_store.get_secret(db, settings_store.KEY_SMTP_PASSWORD) == "hunter2-and-more"

    def test_secrets_are_not_written_to_the_audit_log(
        self, admin_client: TestClient, db: Session
    ) -> None:
        admin_client.put("/api/settings", json={"smtp_password": "hunter2-and-more"})
        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "settings.updated"))
        assert entry is not None
        assert "hunter2-and-more" not in repr(entry.after)
        assert entry.after["smtp_password"] == "[REDACTED]"

    def test_a_secret_can_be_cleared(self, admin_client: TestClient) -> None:
        admin_client.put("/api/settings", json={"smtp_password": "hunter2-and-more"})
        admin_client.put("/api/settings", json={"smtp_password": ""})
        assert admin_client.get("/api/settings").json()["smtp_password_configured"] is False

    def test_a_plaintext_webhook_to_a_remote_host_is_rejected(
        self, admin_client: TestClient
    ) -> None:
        response = admin_client.put("/api/settings", json={"webhook_url": "ftp://nope"})
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_viewer_cannot_change_settings(self, viewer_client: TestClient) -> None:
        assert (
            viewer_client.put("/api/settings", json={"schedule_interval_minutes": 5}).status_code
            == httpx.codes.FORBIDDEN
        )

    def test_viewer_can_read_settings(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/settings").status_code == httpx.codes.OK

    def test_settings_changes_are_audited(self, admin_client: TestClient, db: Session) -> None:
        admin_client.put("/api/settings", json={"retention_days": 90})
        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "settings.updated"))
        assert entry is not None
        assert entry.before["retention_days"] == 365
        assert entry.after["retention_days"] == 90


class TestBulkEdit:
    def _two_limits(self, admin_client: TestClient) -> list[int]:
        first = admin_client.post(
            "/api/limits",
            json={"entity_type": "project", "entity_id": "proj-api", "credit_limit": 10},
        ).json()["id"]
        second = admin_client.post(
            "/api/limits",
            json={"entity_type": "project", "entity_id": "proj-web", "credit_limit": 10},
        ).json()["id"]
        return [first, second]

    def test_applies_one_change_to_many_limits(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        ids = self._two_limits(admin_client)
        response = admin_client.post(
            "/api/limits/bulk", json={"limit_ids": ids, "credit_limit": 99, "enforce": True}
        )
        assert response.status_code == httpx.codes.OK
        assert response.json()["updated"] == 2
        assert all(item["credit_limit"] == 99 for item in admin_client.get("/api/limits").json())

    def test_bulk_disabling_enforcement_lifts_restrictions(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        ids = self._two_limits(admin_client)
        admin_client.post("/api/limits/bulk", json={"limit_ids": ids, "enforce": True})
        client = connection_service.get_client(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()
        tenant.set_entity_credits(
            view="project", name="payments/web", credits=999, entity_id="proj-web"
        )
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is False

        response = admin_client.post("/api/limits/bulk", json={"limit_ids": ids, "enforce": False})
        assert response.json()["restrictions_lifted"] == 2
        assert tenant.auto_triage["proj-web"]["enabled"] is True

    def test_missing_limits_are_reported_not_fatal(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        ids = self._two_limits(admin_client)
        response = admin_client.post(
            "/api/limits/bulk", json={"limit_ids": [*ids, 9999], "credit_limit": 5}
        )
        assert response.json()["updated"] == 2
        assert response.json()["errors"]

    def test_viewer_cannot_bulk_edit(self, viewer_client: TestClient, tenant: FakeTenant) -> None:
        response = viewer_client.post(
            "/api/limits/bulk", json={"limit_ids": [1], "credit_limit": 5}
        )
        assert response.status_code == httpx.codes.FORBIDDEN


class TestCsv:
    def test_export_has_a_header_and_a_row_per_limit(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        response = admin_client.get("/api/limits/export")
        assert response.status_code == httpx.codes.OK
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers["content-disposition"]
        lines = response.text.strip().splitlines()
        assert lines[0].startswith("entity_type,entity_id")
        assert "user-harsh" in lines[1]

    def test_a_round_trip_import_is_a_no_op_update(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        admin_client.post(
            "/api/limits",
            json={"entity_type": "user", "entity_id": "user-harsh", "credit_limit": 10},
        )
        exported = admin_client.get("/api/limits/export").text
        response = admin_client.post(
            "/api/limits/import?dry_run=true",
            files={"file": ("limits.csv", exported, "text/csv")},
        )
        assert response.status_code == httpx.codes.OK
        assert response.json() == {
            "created": 0,
            "updated": 1,
            "skipped": 0,
            "errors": [],
            "dry_run": True,
        }

    def test_dry_run_writes_nothing(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        csv_content = "entity_type,entity_id,credit_limit\nuser,user-harsh,50\n"
        response = admin_client.post(
            "/api/limits/import?dry_run=true",
            files={"file": ("limits.csv", csv_content, "text/csv")},
        )
        assert response.json()["created"] == 1
        assert db.scalar(select(CreditLimit)) is None

    def test_applying_an_import_creates_limits(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        csv_content = (
            "entity_type,entity_id,credit_limit,period_type,warning_threshold_pct,enforce\n"
            "user,user-harsh,50,monthly,70,true\n"
            "project,proj-api,80,quarterly,90,false\n"
        )
        response = admin_client.post(
            "/api/limits/import?dry_run=false",
            files={"file": ("limits.csv", csv_content, "text/csv")},
        )
        assert response.json()["created"] == 2
        limits = {row["entity_id"]: row for row in admin_client.get("/api/limits").json()}
        assert limits["user-harsh"]["credit_limit"] == 50
        assert limits["user-harsh"]["warning_threshold_pct"] == 70
        assert limits["user-harsh"]["enforce"] is True
        assert limits["proj-api"]["period_type"] == "quarterly"

    def test_an_absent_enforce_column_means_monitor_only(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        """An import must not be able to switch on enforcement by omission."""
        csv_content = "entity_type,entity_id,credit_limit\nuser,user-harsh,50\n"
        admin_client.post(
            "/api/limits/import?dry_run=false",
            files={"file": ("limits.csv", csv_content, "text/csv")},
        )
        assert admin_client.get("/api/limits").json()[0]["enforce"] is False

    def test_a_bad_row_rejects_the_whole_file(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        csv_content = (
            "entity_type,entity_id,credit_limit\nuser,user-harsh,50\nuser,user-does-not-exist,10\n"
        )
        response = admin_client.post(
            "/api/limits/import?dry_run=false",
            files={"file": ("limits.csv", csv_content, "text/csv")},
        )
        body = response.json()
        assert body["errors"]
        assert body["created"] == 0
        assert db.scalar(select(CreditLimit)) is None

    def test_missing_columns_are_reported(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits/import",
            files={"file": ("limits.csv", "entity_type,entity_id\nuser,user-harsh\n", "text/csv")},
        )
        assert "credit_limit" in response.json()["errors"][0]

    def test_duplicate_rows_are_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        csv_content = "entity_type,entity_id,credit_limit\nuser,user-harsh,10\nuser,user-harsh,20\n"
        response = admin_client.post(
            "/api/limits/import", files={"file": ("limits.csv", csv_content, "text/csv")}
        )
        assert any("duplicate" in error for error in response.json()["errors"])

    def test_invalid_entity_type_is_reported_with_the_value(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits/import",
            files={
                "file": (
                    "limits.csv",
                    "entity_type,entity_id,credit_limit\nteam,x,10\n",
                    "text/csv",
                )
            },
        )
        assert "'team'" in response.json()["errors"][0]

    def test_a_non_utf8_file_is_rejected(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        response = admin_client.post(
            "/api/limits/import",
            files={"file": ("limits.csv", b"\xff\xfe\x00bad", "text/csv")},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "not_utf8"

    def test_a_utf8_bom_is_tolerated(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        """Excel writes a BOM, and admins export limits from Excel."""
        content = "﻿entity_type,entity_id,credit_limit\nuser,user-harsh,10\n".encode()
        response = admin_client.post(
            "/api/limits/import", files={"file": ("limits.csv", content, "text/csv")}
        )
        assert response.json()["errors"] == []
        assert response.json()["created"] == 1

    def test_viewer_cannot_import(self, viewer_client: TestClient, tenant: FakeTenant) -> None:
        response = viewer_client.post(
            "/api/limits/import",
            files={"file": ("limits.csv", "entity_type,entity_id,credit_limit\n", "text/csv")},
        )
        assert response.status_code == httpx.codes.FORBIDDEN

    def test_viewer_can_export(self, viewer_client: TestClient, tenant: FakeTenant) -> None:
        assert viewer_client.get("/api/limits/export").status_code == httpx.codes.OK


class TestCsvService:
    def test_custom_periods_round_trip(self, db: Session, tenant: FakeTenant) -> None:
        content = (
            "entity_type,entity_id,credit_limit,period_type,custom_period_start,custom_period_end\n"
            "user,user-harsh,10,custom,2026-01-01T00:00:00Z,2026-06-30T00:00:00Z\n"
        )
        result = limits_csv.import_limits(db, content=content, actor=ACTOR, dry_run=False)
        db.commit()
        assert result.errors == []
        limit = db.scalar(select(CreditLimit))
        assert limit is not None
        assert limit.custom_period_start is not None
        assert limit.custom_period_start.year == 2026

    def test_a_custom_period_without_a_start_is_an_error(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        content = "entity_type,entity_id,credit_limit,period_type\nuser,user-harsh,10,custom\n"
        result = limits_csv.import_limits(db, content=content, actor=ACTOR)
        assert any("custom_period_start" in error for error in result.errors)

    def test_member_usage_on_a_non_group_is_an_error(self, db: Session, tenant: FakeTenant) -> None:
        content = (
            "entity_type,entity_id,credit_limit,include_member_usage\nuser,user-harsh,10,true\n"
        )
        result = limits_csv.import_limits(db, content=content, actor=ACTOR)
        assert any("group limits" in error for error in result.errors)

    def test_row_outcomes_describe_what_would_happen(self, db: Session, tenant: FakeTenant) -> None:
        content = "entity_type,entity_id,credit_limit,enforce\nuser,user-harsh,10,true\n"
        result = limits_csv.import_limits(db, content=content, actor=ACTOR)
        assert result.rows[0].action == "create"
        assert "enforcing" in (result.rows[0].detail or "")

    def test_blank_rows_are_ignored(self, db: Session, tenant: FakeTenant) -> None:
        content = "entity_type,entity_id,credit_limit\n\nuser,user-harsh,10\n\n"
        result = limits_csv.import_limits(db, content=content, actor=ACTOR)
        assert result.errors == []
        assert result.created == 1

    @pytest.mark.parametrize("value", ["true", "TRUE", "yes", "1", "on"])
    def test_truthy_spellings(self, db: Session, tenant: FakeTenant, value: str) -> None:
        content = f"entity_type,entity_id,credit_limit,enforce\nuser,user-harsh,10,{value}\n"
        result = limits_csv.import_limits(db, content=content, actor=ACTOR)
        assert result.errors == []
        assert "enforcing" in (result.rows[0].detail or "")

    def test_a_nonsense_boolean_is_an_error(self, db: Session, tenant: FakeTenant) -> None:
        content = "entity_type,entity_id,credit_limit,enforce\nuser,user-harsh,10,maybe\n"
        result = limits_csv.import_limits(db, content=content, actor=ACTOR)
        assert any("maybe" in error for error in result.errors)

    def test_export_includes_usage_context(self, db: Session, tenant: FakeTenant) -> None:
        limit = CreditLimit(
            entity_type=EntityType.USER,
            entity_id="user-sean",
            entity_label="Sean Casey",
            credit_limit=10,
            period_type="monthly",
        )
        db.add(limit)
        db.commit()
        client = connection_service.get_client(db)
        evaluation.evaluate_all(db, client=client, actor=ACTOR)
        db.commit()

        content = limits_csv.export_limits(db)
        assert "credits_used,period_key,status" in content.splitlines()[0]
        assert "user-sean" in content
