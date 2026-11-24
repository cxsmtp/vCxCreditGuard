"""Policy violations: what was done against a restriction in force.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import AuditLogEntry, EnforcementAction, Notification, PolicyViolation
from app.models.enums import EntityType, PeriodType
from app.models.violations import (
    KIND_AI_SCAN,
    KIND_FUSION_SCAN,
    KIND_SETTING_REENABLED,
    KIND_USAGE_AFTER,
)
from app.services import connection as connection_service
from app.services import (
    cycle,
    enforcement,
    key_permissions,
    limits_service,
    org_sync,
    settings_store,
    violations,
)
from app.services.audit import AuditActor
from tests.conftest import USING_SQLITE, make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
PERIOD = "2026-08"


@pytest.fixture
def tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = fake.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    org_sync.sync_org_model(db, client)
    db.commit()
    key_permissions.discard_pending_denials()
    return fake


def restrict(db: Session, tenant: FakeTenant, *, entity_id: str = "proj-api", actions=None):
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id=entity_id,
            credit_limit=1,
            period_type=PeriodType.MONTHLY,
            enforce=True,
            project_actions=actions or ["auto_triage", "fusion"],
        ),
        actor=ACTOR,
    )
    db.commit()
    enforcement.apply_enforcement(db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()
    return limit


def rows(db: Session, kind: str | None = None) -> list[PolicyViolation]:
    db.expire_all()
    query = select(PolicyViolation).order_by(PolicyViolation.id)
    if kind:
        query = query.where(PolicyViolation.kind == kind)
    return list(db.scalars(query))


def later(minutes: int = 30):
    return utcnow() + timedelta(minutes=minutes)


class TestSettingReenabled:
    def test_reenabled_fusion_and_auto_triage_are_recorded(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        limit = restrict(db, tenant)
        tenant.fusion_setting("proj-api")["value"] = "true"
        tenant.auto_triage["proj-api"]["enabled"] = True
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        found = rows(db, KIND_SETTING_REENABLED)
        assert len(found) == 2
        fusion = next(v for v in found if v.evidence["restriction"] == "disable_fusion")
        assert fusion.evidence["found"]["value"] == "true"
        assert fusion.evidence["reapplied"] is True
        assert fusion.actor is None  # Checkmarx does not say who
        assert fusion.limit_id == limit.id
        assert tenant.fusion_setting("proj-api")["value"] == "false"
        policy = db.scalars(select(Notification).where(Notification.category == "policy")).all()
        assert len(policy) == 2
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "violation.detected")
            )
            == 2
        )

    def test_nothing_recorded_while_it_holds(self, db: Session, tenant: FakeTenant) -> None:
        limit = restrict(db, tenant)
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert rows(db) == []


class TestScans:
    def test_fusion_scan_after_the_restriction_is_recorded_once(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-before",
            initiator="early@example.com",
            completed_at=utcnow() - timedelta(hours=2),
            engines=["sast", "ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
        )
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-fusion",
            initiator="dev@example.com",
            completed_at=later(30),
            engines=["sast", "ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
            source_origin="webapp",
        )
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-last",
            initiator="dev@example.com",
            completed_at=later(40),
            engines=["sast", "ai"],
            ai={"fusionEnabled": "false", "llmModel": "opus-5.5"},
        )
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-plain",
            initiator="dev@example.com",
            completed_at=later(50),
        )
        settings_store.set_value(
            db,
            settings_store.KEY_ACTION_RATES,
            {"rates": list(tenant.action_rates or [])},
        )
        db.commit()
        result = violations.detect(db, tenant.client())
        assert result.errors == []
        fusion = rows(db, KIND_FUSION_SCAN)
        assert [v.evidence["scan_id"] for v in fusion] == ["scan-fusion"]
        assert fusion[0].actor == "dev@example.com"
        assert fusion[0].source == "webapp / github"
        assert fusion[0].evidence["llm_model"] == "opus-5.5"
        assert fusion[0].credits == 2
        ai = rows(db, KIND_AI_SCAN)
        assert [v.evidence["scan_id"] for v in ai] == ["scan-last"]
        assert ai[0].severity == "info"
        # A second run reports nothing again (cursor and dedupe).
        again = violations.detect(db, tenant.client())
        assert again.detected == 0
        assert len(rows(db)) == 2
        cursors = settings_store.get_value(db, settings_store.KEY_VIOLATION_SCAN_CURSORS)
        assert "proj-api" in cursors

    def test_settings_only_in_the_scans_own_read(self, db: Session, tenant: FakeTenant) -> None:
        restrict(db, tenant)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-detail",
            initiator="dev@example.com",
            completed_at=later(30),
            engines=["ai"],
            ai={"fusionEnabled": True, "llmModel": "haiku-4.5"},
            metadata_in_listing=False,
        )
        violations.detect(db, tenant.client())
        found = rows(db, KIND_FUSION_SCAN)
        assert len(found) == 1 and found[0].evidence["llm_model"] == "haiku-4.5"
        assert ("GET", "/api/scans/scan-detail") in tenant.requests

    def test_no_restriction_no_scan_reads(self, db: Session, tenant: FakeTenant) -> None:
        restrict(db, tenant, actions=["auto_triage"])
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-fusion",
            initiator="dev@example.com",
            completed_at=later(30),
            engines=["ai"],
            ai={"fusionEnabled": "true"},
        )
        before = len(tenant.requests)
        violations.detect(db, tenant.client())
        assert not [p for _m, p in tenant.requests[before:] if "/scans" in p]
        assert rows(db) == []

    def test_one_failing_project_does_not_stop_the_others(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant, entity_id="proj-api")
        restrict(db, tenant, entity_id="proj-web")
        for project in ("proj-api", "proj-web"):
            tenant.add_scan(
                project_id=project,
                scan_id=f"scan-{project}",
                initiator="dev@example.com",
                completed_at=later(30),
                engines=["ai"],
                ai={"fusionEnabled": "true"},
            )
        original = tenant.handler

        def failing(request):  # type: ignore[no-untyped-def]
            if "/api/scans" in request.url.path and "proj-api" in str(request.url):
                import httpx

                return httpx.Response(500, json={"message": "boom"})
            return original(request)

        tenant.handler = failing  # type: ignore[method-assign]
        result = violations.detect(db, tenant.client())
        assert len(result.errors) == 1
        assert [v.target_id for v in rows(db, KIND_FUSION_SCAN)] == ["proj-web"]

    def test_no_write_lock_is_held_while_scans_are_read(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        if not USING_SQLITE:
            pytest.skip("SQLite lock probe")
        from tests.test_cycle_transactions import _watch_for_write_locks

        restrict(db, tenant)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-detail",
            initiator="dev@example.com",
            completed_at=later(30),
            engines=["ai"],
            ai={"fusionEnabled": "true"},
            metadata_in_listing=False,
        )
        held = _watch_for_write_locks(tenant)
        violations.detect(db, tenant.client())
        assert held == []
        assert len(rows(db, KIND_FUSION_SCAN)) == 1


class TestUsageAfter:
    def test_rise_after_a_user_restriction_is_recorded_and_kept_up_to_date(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).steps["violations"]
        limits_service.create_limit(
            db,
            data=limits_service.LimitInput(
                entity_type=EntityType.USER,
                entity_id="user-harsh",
                credit_limit=2,
                period_type=PeriodType.LIFETIME,
                enforce=True,
            ),
            actor=ACTOR,
        )
        db.commit()
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        assert db.scalar(select(EnforcementAction)).status == "applied"
        assert rows(db, KIND_USAGE_AFTER) == []
        tenant.set_user_credits(
            name="Harsh Gokani",
            email="harsh.gokani@checkmarx.com",
            credits=6,
            actions={"remediation": 2},
        )
        cycle.run_cycle(trigger="manual")
        found = rows(db, KIND_USAGE_AFTER)
        assert len(found) == 1
        assert found[0].evidence["rise_by_action"] == {"remediation": 1}
        assert found[0].actor == "Harsh Gokani"
        tenant.set_user_credits(
            name="Harsh Gokani",
            email="harsh.gokani@checkmarx.com",
            credits=9,
            actions={"remediation": 3},
        )
        cycle.run_cycle(trigger="manual")
        found = rows(db, KIND_USAGE_AFTER)
        assert len(found) == 1
        assert found[0].evidence["rise_by_action"] == {"remediation": 2}
        assert found[0].updated_at is not None


class TestApi:
    def _one(self, db: Session, tenant: FakeTenant) -> PolicyViolation:
        limit = restrict(db, tenant)
        tenant.fusion_setting("proj-api")["value"] = "true"
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        return rows(db)[0]

    def test_admin_lists_acknowledges_and_resolves(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        violation = self._one(db, tenant)
        listed = admin_client.get("/api/violations")
        assert listed.status_code == 200
        body = listed.json()
        assert body["open"] == 1 and body["total"] == 1
        assert body["items"][0]["kind_label"] == "Setting switched back on"
        assert admin_client.get("/api/me").json()["open_violations"] == 1
        assert admin_client.get("/api/violations", params={"status": "bogus"}).status_code == 400
        assert (
            admin_client.get("/api/violations", params={"kind": KIND_FUSION_SCAN}).json()["total"]
            == 0
        )
        acked = admin_client.post(
            f"/api/violations/{violation.id}/acknowledge", json={"note": "asked the team"}
        )
        assert acked.json()["status"] == "acknowledged"
        assert acked.json()["note"] == "asked the team"
        resolved = admin_client.post(f"/api/violations/{violation.id}/resolve", json={})
        assert resolved.json()["status"] == "resolved"
        assert admin_client.post(f"/api/violations/{violation.id}/resolve").status_code == 409
        db.expire_all()
        audits = [
            entry.action
            for entry in db.scalars(
                select(AuditLogEntry).where(AuditLogEntry.target_type == "policy_violation")
            )
        ]
        assert audits == ["violation.detected", "violation.acknowledged", "violation.resolved"]
        assert admin_client.get("/api/me").json()["open_violations"] == 0

    def test_viewers_see_none(
        self, viewer_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        violation = self._one(db, tenant)
        assert viewer_client.get("/api/violations").status_code == 403
        assert viewer_client.post(f"/api/violations/{violation.id}/resolve").status_code == 403
        assert viewer_client.get("/api/me").json()["open_violations"] is None
