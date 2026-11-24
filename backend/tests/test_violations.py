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
        # Announced in the enforcement category, as a re-applied restriction
        # always was (e-mail and webhook consumers that follow it still get it).
        drift = db.scalars(
            select(Notification).where(Notification.body.like("%Policy violations page%"))
        ).all()
        assert sorted(n.category for n in drift) == ["enforcement", "enforcement"]
        assert _count(db, Notification, Notification.category == "policy") == 0
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
        assert len(ai) == 1
        assert ai[0].evidence["scan_ids"] == ["scan-last"]
        assert ai[0].evidence["without_fusion"] == 1
        assert ai[0].severity == "info"
        # A second run reports nothing again (cursor and dedupe).
        again = violations.detect(db, tenant.client())
        assert again.detected == 0
        assert len(rows(db)) == 2
        assert rows(db, KIND_AI_SCAN)[0].evidence["scans"] == 1
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


# --------------------------------------------------------- review follow-ups


def _count(db: Session, model, *conditions) -> int:  # type: ignore[no-untyped-def]
    db.expire_all()
    return int(db.scalar(select(func.count()).select_from(model).where(*conditions)) or 0)


class TestOneEventOneAlert:
    def test_switched_back_on_every_cycle_is_one_row_a_day(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        limit = restrict(db, tenant, actions=["fusion"])
        for _ in range(3):
            tenant.fusion_setting("proj-api")["value"] = "true"
            tenant.repo_fusion["repo-1"]["enabled"] = True
            enforcement.apply_enforcement(
                db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
            )
            db.commit()
        found = rows(db, KIND_SETTING_REENABLED)
        # One per restriction (project half, repository half), not one per cycle.
        assert sorted(v.evidence["restriction"] for v in found) == [
            "disable_fusion",
            "disable_repo_fusion",
        ]
        # Fusion back on is one event: one notification, in the enforcement
        # category, pointing at the violation.
        assert _count(db, Notification, Notification.category == "policy") == 0
        assert (
            _count(
                db,
                Notification,
                Notification.category == "enforcement",
                Notification.title.like("%turned off again%"),
            )
            == 1
        )
        # Every re-assert is still in the audit log.
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "enforcement.reconciled") == 6


class TestScansFollowUp:
    def test_viewer_sees_no_scan_initiator_in_notifications_or_audit(
        self, viewer_client: TestClient, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="s1",
            initiator="secret.person@example.com",
            completed_at=later(30),
            engines=["ai"],
            ai={"fusionEnabled": "true"},
        )
        violations.detect(db, tenant.client())
        notes = viewer_client.get("/api/notifications")
        audit = viewer_client.get("/api/audit", params={"action": "violation.detected"})
        assert notes.status_code == 200 and audit.status_code == 200
        assert "s1" in notes.text  # the notification is there ...
        assert "secret.person@example.com" not in notes.text  # ... without the person
        assert "secret.person@example.com" not in audit.text
        # Admins still see who on the violation itself.
        listed = admin_client.get("/api/violations", params={"kind": KIND_FUSION_SCAN}).json()
        assert listed["items"][0]["actor"] == "secret.person@example.com"

    def test_ai_scans_without_fusion_are_counted_quietly(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant)
        for index, fusion in enumerate(("false", "false", None)):
            tenant.add_scan(
                project_id="proj-api",
                scan_id=f"ai-{index}",
                initiator="dev@example.com",
                completed_at=later(30 + index),
                engines=["ai"],
                ai={"llmModel": "opus-5.5", **({"fusionEnabled": fusion} if fusion else {})},
            )
        violations.detect(db, tenant.client())
        violations.detect(db, tenant.client())
        found = rows(db, KIND_AI_SCAN)
        assert len(found) == 1
        assert found[0].severity == "info"
        assert found[0].evidence["scans"] == 3
        assert found[0].evidence["without_fusion"] == 2
        assert found[0].evidence["not_said"] == 1
        assert found[0].actor is None
        assert _count(db, Notification, Notification.category == "policy") == 0
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "violation.detected") == 0

    def test_a_scan_not_classified_this_cycle_is_left_for_the_next(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        restrict(db, tenant)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-detail",
            initiator="dev@example.com",
            completed_at=later(30),
            engines=["ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
            metadata_in_listing=False,
        )
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-newer",
            initiator="dev@example.com",
            completed_at=later(60),
            engines=["ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
        )
        monkeypatch.setattr(violations, "MAX_SCAN_READS_PER_CYCLE", 0)
        violations.detect(db, tenant.client())
        assert [v.evidence["scan_id"] for v in rows(db, KIND_FUSION_SCAN)] == ["scan-newer"]
        assert rows(db, KIND_AI_SCAN) == []
        monkeypatch.setattr(violations, "MAX_SCAN_READS_PER_CYCLE", 50)
        violations.detect(db, tenant.client())
        violations.detect(db, tenant.client())
        assert sorted(v.evidence["scan_id"] for v in rows(db, KIND_FUSION_SCAN)) == [
            "scan-detail",
            "scan-newer",
        ]
        assert rows(db, KIND_AI_SCAN) == []

    def test_only_scans_that_ran_are_recorded_and_priced(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant)
        settings_store.set_value(
            db, settings_store.KEY_ACTION_RATES, {"rates": list(tenant.action_rates or [])}
        )
        db.commit()
        fusion = {"fusionEnabled": "true", "llmModel": "opus-5.5"}
        for scan_id, status in (
            ("queued", "Queued"),
            ("failed", "Failed"),
            ("canceled", "Canceled"),
        ):
            tenant.add_scan(
                project_id="proj-api",
                scan_id=scan_id,
                status=status,
                initiator="dev@example.com",
                completed_at=later(30),
                engines=["ai"],
                ai=fusion,
            )
        violations.detect(db, tenant.client())
        assert rows(db) == []
        # The queued one completes: recorded then, once, and priced.
        queued = tenant.scans["proj-api"][0]
        queued["status"] = "Completed"
        violations.detect(db, tenant.client())
        found = rows(db, KIND_FUSION_SCAN)
        assert [v.evidence["scan_id"] for v in found] == ["queued"]
        assert found[0].credits == 2

    def test_a_scan_still_running_after_a_day_is_recorded_unpriced(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant)
        settings_store.set_value(
            db, settings_store.KEY_ACTION_RATES, {"rates": list(tenant.action_rates or [])}
        )
        db.commit()
        tenant.add_scan(
            project_id="proj-api",
            scan_id="stuck",
            status="Running",
            initiator="dev@example.com",
            completed_at=later(30),
            created_at=later(20),
            engines=["ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
        )
        violations.detect(db, tenant.client())
        assert rows(db) == []
        moment = utcnow() + timedelta(days=2)
        from app.services import violations as module

        original = module.utcnow
        try:
            module.utcnow = lambda: moment  # type: ignore[assignment]
            violations.detect(db, tenant.client())
        finally:
            module.utcnow = original  # type: ignore[assignment]
        found = rows(db, KIND_FUSION_SCAN)
        assert [v.evidence["scan_id"] for v in found] == ["stuck"]
        assert found[0].credits is None
        assert "had not finished" in found[0].detail


class TestUsageBaseline:
    def test_each_kind_is_measured_from_its_own_restriction(self, db: Session) -> None:
        """Auto Triage restricted at T0, Fusion at T2. Fusion used between T0 and
        T2 (before Fusion was restricted) is not usage after a restriction."""
        from decimal import Decimal

        from app.models.usage import UsageRecord, UsageSnapshot

        now = utcnow()
        t0, t1, t2, t3 = (now - timedelta(hours=h) for h in (10, 8, 4, 1))

        def snap(at, fusion: int, auto_triage: int = 1) -> None:  # type: ignore[no-untyped-def]
            snapshot = UsageSnapshot(
                collected_at=at,
                view_by="project",
                period_param="P30D",
                total_credits=Decimal(0),
                pages_fetched=1,
            )
            db.add(snapshot)
            db.flush()
            db.add(
                UsageRecord(
                    snapshot_id=snapshot.id,
                    view_by="project",
                    subject_key="proj-x",
                    entity_type="project",
                    entity_id="proj-x",
                    credits_used=Decimal(fusion * 2 + auto_triage),
                    actions={"fusion": fusion, "auto_triage": auto_triage},
                )
            )
            db.flush()

        snap(t0 - timedelta(minutes=5), 0)  # before the Auto Triage restriction
        snap(t1, 3)  # 3 Fusion scans while Fusion was still allowed
        snap(t2 - timedelta(minutes=5), 3)  # just before Fusion was restricted
        snap(t3, 3)  # no Fusion since
        for kind, at in (("disable_auto_triage", t0), ("disable_fusion", t2)):
            db.add(
                EnforcementAction(
                    idempotency_key=f"k-{kind}",
                    kind=kind,
                    status="applied",
                    entity_type="project",
                    entity_id="proj-x",
                    target_type="cx_project",
                    target_id="proj-x",
                    target_label="proj-x",
                    limit_id=None,
                    period_key=PERIOD,
                    created_at=at,
                    applied_at=at,
                    attempts=1,
                )
            )
        db.commit()
        violations._detect_usage(db, violations.DetectionResult())
        db.commit()
        assert rows(db, KIND_USAGE_AFTER) == []

        # Fusion used after its own restriction is still found.
        snap(now, 5)
        db.commit()
        violations._detect_usage(db, violations.DetectionResult())
        db.commit()
        found = rows(db, KIND_USAGE_AFTER)
        assert len(found) == 1
        assert found[0].evidence["rise_by_action"] == {"fusion": 2}


class TestApiAndRetention:
    def test_naive_since_and_until_are_taken_as_utc(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        limit = restrict(db, tenant)
        tenant.fusion_setting("proj-api")["value"] = "true"
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        start = (utcnow() - timedelta(hours=1)).replace(tzinfo=None).isoformat()
        end = (utcnow() + timedelta(hours=1)).replace(tzinfo=None).isoformat()
        listed = admin_client.get("/api/violations", params={"since": start, "until": end})
        assert listed.status_code == 200
        assert listed.json()["total"] == 1
        aware = admin_client.get(
            "/api/violations", params={"since": (utcnow() + timedelta(hours=1)).isoformat()}
        )
        assert aware.status_code == 200 and aware.json()["total"] == 0

    def test_resolved_and_informational_rows_follow_the_retention_window(self, db: Session) -> None:
        from app.models.violations import STATUS_OPEN, STATUS_RESOLVED
        from app.services import retention

        old = utcnow() - timedelta(days=400)

        def add(key: str, kind: str, status: str) -> None:
            db.add(
                PolicyViolation(
                    kind=kind,
                    detected_at=old,
                    target_type="cx_project",
                    target_id="proj-x",
                    detail="synthetic",
                    severity="warning",
                    status=status,
                    resolved_at=old if status == STATUS_RESOLVED else None,
                    dedupe_key=key,
                )
            )

        add("resolved", KIND_FUSION_SCAN, STATUS_RESOLVED)
        add("open", KIND_FUSION_SCAN, STATUS_OPEN)
        add("info", KIND_AI_SCAN, STATUS_OPEN)
        db.commit()
        result = retention.prune(db, retention_days=90)
        db.commit()
        assert result.policy_violations == 2
        assert [v.dedupe_key for v in rows(db)] == ["open"]


class TestInformationIsNotAViolation:
    def test_ai_scan_info_rows_do_not_count_as_open_violations(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        restrict(db, tenant)
        for index in range(3):
            tenant.add_scan(
                project_id="proj-api",
                scan_id=f"llm-{index}",
                initiator="dev@example.com",
                completed_at=later(30 + index),
                engines=["ai"],
                ai={"fusionEnabled": "false"},
            )
        violations.detect(db, tenant.client())
        assert len(rows(db, KIND_AI_SCAN)) == 1
        assert _count(db, Notification, Notification.category == "policy") == 0
        # Information only: not an open violation to follow up.
        assert violations.open_count(db) == 0
        assert admin_client.get("/api/me").json()["open_violations"] == 0
        listed = admin_client.get("/api/violations", params={"kind": "violations"}).json()
        assert listed["items"] == [] and listed["open"] == 0
        info = admin_client.get("/api/violations", params={"kind": "information"}).json()
        assert [item["kind"] for item in info["items"]] == [KIND_AI_SCAN]
        assert info["items"][0]["information"] is True
        # A real violation is still counted.
        tenant.add_scan(
            project_id="proj-api",
            scan_id="fusion-1",
            initiator="dev@example.com",
            completed_at=later(40),
            engines=["ai"],
            ai={"fusionEnabled": "true"},
        )
        violations.detect(db, tenant.client())
        assert violations.open_count(db) == 1
        assert admin_client.get("/api/me").json()["open_violations"] == 1
        bad = admin_client.get("/api/violations", params={"kind": "nonsense"})
        assert bad.status_code == 400


def _detail_reads(tenant: FakeTenant) -> list[str]:
    return [
        path
        for method, path in tenant.requests
        if method == "GET" and "/api/scans/" in path and not path.rstrip("/").endswith("/api/scans")
    ]


class TestScanReadsAreNotWasted:
    def test_a_running_scan_does_not_make_reads_be_spent_again_or_starve_other_projects(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        restrict(db, tenant, entity_id="proj-api")
        restrict(db, tenant, entity_id="proj-web")
        tenant.add_scan(
            project_id="proj-api",
            scan_id="running",
            status="Running",
            initiator="a@example.com",
            completed_at=later(20),
            created_at=later(5),
            engines=["ai"],
            ai={"fusionEnabled": "false"},
        )
        for i in range(3):
            tenant.add_scan(
                project_id="proj-api",
                scan_id=f"api-{i}",
                initiator="a@example.com",
                completed_at=later(40 + i),
                engines=["ai"],
                ai={"fusionEnabled": "false"},
                metadata_in_listing=False,
            )
        tenant.add_scan(
            project_id="proj-web",
            scan_id="web-fusion",
            initiator="b@example.com",
            completed_at=later(50),
            engines=["ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
            metadata_in_listing=False,
        )
        monkeypatch.setattr(violations, "MAX_SCAN_READS_PER_CYCLE", 3)
        per_cycle = []
        for cycle_number in range(5):
            tenant.requests.clear()
            violations.detect(db, tenant.client())
            per_cycle.append(len(_detail_reads(tenant)))
            if cycle_number == 0:
                # proj-api cannot spend the read kept for proj-web.
                assert [v.evidence["scan_id"] for v in rows(db, KIND_FUSION_SCAN)] == ["web-fusion"]
        # Each scan is read once, ever; the running one holds nobody back.
        assert per_cycle == [3, 1, 0, 0, 0]
        assert [v.evidence["scan_id"] for v in rows(db, KIND_FUSION_SCAN)] == ["web-fusion"]
        ai = rows(db, KIND_AI_SCAN)
        assert sum(v.evidence["scans"] for v in ai) == 3

    def test_a_busy_project_is_not_held_back_by_idle_ones(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        restrict(db, tenant, entity_id="proj-api")
        restrict(db, tenant, entity_id="proj-web")
        for i in range(4):
            tenant.add_scan(
                project_id="proj-api",
                scan_id=f"busy-{i}",
                initiator="a@example.com",
                completed_at=later(40 + i),
                engines=["ai"],
                ai={"fusionEnabled": "true"},
                metadata_in_listing=False,
            )
        monkeypatch.setattr(violations, "MAX_SCAN_READS_PER_CYCLE", 4)
        tenant.requests.clear()
        violations.detect(db, tenant.client())
        assert len(_detail_reads(tenant)) == 4
        assert len(rows(db, KIND_FUSION_SCAN)) == 4

    def test_a_cursor_held_by_a_running_scan_moves_on_when_scans_pile_up(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """More scans pile up after a running one than one listing reaches: the
        cursor moves on, the running scan is still classified once it finishes,
        and the scans that could not be reached are said once (information)."""
        from app.checkmarx import scans as scans_api

        not_checked = "scans_not_checked"
        monkeypatch.setattr(violations, "SCAN_PAGE_SIZE", 2, raising=False)
        monkeypatch.setattr(violations, "MAX_PAGES_PER_PROJECT", 2)
        real_list = scans_api.list_project_scans

        def small_pages(client, **kwargs):  # type: ignore[no-untyped-def]
            kwargs["page_size"] = 2  # two pages of two: four scans a listing
            return real_list(client, **kwargs)

        monkeypatch.setattr(scans_api, "list_project_scans", small_pages)
        restrict(db, tenant)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="long-run",
            status="Running",
            initiator="dev@example.com",
            completed_at=later(200),
            created_at=later(5),
            engines=["ai"],
            ai={"fusionEnabled": "true", "llmModel": "opus-5.5"},
        )
        violations.detect(db, tenant.client())
        assert rows(db) == []
        for i in range(6):
            tenant.add_scan(
                project_id="proj-api",
                scan_id=f"pile-{i}",
                initiator="dev@example.com",
                completed_at=later(20 + i),
                created_at=later(10 + i),
                engines=["ai"],
                ai={"fusionEnabled": "false"},
            )
        violations.detect(db, tenant.client())
        # The four newest were looked at.
        assert rows(db, KIND_AI_SCAN)[0].evidence["scans"] == 4
        # The long scan finishes; it is no longer in the listing's reach.
        next(s for s in tenant.scans["proj-api"] if s["id"] == "long-run")["status"] = "Completed"
        for _ in range(3):
            violations.detect(db, tenant.client())
        assert [v.evidence["scan_id"] for v in rows(db, KIND_FUSION_SCAN)] == ["long-run"]
        # The two it could not reach are said once, as information.
        notes = rows(db, not_checked)
        assert len(notes) == 1 and notes[0].severity == "info"
        assert notes[0].evidence["occurrences"] == 1
        assert violations.open_count(db) == 1  # the Fusion scan, not the note
        # Nothing left pending, and no scan is read again.
        tenant.requests.clear()
        violations.detect(db, tenant.client())
        assert _detail_reads(tenant) == []
