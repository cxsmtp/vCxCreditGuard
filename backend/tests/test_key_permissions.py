"""The API key permission checker, run-time refusals, and the clearer messages.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.db.base import utcnow
from app.db.session import session_scope
from app.models import AuditLogEntry, EnforcementAction, Notification
from app.models.enums import EnforcementKind, EntityType, PeriodType, RunStatus
from app.services import connection as connection_service
from app.services import cycle, enforcement, key_permissions, limits_service, org_sync
from app.services import notifications as notification_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key, sqlite_only
from tests.fake_tenant import FakeTenant, access_token_with, populated_tenant
from tests.test_cycle_transactions import _watch_for_write_locks

ACTOR = AuditActor.system("test")
PERIOD = "2026-08"


@pytest.fixture
def tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = fake.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    key_permissions.discard_pending_denials()
    yield fake
    key_permissions.discard_pending_denials()


def synced(db: Session, tenant: FakeTenant) -> None:
    org_sync.sync_org_model(db, tenant.client())
    db.commit()


def check(db: Session, **kwargs) -> dict:
    report = key_permissions.run_check(
        db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR, **kwargs
    )
    assert report is not None
    return report


def by_id(report: dict) -> dict[str, dict]:
    return {entry["id"]: entry for entry in report["checks"]}


def add_limit(
    db: Session, entity_type: EntityType, entity_id: str, *, enforce: bool, credit_limit=10
):
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=entity_type,
            entity_id=entity_id,
            credit_limit=credit_limit,
            period_type=PeriodType.MONTHLY,
            enforce=enforce,
        ),
        actor=ACTOR,
    )
    db.commit()
    return limit


def permission_notifications(db: Session) -> list[Notification]:
    db.expire_all()
    return list(
        db.scalars(
            select(Notification)
            .where(Notification.category == notification_service.CATEGORY_PERMISSIONS)
            .order_by(Notification.id)
        )
    )


# ------------------------------------------------------------------ probes


class TestProbes:
    def test_everything_allowed_is_ok(self, db: Session, tenant: FakeTenant) -> None:
        synced(db, tenant)
        report = check(db)
        checks = by_id(report)
        for read in ("iam_users", "iam_groups", "projects", "applications", "consumption"):
            assert checks[read]["status"] == key_permissions.STATUS_OK, read
        assert checks["ai_config_read"]["status"] == key_permissions.STATUS_OK
        assert checks["repo_read"]["status"] == key_permissions.STATUS_OK
        assert checks["iam_clients"]["status"] == key_permissions.STATUS_OK
        assert checks["iam_user_roles"]["status"] == key_permissions.STATUS_OK
        for write in ("role_mapping_write", "ai_config_write", "repo_write"):
            assert checks[write]["status"] == key_permissions.STATUS_NOT_TESTED
            assert "first time" in checks[write]["detail"]
        assert report["verdict"] == key_permissions.VERDICT_OK

    def test_only_reads_are_made(self, db: Session, tenant: FakeTenant) -> None:
        synced(db, tenant)
        before = len(tenant.requests)
        check(db)
        made = tenant.requests[before:]
        assert made
        assert {method for method, _path in made} <= {"GET", "POST"}
        # The only POST is the token exchange.
        assert all(path.endswith("openid-connect/token") for m, path in made if m == "POST")

    def test_a_refused_read_is_denied_and_its_write_will_fail(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        tenant.fail_requests[("GET", "/ai-agents-coordinator/")] = 403
        checks = by_id(check(db))
        assert checks["ai_config_read"]["status"] == key_permissions.STATUS_DENIED
        assert checks["ai_config_write"]["expectation"] == key_permissions.EXPECT_WILL_FAIL
        assert checks["ai_config_write"]["problem"] is True
        assert checks["projects"]["status"] == key_permissions.STATUS_OK

    def test_per_project_reads_are_skipped_without_a_project(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty = FakeTenant()
        connection_service.save_connection(db, api_key=make_api_key(), actor=ACTOR)
        db.commit()
        client = empty.client()
        monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
        checks = by_id(check(db))
        assert checks["ai_config_read"]["status"] == key_permissions.STATUS_SKIPPED
        assert "No project" in checks["ai_config_read"]["detail"]
        assert checks["repo_read"]["status"] == key_permissions.STATUS_SKIPPED

    def test_a_404_is_not_found_and_not_a_missing_permission(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.credit_info = None
        report = check(db)
        assert by_id(report)["credit_pool"]["status"] == key_permissions.STATUS_NOT_FOUND
        assert by_id(report)["credit_pool"]["problem"] is False

    def test_client_lookup_refused_skips_what_depends_on_it(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        tenant.fail_requests[("GET", "/auth/admin/realms/acme-corp/clients")] = 403
        checks = by_id(check(db))
        assert checks["iam_clients"]["status"] == key_permissions.STATUS_DENIED
        assert checks["iam_client_roles"]["status"] == key_permissions.STATUS_SKIPPED
        assert checks["role_mapping_write"]["expectation"] == key_permissions.EXPECT_WILL_FAIL

    def test_the_token_is_never_stored_or_returned(self, db: Session, tenant: FakeTenant) -> None:
        tenant.access_token = access_token_with(realm_roles=["ast-admin"])
        report = check(db)
        stored = key_permissions.load(db)
        assert tenant.access_token not in str(stored)
        assert tenant.access_token not in str(report)
        assert report["token"]["realm_roles"] == ["ast-admin"]

    def test_a_cycle_does_not_read_scans_while_charging_is_off(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.steps["key_permissions"]["ok"] is True
        assert not [path for _m, path in tenant.requests if "/api/scans" in path]
        db.expire_all()
        assert key_permissions.current_report(db) is not None
        # Not due again straight away.
        assert key_permissions.check_due(db) is False


# ------------------------------------------------------------- token claims


class TestTokenClaims:
    def test_roles_and_groups_are_extracted(self) -> None:
        token = access_token_with(
            realm_roles=["ast-admin", "offline_access"],
            client_roles={"realm-management": ["view-users"], "ast-app": ["view-scans"]},
            groups=["/CreditGuard"],
        )
        claims = key_permissions.token_claims(token)
        assert claims["readable"] is True
        assert claims["realm_roles"] == ["ast-admin", "offline_access"]
        assert claims["client_roles"] == {
            "realm-management": ["view-users"],
            "ast-app": ["view-scans"],
        }
        assert claims["groups"] == ["/CreditGuard"]

    @pytest.mark.parametrize(
        "token",
        [None, "", "opaque-token", "a.b", "a.!!!.c", "a..c", "a.WzEsMl0.c", "a.bm90IGpzb24.c"],
    )
    def test_a_malformed_token_is_unreadable_not_an_error(self, token) -> None:
        claims = key_permissions.token_claims(token)
        assert claims["readable"] is False
        assert claims["realm_roles"] == []

    def test_missing_manage_users_marks_role_mapping_probably_denied(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.access_token = access_token_with(
            client_roles={"realm-management": ["view-users", "view-clients"]}
        )
        checks = by_id(check(db))
        assert checks["role_mapping_write"]["expectation"] == key_permissions.EXPECT_PROBABLY_DENIED

    def test_manage_users_present_is_not_flagged(self, db: Session, tenant: FakeTenant) -> None:
        tenant.access_token = access_token_with(
            client_roles={"realm-management": ["view-users", "manage-users"]}
        )
        assert by_id(check(db))["role_mapping_write"]["expectation"] is None


# ----------------------------------------------------------------- verdict


class TestVerdict:
    def test_enforce_only_gap_is_limited_until_a_limit_enforces(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        tenant.fail_requests[("GET", "/ai-agents-coordinator/")] = 403
        assert check(db)["verdict"] == key_permissions.VERDICT_LIMITED

        add_limit(db, EntityType.PROJECT, "proj-web", enforce=False)
        assert key_permissions.current_report(db)["verdict"] == key_permissions.VERDICT_LIMITED

        # A user limit does not need the project configuration calls.
        add_limit(db, EntityType.USER, "user-harsh", enforce=True)
        assert key_permissions.current_report(db)["verdict"] == key_permissions.VERDICT_LIMITED

        add_limit(db, EntityType.APPLICATION, "app-payments", enforce=True)
        report = key_permissions.current_report(db)
        assert report["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        assert "restrict projects' Auto Triage" in report["summary"]
        assert report["summary"].startswith("The Checkmarx API key is missing permissions")

    def test_a_core_gap_is_insufficient_whatever_is_configured(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        report = check(db)
        assert report["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        assert "count credit usage" in report["summary"]

    def test_the_explanation_says_why_and_what_to_do(self, db: Session, tenant: FakeTenant) -> None:
        synced(db, tenant)
        tenant.fail_requests[("GET", "/repos-manager/")] = 403
        tenant.access_token = access_token_with(realm_roles=["ast-scanner"])
        explanation = check(db)["explanation"]
        why = " ".join(explanation["why"])
        assert "only the roles chosen when it was created" in why
        assert "dedicated service account" in why
        assert any("/api/repos-manager/repo/{repoId}" in line for line in explanation["missing"])
        assert any("ast-scanner" in line for line in explanation["roles"])
        assert any("Check again" in line for line in explanation["what_to_do"])


# ------------------------------------------------------ notifications, audit


class TestNotifications:
    def test_one_notification_per_distinct_problem(self, db: Session, tenant: FakeTenant) -> None:
        synced(db, tenant)
        tenant.fail_requests[("GET", "/ai-agents-coordinator/")] = 403
        check(db)
        check(db)
        first = permission_notifications(db)
        assert len(first) == 1
        assert first[0].severity == "warning"

        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        check(db)
        check(db)
        second = permission_notifications(db)
        assert len(second) == 2
        assert second[1].severity == "error"

        tenant.fail_requests.clear()
        check(db)
        check(db)
        third = permission_notifications(db)
        assert len(third) == 3
        assert third[2].title == "API key permissions are now sufficient"
        assert third[2].severity == "info"

    def test_verdict_changes_are_audited(self, db: Session, tenant: FakeTenant) -> None:
        check(db)  # ok on the first check: nothing worth auditing
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        check(db)
        check(db)
        tenant.fail_requests.clear()
        check(db)
        db.expire_all()
        entries = list(
            db.scalars(
                select(AuditLogEntry)
                .where(AuditLogEntry.action == "connection.permissions_changed")
                .order_by(AuditLogEntry.id)
            )
        )
        assert [entry.after["verdict"] for entry in entries] == ["insufficient", "ok"]

    def test_a_problem_logs_a_warning(
        self, db: Session, tenant: FakeTenant, caplog: pytest.LogCaptureFixture
    ) -> None:
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        with caplog.at_level("WARNING", logger="app.services.key_permissions"):
            check(db)
        assert any("missing permissions" in record.message for record in caplog.records)


# ---------------------------------------------------------- run-time refusals


class TestRuntimeRefusals:
    def test_a_refused_restriction_is_recorded_and_raises_the_verdict(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        check(db)
        assert key_permissions.current_report(db)["verdict"] == key_permissions.VERDICT_OK

        tenant.fail_requests[("DELETE", "/role-mappings/")] = 403
        limit = add_limit(db, EntityType.USER, "user-harsh", enforce=True)
        outcome = enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.failed

        report = key_permissions.current_report(db)
        checks = by_id(report)
        assert checks["role_mapping_write"]["runtime_denied_at"] is not None
        assert report["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        denial = report["runtime_denials"][0]
        assert denial["method"] == "DELETE"
        assert denial["path"] == (
            "/auth/admin/realms/<tenant>/users/{userId}/role-mappings/clients/{clientUuid}"
        )
        assert "user-harsh" not in str(report["runtime_denials"])
        assert len(permission_notifications(db)) == 1

        # The probes cannot see it, so an automatic re-check keeps it...
        key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(key_permissions.current_report(db))["role_mapping_write"]["problem"]
        # ...and only "Check again" clears it.
        assert check(db, clear_runtime=True)["verdict"] == key_permissions.VERDICT_OK

    def test_a_swallowed_403_in_a_cycle_is_recorded(self, db: Session, tenant: FakeTenant) -> None:
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        tenant.fail_requests[("GET", "/credits/info")] = 403
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        report = key_permissions.current_report(db)
        assert by_id(report)["credit_pool"]["runtime_denied_at"] is not None
        assert report["verdict"] == key_permissions.VERDICT_LIMITED

    def test_probe_refusals_are_not_run_time_refusals(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/credits/info")] = 403
        check(db)
        assert key_permissions.pending_denials() == 0
        assert key_permissions.current_report(db)["runtime_denials"] == []


# --------------------------------------------------------- write lock, API


@sqlite_only
class TestNoWriteLock:
    def test_probes_hold_no_write_lock(self, db: Session, tenant: FakeTenant) -> None:
        synced(db, tenant)
        held = _watch_for_write_locks(tenant)
        # Something pending in the caller's transaction, audit chain included.
        from app.services.audit import record_audit

        record_audit(db, action="test.pending", actor=ACTOR, target_type="test")
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        check(db)
        assert tenant.requests
        assert held == []

    def test_connection_test_route_holds_no_write_lock(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        held = _watch_for_write_locks(tenant)
        response = admin_client.post("/api/connection/test")
        assert response.status_code == httpx.codes.OK
        assert response.json()["permissions"]["verdict"] == "ok"
        assert held == []


class TestApi:
    def test_save_returns_the_report(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        response = admin_client.put("/api/connection", json={"api_key": make_api_key()})
        assert response.status_code == httpx.codes.OK
        permissions = response.json()["permissions"]
        assert permissions["verdict"] == "insufficient"
        assert permissions["details_visible"] is True
        assert any(
            c["id"] == "consumption" and c["status"] == "denied" for c in permissions["checks"]
        )

    def test_a_failing_check_never_fails_the_save(
        self,
        admin_client: TestClient,
        db: Session,
        tenant: FakeTenant,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def boom(*_args, **_kwargs):
            raise RuntimeError("probe exploded")

        monkeypatch.setattr(key_permissions, "_run_probes", boom)
        response = admin_client.put("/api/connection", json={"api_key": make_api_key()})
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["ok"] is True
        assert body["permissions"] is None
        db.expire_all()
        assert connection_service.get_connection(db) is not None

    def test_viewer_sees_the_summary_only(
        self, viewer_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        tenant.access_token = access_token_with(realm_roles=["ast-admin"])
        check(db)
        body = viewer_client.get("/api/connection/permissions").json()
        assert body["available"] is True
        report = body["report"]
        assert report["verdict"] == "insufficient"
        assert report["details_visible"] is False
        assert report["checks"] == []
        assert report["token"] is None
        assert report["explanation"]["roles"] == []
        assert viewer_client.post("/api/connection/permissions").status_code == 403

        me = viewer_client.get("/api/me").json()
        assert me["key_permissions"]["verdict"] == "insufficient"
        assert me["key_permissions"]["problem_key"]

    def test_check_again(self, admin_client: TestClient, tenant: FakeTenant) -> None:
        response = admin_client.post("/api/connection/permissions")
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["report"]["verdict"] == "ok"
        assert body["report"]["trigger"] == "manual"
        full = admin_client.get("/api/connection/permissions").json()["report"]
        assert full["details_visible"] is True and full["checks"]

    def test_the_report_is_not_a_setting(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        from app.services import settings_store

        check(db)
        assert settings_store.KEY_KEY_PERMISSIONS not in settings_store.all_public_settings(db)


# ------------------------------------------------------------ false drift


class TestUnreadableIsNotDrift:
    def _restricted(self, db: Session, tenant: FakeTenant):
        synced(db, tenant)
        limit = add_limit(db, EntityType.PROJECT, "proj-api", enforce=True)
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert tenant.repo_severities["repo-1"] == []
        return limit

    def test_an_unreadable_setting_is_reapplied_silently(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        limit = self._restricted(db, tenant)
        tenant.fail_requests[("GET", "/repos-manager/")] = 500
        before = len(tenant.requests)
        outcome = enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert outcome.reconciled == []
        assert [a.kind for a in outcome.unverified] == [EnforcementKind.DISABLE_PR_REMEDIATION]
        assert outcome.as_stats()["unverified"] == 1
        # Still re-applied, to keep it in force.
        assert ("PATCH", "/api/repos-manager/repo/repo-1") in tenant.requests[before:]
        assert tenant.repo_severities["repo-1"] == []
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "enforcement.reconciled")
            )
            == 0
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(Notification)
                .where(Notification.title.like("%re-disabled%"))
            )
            == 0
        )

    def test_a_refused_read_is_also_recorded_as_a_missing_permission(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        limit = self._restricted(db, tenant)
        tenant.fail_requests[("GET", "/repos-manager/")] = 403
        outcome = enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.reconciled == []
        report = key_permissions.current_report(db)
        assert by_id(report)["repo_read"]["runtime_denied_at"] is not None

    def test_real_drift_is_still_reported(self, db: Session, tenant: FakeTenant) -> None:
        limit = self._restricted(db, tenant)
        tenant.repo_severities["repo-1"] = ["CRITICAL"]
        outcome = enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in outcome.reconciled] == [EnforcementKind.DISABLE_PR_REMEDIATION]
        assert (
            db.scalar(
                select(func.count())
                .select_from(Notification)
                .where(Notification.title.like("%PR triage and remediation re-disabled%"))
            )
            == 1
        )


# ------------------------------------------------------------ the messages


class TestBreachMessages:
    def test_a_project_breach_says_what_was_used_and_what_is_not_stopped(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=4,
            entity_id="proj-web",
            actions={"fusion": 2},
        )
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        add_limit(db, EntityType.PROJECT, "proj-web", enforce=True, credit_limit=3)
        cycle.run_cycle(trigger="manual")  # the period's baseline
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=8,
            entity_id="proj-web",
            actions={"fusion": 6},
        )
        cycle.run_cycle(trigger="manual")
        period = utcnow().strftime("%Y-%m")

        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        assert f"4 credits used in {period}: Fusion scan 4." in breach.body
        assert "does not stop Fusion scans; CreditGuard cannot switch Fusion off yet" in breach.body

        restricted = db.scalar(
            select(Notification).where(Notification.title.like("%Auto Triage disabled"))
        )
        assert restricted is not None
        assert f"4 credits used in {period}: Fusion scan 4." in restricted.body
        assert "Turning off Auto Triage and PR triage and remediation does not stop Fusion" in (
            restricted.body
        )
        assert "Most of these credits were Fusion scans." in restricted.body

    def test_a_user_restriction_lists_the_actions_and_the_roles_removed(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        add_limit(db, EntityType.USER, "user-harsh", enforce=True, credit_limit=5)
        cycle.run_cycle(trigger="manual")
        tenant.set_user_credits(
            name="Harsh Gokani",
            email="harsh.gokani@checkmarx.com",
            credits=20,
            actions={"remediation": 1, "triage": 2, "fusion": 10},
        )
        cycle.run_cycle(trigger="manual")
        period = utcnow().strftime("%Y-%m")

        db.expire_all()
        restricted = db.scalar(
            select(Notification).where(Notification.title.like("User % restricted"))
        )
        assert restricted is not None
        body = restricted.body
        assert f"17 credits used in {period}." in body
        assert "AI Triage 2 transactions, Fusion scan 10 transactions" in body
        assert "The AI roles were removed: " in body
        assert all(role in body for role in AI_ROLE_NAMES)
        assert "Most of the actions behind them were Fusion scans." in body
        assert "does not stop Fusion scans" in body
        action = db.scalar(select(EnforcementAction))
        assert action is not None


def test_a_session_scope_reader_sees_the_report(tenant: FakeTenant) -> None:
    with session_scope() as session:
        key_permissions.run_check(session, trigger="manual", actor=ACTOR)
    with session_scope() as session:
        assert key_permissions.summary(session)["verdict"] == "ok"
