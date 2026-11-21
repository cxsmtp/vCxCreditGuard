"""The API key permission checker, run-time refusals, and the clearer messages.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx.errors import CheckmarxPermissionError
from app.checkmarx.iam import AI_ROLE_NAMES
from app.db.base import utcnow
from app.db.session import session_scope
from app.models import AuditLogEntry, EnforcementAction, LimitPeriodState, Notification
from app.models.enums import EnforcementKind, EntityType, PeriodType, RunStatus
from app.services import connection as connection_service
from app.services import (
    cycle,
    enforcement,
    evaluation,
    key_permissions,
    limits_service,
    org_sync,
    usage_mix,
)
from app.services import notifications as notification_service
from app.services.audit import AuditActor
from app.services.periods import current_window
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
        # Not needed with this setup (no enforcing project limit): info only.
        assert first[0].severity == "info"

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
        # ...and so does "Check again": pressing a button is no evidence.
        report = check(db, clear_runtime=True)
        assert report["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is not None

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
        month = utcnow().strftime("%B %Y")
        # One sentence: the credits against the limit, and what they went on.
        assert breach.body.startswith(f"4 of 3 credits used in {month}: Fusion scan 4.\n")
        assert "4.0000" not in breach.body
        assert breach.body.count("credits used") == 1
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


# ------------------------------------------- review findings (reproductions)


class TestRefusalsBelongToTheirKey:
    """B1: a refusal met with one key never lands on the report of the next."""

    def test_a_connection_test_403_is_not_queued_as_a_runtime_refusal(
        self, admin_client: TestClient, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/projects")] = 403
        admin_client.post("/api/connection/test")
        # The connection test is itself a probe, not a run-time event.
        assert key_permissions.pending_denials() == 0

    def test_old_keys_connection_test_403_does_not_land_on_the_new_keys_report(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        # Admin pastes an under-privileged key: the connection test's project read is refused.
        tenant.fail_requests[("GET", "/projects")] = 403
        first = admin_client.put("/api/connection", json={"api_key": make_api_key(subject="key-a")})
        assert first.json()["permissions"]["verdict"] == "insufficient"
        # Then pastes the right key: everything is allowed.
        tenant.fail_requests.clear()
        second = admin_client.put(
            "/api/connection", json={"api_key": make_api_key(subject="key-b")}
        )
        assert second.json()["permissions"]["verdict"] == "ok"
        # The next cycle must not flush the old key's 403 onto the new key's report.
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        db.expire_all()
        report = key_permissions.current_report(db)
        assert report["verdict"] == "ok", (report["summary"], report["runtime_denials"])

    def test_a_refusal_tagged_with_another_key_is_dropped(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        check(db)
        old_key = tenant.client()
        old_key.key_fingerprint = "an-earlier-key"
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        with pytest.raises(CheckmarxPermissionError):
            old_key.get_json("/api/credits/consumption")
        assert key_permissions.pending_denials() == 1
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        report = key_permissions.current_report(db)
        assert report["verdict"] == key_permissions.VERDICT_OK
        assert report["runtime_denials"] == []

    def test_saving_another_key_discards_the_queue(self, db: Session, tenant: FakeTenant) -> None:
        tenant.fail_requests[("GET", "/credits/info")] = 403
        with pytest.raises(CheckmarxPermissionError):
            tenant.client().get_json("/api/credits/info")
        assert key_permissions.pending_denials() == 1
        connection_service.save_connection(db, api_key=make_api_key(subject="key-c"), actor=ACTOR)
        db.commit()
        assert key_permissions.pending_denials() == 0


class TestRuntimeRefusalsClear:
    """S1: a refusal goes when there is evidence it no longer happens, not before."""

    def test_runtime_read_refusal_is_cleared_when_the_probe_later_succeeds(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        # A one-off 403 on a core read during a cycle...
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        assert by_id(key_permissions.current_report(db))["consumption"]["runtime_denied_at"]
        # ...goes away. The automatic 6-hourly re-check reads it fine.
        tenant.fail_requests.clear()
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(report)["consumption"]["status"] == key_permissions.STATUS_OK
        assert report["verdict"] == key_permissions.VERDICT_OK, report["summary"]
        assert report["runtime_denials"] == []

    def test_a_refused_change_clears_when_the_same_change_later_succeeds(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        check(db)
        limit = add_limit(db, EntityType.USER, "user-harsh", enforce=True)
        tenant.fail_requests[("DELETE", "/role-mappings/")] = 403
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert key_permissions.current_report(db)["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        # Check again is no evidence the change works.
        assert check(db, clear_runtime=True)["verdict"] == key_permissions.VERDICT_INSUFFICIENT

        # The permission is granted; the next attempt goes through.
        tenant.fail_requests.clear()
        outcome = enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert not outcome.failed
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        report = key_permissions.current_report(db)
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is None
        assert report["runtime_denials"] == []
        assert report["verdict"] == key_permissions.VERDICT_OK
        recovered = permission_notifications(db)[-1]
        assert recovered.title == "API key permissions are now sufficient"
        assert "Every permission CreditGuard checked" not in recovered.body
        assert "confirmed the first time CreditGuard makes it" in recovered.body

    def test_a_successful_get_is_not_even_queued(self, db: Session, tenant: FakeTenant) -> None:
        synced(db, tenant)
        tenant.client().get_json("/api/projects")
        assert key_permissions.pending_denials() == 0

    def test_a_refusal_recorded_while_probing_is_kept(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M1: a flush from another thread during the probes is not overwritten."""
        synced(db, tenant)
        check(db)
        real = key_permissions._run_probes

        def probes_while_someone_flushes(*args, **kwargs):
            results = real(*args, **kwargs)
            key_permissions._on_forbidden(
                "DELETE",
                "https://iam.example/auth/admin/realms/acme-corp/users/u1/role-mappings/clients/c1",
                None,
            )
            with session_scope() as other:
                assert key_permissions.flush_runtime_denials(other, actor=ACTOR) == 1
            return results

        monkeypatch.setattr(key_permissions, "_run_probes", probes_while_someone_flushes)
        report = check(db)
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is not None
        db.expire_all()
        stored = key_permissions.current_report(db)
        assert by_id(stored)["role_mapping_write"]["runtime_denied_at"] is not None


class TestNotificationPrivacy:
    """S2: the notification body is readable by viewers, so it never carries roles."""

    def test_viewer_cannot_read_key_roles_through_notifications(
        self, viewer_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        tenant.access_token = access_token_with(
            realm_roles=["secret-role-name"], groups=["/Secret Group"]
        )
        check(db)
        report = viewer_client.get("/api/connection/permissions").json()["report"]
        assert "secret-role-name" not in str(report)
        items = viewer_client.get("/api/notifications", params={"category": "permissions"}).json()
        assert items["items"]
        assert "secret-role-name" not in str(items), "roles leak to viewers via notifications"
        assert "Secret Group" not in str(items)
        assert "Key permissions card on the Connection page" in items["items"][0]["body"]


class TestAttention:
    """S5, M4: only a confirmed gap in something needed now raises the alarm."""

    def test_an_optional_gap_is_for_the_card_only(
        self, viewer_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/credits/info")] = 403
        report = check(db)
        assert report["verdict"] == key_permissions.VERDICT_LIMITED
        assert report["attention"] is False
        assert "read the credit pool" in report["summary"]
        me = viewer_client.get("/api/me").json()["key_permissions"]
        assert me["attention"] is False
        notes = permission_notifications(db)
        assert [note.severity for note in notes] == ["info"]

    def test_a_confirmed_required_gap_asks_for_attention(
        self, viewer_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        assert check(db)["attention"] is True
        assert viewer_client.get("/api/me").json()["key_permissions"]["attention"] is True

    def test_applications_and_groups_matter_only_with_such_limits(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        tenant.fail_requests[("GET", "/api/applications")] = 403
        tenant.fail_requests[("GET", "/groups")] = 403
        report = check(db)
        assert report["verdict"] == key_permissions.VERDICT_LIMITED
        assert report["attention"] is False
        assert by_id(report)["applications"]["required"] is False

        add_limit(db, EntityType.APPLICATION, "app-payments", enforce=False)
        report = key_permissions.current_report(db)
        assert report["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        assert report["attention"] is True
        assert by_id(report)["applications"]["required"] is True
        assert by_id(report)["iam_groups"]["required"] is False

        add_limit(db, EntityType.GROUP, "grp-payments", enforce=False)
        assert by_id(key_permissions.current_report(db))["iam_groups"]["required"] is True

    def test_org_sync_survives_refused_groups_and_applications(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.fail_requests[("GET", "/api/applications")] = 403
        tenant.fail_requests[("GET", "/groups")] = 403
        result = org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert result.users > 0 and result.projects > 0
        assert result.warnings == []

        # With a group limit in place the refusal is a warning.
        tenant.fail_requests.clear()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        add_limit(db, EntityType.GROUP, "grp-payments", enforce=False)
        tenant.fail_requests[("GET", "/groups")] = 403
        result = org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert any("may not read groups" in warning for warning in result.warnings)
        # Memberships still resolve from the groups synced before.
        assert result.memberships > 0

    def test_probably_refused_is_a_card_warning_not_a_red_verdict(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        add_limit(db, EntityType.USER, "user-harsh", enforce=True)
        tenant.access_token = access_token_with(client_roles={"realm-management": ["view-users"]})
        report = check(db)
        checks = by_id(report)
        assert checks["role_mapping_write"]["expectation"] == key_permissions.EXPECT_PROBABLY_DENIED
        assert checks["role_mapping_write"]["severe"] is False
        assert report["verdict"] == key_permissions.VERDICT_LIMITED
        assert report["attention"] is False
        assert report["summary"].startswith("The Checkmarx API key may be missing")

    def test_problem_since_survives_a_failed_token_exchange(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        """M2: an unknown check in between does not start a new episode."""
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        check(db)
        since = key_permissions.load(db)["problem_since"]
        tenant.fail_requests[("POST", "/openid-connect/token")] = 401
        connection_service.get_client(db).tokens.invalidate()
        assert check(db)["verdict"] == key_permissions.VERDICT_UNKNOWN
        assert key_permissions.load(db)["problem_since"] == since
        del tenant.fail_requests[("POST", "/openid-connect/token")]
        connection_service.get_client(db).tokens.invalidate()
        check(db)
        assert key_permissions.load(db)["problem_since"] == since
        assert len(permission_notifications(db)) == 1


class TestRoutes:
    def test_changing_the_api_address_checks_the_key_again(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        """M3."""
        tenant.fail_requests[("GET", "/credits/consumption")] = 403
        response = admin_client.patch(
            "/api/connection/api-base-url", json={"api_base_url": "https://eu.ast.checkmarx.net"}
        )
        assert response.status_code == httpx.codes.OK, response.text
        assert response.json()["permissions"]["verdict"] == "insufficient"

    def test_a_malformed_stored_report_reads_as_none(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        """M6."""
        from app.services import settings_store

        check(db)
        stored = key_permissions.load(db)
        stored["checks"][0]["runtime_denied_at"] = "not a date"
        settings_store.set_value(db, settings_store.KEY_KEY_PERMISSIONS, stored)
        db.commit()
        response = admin_client.get("/api/connection/permissions")
        assert response.status_code == httpx.codes.OK
        assert response.json() == {"available": False, "report": None}


class TestUnverifiedReapplyAudit:
    def test_the_first_unverified_reapply_is_audited_once(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        """M5: the tenant was written to, so it is audited; once, not every cycle."""
        synced(db, tenant)
        limit = add_limit(db, EntityType.PROJECT, "proj-api", enforce=True)
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        tenant.fail_requests[("GET", "/repos-manager/")] = 500
        for _ in range(3):
            enforcement.apply_enforcement(
                db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
            )
            db.commit()
        entries = list(
            db.scalars(
                select(AuditLogEntry).where(
                    AuditLogEntry.action == enforcement.AUDIT_UNVERIFIED_REAPPLY
                )
            )
        )
        assert len(entries) == 1
        assert entries[0].target_type == "enforcement_action"


class TestUsageMixWording:
    def test_sliding_window_does_not_attribute_all_credits_to_one_action(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        """S3."""
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=10,
            entity_id="proj-web",
            actions={"fusion": 10, "triage": 5},
        )
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        add_limit(db, EntityType.PROJECT, "proj-web", enforce=False, credit_limit=3)
        cycle.run_cycle(trigger="manual")  # baseline
        # Window slid: 4 old Fusion transactions dropped out, 2 new Fusion and 1
        # new triage happened. Fusion count falls by 2, triage rises by 1.
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=14,
            entity_id="proj-web",
            actions={"fusion": 8, "triage": 6},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        assert ": AI Triage 4." not in breach.body, breach.body
        assert "whole lookback window" in breach.body
        assert "Most of" not in breach.body

    def test_the_wording_of_a_lifetime_period_and_what_a_project_restriction_leaves(
        self,
    ) -> None:
        """S4."""
        assert usage_mix.period_phrase("lifetime") == "in the reporting window"
        text = usage_mix.does_not_stop(EnforcementKind.DISABLE_AUTO_TRIAGE, None)
        assert "count only towards user limits" not in text
        assert "only a user limit can stop those" in text

    def test_the_breakdown_is_computed_only_for_a_new_notification(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M8."""
        tenant.set_entity_credits(
            view="project", name="payments/web", credits=4, entity_id="proj-web"
        )
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        limit = add_limit(db, EntityType.PROJECT, "proj-web", enforce=False, credit_limit=3)
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(
            view="project", name="payments/web", credits=8, entity_id="proj-web"
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        state = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
        assert state is not None and state.breached_at is not None
        calls: list[int] = []
        real = usage_mix.mix_for

        def counting(*args, **kwargs):
            calls.append(1)
            return real(*args, **kwargs)

        monkeypatch.setattr(usage_mix, "mix_for", counting)
        # Raised again (a re-breach in the same period): the dedupe key exists.
        evaluation._notify_breach(db, limit, state, current_window(limit), exempt=False)
        assert calls == []
        before = db.scalar(select(func.count()).select_from(Notification))
        db.commit()
        assert db.scalar(select(func.count()).select_from(Notification)) == before


# ----------------------------------------------------- follow-up review (kp2)

_API = "https://eu.ast.checkmarx.net/api"
_IAM = "https://eu.iam.checkmarx.net/auth/admin/realms/acme-corp"


def permission_audits(db: Session) -> list[AuditLogEntry]:
    return list(
        db.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "connection.permissions_changed")
        )
    )


class TestRefusalOnOneResource:
    """A read refused on one project is not disproved by reading another one."""

    def test_a_read_refused_on_one_project_does_not_flip_with_the_probe(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        check(db)
        # The key cannot see proj-tools; the probe reads proj-api fine.
        limit = add_limit(db, EntityType.PROJECT, "proj-tools", enforce=True)
        tenant.fail_requests[("GET", "/projects/proj-tools/configuration")] = 403
        verdicts = []
        for _ in range(3):
            enforcement.apply_enforcement(
                db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
            )
            db.commit()
            verdicts.append(key_permissions.current_report(db)["verdict"])
            key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
            verdicts.append(key_permissions.current_report(db)["verdict"])
        assert verdicts == [key_permissions.VERDICT_INSUFFICIENT] * 6
        assert len(permission_notifications(db)) == 1
        assert len(permission_audits(db)) == 1

        report = key_permissions.current_report(db)
        checks = by_id(report)
        # The project the probe read is readable; the refusal on the other one stays.
        assert checks["ai_config_read"]["status"] == key_permissions.STATUS_OK
        assert checks["ai_config_read"]["runtime_denied_at"] is not None
        assert "still refused (403) on 1 project" in checks["ai_config_read"]["detail"]
        # The project id is kept internally only.
        assert "proj-tools" not in str(report)
        assert "proj-tools" in str(key_permissions.load(db)["runtime_denials"])
        assert "last_attention" not in key_permissions.load(db)

        # Once the key may read that project, the next check sees it and clears it.
        tenant.fail_requests.clear()
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert report["verdict"] == key_permissions.VERDICT_OK, report["summary"]
        assert report["runtime_denials"] == []
        assert by_id(report)["ai_config_read"]["runtime_denied_at"] is None

    def test_admin_api_does_not_show_the_refused_resource(
        self, admin_client: TestClient, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        check(db)
        key_permissions._on_forbidden(
            "GET", f"{_API}/ai-agents-coordinator/projects/proj-tools/configuration", None
        )
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        body = admin_client.get("/api/connection/permissions").json()
        assert body["report"]["runtime_denials"]
        assert "proj-tools" not in str(body)

    def test_a_later_successful_read_of_the_same_project_clears_it(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        check(db)
        tenant.fail_requests[("GET", "/projects/proj-tools/configuration")] = 403
        with pytest.raises(CheckmarxPermissionError):
            tenant.client().get_json("/ai-agents-coordinator/projects/proj-tools/configuration")
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        assert by_id(key_permissions.current_report(db))["ai_config_read"]["runtime_denied_at"]

        tenant.fail_requests.clear()
        # Reading another project is no evidence; it is not even queued.
        tenant.client().get_json("/ai-agents-coordinator/projects/proj-api/configuration")
        assert key_permissions.pending_denials() == 0
        # Reading the refused one is.
        tenant.client().get_json("/ai-agents-coordinator/projects/proj-tools/configuration")
        assert key_permissions.pending_denials() == 1
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        report = key_permissions.current_report(db)
        assert report["runtime_denials"] == []
        assert by_id(report)["ai_config_read"]["runtime_denied_at"] is None

    def test_a_repository_refused_at_run_time_is_probed_directly(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        synced(db, tenant)
        tenant.add_project(project_id="proj-z", name="zz/other", repo_id="repo-9")
        synced(db, tenant)
        check(db)
        tenant.fail_requests[("GET", "/repos-manager/repo/repo-9")] = 403
        with pytest.raises(CheckmarxPermissionError):
            tenant.client().get_json("/repos-manager/repo/repo-9", params={"projectId": "proj-z"})
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        # The probe reads repo-1 (proj-api) fine, but repo-9 is still refused.
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(report)["repo_read"]["runtime_denied_at"] is not None
        tenant.fail_requests.clear()
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(report)["repo_read"]["runtime_denied_at"] is None
        assert report["runtime_denials"] == []


class TestRefusalsNotNeededNow:
    """A refused change nothing needs any more does not stay listed forever."""

    def _refuse_role_removal(self, db: Session, tenant: FakeTenant):
        synced(db, tenant)
        check(db)
        limit = add_limit(db, EntityType.USER, "user-harsh", enforce=True)
        tenant.fail_requests[("DELETE", "/role-mappings/")] = 403
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert key_permissions.current_report(db)["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        return limit

    def test_check_again_drops_a_refused_change_no_limit_needs(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        limit = self._refuse_role_removal(db, tenant)
        limit.enforce = False
        db.commit()
        # A recent refusal survives the automatic check (it is not needed now,
        # so it is on the card only)...
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is not None
        assert report["attention"] is False
        # ...and "Check again" drops it.
        report = check(db, clear_runtime=True)
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is None
        assert report["runtime_denials"] == []
        assert report["verdict"] == key_permissions.VERDICT_OK

    def test_an_old_refused_change_no_limit_needs_is_dropped_by_the_automatic_check(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        from app.services import settings_store

        limit = self._refuse_role_removal(db, tenant)
        stored = key_permissions.load(db)
        old = (utcnow() - key_permissions.UNNEEDED_REFUSAL_AGE * 2).isoformat()
        for entry in stored["runtime_denials"]:
            entry["first_seen"] = entry["last_seen"] = old
        for entry in stored["checks"]:
            if entry["runtime_denied_at"]:
                entry["runtime_denied_at"] = old
        settings_store.set_value(db, settings_store.KEY_KEY_PERMISSIONS, stored)
        db.commit()

        # Still needed (the limit enforces): kept, however old.
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is not None
        # Not needed any more: dropped by the automatic check.
        limit.enforce = False
        db.commit()
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_CYCLE, actor=ACTOR)
        assert by_id(report)["role_mapping_write"]["runtime_denied_at"] is None
        assert report["runtime_denials"] == []


class TestFlushKeepsEvents:
    def test_a_failed_flush_puts_the_events_back(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        check(db)
        key_permissions._on_forbidden("GET", f"{_API}/credits/info", None)
        real = key_permissions._finish

        def broken(*args, **kwargs):
            raise RuntimeError("database went away")

        monkeypatch.setattr(key_permissions, "_finish", broken)
        assert key_permissions.flush_runtime_denials(db, actor=ACTOR) == 0
        assert key_permissions.pending_denials() == 1
        monkeypatch.setattr(key_permissions, "_finish", real)
        assert key_permissions.flush_runtime_denials(db, actor=ACTOR) == 1
        db.commit()
        assert by_id(key_permissions.current_report(db))["credit_pool"]["runtime_denied_at"]

    def test_the_put_back_queue_stays_bounded(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        check(db)
        cap = key_permissions._MAX_PENDING
        for _ in range(cap):
            key_permissions._on_forbidden("GET", f"{_API}/credits/info", None)

        def broken(*args, **kwargs):
            # More arrive while the flush is under way.
            for _ in range(5):
                key_permissions._on_forbidden("GET", f"{_API}/credits/info", None)
            raise RuntimeError("database went away")

        monkeypatch.setattr(key_permissions, "_finish", broken)
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        assert key_permissions.pending_denials() == cap


def test_events_wait_while_no_connection_is_stored(db: Session) -> None:
    key_permissions.discard_pending_denials()
    try:
        key_permissions._on_forbidden("GET", f"{_API}/credits/info", None)
        assert key_permissions.flush_runtime_denials(db, actor=ACTOR) == 0
        assert key_permissions.pending_denials() == 1
    finally:
        key_permissions.discard_pending_denials()


class TestListeners:
    def test_an_unrelated_change_going_through_does_not_clear_a_refusal(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        check(db)
        refused = f"{_API}/ai-agents-coordinator/projects/p1/configuration"
        key_permissions._on_forbidden("PUT", refused, None)
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        key_permissions.load(db)
        key_permissions._on_success("PATCH", f"{_API}/repos-manager/repo/r1?projectId=p1", None)
        key_permissions._on_success("POST", refused, None)
        key_permissions._on_success("DELETE", f"{_IAM}/users/u1/role-mappings/clients/c1", None)
        assert key_permissions.pending_denials() == 0
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        assert by_id(key_permissions.current_report(db))["ai_config_write"]["runtime_denied_at"]
        # The same change going through does clear it.
        key_permissions._on_success(
            "PUT", f"{_API}/ai-agents-coordinator/projects/p2/configuration", None
        )
        assert key_permissions.pending_denials() == 1
        key_permissions.flush_runtime_denials(db, actor=ACTOR)
        db.commit()
        report = key_permissions.current_report(db)
        assert by_id(report)["ai_config_write"]["runtime_denied_at"] is None

    def test_pausing_the_listeners_is_per_thread(self, tenant: FakeTenant) -> None:
        import threading

        from app.checkmarx.client import listeners_paused

        tenant.fail_requests[("GET", "/credits/info")] = 403
        client = tenant.client()
        inside = threading.Event()
        release = threading.Event()
        paused_calls: list[Exception] = []

        def paused_thread() -> None:
            with listeners_paused():
                try:
                    client.get_json("/api/credits/info")
                except CheckmarxPermissionError as exc:
                    paused_calls.append(exc)
                inside.set()
                release.wait(5)

        worker = threading.Thread(target=paused_thread)
        worker.start()
        try:
            assert inside.wait(5)
            assert paused_calls
            # The paused thread's own 403 was not queued...
            assert key_permissions.pending_denials() == 0
            # ...while another thread's, made during the pause, is.
            with pytest.raises(CheckmarxPermissionError):
                client.get_json("/api/credits/info")
            assert key_permissions.pending_denials() == 1
        finally:
            release.set()
            worker.join()


class TestMaskedSlide:
    def test_a_masked_slide_does_not_put_every_credit_on_one_action(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        """Fusion steady at 10 in a sliding window (5 left, 5 new); triage 2 -> 3."""
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=10,
            entity_id="proj-web",
            actions={"fusion": 10, "triage": 2},
        )
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        add_limit(db, EntityType.PROJECT, "proj-web", enforce=False, credit_limit=3)
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=16,
            entity_id="proj-web",
            actions={"fusion": 10, "triage": 3},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        assert ": AI Triage 6." not in breach.body, breach.body
        assert "AI Triage 1 transaction" in breach.body
        assert "can hide new ones" in breach.body

    def test_one_action_alone_still_gets_the_credits(self, db: Session, tenant: FakeTenant) -> None:
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=10,
            entity_id="proj-web",
            actions={"triage": 2},
        )
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        add_limit(db, EntityType.PROJECT, "proj-web", enforce=False, credit_limit=3)
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=16,
            entity_id="proj-web",
            actions={"triage": 5},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        assert ": AI Triage 6." in breach.body, breach.body
