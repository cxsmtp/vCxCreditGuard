"""Settings → Enforcement → Run self-test.

Against the fake tenant (and the built-in demo tenant), synthetic data only.
"""

from __future__ import annotations

import threading
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.db.base import utcnow
from app.db.session import get_session_factory
from app.models import (
    AuditLogEntry,
    CreditLimit,
    EnforcementAction,
    Exemption,
    LimitPeriodState,
    Notification,
)
from app.models.enums import EnforcementStatus, EntityType, LimitStatus
from app.models.selftest import EnforcementSelfTest
from app.services import (
    audit_chain,
    demo_service,
    demo_tenant,
    diagnostics,
    enforcement,
    evaluation,
    notifications,
    org_sync,
    settings_store,
)
from app.services import connection as connection_service
from app.services import enforcement_selftest as selftest
from app.services.audit import AuditActor
from app.services.periods import current_window
from tests.conftest import make_api_key
from tests.fake_tenant import CLIENT_UUID, FakeTenant, populated_tenant

ACTOR = AuditActor.system("selftest-test")
AI = set(AI_ROLE_NAMES)


def setup_tenant(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    db.commit()
    return tenant, client


def writes(tenant: FakeTenant, since: int = 0) -> list[tuple[str, str]]:
    """Requests that change the tenant (the token exchange is not one)."""
    return [
        (method, path)
        for method, path in tenant.requests[since:]
        if method in ("POST", "DELETE", "PUT", "PATCH") and not path.endswith("/token")
    ]


def request_for(user=None, project=None, actions=None) -> selftest.SelfTestRequest:
    return selftest.SelfTestRequest(
        user_id=user,
        project_id=project,
        project_actions=tuple(actions) if actions is not None else selftest.ALL_PROJECT_ACTIONS,
    )


def run(db, client, *, user=None, project=None, actions=None, confirm=None, demo=False):
    request = request_for(user, project, actions)
    if confirm is None:
        targets, _ = selftest.resolve_targets(db, request)
        confirm = {target.noun: target.label for target in targets}
    return selftest.run(db, client, request, actor=ACTOR, confirm=confirm, demo=demo)


def target_report(row: EnforcementSelfTest, noun: str) -> dict:
    return next(t for t in row.result["targets"] if t["target_type"] == noun)


def setting(report: dict, name: str) -> dict:
    return next(row for row in report["settings"] if row["setting"] == name)


def step(report: dict, name: str) -> dict:
    return next(entry for entry in report["steps"] if entry["step"] == name)


def run_actions(db: Session, row: EnforcementSelfTest) -> list[EnforcementAction]:
    db.expire_all()
    return list(
        db.scalars(
            select(EnforcementAction)
            .where(EnforcementAction.period_key == selftest.period_key_for(row.id))
            .order_by(EnforcementAction.id)
        )
    )


def make_limit(db: Session, *, entity_type, entity_id, credits=10, enforce=True) -> CreditLimit:
    limit = CreditLimit(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=entity_id,
        credit_limit=credits,
        period_type="monthly",
        enforce=enforce,
    )
    db.add(limit)
    db.commit()
    return limit


def period_state(db: Session, limit: CreditLimit, *, used, status=LimitStatus.OK):
    window = current_window(limit, utcnow())
    db.add(
        LimitPeriodState(
            limit_id=limit.id,
            period_key=window.key,
            period_start=window.start,
            period_end=window.end,
            credits_used=Decimal(used),
            usage_available=True,
            status=status,
        )
    )
    db.commit()


# ------------------------------------------------------------------- users


class TestUser:
    def test_a_user_passes_and_is_restored_exactly(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        before = list(tenant.role_mappings["user-alice"])

        row = run(db, client, user="user-alice")

        assert row.status == "passed", row.summary
        report = target_report(row, "user")
        assert [entry["step"] for entry in report["steps"]] == [
            "checks",
            "read_before",
            "apply",
            "verify_restricted",
            "restore",
            "verify_restored",
        ]
        assert all(entry["ok"] for entry in report["steps"])
        assert all(isinstance(entry["ms"], int) for entry in report["steps"])
        direct_ai = setting(report, "Direct AI roles")
        assert set(direct_ai["before"]) == AI
        assert direct_ai["restricted"] == []
        assert direct_ai["restored"] == direct_ai["before"]
        assert direct_ai["changed"] and direct_ai["restored_equal"]
        # Only the AI roles were touched.
        others = setting(report, "Direct client roles")
        assert "view-projects" in others["restricted"]
        assert sorted(tenant.role_mappings["user-alice"]) == sorted(before)

        # A real, tracked restriction, made and restored by the normal code.
        [action] = run_actions(db, row)
        assert action.limit_id is None
        assert action.status == EnforcementStatus.REVERSED
        assert action.reversal_reason == selftest.SELFTEST_REASON
        assert action.entity_type == EntityType.USER
        assert selftest.is_selftest_action(action)
        assert {entry["name"] for entry in action.undo_snapshot["removed_roles"]} == AI
        assert report["cannot_bite"] == []

    def test_the_restriction_code_raises_no_notifications(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        run(db, client, user="user-alice")
        assert db.scalar(select(func.count()).select_from(Notification)) == 0

    def test_a_composite_route_is_reported_as_cannot_bite(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_client_role("scan-fusion", contains=["create-fusion-scan", "view-scans"])
        tenant.add_group(group_id="grp-fusion", name="Fusion users", roles=["scan-fusion"])
        tenant.join_group("user-alice", "grp-fusion")
        tenant, client = setup_tenant(db, tenant)

        row = run(db, client, user="user-alice")

        assert row.status == "warning", row.summary
        report = target_report(row, "user")
        assert [item["role"] for item in report["cannot_bite"]] == ["create-fusion-scan"]
        via = " ".join(report["cannot_bite"][0]["via"])
        assert "scan-fusion" in via and "Fusion users" in via
        assert "cannot bite" in " ".join(report["warnings"])
        assert "cannot bite" in row.summary
        # The direct mappings were still removed, and put back.
        assert setting(report, "Direct AI roles")["restricted"] == []
        assert set(AI) <= set(tenant.role_mappings["user-alice"])
        assert all(entry["ok"] for entry in report["steps"])

    def test_role_order_does_not_count_and_an_extra_role_does(self, db: Session) -> None:
        tenant = FakeTenant()
        tenant.add_user(
            user_id="u1",
            username="dana@example.com",
            first_name="Dana",
            last_name="Diaz",
            roles=["view-scans", *AI_ROLE_NAMES, "view-projects"],
        )
        tenant, client = setup_tenant(db, tenant)

        row = run(db, client, user="u1")
        # The restore maps the roles back at the end of the list: another order.
        assert tenant.role_mappings["u1"][:2] == ["view-scans", "view-projects"]
        assert row.status == "passed", row.summary

        # Someone grants a role while the test runs: a difference, reported,
        # and never "restored" away.
        def grant(request: httpx.Request) -> None:
            if (
                request.method == "POST"
                and "/role-mappings/clients/" in request.url.path
                and "view-risk-management" not in tenant.role_mappings["u1"]
            ):
                tenant.role_mappings["u1"].append("view-risk-management")

        tenant.on_request = grant
        row = run(db, client, user="u1")
        tenant.on_request = None

        assert row.status == "failed"
        report = target_report(row, "user")
        verify = step(report, "verify_restored")
        assert not verify["ok"]
        assert "+view-risk-management" in verify["detail"]
        assert not setting(report, "Direct client roles")["restored_equal"]
        # What the restriction took is back, so nothing is held for a retry.
        assert report["restore"]["held"] == []
        [action] = run_actions(db, row)
        assert action.status == EnforcementStatus.REVERSED
        assert "view-risk-management" in tenant.role_mappings["u1"]
        assert set(tenant.role_mappings["u1"]) >= AI


# ---------------------------------------------------------------- projects


class TestProject:
    def test_a_project_passes(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}

        row = run(db, client, project="proj-api")

        assert row.status == "passed", row.summary
        report = target_report(row, "project")
        outcomes = {item["kind"]: item["outcome"] for item in report["kinds"]}
        assert outcomes == {
            "disable_auto_triage": "applied",
            "disable_pr_remediation": "applied",
            "disable_fusion": "applied",
            "disable_repo_fusion": "applied",
        }
        assert setting(report, "Auto Triage: on")["restricted"] is False
        assert setting(report, "PR triage and remediation: severities")["restricted"] == []
        assert setting(report, "Fusion: value")["restricted"] == "false"
        assert setting(report, "Fusion: allowOverride")["restricted"] is False
        assert (
            setting(report, "Repository Fusion (fusionScanConfig)")["restricted"]["enabled"]
            is False
        )
        assert all(row_["restored_equal"] for row_ in report["settings"])
        assert tenant.auto_triage["proj-api"]["enabled"] is True
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]
        assert tenant.fusion_setting("proj-api")["value"] == "true"
        assert tenant.repo_fusion["repo-1"]["enabled"] is True
        assert {a.status for a in run_actions(db, row)} == {EnforcementStatus.REVERSED}

    def test_only_the_chosen_settings_are_tested(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        row = run(db, client, project="proj-api", actions=["auto_triage"])
        report = target_report(row, "project")
        assert [item["kind"] for item in report["kinds"]] == ["disable_auto_triage"]
        assert not tenant.config_patches  # Fusion untouched
        assert row.status == "passed"

    def test_a_setting_the_restriction_leaves_alone_is_a_warning(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.repo_severities_editable = False
        row = run(db, client, project="proj-api", actions=["pr_remediation"])
        assert row.status == "warning", row.summary
        report = target_report(row, "project")
        assert report["kinds"][0]["outcome"] == "not_restricted"
        assert "cannot turn it off" in " ".join(report["warnings"])

    def test_an_inherited_fusion_value_is_not_tested(self, db: Session) -> None:
        """Restore can only write Fusion at the project level, which would pin an
        inherited value there: the self-test leaves it alone and says so."""
        tenant, client = setup_tenant(db)
        tenant.set_fusion_setting("proj-web", value="true", origin="Tenant")
        before = dict(tenant.fusion_setting("proj-web"))

        check = selftest.check(db, client, request_for(project="proj-web"), demo=False)
        assert "inherited from the tenant" in " ".join(check.targets[0]["changes"])
        assert "inherited from the tenant" in " ".join(check.warnings)

        row = run(db, client, project="proj-web", actions=["fusion"])
        report = target_report(row, "project")
        assert row.status == "warning", row.summary
        assert [item["outcome"] for item in report["kinds"]] == ["not_applicable"]
        assert "pin it on the project" in " ".join(report["warnings"])
        assert not tenant.config_patches
        assert tenant.fusion_setting("proj-web") == before
        assert not run_actions(db, row)

        # With other settings chosen, those are tested and Fusion still is not.
        row = run(db, client, project="proj-api", actions=["auto_triage", "fusion"])
        assert row.status == "passed"
        tenant.set_fusion_setting("proj-api", value="false", origin="Tenant")
        row = run(db, client, project="proj-api", actions=["auto_triage", "fusion"])
        report = target_report(row, "project")
        outcomes = {item["kind"]: item["outcome"] for item in report["kinds"]}
        assert outcomes["disable_auto_triage"] == "applied"
        assert outcomes["disable_fusion"] == "not_applicable"
        assert tenant.fusion_setting("proj-api")["originLevel"] == "Tenant"
        assert row.status == "warning"

    def test_an_inherited_ai_agent_configuration_is_not_tested(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        original = tenant._auto_triage_response

        def tenant_scope(request: httpx.Request, path: str):  # type: ignore[no-untyped-def]
            response = original(request, path)
            if request.method != "GET":
                return response
            payload = response.json()
            payload["scope"] = "tenant"
            return httpx.Response(200, json=payload)

        tenant._auto_triage_response = tenant_scope  # type: ignore[method-assign]
        check = selftest.check(
            db, client, request_for(project="proj-api", actions=["auto_triage"]), demo=False
        )
        assert "it is inherited" in " ".join(check.targets[0]["changes"])
        assert "it is inherited" in " ".join(check.warnings)

        row = run(db, client, project="proj-api", actions=["auto_triage", "pr_remediation"])
        report = target_report(row, "project")
        outcomes = {item["kind"]: item["outcome"] for item in report["kinds"]}
        assert outcomes == {
            "disable_pr_remediation": "applied",
            "disable_auto_triage": "not_applicable",
        }
        assert not tenant.auto_triage_puts
        assert "it is inherited" in " ".join(report["warnings"])
        assert row.status == "warning", row.summary

    def test_a_change_in_where_fusion_is_set_is_a_failure(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        original = tenant._project_config_response
        patches = {"count": 0}

        def drift_on_restore(request: httpx.Request, params):  # type: ignore[no-untyped-def]
            response = original(request, params)
            if request.method == "PATCH":
                patches["count"] += 1
                if patches["count"] == 2:  # the restore
                    tenant.fusion_setting("proj-web")["originLevel"] = "Tenant"
            return response

        tenant._project_config_response = drift_on_restore  # type: ignore[method-assign]
        row = run(db, client, project="proj-web", actions=["fusion"])
        report = target_report(row, "project")
        assert row.status == "failed", row.summary
        assert not setting(report, "Fusion: origin level")["restored_equal"]
        assert "Fusion: origin level" in step(report, "verify_restored")["detail"]

    def test_a_pinned_ai_configuration_shows_as_a_failure(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        original = tenant._auto_triage_response
        puts = {"count": 0}

        def pin_on_restore(request: httpx.Request, path: str):  # type: ignore[no-untyped-def]
            response = original(request, path)
            if request.method == "PUT":
                puts["count"] += 1
                if puts["count"] == 2:  # the restore
                    tenant.allow_ai_usage["proj-web"] = False
            return response

        tenant._auto_triage_response = pin_on_restore  # type: ignore[method-assign]
        row = run(db, client, project="proj-web", actions=["auto_triage"])
        report = target_report(row, "project")
        assert setting(report, "AI agent configuration: scope")["before"] == "project"
        assert not setting(report, "AI agent configuration: allowAiUsage")["restored_equal"]
        assert row.status == "failed"

    def test_both_targets_in_one_run(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        row = run(db, client, user="user-bob", project="proj-web")
        assert row.status == "passed", row.summary
        assert [t["target_type"] for t in row.result["targets"]] == ["user", "project"]
        assert row.user_label == "Bob Baker" and row.project_label == "payments/web"


# -------------------------------------------------------- failures, restore


class TestRestoreAlways:
    def test_a_failed_verification_still_restores(self, db: Session) -> None:
        tenant, client = setup_tenant(db)

        # Someone maps a role back right after the restriction removed it.
        def drift(request: httpx.Request) -> None:
            if (
                request.method == "GET"
                and request.url.path.endswith("/role-mappings/clients/" + CLIENT_UUID)
                and tenant.requests.count(("DELETE", request.url.path)) == 1
                and "manage-fusion" not in tenant.role_mappings["user-alice"]
            ):
                tenant.role_mappings["user-alice"].append("manage-fusion")

        tenant.on_request = drift
        row = run(db, client, user="user-alice")
        tenant.on_request = None

        report = target_report(row, "user")
        assert row.status == "failed"
        assert not step(report, "verify_restricted")["ok"]
        assert "manage-fusion" in step(report, "verify_restricted")["detail"]
        assert step(report, "restore")["ok"]
        assert step(report, "verify_restored")["ok"]
        assert set(tenant.role_mappings["user-alice"]) >= AI

    def test_an_error_in_verification_still_restores(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)

        def boom(*_args, **_kwargs):
            raise RuntimeError("verification blew up")

        monkeypatch.setattr(selftest, "_verify_restricted", boom)
        row = run(db, client, user="user-alice")

        report = target_report(row, "user")
        assert row.status == "failed"
        assert "verification blew up" in step(report, "verify_restricted")["detail"]
        assert step(report, "restore")["ok"]
        assert set(tenant.role_mappings["user-alice"]) >= AI
        assert all(not enforcement.may_be_in_force(a) for a in run_actions(db, row))

    def test_an_error_while_applying_still_restores(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The write landed, then something broke before the outcome was recorded."""
        tenant, client = setup_tenant(db)
        real = enforcement._enforce_target

        def crash_after(*args, **kwargs):
            real(*args, **kwargs)
            raise RuntimeError("process hiccup")

        monkeypatch.setattr(enforcement, "_enforce_target", crash_after)
        row = run(db, client, user="user-alice")

        report = target_report(row, "user")
        assert not step(report, "apply")["ok"]
        assert step(report, "restore")["ok"]
        assert step(report, "verify_restored")["ok"]
        assert set(tenant.role_mappings["user-alice"]) >= AI

    def test_a_failed_restore_is_held_in_doubt_and_the_next_cycle_restores_it(
        self, db: Session
    ) -> None:
        tenant, client = setup_tenant(db)
        tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400

        row = run(db, client, user="user-alice")

        assert row.status == "restore_failed"
        report = target_report(row, "user")
        assert not step(report, "restore")["ok"]
        assert not step(report, "verify_restored")["ok"]
        assert "RESTORE FAILED" in row.summary
        # The target is still restricted, and the record says so: in doubt,
        # in force, with the exact snapshot.
        assert not AI & set(tenant.role_mappings["user-alice"])
        [action] = run_actions(db, row)
        assert action.undo_snapshot[enforcement.OUTCOME_UNKNOWN] is True
        assert enforcement.may_be_in_force(action)
        assert action.error
        snapshot = report["restore"]["actions"][0]["snapshot"]
        assert {entry["name"] for entry in snapshot["removed_roles"]} == AI
        assert report["restore"]["held"] == [action.id]
        # A prominent alert, with Restore offered on it.
        alert = db.scalar(select(Notification).where(Notification.title.like("Self-test%")))
        assert alert is not None and alert.severity == "critical"
        assert alert.enforcement_action_id == action.id
        assert "create-fusion-scan" in alert.body
        assert (
            db.scalar(
                select(AuditLogEntry).where(AuditLogEntry.action == "selftest.restore_failed")
            ).before
            == snapshot
        )

        # The next cycle restores it through the normal sweep.
        tenant.fail_requests.clear()
        evaluation.evaluate_all(db, client=client)
        db.commit()
        db.expire_all()
        action = db.get(EnforcementAction, action.id)
        assert action.status == EnforcementStatus.REVERSED
        assert set(tenant.role_mappings["user-alice"]) >= AI

    def test_a_restore_not_kept_is_held_for_the_cycle(self, db: Session) -> None:
        """The tenant answers OK to the restore but does not keep it."""
        tenant, client = setup_tenant(db)
        original = tenant._role_mapping_response
        dropping = {"on": True}

        def drop_posts(request: httpx.Request, path: str) -> httpx.Response:
            if request.method == "POST" and dropping["on"]:
                return httpx.Response(204)
            return original(request, path)

        tenant._role_mapping_response = drop_posts  # type: ignore[method-assign]
        row = run(db, client, user="user-alice")

        assert row.status == "restore_failed"
        report = target_report(row, "user")
        assert "did not read back as mapped" in " ".join(report["failures"])
        [action] = run_actions(db, row)
        assert action.status == EnforcementStatus.FAILED
        assert action.undo_snapshot[enforcement.OUTCOME_UNKNOWN] is True
        assert enforcement.may_be_in_force(action)

        dropping["on"] = False
        evaluation.evaluate_all(db, client=client)
        db.commit()
        db.expire_all()
        assert db.get(EnforcementAction, action.id).status == EnforcementStatus.REVERSED
        assert set(tenant.role_mappings["user-alice"]) >= AI

    def test_the_full_cycle_retries_the_restore(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import cycle

        tenant = populated_tenant()
        connection_service.save_connection(db, api_key=make_api_key(), actor=ACTOR)
        db.commit()
        monkeypatch.setattr(connection_service, "get_client", lambda _session: tenant.client())
        tenant, client = setup_tenant(db, tenant)
        tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
        row = run(db, client, user="user-alice")
        assert row.status == "restore_failed"

        tenant.fail_requests.clear()
        cycle.run_cycle(trigger="manual")
        assert set(tenant.role_mappings["user-alice"]) >= AI
        assert not any(enforcement.may_be_in_force(a) for a in run_actions(db, row))


# ---------------------------------------------------------------- refusals


class TestRefusals:
    def refused(self, db, client, **kwargs) -> list[str]:
        with pytest.raises(selftest.SelfTestRefused) as caught:
            run(db, client, **kwargs)
        return [refusal.code for refusal in caught.value.refusals]

    def test_a_target_restricted_now(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-alice")
        enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-11", actor=ACTOR)
        db.commit()
        since = len(tenant.requests)
        assert self.refused(db, client, user="user-alice") == ["restricted"]
        assert not writes(tenant, since)

    def test_a_restriction_in_doubt_counts(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        db.add(
            EnforcementAction(
                idempotency_key="x|y|disable_auto_triage|proj-api",
                kind="disable_auto_triage",
                status=EnforcementStatus.FAILED,
                entity_type=EntityType.PROJECT,
                entity_id="proj-api",
                target_type=enforcement.TARGET_PROJECT,
                target_id="proj-api",
                undo_snapshot={
                    "kind": "disable_auto_triage",
                    "enabled_before": True,
                    enforcement.OUTCOME_UNKNOWN: True,
                },
                created_at=utcnow(),
                attempts=1,
            )
        )
        db.commit()
        assert self.refused(db, client, project="proj-api") == ["restricted"]

    def test_a_user_budget_near_its_limit(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-alice", enforce=False)
        period_state(db, limit, used=9)  # 90% of 10, warning threshold 80%
        assert self.refused(db, client, user="user-alice") == ["near_limit"]

    def test_a_budget_well_within_its_limit_is_fine(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-alice")
        period_state(db, limit, used=2)
        assert run(db, client, user="user-alice").status == "passed"

    def test_an_application_budget_covering_the_project(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.APPLICATION, entity_id="app-payments")
        period_state(db, limit, used=1, status=LimitStatus.WARNED)
        assert self.refused(db, client, project="proj-api") == ["near_limit"]

    def test_an_inactive_budget_does_not_count(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-api")
        period_state(db, limit, used=10, status=LimitStatus.BREACHED)
        limit.is_active = False
        db.commit()
        assert run(db, client, project="proj-api", actions=["auto_triage"]).status == "passed"

    def test_a_user_with_a_protected_role(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_user(
            user_id="user-root",
            username="root@example.com",
            first_name="Root",
            last_name="Admin",
            roles=[*AI_ROLE_NAMES, "ast-admin"],
        )
        _tenant, client = setup_tenant(db, tenant)
        # No role is protected by default; an admin's list is honoured.
        settings_store.set_value(db, settings_store.KEY_PROTECTED_ROLES, "ast-admin, iam-admin")
        db.commit()
        assert self.refused(db, client, user="user-root") == ["protected"]

    def test_a_protected_role_granted_since_the_sync(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        settings_store.set_value(db, settings_store.KEY_PROTECTED_ROLES, "ast-admin, iam-admin")
        db.commit()
        tenant.add_client_role("iam-admin")
        tenant.role_mappings["user-alice"].append("iam-admin")
        before = list(tenant.role_mappings["user-alice"])

        row = run(db, client, user="user-alice")

        report = target_report(row, "user")
        assert row.status == "failed"
        assert "protected role" in step(report, "read_before")["detail"]
        assert [entry["step"] for entry in report["steps"]] == ["checks", "read_before"]
        assert tenant.role_mappings["user-alice"] == before
        assert not run_actions(db, row)

    def test_the_api_key_user(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        _tenant, client = setup_tenant(db)
        monkeypatch.setattr(connection_service, "api_key_subject", lambda _session: "user-bob")
        assert self.refused(db, client, user="user-bob") == ["api_key_user"]

    def test_an_exempt_target(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        db.add(Exemption(entity_type=EntityType.PROJECT, entity_id="proj-web", reason="break"))
        db.commit()
        assert self.refused(db, client, project="proj-web") == ["exempt"]

    def test_a_project_with_a_running_scan(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.add_scan(
            project_id="proj-api",
            scan_id="scan-running",
            initiator="alice.archer@example.com",
            completed_at=utcnow(),
            status="Running",
        )
        assert self.refused(db, client, project="proj-api") == ["scan_running"]

    def test_unreadable_scans_are_a_warning(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.fail_requests[("GET", "/api/scans")] = 400
        row = run(db, client, project="proj-web", actions=["auto_triage"])
        assert row.status == "passed"
        assert "could not be checked" in " ".join(row.result["warnings"])

    def test_a_demo_target_outside_demo_mode(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        demo_service.seed(db)
        db.commit()
        assert self.refused(db, client, user="demo-user-ada") == ["demo"]

    def test_a_refusal_is_audited_and_changes_nothing(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        db.add(Exemption(entity_type=EntityType.USER, entity_id="user-alice", reason="x"))
        db.commit()
        self.refused(db, client, user="user-alice")
        assert not writes(tenant)
        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "selftest.refused"))
        assert entry is not None and "exempt" in entry.detail
        assert db.scalar(select(func.count()).select_from(EnforcementSelfTest)) == 0

    def test_the_name_must_be_typed(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        with pytest.raises(selftest.ConfirmationMismatch):
            run(db, client, user="user-alice", confirm={"user": "alice"})
        with pytest.raises(selftest.ConfirmationMismatch):
            run(db, client, user="user-alice", project="proj-api", confirm={"user": "Alice Archer"})
        assert not writes(tenant)

    def test_nothing_chosen(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        with pytest.raises(selftest.SelfTestInvalid):
            run(db, client, confirm={})


# -------------------------------------------------------------- concurrency


class TestConcurrency:
    def test_a_second_self_test_is_refused_while_one_runs(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        seen: list[Exception] = []

        def second(request: httpx.Request) -> None:
            if request.method == "DELETE" and not seen:
                other = get_session_factory()()
                try:
                    run(other, client, user="user-bob")
                except Exception as exc:  # noqa: BLE001
                    seen.append(exc)
                finally:
                    other.close()

        tenant.on_request = second
        row = run(db, client, user="user-alice")
        tenant.on_request = None
        assert row.status == "passed"
        assert len(seen) == 1 and isinstance(seen[0], selftest.SelfTestBusy)
        assert set(tenant.role_mappings["user-bob"]) >= AI

    def test_a_run_another_process_holds_is_respected(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        db.add(EnforcementSelfTest(started_at=utcnow(), status="running"))
        db.commit()
        with pytest.raises(selftest.SelfTestBusy):
            run(db, client, user="user-alice")
        assert selftest.check(db, client, request_for("user-alice"), demo=False).busy

    def test_a_stale_running_row_reads_as_interrupted(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        stale = EnforcementSelfTest(
            started_at=utcnow() - selftest.STALE_AFTER * 2, status="running"
        )
        db.add(stale)
        db.commit()
        assert selftest.as_dict(stale)["status"] == "interrupted"
        assert run(db, client, user="user-alice").status == "passed"

    def test_a_cycle_on_the_same_target_waits_for_the_self_test(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-alice")
        limit_id = limit.id
        cycle_done = threading.Event()
        started = threading.Event()
        errors: list[BaseException] = []

        def the_cycle() -> None:
            session = get_session_factory()()
            try:
                started.set()
                enforcement.apply_enforcement(
                    session,
                    client,
                    limit=session.get(CreditLimit, limit_id),
                    period_key="2026-11",
                    actor=AuditActor.system("scheduler"),
                )
                session.commit()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                session.close()
                cycle_done.set()

        worker = threading.Thread(target=the_cycle)

        def start_cycle(request: httpx.Request) -> None:
            if request.method == "DELETE" and not started.is_set():
                worker.start()
                started.wait(5)

        tenant.on_request = start_cycle
        row = run(db, client, user="user-alice")
        tenant.on_request = None
        assert cycle_done.wait(10)
        worker.join(5)
        assert not errors

        # The cycle's write came after the self-test's restore, and the
        # self-test read the state back as before.
        writes = [
            method
            for method, path in tenant.requests
            if "/role-mappings/clients/" in path and method in ("POST", "DELETE")
        ]
        assert writes == ["DELETE", "POST", "DELETE"]
        assert row.status == "passed", row.summary
        db.expire_all()
        real = db.scalar(select(EnforcementAction).where(EnforcementAction.limit_id == limit_id))
        assert real.status == EnforcementStatus.APPLIED
        assert {entry["name"] for entry in real.undo_snapshot["removed_roles"]} == AI

    def test_suppression_is_per_thread(self, db: Session) -> None:
        seen: list[object] = []

        def other_thread() -> None:
            session = get_session_factory()()
            try:
                seen.append(
                    notifications.notify(
                        session, category="enforcement", severity="info", title="elsewhere"
                    )
                )
                session.commit()
            finally:
                session.close()

        with notifications.suppressed():
            assert notifications.notify(db, category="x", severity="info", title="t") is None
            worker = threading.Thread(target=other_thread)
            worker.start()
            worker.join(5)
        assert seen and seen[0] is not None


# ------------------------------------------------------------- audit, notes


class TestAuditAndNotes:
    def test_start_each_step_outcome_and_restore_are_audited(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        row = run(db, client, user="user-alice")
        entries = [
            entry
            for entry in db.scalars(select(AuditLogEntry).order_by(AuditLogEntry.id))
            if entry.action != "org.synced"
        ]
        actions = [entry.action for entry in entries]
        assert actions[0] == "selftest.started"
        assert actions[-1] == "selftest.finished"
        assert actions.count("selftest.step") == 6
        assert "enforcement.applied" in actions
        assert "enforcement.reversed" in actions
        assert actions.index("enforcement.applied") < actions.index("enforcement.reversed")
        steps = [e.after["step"] for e in entries if e.action == "selftest.step"]
        assert steps == [
            "checks",
            "read_before",
            "apply",
            "verify_restricted",
            "restore",
            "verify_restored",
        ]
        finished = entries[-1]
        assert finished.target_id == str(row.id)
        assert finished.after["status"] == "passed"
        assert audit_chain.verify_chain(db).ok

    def test_monitor_only_and_paused_are_said(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, True)
        db.commit()
        row = run(db, client, user="user-alice")
        assert row.status == "passed"
        notes = " ".join(row.result["notes"])
        assert "paused" in notes
        assert "monitor only" in notes
        make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-tools", enforce=True)
        assert "monitor only" not in " ".join(selftest.enforcement_notes(db))

    def test_only_the_last_results_are_kept(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        for index in range(selftest.KEEP_RESULTS + 2):
            db.add(EnforcementSelfTest(started_at=utcnow(), status="passed", summary=str(index)))
        db.commit()
        run(db, client, user="user-alice")
        assert db.scalar(select(func.count()).select_from(EnforcementSelfTest)) == (
            selftest.KEEP_RESULTS
        )

    def test_diagnostics_show_the_last_self_test(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        report = diagnostics.run_diagnostics(db)
        assert "enforcement_selftest" not in {c.key for c in report.checks}
        run(db, client, user="user-alice")
        check = next(
            c for c in diagnostics.run_diagnostics(db).checks if c.key == "enforcement_selftest"
        )
        assert check.status == diagnostics.OK
        assert "passed" in check.detail

        tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
        run(db, client, user="user-bob")
        check = next(
            c for c in diagnostics.run_diagnostics(db).checks if c.key == "enforcement_selftest"
        )
        assert check.status == diagnostics.FAIL
        assert check.remediation


# --------------------------------------------------------------------- API


@pytest.fixture
def api_tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    tenant, _client = setup_tenant(db)
    monkeypatch.setattr(connection_service, "get_client", lambda _session: tenant.client())
    return tenant


class TestApi:
    def test_viewers_get_403(self, viewer_client: TestClient, api_tenant: FakeTenant) -> None:
        assert viewer_client.get("/api/settings/selftest").status_code == 403
        response = viewer_client.post(
            "/api/settings/selftest/check", json={"user_id": "user-alice"}
        )
        assert response.status_code == 403
        response = viewer_client.post(
            "/api/settings/selftest/run",
            json={"user_id": "user-alice", "confirm_user": "Alice Archer"},
        )
        assert response.status_code == 403
        assert not writes(api_tenant)

    def test_check_then_run(self, admin_client: TestClient, api_tenant: FakeTenant) -> None:
        response = admin_client.post(
            "/api/settings/selftest/check",
            json={"user_id": "user-alice", "project_id": "proj-api", "project_actions": ["fusion"]},
        )
        assert response.status_code == 200, response.text
        plan = response.json()
        assert plan["allowed"] is True
        assert [t["label"] for t in plan["targets"]] == ["Alice Archer", "payments/api"]
        user_changes = " ".join(plan["targets"][0]["changes"])
        assert "create-fusion-scan" in user_changes
        assert "Fusion" in " ".join(plan["targets"][1]["changes"])
        assert "few seconds" in plan["duration"]
        # The check never writes.
        assert not writes(api_tenant)

        wrong = admin_client.post(
            "/api/settings/selftest/run",
            json={"user_id": "user-alice", "confirm_user": "Alice"},
        )
        assert wrong.status_code == 400
        assert wrong.json()["detail"]["code"] == "confirmation"

        done = admin_client.post(
            "/api/settings/selftest/run",
            json={
                "user_id": "user-alice",
                "project_id": "proj-api",
                "project_actions": ["fusion"],
                "confirm_user": "Alice Archer",
                "confirm_project": "payments/api",
            },
        )
        assert done.status_code == 200, done.text
        result = done.json()["result"]
        assert result["status"] == "passed"
        assert result["actor_name"] == "admin"

        listing = admin_client.get("/api/settings/selftest").json()
        assert listing["results"][0]["id"] == result["id"]
        assert listing["running"] is False
        assert listing["keep"] == selftest.KEEP_RESULTS

    def test_a_refusal_is_409_with_reasons(
        self, admin_client: TestClient, api_tenant: FakeTenant, db: Session
    ) -> None:
        db.add(Exemption(entity_type=EntityType.USER, entity_id="user-alice", reason="x"))
        db.commit()
        check = admin_client.post("/api/settings/selftest/check", json={"user_id": "user-alice"})
        assert check.json()["allowed"] is False
        assert check.json()["refusals"][0]["code"] == "exempt"
        response = admin_client.post(
            "/api/settings/selftest/run",
            json={"user_id": "user-alice", "confirm_user": "Alice Archer"},
        )
        assert response.status_code == 409
        assert "exempt" in " ".join(response.json()["detail"]["problems"])


class TestDemo:
    @pytest.fixture(autouse=True)
    def fresh_demo_tenant(self):
        demo_tenant.tenant().reset()
        yield
        demo_tenant.tenant().reset()

    def test_demo_mode_runs_against_the_demo_tenant(
        self, admin_client: TestClient, db: Session
    ) -> None:
        demo_service.seed(db)
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()

        check = admin_client.post(
            "/api/settings/selftest/check", json={"user_id": "demo-user-grace"}
        ).json()
        assert check["allowed"] is True and check["demo"] is True
        assert "demo tenant" in " ".join(check["notes"])

        response = admin_client.post(
            "/api/settings/selftest/run",
            json={"user_id": "demo-user-grace", "confirm_user": "Grace Hopper"},
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert result["demo"] is True
        assert result["status"] == "warning"  # Grace keeps create-fusion-scan via a group
        user = result["result"]["targets"][0]
        assert [item["role"] for item in user["cannot_bite"]] == ["create-fusion-scan"]
        assert all(entry["ok"] for entry in user["steps"])

        project = admin_client.post(
            "/api/settings/selftest/run",
            json={"project_id": "demo-proj-web", "confirm_project": "payments/web"},
        ).json()["result"]
        assert project["status"] == "passed", project["summary"]
        state = demo_tenant.tenant().state
        assert state["projects"]["demo-proj-web"]["auto_triage"]["enabled"] is True
        assert state["repos"]["demo-repo-1"]["fusionScanConfig"]["enabled"] is True

    def test_demo_mode_refuses_a_real_target(self, db: Session) -> None:
        _tenant, _client = setup_tenant(db)
        demo_service.seed(db)
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()
        with pytest.raises(selftest.SelfTestRefused) as caught:
            run(db, demo_tenant.client(), user="user-alice", demo=True)
        assert caught.value.refusals[0].code == "demo"


# ------------------------------------------------------ review follow-ups


def held_restriction(db: Session, client, tenant: FakeTenant):
    """A self-test whose restore failed: Alice stays restricted, held in doubt."""
    tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
    row = run(db, client, user="user-alice")
    assert row.status == "restore_failed"
    [held] = run_actions(db, row)
    tenant.fail_requests.clear()
    return row, held


class TestCleanup:
    def test_restore_on_the_alert_keeps_a_real_budgets_restriction(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)
        monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
        _row, held = held_restriction(db, client, tenant)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-alice")
        enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-11", actor=ACTOR)
        db.commit()

        response = admin_client.post(f"/api/notifications/enforcements/{held.id}/restore")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["restored"] is False
        assert "a real budget still restricts Alice Archer" in body["message"]
        db.expire_all()
        held = db.get(EnforcementAction, held.id)
        real = db.scalar(select(EnforcementAction).where(EnforcementAction.limit_id == limit.id))
        assert held.status == EnforcementStatus.REVERSED
        assert held.reversal_reason == selftest.SELFTEST_CLEANUP_REASON
        assert real.status == EnforcementStatus.APPLIED
        assert not AI & set(tenant.role_mappings["user-alice"])
        # The real restriction now carries what must eventually be given back.
        assert {e["name"] for e in real.undo_snapshot["removed_roles"]} == AI

    def test_restore_on_the_alert_alone_gives_the_access_back(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)
        monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
        _row, held = held_restriction(db, client, tenant)
        response = admin_client.post(f"/api/notifications/enforcements/{held.id}/restore")
        assert response.status_code == 200, response.text
        assert set(tenant.role_mappings["user-alice"]) >= AI

    def test_the_sweep_lifts_a_hold_as_selftest_cleanup(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        _row, held = held_restriction(db, client, tenant)
        evaluation.evaluate_all(db, client=client)
        db.commit()
        db.expire_all()
        assert db.get(EnforcementAction, held.id).reversal_reason == "selftest_cleanup"
        entry = db.scalar(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "enforcement.reversed")
            .order_by(AuditLogEntry.id.desc())
        )
        assert entry.detail == "Access restored (a self-test's restriction was cleaned up)."
        notice = db.scalar(select(Notification).where(Notification.title.like("%restored%")))
        assert notice is not None and "self-test" in notice.body

    def test_in_doubt_holds_count_as_restrictions_in_force(
        self, admin_client: TestClient, db: Session
    ) -> None:
        tenant = populated_tenant()
        tenant.add_user(user_id="u-held", username="held@example.com", roles=list(AI_ROLE_NAMES))
        tenant, client = setup_tenant(db, tenant)
        original = tenant._role_mapping_response

        def drop_posts(request: httpx.Request, path: str) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(204)
            return original(request, path)

        tenant._role_mapping_response = drop_posts  # type: ignore[method-assign]
        row = run(db, client, user="u-held")
        [held] = run_actions(db, row)
        assert held.status == EnforcementStatus.FAILED and enforcement.may_be_in_force(held)
        assert [a.id for a in selftest.unsettled_in_force(db)] == [held.id]
        status = admin_client.get("/api/ops/status").json()
        assert any(value == 1 for key, value in status.items() if "restrict" in key), status


class TestDemoHolds:
    @pytest.fixture(autouse=True)
    def fresh_demo_tenant(self):
        demo_tenant.tenant().reset()
        yield
        demo_tenant.tenant().reset()

    def held_demo(self, db: Session, monkeypatch: pytest.MonkeyPatch):
        demo_service.seed(db)
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()
        real_iam = demo_tenant.DemoTenant._iam

        def failing_posts(self, method, path, body):  # type: ignore[no-untyped-def]
            if method == "POST" and "role-mappings" in path:
                return httpx.Response(500, json={"message": "down"})
            return real_iam(self, method, path, body)

        monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", failing_posts)
        row = run(db, demo_tenant.client(), user="demo-user-ada", demo=True)
        assert row.status == "restore_failed"
        monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", real_iam)
        [held] = run_actions(db, row)
        return held

    def test_the_demo_cycle_restores_a_demo_hold(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import cycle

        held = self.held_demo(db, monkeypatch)
        assert not AI & set(demo_tenant.tenant().state["users"]["demo-user-ada"])
        check = next(
            c for c in diagnostics.run_diagnostics(db).checks if c.key == "enforcement_selftest"
        )
        assert check.status == diagnostics.FAIL

        cycle.run_cycle(trigger="manual")

        db.expire_all()
        assert db.get(EnforcementAction, held.id).status == EnforcementStatus.REVERSED
        assert set(demo_tenant.tenant().state["users"]["demo-user-ada"]) >= AI
        check = next(
            c for c in diagnostics.run_diagnostics(db).checks if c.key == "enforcement_selftest"
        )
        assert check.status != diagnostics.FAIL

    def test_the_live_sweep_never_sends_a_demo_hold_to_the_tenant(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        live, client = setup_tenant(db)
        held = self.held_demo(db, monkeypatch)
        since = len(live.requests)
        evaluation.evaluate_all(db, client=client)
        db.commit()
        assert not [p for _m, p in live.requests[since:] if "demo-" in p]
        db.expire_all()
        assert enforcement.may_be_in_force(db.get(EnforcementAction, held.id))


class TestOneAtATime:
    def test_the_database_refuses_a_second_running_row(self, db: Session) -> None:
        from sqlalchemy.exc import IntegrityError

        db.add(EnforcementSelfTest(started_at=utcnow(), status="running"))
        db.commit()
        db.add(EnforcementSelfTest(started_at=utcnow(), status="running"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        db.add(EnforcementSelfTest(started_at=utcnow(), status="passed"))
        db.add(EnforcementSelfTest(started_at=utcnow(), status="passed"))
        db.commit()

    def test_a_row_inserted_meanwhile_is_busy_not_an_error(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Another process inserts its running row after this one's check."""
        _tenant, client = setup_tenant(db)
        real = selftest._check_confirmation

        def other_process_starts(targets, confirm):  # type: ignore[no-untyped-def]
            real(targets, confirm)
            other = get_session_factory()()
            other.add(EnforcementSelfTest(started_at=utcnow(), status="running"))
            other.commit()
            other.close()

        monkeypatch.setattr(selftest, "_check_confirmation", other_process_starts)
        with pytest.raises(selftest.SelfTestBusy):
            run(db, client, user="user-alice")

    def test_a_stale_running_row_is_rewritten_as_interrupted(self, db: Session) -> None:
        _tenant, client = setup_tenant(db)
        stale = EnforcementSelfTest(
            started_at=utcnow() - selftest.STALE_AFTER * 2, status="running"
        )
        db.add(stale)
        db.commit()
        assert run(db, client, user="user-alice").status == "passed"
        db.expire_all()
        stale = db.get(EnforcementSelfTest, stale.id)
        assert stale.status == "interrupted"
        assert stale.finished_at is not None and "Interrupted" in stale.summary

    def test_a_scan_started_after_the_first_check_is_caught_under_the_lock(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)
        # The first listing (before the lock) finds nothing; one starts before
        # the second (under the lock).
        calls = {"n": 0}
        real_running = selftest._running_scans

        def running_second_time(client_, project_id):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2:
                tenant.add_scan(
                    project_id=project_id,
                    scan_id="late-scan",
                    initiator=None,
                    completed_at=utcnow(),
                    status="Queued",
                )
            return real_running(client_, project_id)

        monkeypatch.setattr(selftest, "_running_scans", running_second_time)
        since = len(tenant.requests)
        row = run(db, client, project="proj-api", actions=["auto_triage"])
        report = target_report(row, "project")
        assert row.status == "failed"
        assert not step(report, "checks")["ok"]
        assert "scan is running or queued" in step(report, "checks")["detail"]
        assert not writes(tenant, since)
