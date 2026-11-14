"""Limits on what enforcement may do: the safety ceiling, pausing, protected
identities, changes that could not be undone, and several limits restricting the
same target."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.models import AuditLogEntry, CreditLimit, EnforcementAction, Notification
from app.models.enums import (
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    PeriodType,
    Severity,
)
from app.models.org import CxProject
from app.services import connection as connection_service
from app.services import enforcement, evaluation, ingestion, org_sync, settings_store
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import ALL_ROLES, FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
PERIOD = "2026-08"


def synced(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    return tenant, client


def limit_on(
    db: Session,
    entity_id: str,
    *,
    entity_type: EntityType = EntityType.USER,
    credit_limit: int = 1,
) -> CreditLimit:
    limit = CreditLimit(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=entity_id,
        credit_limit=credit_limit,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    return limit


def has_ai_roles(tenant: FakeTenant, user_id: str) -> bool:
    return all(role in tenant.role_mappings[user_id] for role in AI_ROLE_NAMES)


def breach_two_users(db: Session):
    """Harsh and Sean both go over an enforced limit in the same cycle."""
    tenant, client = synced(db)
    limit_on(db, "user-harsh")
    limit_on(db, "user-sean")
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)  # baseline
    tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
    tenant.set_user_credits(name="Sean Casey", credits=60)
    ingestion.ingest_usage(db, client)
    return tenant, client


def set_ceiling(db: Session, value: int) -> None:
    settings_store.set_value(db, settings_store.KEY_MAX_NEW_ENFORCEMENTS, value)
    db.commit()


class TestSafetyCeiling:
    def test_too_many_limits_breaching_at_once_restricts_nobody(self, db: Session) -> None:
        tenant, client = breach_two_users(db)
        set_ceiling(db, 1)

        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)

        # Not one of them, not the first few: nobody.
        assert has_ai_roles(tenant, "user-harsh") and has_ai_roles(tenant, "user-sean")
        assert result.enforced == 0 and result.deferred == 2
        assert result.enforcement_paused and "safety ceiling of 1" in result.enforcement_paused
        assert db.scalar(select(func.count()).select_from(EnforcementAction)) == 0

        guard = settings_store.enforcement_guard(db)
        assert guard.paused is True and "2 limits" in guard.pause_reason
        alert = db.scalar(
            select(Notification).where(Notification.title.like("Enforcement paused%"))
        )
        assert alert is not None and alert.severity == Severity.CRITICAL
        assert db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "enforcement.paused"))

    def test_it_stays_paused_until_an_admin_resumes(self, db: Session) -> None:
        tenant, client = breach_two_users(db)
        set_ceiling(db, 1)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)

        # Even with a single limit now over the line, nothing is applied.
        tenant.set_user_credits(name="Sean Casey", credits=5)
        ingestion.ingest_usage(db, client)
        again = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert again.enforced == 0 and has_ai_roles(tenant, "user-harsh")
        # One alert, not one per cycle.
        assert (
            db.scalar(
                select(func.count())
                .select_from(Notification)
                .where(Notification.title.like("Enforcement paused%"))
            )
            == 1
        )

        # The admin has looked, and resumes.
        settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, False)
        db.commit()
        resumed = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert resumed.enforced == 1
        assert not has_ai_roles(tenant, "user-harsh")

    def test_within_the_ceiling_enforcement_is_normal(self, db: Session) -> None:
        tenant, client = breach_two_users(db)
        set_ceiling(db, 2)
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert result.enforced == 2 and result.enforcement_paused is None
        assert not has_ai_roles(tenant, "user-harsh") and not has_ai_roles(tenant, "user-sean")

    def test_restrictions_already_in_place_do_not_count_towards_it(self, db: Session) -> None:
        tenant, client = breach_two_users(db)
        set_ceiling(db, 2)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        # Both are restricted. With a ceiling of 1 the next cycle must not trip:
        # nothing new is starting.
        set_ceiling(db, 1)
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert result.enforcement_paused is None
        assert settings_store.enforcement_guard(db).paused is False

    def test_zero_means_no_ceiling(self, db: Session) -> None:
        tenant, client = breach_two_users(db)
        set_ceiling(db, 0)
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert result.enforced == 2


class TestPause:
    def test_a_pause_stops_new_restrictions_but_not_restores(self, db: Session) -> None:
        tenant, client = breach_two_users(db)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert not has_ai_roles(tenant, "user-harsh")

        settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, True)
        db.commit()
        # Harsh's budget is raised while enforcement is paused: access comes back.
        harsh = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-harsh"))
        harsh.credit_limit = 10_000
        db.commit()
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        assert result.restored == 1 and has_ai_roles(tenant, "user-harsh")
        # Sean stays as he was: not re-checked, not released.
        assert not has_ai_roles(tenant, "user-sean")

    def test_the_settings_api_pauses_and_resumes_with_a_reason(
        self, admin_client: TestClient
    ) -> None:
        paused = admin_client.put("/api/settings", json={"enforcement_paused": True}).json()
        assert paused["enforcement_paused"] is True
        assert paused["enforcement_pause_reason"] == "Paused by admin."

        resumed = admin_client.put(
            "/api/settings",
            json={"enforcement_paused": False, "max_new_enforcements_per_cycle": 40},
        ).json()
        assert resumed["enforcement_paused"] is False
        assert resumed["enforcement_pause_reason"] is None
        assert resumed["max_new_enforcements_per_cycle"] == 40

    def test_a_viewer_cannot_resume_enforcement(self, viewer_client: TestClient) -> None:
        response = viewer_client.put("/api/settings", json={"enforcement_paused": False})
        assert response.status_code == httpx.codes.FORBIDDEN


def _with_admin_role(tenant: FakeTenant, user_id: str) -> FakeTenant:
    """Give a tenant user the administrator role, as the user list reports it."""
    for user in tenant.users:
        if user["id"] == user_id:
            user["roles"] = [*ALL_ROLES, "ast-admin"]
    return tenant


class TestProtectedIdentities:
    def test_the_api_keys_own_account_is_never_restricted(self, db: Session) -> None:
        tenant, client = synced(db)
        connection_service.save_connection(
            db, api_key=make_api_key(subject="user-harsh"), actor=ACTOR
        )
        db.commit()
        limit = limit_on(db, "user-harsh")

        assert enforcement.plan_targets(db, entity_type="user", entity_id="user-harsh") == []
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        assert outcome.applied == [] and outcome.failed == []
        assert has_ai_roles(tenant, "user-harsh")
        # Anyone else is still restricted as normal.
        other = limit_on(db, "user-sean")
        enforcement.apply_enforcement(db, client, limit=other, period_key=PERIOD, actor=ACTOR)
        assert not has_ai_roles(tenant, "user-sean")

    def test_a_tenant_administrator_is_not_restricted(self, db: Session) -> None:
        tenant = _with_admin_role(populated_tenant(), "user-harsh")
        tenant, client = synced(db, tenant)
        limit = limit_on(db, "user-harsh")

        for _ in range(3):
            outcome = enforcement.apply_enforcement(
                db, client, limit=limit, period_key=PERIOD, actor=ACTOR
            )
            # A decision, not a failure: the cycle is not degraded by it.
            assert outcome.applied == [] and outcome.failed == []
            assert any("protected role (ast-admin)" in note for note in outcome.skipped)
        assert has_ai_roles(tenant, "user-harsh")
        assert not [r for r in tenant.requests if r[0] == "DELETE"]

        action = db.scalar(select(EnforcementAction))
        assert enforcement.may_be_in_force(action) is False
        notices = list(
            db.scalars(select(Notification).where(Notification.title.like("%but protected")))
        )
        assert len(notices) == 1 and notices[0].severity == Severity.WARNING
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "enforcement.protected")
            )
            == 1
        )

    def test_the_protected_roles_are_configurable(self, db: Session) -> None:
        tenant = _with_admin_role(populated_tenant(), "user-harsh")
        tenant, client = synced(db, tenant)
        settings_store.set_value(db, settings_store.KEY_PROTECTED_ROLES, "")
        db.commit()
        limit = limit_on(db, "user-harsh")
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        assert len(outcome.applied) == 1 and not has_ai_roles(tenant, "user-harsh")


class TestChangesThatCouldNotBeUndone:
    def _project_limit(self, db: Session):
        tenant, client = synced(db)
        # The tenant will not say what the repository's setting is.
        tenant.fail_requests[("GET", "/repos-manager/repo/")] = 404
        return tenant, client, limit_on(db, "proj-api", entity_type=EntityType.PROJECT)

    def test_an_unreadable_setting_is_left_alone(self, db: Session) -> None:
        tenant, client, limit = self._project_limit(db)
        project = db.get(CxProject, "proj-api")
        project.pr_remediation_severities = None  # and nothing was ever recorded
        db.commit()

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        # Auto Triage, which can be read and so restored, is still disabled...
        assert [a.kind for a in outcome.applied] == [EnforcementKind.DISABLE_AUTO_TRIAGE]
        # ...but the repository setting is untouched rather than guessed at.
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]
        assert any("could not be read" in note for note in outcome.failed)

    def test_a_recorded_off_setting_is_restored_to_off(self, db: Session) -> None:
        """It used to be restored to the defaults, switching on something that
        had been deliberately off."""
        tenant, client, limit = self._project_limit(db)
        tenant.repo_severities["repo-1"] = []
        project = db.get(CxProject, "proj-api")
        project.pr_remediation_severities = []
        db.commit()

        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        enforcement.restore_for_limit(
            db, client, limit_id=limit.id, actor=ACTOR, reason="limit_removed"
        )
        assert tenant.repo_severities["repo-1"] == []


class TestSeveralLimitsOnOneTarget:
    """A project under both its own limit and its application's limit."""

    def _both_restricting(self, db: Session):
        tenant, client = synced(db)
        project_limit = limit_on(db, "proj-api", entity_type=EntityType.PROJECT)
        app_limit = limit_on(db, "app-payments", entity_type=EntityType.APPLICATION)
        enforcement.apply_enforcement(
            db, client, limit=project_limit, period_key=PERIOD, actor=ACTOR
        )
        # By now Auto Triage is already off: the application's limit reads "off".
        enforcement.apply_enforcement(db, client, limit=app_limit, period_key=PERIOD, actor=ACTOR)
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        return tenant, client, project_limit, app_limit

    def _triage_action(self, db: Session, limit: CreditLimit) -> EnforcementAction:
        action = db.scalar(
            select(EnforcementAction).where(
                EnforcementAction.limit_id == limit.id,
                EnforcementAction.target_id == "proj-api",
                EnforcementAction.kind == EnforcementKind.DISABLE_AUTO_TRIAGE,
            )
        )
        db.refresh(action)
        return action

    def test_the_second_limit_knows_what_was_there_before_the_first(self, db: Session) -> None:
        _tenant, _client, _project_limit, app_limit = self._both_restricting(db)
        assert self._triage_action(db, app_limit).undo_snapshot["enabled_before"] is True

    def test_lifting_one_leaves_the_target_restricted_by_the_other(self, db: Session) -> None:
        tenant, client, project_limit, app_limit = self._both_restricting(db)
        writes_before = [r for r in tenant.requests if r[0] != "GET"]

        lifted = enforcement.restore_for_limit(
            db, client, limit_id=project_limit.id, actor=ACTOR, reason="limit_removed"
        )
        assert lifted >= 1
        assert self._triage_action(db, project_limit).status == EnforcementStatus.REVERSED
        # Nothing was changed in Checkmarx: the application's limit still applies.
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert [r for r in tenant.requests if r[0] != "GET"] == writes_before
        assert self._triage_action(db, app_limit).status == EnforcementStatus.APPLIED

    def test_the_last_one_to_lift_gives_everything_back(self, db: Session) -> None:
        """Either order: whichever limit lets go last restores the original
        state, not the already-restricted state it happened to see."""
        tenant, client, project_limit, app_limit = self._both_restricting(db)
        enforcement.restore_for_limit(
            db, client, limit_id=project_limit.id, actor=ACTOR, reason="limit_removed"
        )
        enforcement.restore_for_limit(
            db, client, limit_id=app_limit.id, actor=ACTOR, reason="limit_removed"
        )
        assert tenant.auto_triage["proj-api"]["enabled"] is True
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]

    def test_the_other_order_also_gives_everything_back(self, db: Session) -> None:
        tenant, client, project_limit, app_limit = self._both_restricting(db)
        enforcement.restore_for_limit(
            db, client, limit_id=app_limit.id, actor=ACTOR, reason="limit_removed"
        )
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        enforcement.restore_for_limit(
            db, client, limit_id=project_limit.id, actor=ACTOR, reason="limit_removed"
        )
        assert tenant.auto_triage["proj-api"]["enabled"] is True
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]

    def test_an_admin_restore_gives_it_back_whichever_limits_took_it(self, db: Session) -> None:
        tenant, client, project_limit, app_limit = self._both_restricting(db)
        action = self._triage_action(db, project_limit)
        assert enforcement.restore_action(
            db, client, action=action, actor=ACTOR, reason=enforcement.ADMIN_REASON
        )
        assert tenant.auto_triage["proj-api"]["enabled"] is True
        other = self._triage_action(db, app_limit)
        assert other.status == EnforcementStatus.REVERSED
        assert other.reversal_reason == enforcement.ADMIN_REASON
