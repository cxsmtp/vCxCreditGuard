"""Applying and reversing restrictions."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.models import AuditLogEntry, CreditLimit, EnforcementAction, Exemption, Notification
from app.models.enums import EnforcementKind, EnforcementStatus, EntityType
from app.services import enforcement, limits_service, org_sync
from app.services.audit import AuditActor
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
PERIOD = "2026-08"


def setup_tenant(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    db.commit()
    return tenant, client


def make_limit(
    db: Session,
    *,
    entity_type: EntityType,
    entity_id: str,
    label: str | None = None,
    enforce: bool = True,
) -> CreditLimit:
    limit = CreditLimit(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=label or entity_id,
        credit_limit=10,
        period_type="monthly",
        enforce=enforce,
    )
    db.add(limit)
    db.commit()
    return limit


class TestUserEnforcement:
    def test_removes_only_the_ai_roles(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", label="Harsh Gokani"
        )

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert len(outcome.applied) == 1
        remaining = tenant.role_mappings["user-harsh"]
        assert not any(role in remaining for role in AI_ROLE_NAMES)
        assert "view-projects" in remaining
        assert "view-scans" not in remaining

    def test_snapshot_records_exactly_what_was_removed(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-harsh")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        action = db.scalar(select(EnforcementAction))
        assert action is not None
        removed = {entry["name"] for entry in action.undo_snapshot["removed_roles"]}
        assert removed == set(AI_ROLE_NAMES)
        assert "view-projects" in action.undo_snapshot["roles_before"]

    def test_restore_puts_the_roles_back(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-harsh")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        action = db.scalar(select(EnforcementAction))
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR) is True
        db.commit()

        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert action.status == EnforcementStatus.REVERSED
        assert action.reversal_reason == "admin"

    def test_a_user_without_the_roles_is_handled_without_error(self, db: Session) -> None:
        """Idempotent by construction: nothing to remove means an empty snapshot."""
        tenant = FakeTenant()
        tenant.add_user(user_id="u1", username="a@example.com", roles=["view-projects"])
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="u1")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert len(outcome.applied) == 1
        action = outcome.applied[0]
        assert action.undo_snapshot["removed_roles"] == []

        # Restoring must not grant roles the user never had.
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.role_mappings["u1"] == ["view-projects"]


class TestProjectEnforcement:
    def test_disables_auto_triage_and_pr_remediation(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.PROJECT, entity_id="proj-api", label="payments/api"
        )

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        kinds = {action.kind for action in outcome.applied}
        assert kinds == {
            EnforcementKind.DISABLE_AUTO_TRIAGE,
            EnforcementKind.DISABLE_PR_REMEDIATION,
        }
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert tenant.repo_severities["repo-1"] == []

    def test_integer_repo_id_still_disables_pr_remediation(self, db: Session) -> None:
        """Regression: Checkmarx reports repoId as an integer, and a project that
        has both Auto Triage and SCM-based triage and remediation enabled must
        have both disabled when its limit is breached."""
        tenant = FakeTenant()
        tenant.add_project(
            project_id="proj-api", name="singakash/CxHybrid", repo_id=228481
        )
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(
            db, entity_type=EntityType.PROJECT, entity_id="proj-api", label="singakash/CxHybrid"
        )

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        kinds = {action.kind for action in outcome.applied}
        assert kinds == {
            EnforcementKind.DISABLE_AUTO_TRIAGE,
            EnforcementKind.DISABLE_PR_REMEDIATION,
        }
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert tenant.repo_severities["228481"] == []

    def test_projects_without_a_repo_id_only_get_the_auto_triage_action(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert {action.kind for action in outcome.applied} == {EnforcementKind.DISABLE_AUTO_TRIAGE}

    def test_auto_triage_config_is_preserved_across_disable_and_restore(self, db: Session) -> None:
        """A restore that reset branches or severities would be a silent regression."""
        tenant, client = setup_tenant(db)
        tenant.auto_triage["proj-web"]["config"] = {
            "branches": ["release", "main"],
            "scannerTypes": ["SAST"],
            "riskStatuses": ["NEW", "RECURRENT"],
            "severityLevels": ["CRITICAL"],
        }
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        enforcement.restore_action(db, client, action=outcome.applied[0], actor=ACTOR)
        db.commit()

        state = tenant.auto_triage["proj-web"]
        assert state["enabled"] is True
        # Every field of the monitored config is restored exactly: which branches,
        # which scanners, which severities and which risk states.
        assert state["config"]["branches"] == ["release", "main"]
        assert state["config"]["scannerTypes"] == ["SAST"]
        assert state["config"]["riskStatuses"] == ["NEW", "RECURRENT"]
        assert state["config"]["severityLevels"] == ["CRITICAL"]

    def test_auto_triage_snapshot_stores_the_full_config_before_disabling(
        self, db: Session
    ) -> None:
        """The current monitored config - branches, severities and risk states - is
        captured on the enforcement row at disable time for a faithful Restore."""
        tenant, client = setup_tenant(db)
        tenant.auto_triage["proj-web"]["config"] = {
            "branches": ["main", "feature/release"],
            "scannerTypes": ["SAST", "SCA"],
            "riskStatuses": ["NEW"],
            "severityLevels": ["CRITICAL", "HIGH", "MEDIUM"],
        }
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        captured = outcome.applied[0].undo_snapshot["config_before"]
        assert captured["branches"] == ["main", "feature/release"]
        assert captured["scannerTypes"] == ["SAST", "SCA"]
        assert captured["riskStatuses"] == ["NEW"]
        assert captured["severityLevels"] == ["CRITICAL", "HIGH", "MEDIUM"]

    def test_already_disabled_auto_triage_stays_disabled_after_restore(self, db: Session) -> None:
        """Restore replays the previous state, it does not turn features on."""
        tenant = populated_tenant()
        tenant.auto_triage["proj-web"]["enabled"] = False
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.applied[0].undo_snapshot["enabled_before"] is False

        enforcement.restore_action(db, client, action=outcome.applied[0], actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is False

    def test_pr_severities_are_restored_to_their_previous_value(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-api")
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        pr_action = next(
            action
            for action in outcome.applied
            if action.kind == EnforcementKind.DISABLE_PR_REMEDIATION
        )
        enforcement.restore_action(db, client, action=pr_action, actor=ACTOR)
        db.commit()
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]


class TestFanOut:
    def test_a_group_limit_restricts_every_project_in_the_group(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.GROUP, entity_id="grp-payments", label="Payments"
        )

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        targets = {action.target_id for action in outcome.applied}
        assert targets == {"proj-api", "proj-web"}
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert tenant.auto_triage["proj-web"]["enabled"] is False
        # A project in a different group is untouched.
        assert tenant.auto_triage["proj-tools"]["enabled"] is True

    def test_an_application_limit_restricts_every_associated_project(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.APPLICATION, entity_id="app-payments", label="Payments"
        )
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert {action.target_id for action in outcome.applied} == {"proj-api", "proj-web"}

    def test_each_target_gets_its_own_reversible_record(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.GROUP, entity_id="grp-payments")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        actions = list(db.scalars(select(EnforcementAction)))
        assert len({action.idempotency_key for action in actions}) == len(actions)
        assert all(action.undo_snapshot for action in actions)

    def test_a_group_with_no_projects_reports_nothing_to_do(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.GROUP, entity_id="grp-platform")
        # platform has one project, so remove it to make the group empty.
        db.query(type(db.get(CreditLimit, limit.id))).count()  # keep session warm
        from app.models import CxProjectGroup

        db.query(CxProjectGroup).delete()
        db.commit()

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.applied == []
        assert any("no targets" in reason for reason in outcome.skipped)


class TestIdempotency:
    def test_re_running_does_not_duplicate_actions(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-api")

        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        second = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        # No new rows and nothing re-restricted: the actions are still in force.
        assert second.applied == []
        assert len(list(db.scalars(select(EnforcementAction)))) == 2
        # Both halves verified still disabled (Auto Triage via GET, PR remediation
        # severities via GET) - nothing drifted, nothing re-asserted.
        assert second.reconciled == []
        assert len(second.skipped) == 2
        assert all("already applied and verified" in r for r in second.skipped)

    def test_re_running_does_not_overwrite_the_undo_snapshot(self, db: Session) -> None:
        """The dangerous version of this bug: a second run snapshots the disabled
        state, and restore then leaves the feature off forever."""
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        action = db.scalar(select(EnforcementAction))
        assert action.undo_snapshot["enabled_before"] is True
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is True

    def test_a_new_period_enforces_again(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-08", actor=ACTOR)
        db.commit()
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key="2026-09", actor=ACTOR
        )
        db.commit()
        assert len(outcome.applied) == 1

    def test_an_admin_restore_is_not_undone_by_the_next_cycle(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        enforcement.restore_action(db, client, action=outcome.applied[0], actor=ACTOR)
        db.commit()

        again = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert again.applied == []
        assert any("restored by an admin" in reason for reason in again.skipped)
        assert tenant.auto_triage["proj-web"]["enabled"] is True

    def test_restoring_twice_is_a_no_op(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        action = outcome.applied[0]
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR) is True
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR) is False


class TestReconciliation:
    """Already-applied restrictions are re-verified every run and re-asserted if
    they drifted back on in Checkmarx One."""

    def test_auto_triage_drift_is_redisabled_with_snapshot_preserved(
        self, db: Session
    ) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        out1 = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert out1.applied[0].undo_snapshot["enabled_before"] is True

        # Drift: someone re-enables Auto Triage in Checkmarx One.
        tenant.auto_triage["proj-web"]["enabled"] = True
        out2 = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert out2.applied == []
        assert len(out2.reconciled) == 1
        assert tenant.auto_triage["proj-web"]["enabled"] is False
        # The pre-restriction snapshot is untouched, so Restore still re-enables it.
        assert out1.applied[0].undo_snapshot["enabled_before"] is True

    def test_user_roles_drift_is_removed_again(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-harsh")
        enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert not any(r in tenant.role_mappings["user-harsh"] for r in AI_ROLE_NAMES)

        # Drift: an AI role is granted back to the restricted user.
        tenant.role_mappings["user-harsh"].append(AI_ROLE_NAMES[0])
        out2 = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert len(out2.reconciled) == 1
        assert not any(r in tenant.role_mappings["user-harsh"] for r in AI_ROLE_NAMES)

    def test_pr_remediation_drift_is_reasserted(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-api")
        enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert tenant.repo_severities["repo-1"] == []

        # Drift: severities are re-enabled for the repository.
        tenant.repo_severities["repo-1"] = ["CRITICAL", "HIGH"]
        out2 = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert tenant.repo_severities["repo-1"] == []
        assert any(
            a.kind == EnforcementKind.DISABLE_PR_REMEDIATION for a in out2.reconciled
        )

    def test_pr_severities_are_captured_and_restored_exactly(self, db: Session) -> None:
        """The real, current severities (including MEDIUM/LOW) are captured before
        the feature is disabled, and a Restore replays exactly that set."""
        tenant, client = setup_tenant(db)
        # Configure a repository triaging on all four severities.
        tenant.repo_severities["repo-1"] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-api")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        pr_action = next(
            a
            for a in outcome.applied
            if a.kind == EnforcementKind.DISABLE_PR_REMEDIATION
        )
        # Disabling captured what was really configured, not a C/H default.
        assert pr_action.undo_snapshot["severities_before"] == [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
        ]
        assert tenant.repo_severities["repo-1"] == []

        # Restore puts back the exact configuration that was present.
        enforcement.restore_action(db, client, action=pr_action, actor=ACTOR)
        db.commit()
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_reconciliation_is_audited(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        tenant.auto_triage["proj-web"]["enabled"] = True
        enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert db.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "enforcement.reconciled")
        ) is not None


class TestExemptions:
    def test_an_exempt_entity_is_never_restricted(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        db.add(Exemption(entity_type=EntityType.USER, entity_id="user-harsh", reason="on call"))
        db.commit()
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-harsh")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.applied == []
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    def test_an_exempt_project_inside_a_breached_application_is_skipped(self, db: Session) -> None:
        """Exemptions apply at the target level, not just the limit level."""
        tenant, client = setup_tenant(db)
        db.add(Exemption(entity_type=EntityType.PROJECT, entity_id="proj-api", reason="critical"))
        db.commit()
        limit = make_limit(db, entity_type=EntityType.APPLICATION, entity_id="app-payments")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert {action.target_id for action in outcome.applied} == {"proj-web"}
        assert tenant.auto_triage["proj-api"]["enabled"] is True

    def test_removing_an_exemption_allows_the_next_cycle_to_restrict_again(
        self, db: Session
    ) -> None:
        """Regression: an exemption that lifts a restriction is conditional, so
        removing it must let the next cycle restrict the project again instead of
        leaving it unlocked (treated as an admin restore) for the whole period."""
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is False

        # Granting an exemption lifts the active restriction.
        exemption = limits_service.add_exemption(
            db,
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            reason="on call",
            actor=ACTOR,
            client=client,
        )
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is True
        action = db.scalar(select(EnforcementAction))
        assert action.reversal_reason == "exempted"

        # Removing the exemption means the next cycle restricts again.
        limits_service.remove_exemption(db, exemption=exemption, actor=ACTOR)
        db.commit()
        again = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert len(again.applied) == 1
        assert again.applied[0].reversal_reason is None
        assert tenant.auto_triage["proj-web"]["enabled"] is False


class TestFailureHandling:
    def test_an_api_failure_is_recorded_and_notified(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.fail_paths["/ai-agents-coordinator/"] = 500
        tenant_obj, client = setup_tenant(db, tenant)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()

        assert outcome.applied == []
        assert outcome.failed
        action = db.scalar(select(EnforcementAction))
        assert action.status == EnforcementStatus.FAILED
        assert action.error
        assert db.scalar(select(Notification).where(Notification.severity == "error")) is not None

    def test_a_failed_action_is_retried_on_the_next_run(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.fail_paths["/ai-agents-coordinator/"] = 500
        tenant_obj, client = setup_tenant(db, tenant)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        tenant_obj.fail_paths.clear()
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert len(outcome.applied) == 1
        action = db.scalar(select(EnforcementAction))
        assert action.status == EnforcementStatus.APPLIED
        assert action.attempts == 2
        assert action.error is None

    def test_one_failing_target_does_not_block_the_others(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.fail_paths["/repos-manager/"] = 500
        tenant_obj, client = setup_tenant(db, tenant)
        limit = make_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-api")

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert len(outcome.applied) == 1
        assert len(outcome.failed) == 1
        assert tenant_obj.auto_triage["proj-api"]["enabled"] is False


class TestAuditAndNotifications:
    def test_enforcement_is_audited_with_before_and_after(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, entity_type=EntityType.USER, entity_id="user-harsh")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        entry = db.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "enforcement.applied")
        )
        assert entry is not None
        assert entry.before["removed_roles"]
        assert entry.after["restricted"] is True

    def test_notification_names_the_roles_removed(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", label="Harsh Gokani"
        )
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        notification = db.scalar(select(Notification).where(Notification.category == "enforcement"))
        assert notification is not None
        assert "Harsh Gokani" in notification.title
        assert "view-risk-management" in (notification.body or "")
        assert "Restore access" in (notification.body or "")

    def test_restoration_is_audited_and_notified(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.PROJECT, entity_id="proj-web", label="payments/web"
        )
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        enforcement.restore_action(
            db, client, action=outcome.applied[0], actor=ACTOR, reason="period_rollover"
        )
        db.commit()

        assert db.scalar(
            select(AuditLogEntry).where(AuditLogEntry.action == "enforcement.reversed")
        )
        notification = db.scalar(select(Notification).where(Notification.category == "restoration"))
        assert notification is not None
        assert "new budget period" in (notification.body or "")


def test_restore_for_limit_reverses_every_target(db: Session) -> None:
    tenant, client = setup_tenant(db)
    limit = make_limit(db, entity_type=EntityType.GROUP, entity_id="grp-payments")
    enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()

    restored = enforcement.restore_for_limit(
        db, client, limit_id=limit.id, actor=ACTOR, reason="limit_removed"
    )
    db.commit()
    # proj-api contributes two actions (Auto Triage and PR remediation), proj-web one.
    assert restored == 3
    assert tenant.auto_triage["proj-api"]["enabled"] is True
    assert tenant.auto_triage["proj-web"]["enabled"] is True
    assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]
