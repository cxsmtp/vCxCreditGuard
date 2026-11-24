"""Fusion: recognising its usage, pricing it, and turning it off per limit.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import Session

from app.checkmarx import credits as credits_api
from app.checkmarx import usage as usage_api
from app.db.migrate import alembic_config
from app.models import AuditLogEntry, EnforcementAction, Notification, PolicyViolation
from app.models.enums import (
    ActionType,
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    PeriodType,
    RunStatus,
)
from app.models.limits import CreditLimit, effective_project_actions
from app.services import connection as connection_service
from app.services import (
    cycle,
    enforcement,
    key_permissions,
    limits_csv,
    limits_service,
    org_sync,
    preview_service,
    settings_store,
    usage_mix,
)
from app.services.audit import AuditActor
from tests.conftest import USING_SQLITE, make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
PERIOD = "2026-08"
ALL = ["auto_triage", "pr_remediation", "fusion"]


def setup_tenant(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    db.commit()
    return tenant, client


def make_limit(
    db: Session,
    *,
    entity_type: EntityType = EntityType.PROJECT,
    entity_id: str = "proj-api",
    actions: list[str] | None = None,
    enforce: bool = True,
) -> CreditLimit:
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=entity_type,
            entity_id=entity_id,
            credit_limit=10,
            period_type=PeriodType.MONTHLY,
            enforce=enforce,
            project_actions=actions,
        ),
        actor=ACTOR,
    )
    db.commit()
    return limit


def actions_by_kind(db: Session) -> dict[str, EnforcementAction]:
    db.expire_all()
    return {action.kind: action for action in db.scalars(select(EnforcementAction))}


# ------------------------------------------------------------ normalisation


class TestNormalisation:
    @pytest.mark.parametrize(
        "raw",
        [
            "fusion",
            "fusion_scan",
            "fusionscan",
            "fusion_scan_-_opus_5.5",
            "fusion_scan___opus_5.5",
            "Fusion Scan - Haiku 4.5",
            "FUSION_SCAN_-_OPUS_4.7",
        ],
    )
    def test_every_fusion_variant_is_fusion(self, raw: str) -> None:
        assert usage_api.normalise_action_type(raw) == ActionType.FUSION

    def test_the_model_stays_readable(self) -> None:
        assert usage_api.fusion_model("fusion_scan_-_opus_5.5") == "Opus 5.5"
        assert usage_api.fusion_model("Fusion Scan - Haiku 4.5") == "Haiku 4.5"
        assert usage_api.fusion_model("fusion") is None
        assert usage_api.fusion_model("triage") is None

    def test_others_are_unchanged(self) -> None:
        assert usage_api.normalise_action_type("auto_triage") == ActionType.AUTO_TRIAGE
        assert usage_api.normalise_action_type("Triage") == ActionType.TRIAGE
        assert usage_api.normalise_action_type("something_new") == "something_new"

    def test_a_row_counts_fusion_models_under_fusion_and_keeps_the_raw(self) -> None:
        item = usage_api.parse_usage_item(
            {
                "name": "payments/api",
                "id": "proj-api",
                "creditsUsed": 7,
                "actionsPerformed": {
                    "actions": [
                        {"actionType": "fusion_scan_-_opus_5.5", "transactionCount": 2},
                        {"actionType": "fusion_scan_-_haiku_4.5", "transactionCount": 2},
                        {"actionType": "auto_triage", "transactionCount": 1},
                    ],
                    "total": 5,
                },
            }
        )
        assert item is not None
        assert item.actions == {"fusion": 4, "auto_triage": 1}
        assert item.raw["actionsPerformed"]["actions"][0]["actionType"] == "fusion_scan_-_opus_5.5"

    def test_fusion_is_not_auto_triage_for_attribution(self) -> None:
        assert usage_mix.bucket("fusion_scan_-_opus_5.5") == "fusion"
        assert usage_mix.bucket("fusion_scan___opus_5.5") == "fusion"  # stored before the fix


# ------------------------------------------------------------------- prices


class TestRates:
    def test_parse_action_rates(self) -> None:
        rates = credits_api.parse_action_rates(
            {
                "count": 2,
                "rates": [
                    {"action_type": "fusion_scan_-_opus_5.5", "credits_per_action": "2"},
                    {"action_type": "broken", "credits_per_action": "n/a"},
                ],
            }
        )
        assert rates is not None
        assert [(rate.action_type, rate.credits_per_action) for rate in rates] == [
            ("fusion_scan_-_opus_5.5", Decimal("2"))
        ]
        assert credits_api.parse_action_rates({"nothing": 1}) is None

    def test_a_cycle_stores_the_rates(self, db: Session, monkeypatch) -> None:
        tenant = _connected(db, monkeypatch)
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.steps["action_rates"] == {"ok": True, "rates": 3}
        db.expire_all()
        stored = settings_store.action_rates(db)
        assert stored is not None
        assert {rate["action_type"] for rate in stored["rates"]} == {
            rate["action_type"] for rate in tenant.action_rates or []
        }

    @pytest.mark.parametrize("status", [403, 404])
    def test_a_refused_or_missing_rates_read_never_breaks_the_cycle(
        self, db: Session, monkeypatch, status: int
    ) -> None:
        tenant = _connected(db, monkeypatch)
        tenant.fail_requests[("GET", "/v1/credits/action-rates")] = status
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.status == RunStatus.SUCCESS
        assert result.steps["action_rates"]["ok"] is False
        db.expire_all()
        assert settings_store.action_rates(db) is None

    def test_priced_fusion_in_the_breach_message(self, db: Session, monkeypatch) -> None:
        tenant = _connected(db, monkeypatch)
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=4,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_5.5": 2},
        )
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        limits_service.create_limit(
            db,
            data=limits_service.LimitInput(
                entity_type=EntityType.PROJECT,
                entity_id="proj-web",
                credit_limit=3,
                period_type=PeriodType.MONTHLY,
                enforce=True,
                project_actions=ALL,
            ),
            actor=ACTOR,
        )
        db.commit()
        cycle.run_cycle(trigger="manual")  # the period's baseline
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=8,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_5.5": 4},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        from app.db.base import utcnow

        month = utcnow().strftime("%B %Y")
        assert breach.body.startswith(
            f"4 of 3 credits used in {month}: Fusion scan (Opus 5.5) 2 scans = 4 credits.\n"
        ), breach.body
        assert "cannot switch Fusion off yet" not in breach.body
        assert "Auto Triage, PR triage and remediation and Fusion are turned off" in breach.body
        turned_off = db.scalar(
            select(Notification).where(Notification.title.like("%: Fusion turned off"))
        )
        assert turned_off is not None
        assert "Fusion was turned off for this project" in turned_off.body
        assert "policy violation" in turned_off.body

    def test_masked_counts_keep_the_honest_fallback(self, db: Session, monkeypatch) -> None:
        tenant = _connected(db, monkeypatch)
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=4,
            entity_id="proj-web",
            actions={"triage": 3, "fusion_scan_-_opus_5.5": 1},
        )
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        limit = make_limit(db, entity_id="proj-web", actions=ALL, enforce=False)
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=8,
            entity_id="proj-web",
            actions={"triage": 3, "fusion_scan_-_opus_5.5": 3},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        mix = usage_mix.for_period(db, limit, _period_key(limit))
        assert mix is not None
        assert mix.masked is True
        assert mix.fusion_priced is None
        text = usage_mix.describe(mix, period_key="2026-11", entity_type="project")
        assert "Fusion scan 2 transactions" in text
        assert "= 4 credits" not in text

    def test_an_unpriced_model_is_not_priced(self, db: Session, monkeypatch) -> None:
        tenant = _connected(db, monkeypatch)
        tenant.action_rates = []
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=2,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_9": 1},
        )
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        limit = make_limit(db, entity_id="proj-web", actions=ALL, enforce=False)
        cycle.run_cycle(trigger="manual")
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=6,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_9": 3},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        mix = usage_mix.for_period(db, limit, _period_key(limit))
        assert mix is not None and mix.fusion_priced is None
        assert usage_mix.describe(mix, period_key="2026-11", entity_type="project").endswith(
            "Fusion scan 4."
        )


def _period_key(limit: CreditLimit) -> str:
    from app.services.periods import current_window

    return current_window(limit).key


def _connected(db: Session, monkeypatch) -> FakeTenant:
    tenant = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = tenant.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    key_permissions.discard_pending_denials()
    return tenant


# ---------------------------------------------------------- turning it off


class TestTurnOffFusion:
    def test_legacy_limit_does_not_touch_fusion(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=None)
        assert limit.project_actions is None
        assert effective_project_actions(limit) == ("auto_triage", "pr_remediation")
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert set(actions_by_kind(db)) == {"disable_auto_triage", "disable_pr_remediation"}
        assert tenant.config_patches == []
        assert tenant.fusion_setting("proj-api")["value"] == "true"

    def test_fusion_only_limit(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        actions = actions_by_kind(db)
        assert set(actions) == {"disable_fusion", "disable_repo_fusion"}
        assert tenant.auto_triage["proj-api"]["enabled"] is True
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]

    def test_apply_locks_and_restore_puts_back_exactly(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=ALL)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.status == EnforcementStatus.APPLIED
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "false" and entry["allowOverride"] is False
        project_id, body = tenant.config_patches[-1]
        assert project_id == "proj-api"
        assert body[0]["key"] == "scan.config.ai.fusionEnabled"
        assert body[0]["name"] == "Fusion Scan" and body[0]["valuetype"] == "Bool"
        snapshot = action.undo_snapshot
        assert snapshot["fusion_enabled_before"] is True
        assert snapshot["value_before"] == "true"
        assert snapshot["allow_override_before"] is True
        assert snapshot["origin_level_before"] == "Project"
        assert snapshot["lock_applied"] is True

        assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "true" and entry["allowOverride"] is True
        restored = db.scalar(
            select(Notification).where(Notification.title.like("%Fusion setting restored"))
        )
        assert restored is not None
        assert "inherited" not in restored.body

    def test_inherited_value_restore_says_it_is_now_on_the_project(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.set_fusion_setting("proj-web", value="true", origin="Tenant", allow_override=True)
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, entity_id="proj-web", actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.undo_snapshot["origin_level_before"] == "Tenant"
        applied = db.scalar(
            select(Notification).where(Notification.title.like("%: Fusion turned off"))
        )
        assert "inherited from the tenant level" in applied.body
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        entry = tenant.fusion_setting("proj-web")
        assert entry["value"] == "true" and entry["originLevel"] == "Project"
        restored = db.scalar(
            select(Notification).where(Notification.title.like("%Fusion setting restored"))
        )
        assert "inherited from the tenant level" in restored.body
        assert "now set on the project" in restored.body

    def test_lock_refused_falls_back_to_the_value_only(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.reject_config_lock = True
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.failed == []
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "false" and entry["allowOverride"] is True
        action = actions_by_kind(db)["disable_fusion"]
        assert action.undo_snapshot["lock_applied"] is False
        assert "400" in action.undo_snapshot["lock_rejected"]
        body = db.scalar(
            select(Notification.body).where(Notification.title.like("%: Fusion turned off"))
        )
        assert "did not accept locking" in body

    def test_lock_can_be_switched_off(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        settings_store.set_value(db, settings_store.KEY_FUSION_LOCK, False)
        db.commit()
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "false" and entry["allowOverride"] is True
        assert actions_by_kind(db)["disable_fusion"].undo_snapshot["lock_requested"] is False

    def test_already_off_and_locked_changes_nothing(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.set_fusion_setting("proj-api", value="false", allow_override=False)
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert tenant.config_patches == []
        action = actions_by_kind(db)["disable_fusion"]
        assert action.undo_snapshot["fusion_write"] is False
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.config_patches == []

    def test_missing_fusion_setting_is_left_alone_and_said(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.set_fusion_setting("proj-api", value=None)
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["auto_triage", "fusion"])
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.failed == []
        actions = actions_by_kind(db)
        assert actions["disable_auto_triage"].status == EnforcementStatus.APPLIED
        assert actions["disable_fusion"].status == EnforcementStatus.FAILED
        assert "no Fusion setting" in actions["disable_fusion"].error
        assert db.scalar(
            select(Notification).where(Notification.title.like("%Fusion left unchanged"))
        )

    def test_repo_half_absent_is_skipped_quietly(self, db: Session) -> None:
        """No fusionScanConfig: nothing to turn off. Recorded as left alone (so
        the safety ceiling does not count it as new every cycle), never as a
        failure of the cycle, without a notification, and audited once per
        project whatever the period."""
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.failed == []
        assert any("nothing to turn off there" in line for line in outcome.skipped)
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert "do not include a Fusion setting" in repo.error
        assert not enforcement.may_be_in_force(repo)
        for period in (PERIOD, "2026-09", "2026-10"):
            again = enforcement.apply_enforcement(
                db, client, limit=limit, period_key=period, actor=ACTOR
            )
            db.commit()
            assert again.failed == []
        audits = list(
            db.scalars(
                select(AuditLogEntry).where(
                    AuditLogEntry.action.in_(
                        ["enforcement.not_applicable", "enforcement.not_restricted"]
                    )
                )
            )
        )
        assert [entry.action for entry in audits] == ["enforcement.not_applicable"]
        assert not db.scalar(
            select(Notification).where(Notification.title.like("%repository Fusion setting%"))
        )
        assert "repo-1" not in tenant.repo_fusion  # nothing invented

        # A repository that gains the setting is restricted from then on.
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        repo = next(
            action
            for action in db.scalars(select(EnforcementAction))
            if action.kind == "disable_repo_fusion" and action.period_key == PERIOD
        )
        assert repo.status == EnforcementStatus.APPLIED
        assert tenant.repo_fusion["repo-1"]["enabled"] is False

    def test_repo_half_present_is_turned_off_and_restored(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert repo.status == EnforcementStatus.APPLIED
        assert tenant.repo_fusion["repo-1"] == {"enabled": False, "llmModel": "opus-5.5"}
        assert repo.undo_snapshot["repo_fusion_before"] == {
            "enabled": True,
            "llmModel": "opus-5.5",
        }
        enforcement.restore_action(db, client, action=repo, actor=ACTOR)
        db.commit()
        assert tenant.repo_fusion["repo-1"] == {"enabled": True, "llmModel": "opus-5.5"}

    def test_drift_is_reasserted_and_unreadable_is_unverified(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        held = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert held.reconciled == [] and held.unverified == []

        tenant.fusion_setting("proj-api")["value"] = "true"
        tenant.repo_fusion["repo-1"]["enabled"] = True
        drift = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert sorted(a.kind for a in drift.reconciled) == [
            EnforcementKind.DISABLE_FUSION,
            EnforcementKind.DISABLE_REPO_FUSION,
        ]
        assert tenant.fusion_setting("proj-api")["value"] == "false"
        assert tenant.repo_fusion["repo-1"]["enabled"] is False
        assert db.scalar(
            select(Notification).where(Notification.title.like("%Fusion turned off again"))
        )

        # A lock removed is drift too.
        tenant.fusion_setting("proj-api")["allowOverride"] = True
        relocked = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in relocked.reconciled] == [EnforcementKind.DISABLE_FUSION]
        assert tenant.fusion_setting("proj-api")["allowOverride"] is False

        tenant.fail_requests[("GET", "/configuration/project")] = 500
        unverified = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in unverified.unverified] == [EnforcementKind.DISABLE_FUSION]
        assert unverified.reconciled == []

    def test_deselecting_fusion_puts_it_back(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=ALL)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert tenant.fusion_setting("proj-api")["value"] == "false"
        limits_service.update_limit(
            db,
            limit=limit,
            changes={"project_actions": ["auto_triage", "pr_remediation"]},
            actor=ACTOR,
            client=client,
        )
        db.commit()
        assert tenant.fusion_setting("proj-api")["value"] == "true"
        actions = actions_by_kind(db)
        assert actions["disable_fusion"].status == EnforcementStatus.REVERSED
        assert actions["disable_fusion"].reversal_reason == enforcement.DESELECTED_REASON
        assert actions["disable_auto_triage"].status == EnforcementStatus.APPLIED
        assert tenant.auto_triage["proj-api"]["enabled"] is False

    def test_group_limit_fans_out_fusion(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(
            db, entity_type=EntityType.GROUP, entity_id="grp-payments", actions=["fusion"]
        )
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        rows = list(db.scalars(select(EnforcementAction)))
        fusion = {row.target_id for row in rows if row.kind == "disable_fusion"}
        assert fusion == {"proj-api", "proj-web"}
        assert tenant.fusion_setting("proj-web")["value"] == "false"

    def test_no_write_lock_is_held_while_fusion_is_changed(self, db: Session) -> None:
        if not USING_SQLITE:
            pytest.skip("SQLite lock probe")
        from tests.test_cycle_transactions import _watch_for_write_locks

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        held = _watch_for_write_locks(tenant)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert held == []


# ------------------------------------------------------ the per-limit choice


class TestChoice:
    def test_user_limits_cannot_choose(self, db: Session) -> None:
        setup_tenant(db)
        with pytest.raises(limits_service.LimitError):
            make_limit(db, entity_type=EntityType.USER, entity_id="user-harsh", actions=["fusion"])

    def test_empty_or_unknown_is_refused(self, db: Session) -> None:
        with pytest.raises(limits_service.LimitError):
            limits_service.normalise_project_actions([])
        with pytest.raises(limits_service.LimitError):
            limits_service.normalise_project_actions(["fusion", "everything"])
        assert limits_service.normalise_project_actions(["fusion", "auto_triage", "fusion"]) == [
            "auto_triage",
            "fusion",
        ]

    def test_api_create_update_and_response(self, admin_client: TestClient, db: Session) -> None:
        setup_tenant(db)
        created = admin_client.post(
            "/api/limits",
            json={
                "entity_type": "project",
                "entity_id": "proj-web",
                "credit_limit": 5,
                "project_actions": ["fusion", "auto_triage"],
            },
        )
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["project_actions"] == ["auto_triage", "fusion"]
        assert body["effective_project_actions"] == ["auto_triage", "fusion"]
        legacy = admin_client.post(
            "/api/limits",
            json={"entity_type": "project", "entity_id": "proj-tools", "credit_limit": 5},
        )
        assert legacy.json()["project_actions"] is None
        assert legacy.json()["effective_project_actions"] == ["auto_triage", "pr_remediation"]
        refused = admin_client.post(
            "/api/limits",
            json={
                "entity_type": "user",
                "entity_id": "user-harsh",
                "credit_limit": 5,
                "project_actions": ["fusion"],
            },
        )
        assert refused.status_code in (400, 422)
        empty = admin_client.patch(f"/api/limits/{body['id']}", json={"project_actions": []})
        assert empty.status_code == 400
        changed = admin_client.patch(
            f"/api/limits/{body['id']}", json={"project_actions": ["pr_remediation"]}
        )
        assert changed.json()["project_actions"] == ["pr_remediation"]

    def test_csv_round_trip_and_legacy(self, db: Session) -> None:
        setup_tenant(db)
        make_limit(db, entity_id="proj-api", actions=["fusion"], enforce=False)
        make_limit(db, entity_id="proj-web", actions=None, enforce=False)
        exported = limits_csv.export_limits(db)
        assert "project_actions" in exported.splitlines()[0]
        assert ",fusion," in exported
        # Re-import changes nothing; a file without the column leaves the choice.
        result = limits_csv.import_limits(db, content=exported, actor=ACTOR, dry_run=False)
        assert result.errors == []
        db.commit()
        api = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "proj-api"))
        web = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "proj-web"))
        assert api.project_actions == ["fusion"] and web.project_actions is None
        minimal = "entity_type,entity_id,credit_limit\nproject,proj-api,12\n"
        limits_csv.import_limits(db, content=minimal, actor=ACTOR, dry_run=False)
        db.commit()
        db.expire_all()
        assert api.project_actions == ["fusion"]
        bad = "entity_type,entity_id,credit_limit,project_actions\nuser,user-harsh,3,fusion\n"
        assert limits_csv.import_limits(db, content=bad, actor=ACTOR, dry_run=True).errors

    def test_preview_shows_fusion_and_the_guard_counts_it(self, db: Session) -> None:
        setup_tenant(db)
        legacy = preview_service.blast_radius(db, entity_type="project", entity_id="proj-api")
        assert legacy.disable_fusion == 0 and legacy.disable_auto_triage == 1
        chosen = preview_service.blast_radius(
            db, entity_type="project", entity_id="proj-api", project_actions=["fusion"]
        )
        assert chosen.disable_fusion == 1 and chosen.disable_repo_fusion == 1
        assert chosen.disable_auto_triage == 0
        assert chosen.project_actions == ["fusion"]
        make_limit(db, entity_id="proj-api", actions=ALL)
        saved = preview_service.blast_radius(db, entity_type="project", entity_id="proj-api")
        assert saved.disable_fusion == 1 and saved.total_actions == 4

        from app.services import evaluation

        limit = db.scalar(select(CreditLimit))
        assert evaluation._starting_targets(
            db,
            limit.id,
            PERIOD,
            [(target.kind, target.target_id) for target in saved.targets],
        ) == [(target.kind, target.target_id) for target in saved.targets]

    def test_blast_radius_api_takes_a_choice(self, admin_client: TestClient, db: Session) -> None:
        setup_tenant(db)
        response = admin_client.get(
            "/api/preview/blast-radius",
            params={"entity_type": "project", "entity_id": "proj-api", "project_actions": "fusion"},
        )
        assert response.status_code == 200
        assert response.json()["disable_fusion"] == 1
        assert response.json()["disable_auto_triage"] == 0
        bad = admin_client.get(
            "/api/preview/blast-radius",
            params={"entity_type": "project", "entity_id": "proj-api", "project_actions": "x"},
        )
        assert bad.status_code == 400


# ------------------------------------------------------------ the migration


def test_migration_up_and_down(tmp_path: Path) -> None:
    if not USING_SQLITE:
        from tests.conftest import TEST_DATABASE_URL

        url = TEST_DATABASE_URL
        engine = create_engine(url)
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
        engine.dispose()
    else:
        url = f"sqlite:///{(tmp_path / 'updown.db').as_posix()}"
    from alembic import command

    config = alembic_config(url)
    command.upgrade(config, "head")
    inspector = inspect(create_engine(url))
    assert "project_actions" in {c["name"] for c in inspector.get_columns("credit_limit")}
    assert "policy_violation" in inspector.get_table_names()
    command.downgrade(config, "c8e1f5a3d6b2")
    inspector = inspect(create_engine(url))
    assert "project_actions" not in {c["name"] for c in inspector.get_columns("credit_limit")}
    assert "policy_violation" not in inspector.get_table_names()
    command.upgrade(config, "head")
    inspector = inspect(create_engine(url))
    assert "policy_violation" in inspector.get_table_names()


# --------------------------------------------------- the permission checker


class TestPermissionChecks:
    def _check(self, db: Session, monkeypatch) -> tuple[FakeTenant, dict]:
        tenant = _connected(db, monkeypatch)
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        assert report is not None
        return tenant, report

    def test_new_entries_are_there(self, db: Session, monkeypatch) -> None:
        _tenant, report = self._check(db, monkeypatch)
        checks = {check["id"]: check for check in report["checks"]}
        assert checks["project_config_read"]["status"] == key_permissions.STATUS_OK
        assert checks["action_rates"]["status"] == key_permissions.STATUS_OK
        assert checks["project_config_write"]["status"] == key_permissions.STATUS_NOT_TESTED
        assert checks["repo_fusion_write"]["status"] == key_permissions.STATUS_NOT_TESTED
        assert checks["project_config_read"]["required"] is False
        assert report["verdict"] == key_permissions.VERDICT_OK

    def test_refused_rates_are_optional(self, db: Session, monkeypatch) -> None:
        tenant = _connected(db, monkeypatch)
        tenant.fail_requests[("GET", "/v1/credits/action-rates")] = 403
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        assert report["attention"] is False
        assert report["verdict"] == key_permissions.VERDICT_LIMITED

    def test_config_read_refused_matters_only_when_a_limit_turns_fusion_off(
        self, db: Session, monkeypatch
    ) -> None:
        tenant = _connected(db, monkeypatch)
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        tenant.fail_requests[("GET", "/configuration/project")] = 403
        make_limit(db, entity_id="proj-api", actions=None)
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        checks = {check["id"]: check for check in report["checks"]}
        assert checks["project_config_read"]["status"] == key_permissions.STATUS_DENIED
        assert checks["project_config_write"]["expectation"] == key_permissions.EXPECT_WILL_FAIL
        assert report["attention"] is False
        limit = db.scalar(select(CreditLimit))
        limits_service.update_limit(db, limit=limit, changes={"project_actions": ALL}, actor=ACTOR)
        db.commit()
        assessed = key_permissions.current_report(db)
        assert assessed["attention"] is True
        assert assessed["verdict"] == key_permissions.VERDICT_INSUFFICIENT
        assert assessed["enforce_fusion"] is True

    def test_a_runtime_refusal_of_the_repo_patch_counts_for_fusion_too(
        self, db: Session, monkeypatch
    ) -> None:
        tenant, _report = self._check(db, monkeypatch)
        make_limit(db, entity_id="proj-api", actions=["fusion"])
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        tenant.fail_requests[("PATCH", "/repos-manager/")] = 403
        limit = db.scalar(select(CreditLimit))
        enforcement.apply_enforcement(
            db, tenant.client(), limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assessed = key_permissions.current_report(db)
        checks = {check["id"]: check for check in assessed["checks"]}
        assert checks["repo_write"]["runtime_denied_at"]
        assert checks["repo_fusion_write"]["runtime_denied_at"]
        assert checks["repo_fusion_write"]["required"] is True


def test_a_config_read_refused_on_one_project_is_cleared_only_by_that_project(
    db: Session, monkeypatch
) -> None:
    from app.checkmarx.errors import CheckmarxPermissionError

    tenant = _connected(db, monkeypatch)
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
    original = tenant.handler

    def refuse_web(request):  # type: ignore[no-untyped-def]
        import httpx

        if "/configuration/project" in request.url.path and "proj-web" in str(request.url):
            return httpx.Response(403, json={"message": "no"})
        return original(request)

    tenant.handler = refuse_web  # type: ignore[method-assign]
    with pytest.raises(CheckmarxPermissionError):
        tenant.client().get_json("/configuration/project", params={"project-id": "proj-web"})
    key_permissions.flush_runtime_denials(db, actor=ACTOR)
    db.commit()
    # Still refused on that project; the check's own project (proj-api) reads fine.
    report = key_permissions.run_check(
        db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR, client=tenant.client()
    )
    check = next(c for c in report["checks"] if c["id"] == "project_config_read")
    assert check["runtime_denied_at"], check
    assert check["status"] == key_permissions.STATUS_OK
    tenant.handler = original  # type: ignore[method-assign]
    report = key_permissions.run_check(
        db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR, client=tenant.client()
    )
    check = next(c for c in report["checks"] if c["id"] == "project_config_read")
    assert not check["runtime_denied_at"]


# ------------------------------------- retries, sibling limits and read-backs


def _count(db: Session, model, *conditions) -> int:  # type: ignore[no-untyped-def]
    db.expire_all()
    return int(db.scalar(select(func.count()).select_from(model).where(*conditions)) or 0)


class TestWhatWasTakenIsGivenBack:
    def test_retry_after_unknown_outcome_with_lock_rejected_restores_fusion(
        self, db: Session, monkeypatch
    ) -> None:
        """Attempt 1: the lock is refused (400), the value-only fallback lands but
        its answer is lost. Attempt 2 reads Fusion already off, and the lock is
        refused again. What attempt 1 took (Fusion on) must still be given back."""
        from app.checkmarx import platform
        from app.checkmarx.errors import CheckmarxError

        tenant = populated_tenant()
        tenant.reject_config_lock = True
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])

        real = platform.set_project_setting
        calls = {"n": 0}

        def flaky(client_, *, project_id, entry):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            real(client_, project_id=project_id, entry=entry)  # 400 for the lock
            if calls["n"] == 2:  # the value-only fallback landed; the answer was lost
                raise CheckmarxError("connection reset")

        monkeypatch.setattr(platform, "set_project_setting", flaky)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.status == EnforcementStatus.FAILED
        assert tenant.fusion_setting("proj-api")["value"] == "false"
        monkeypatch.setattr(platform, "set_project_setting", real)

        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.status == EnforcementStatus.APPLIED
        snapshot = action.undo_snapshot
        assert snapshot["fusion_write"] is True
        assert snapshot["value_before"] == "true"
        assert snapshot["lock_applied"] is False
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "true" and entry["allowOverride"] is True

    def test_sibling_limits_last_release_restores_original(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        project_limit = make_limit(db, actions=["fusion"])
        group_limit = make_limit(
            db, entity_type=EntityType.GROUP, entity_id="grp-payments", actions=["fusion"]
        )
        enforcement.apply_enforcement(
            db, client, limit=project_limit, period_key=PERIOD, actor=ACTOR
        )
        enforcement.apply_enforcement(db, client, limit=group_limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        limits_service.update_limit(
            db,
            limit=project_limit,
            changes={"project_actions": ["auto_triage"]},
            actor=ACTOR,
            client=client,
        )
        db.commit()
        assert tenant.fusion_setting("proj-api")["value"] == "false"
        limits_service.update_limit(
            db, limit=group_limit, changes={"enforce": False}, actor=ACTOR, client=client
        )
        db.commit()
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "true" and entry["allowOverride"] is True

    def test_the_lock_is_still_checked_after_the_first_limit_lets_go(self, db: Session) -> None:
        """The second limit found the lock in place (the first one's): it carries
        the first one's word on the lock, so a lock removed later is re-applied."""
        tenant, client = setup_tenant(db)
        project_limit = make_limit(db, actions=["fusion"])
        group_limit = make_limit(
            db, entity_type=EntityType.GROUP, entity_id="grp-payments", actions=["fusion"]
        )
        enforcement.apply_enforcement(
            db, client, limit=project_limit, period_key=PERIOD, actor=ACTOR
        )
        enforcement.apply_enforcement(db, client, limit=group_limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        limits_service.update_limit(
            db,
            limit=project_limit,
            changes={"project_actions": ["auto_triage"]},
            actor=ACTOR,
            client=client,
        )
        db.commit()
        group_action = next(
            action
            for action in db.scalars(select(EnforcementAction))
            if action.kind == "disable_fusion"
            and action.limit_id == group_limit.id
            and action.target_id == "proj-api"
        )
        assert group_action.undo_snapshot["lock_applied"] is True
        tenant.fusion_setting("proj-api")["allowOverride"] = True
        outcome = enforcement.apply_enforcement(
            db, client, limit=group_limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.target_id for a in outcome.reconciled] == ["proj-api"]
        assert tenant.fusion_setting("proj-api")["allowOverride"] is False

    def test_unreadable_setting_never_unlocks_a_locked_one(self, db: Session) -> None:
        """The setting cannot be read and the locked write is refused: the
        restriction is reported unverifiable, never rewritten unlocked."""
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert tenant.fusion_setting("proj-api")["allowOverride"] is False
        tenant.fail_requests[("GET", "/configuration/project")] = 500
        tenant.reject_config_lock = True
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "false" and entry["allowOverride"] is False
        assert any("could not be verified" in line for line in outcome.skipped)

    def test_project_actions_none_is_stored_as_sql_null(self, db: Session) -> None:
        from sqlalchemy import text

        legacy = make_limit(db, actions=None)
        chosen = make_limit(db, entity_id="proj-web", actions=["fusion"])
        limits_service.update_limit(
            db, limit=chosen, changes={"project_actions": None}, actor=ACTOR
        )
        db.commit()
        nulls = dict(db.execute(text("SELECT id, project_actions IS NULL FROM credit_limit")).all())
        assert bool(nulls[legacy.id]) is True
        assert bool(nulls[chosen.id]) is True
        assert (
            db.scalar(
                select(func.count())
                .select_from(CreditLimit)
                .where(CreditLimit.project_actions.is_(None))
            )
            == 2
        )


class TestReadBack:
    def test_a_lock_the_tenant_does_not_keep_is_recorded_once_and_is_not_drift(
        self, db: Session
    ) -> None:
        tenant = populated_tenant()
        tenant.drop_config_lock = True
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.status == EnforcementStatus.APPLIED
        # One read straight after the write proves nothing (it may be behind):
        # the lock is kept as sent, unconfirmed.
        assert action.undo_snapshot["lock_applied"] is True
        assert action.undo_snapshot["lock_unconfirmed"] is True
        assert "lock_not_kept" not in action.undo_snapshot
        entry = tenant.fusion_setting("proj-api")
        assert entry["value"] == "false" and entry["allowOverride"] is True
        body = db.scalar(
            select(Notification.body).where(Notification.title.like("%: Fusion turned off"))
        )
        assert "could not be confirmed" in body
        # The next cycle reads it absent again: concluded, and said once.
        for _ in range(3):
            outcome = enforcement.apply_enforcement(
                db, client, limit=limit, period_key=PERIOD, actor=ACTOR
            )
            db.commit()
            assert outcome.reconciled == []
        action = actions_by_kind(db)["disable_fusion"]
        assert action.undo_snapshot["lock_applied"] is False
        assert action.undo_snapshot["lock_not_kept"] is True
        assert not action.undo_snapshot.get("lock_unconfirmed")
        assert action.undo_snapshot["fusion_write"] is True  # still given back on Restore
        notes = db.scalars(
            select(Notification).where(Notification.title.like("%Fusion lock not kept"))
        ).all()
        assert len(notes) == 1 and "did not keep it" in notes[0].body
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "enforcement.lock_not_kept") == 1
        # Once concluded the lock is no longer sent.
        patches = len(tenant.config_patches)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert len(tenant.config_patches) == patches
        assert _count(db, PolicyViolation) == 0
        assert _count(db, Notification, Notification.category == "policy") == 0
        # The value part is still enforced.
        tenant.fusion_setting("proj-api")["value"] = "true"
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in outcome.reconciled] == [EnforcementKind.DISABLE_FUSION]
        assert tenant.fusion_setting("proj-api")["value"] == "false"

    def test_a_lock_removed_every_cycle_is_one_violation_and_one_alert_a_day(
        self, db: Session
    ) -> None:
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        for _ in range(3):
            tenant.fusion_setting("proj-api")["allowOverride"] = True
            enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
            db.commit()
            assert tenant.fusion_setting("proj-api")["allowOverride"] is False
        from app.models.violations import KIND_SETTING_REENABLED

        assert _count(db, PolicyViolation, PolicyViolation.kind == KIND_SETTING_REENABLED) == 1
        # The violation's notification is the one alert, in the enforcement
        # category as a re-applied restriction always was.
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
        # Each re-assert is still audited.
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "enforcement.reconciled") == 3

    def test_a_value_the_tenant_does_not_keep_is_not_counted_as_turned_off(
        self, db: Session
    ) -> None:
        """Read back still on: in doubt, retried. The first time quietly (the
        read may be behind the write); an error only when the next cycle still
        reads it on, then once a day however often it is retried."""
        tenant = populated_tenant()
        tenant.drop_config_writes = True
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        could_not = Notification.title.like("Could not restrict%")
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.status == EnforcementStatus.FAILED
        assert "still reads as on" in action.error
        assert "checked again on the next cycle" in action.error
        assert outcome.failed == []
        assert _count(db, Notification, could_not) == 0
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "enforcement.failed") == 0
        # In doubt (part of it may have landed), so Restore still considers it.
        assert enforcement.may_be_in_force(action)
        assert action.undo_snapshot["fusion_enabled_before"] is True
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert outcome.failed
        assert _count(db, Notification, could_not, Notification.severity == "error") == 1
        for _ in range(2):
            enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
            db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert action.status == EnforcementStatus.FAILED
        assert enforcement.may_be_in_force(action)
        assert action.undo_snapshot["fusion_enabled_before"] is True
        assert _count(db, Notification, could_not) == 1
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "enforcement.failed") == 1
        # The value write is still retried every cycle (it may yet hold).
        assert len([p for p in tenant.config_patches if p[0] == "proj-api"]) >= 4

    def test_a_repo_setting_the_tenant_does_not_keep_is_recorded_once(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        tenant.drop_repo_fusion_writes = True
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])

        def repo_patches() -> int:
            return len(
                [
                    path
                    for method, path in tenant.requests
                    if method == "PATCH" and "/repos-manager/repo/" in path
                ]
            )

        sent = []
        for _ in range(4):
            outcome = enforcement.apply_enforcement(
                db, client, limit=limit, period_key=PERIOD, actor=ACTOR
            )
            db.commit()
            assert outcome.failed == []
            sent.append(repo_patches())
        # Read back on two consecutive attempts before it is concluded; then
        # not sent again for the rest of the period.
        assert sent == [1, 2, 2, 2]
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert repo.status == EnforcementStatus.FAILED
        assert "did not keep it" in repo.error
        # Concluded, yet still not certain: what was there before is kept.
        assert enforcement.may_be_in_force(repo)
        assert repo.undo_snapshot["repo_fusion_enabled_before"] is True
        assert repo.undo_snapshot["repo_fusion_before"]["llmModel"] == "opus-5.5"
        assert _count(db, Notification, Notification.severity == "error") == 0
        assert (
            _count(db, Notification, Notification.title.like("%repository Fusion setting not%"))
            == 1
        )
        assert (
            _count(
                db,
                AuditLogEntry,
                AuditLogEntry.action == "enforcement.not_restricted",
                AuditLogEntry.target_id == "proj-api",
            )
            == 1
        )
        assert _count(db, PolicyViolation) == 0


class TestReadBackIsNotCertain:
    """One read straight after a write can be behind it: nothing taken is ever
    forgotten because of it, and nothing is concluded from it alone."""

    def test_repo_read_back_stale_once_then_restore_turns_repo_fusion_back_on(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.checkmarx import platform

        tenant = populated_tenant()
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        real = platform.get_repo_fusion
        calls = {"n": 0}

        def stale(client_, *, repo_id, project_id):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2:  # the read-back right after the PATCH
                return platform.RepoFusionRead(
                    readable=True, config={"enabled": True, "llmModel": "opus-5.5"}
                )
            return real(client_, repo_id=repo_id, project_id=project_id)

        monkeypatch.setattr(platform, "get_repo_fusion", stale)
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert tenant.repo_fusion["repo-1"]["enabled"] is False  # the write did land
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert repo.status == EnforcementStatus.FAILED
        # In doubt, with what was there before: a quiet retry, not a conclusion.
        assert enforcement.may_be_in_force(repo)
        assert repo.undo_snapshot["repo_fusion_enabled_before"] is True
        assert outcome.failed == []
        assert _count(db, Notification, Notification.severity == "error") == 0
        assert _count(db, Notification, Notification.title.like("%not supported%")) == 0

        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert repo.status == EnforcementStatus.APPLIED
        assert repo.undo_snapshot["repo_fusion_enabled_before"] is True
        enforcement.restore_action(db, client, action=repo, actor=ACTOR)
        db.commit()
        assert tenant.repo_fusion["repo-1"] == {"enabled": True, "llmModel": "opus-5.5"}

    def test_a_repo_setting_concluded_not_kept_is_still_given_back(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.repo_fusion["repo-1"] = {"enabled": True, "llmModel": "opus-5.5"}
        tenant.drop_repo_fusion_writes = True
        tenant, client = setup_tenant(db, tenant)
        limit = make_limit(db, actions=["fusion"])
        for _ in range(2):
            enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
            db.commit()
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert "did not keep it" in (repo.error or "")
        # The write was in fact kept after all (it landed late).
        tenant.repo_fusion["repo-1"]["enabled"] = False
        tenant.drop_repo_fusion_writes = False
        assert enforcement.restore_action(db, client, action=repo, actor=ACTOR) is True
        db.commit()
        assert tenant.repo_fusion["repo-1"] == {"enabled": True, "llmModel": "opus-5.5"}
        assert actions_by_kind(db)["disable_repo_fusion"].status == EnforcementStatus.REVERSED

    def test_lock_only_write_with_stale_read_back_is_given_back_on_restore(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fusion already off, unlocked; the lock lands but the read-back is
        stale (allowOverride still true). Restore must unlock it again."""
        import dataclasses

        from app.checkmarx import platform

        tenant, client = setup_tenant(db)
        tenant.fusion_setting("proj-api")["value"] = "false"
        tenant.fusion_setting("proj-api")["allowOverride"] = True
        limit = make_limit(db, actions=["fusion"])
        real = platform.get_fusion_setting
        calls = {"n": 0}

        def stale(client_, *, project_id):  # type: ignore[no-untyped-def]
            current = real(client_, project_id=project_id)
            if project_id == "proj-api":
                calls["n"] += 1
                if calls["n"] == 2:
                    return dataclasses.replace(current, allow_override=True)
            return current

        monkeypatch.setattr(platform, "get_fusion_setting", stale)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert tenant.fusion_setting("proj-api")["allowOverride"] is False  # it did land
        action = actions_by_kind(db)["disable_fusion"]
        assert action.undo_snapshot["fusion_write"] is True
        assert action.undo_snapshot["lock_unconfirmed"] is True
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        entry = tenant.fusion_setting("proj-api")
        assert entry["allowOverride"] is True and entry["value"] == "false"

    def test_a_lock_seen_to_hold_later_is_confirmed_and_its_removal_is_drift(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.checkmarx import platform
        from app.checkmarx.errors import CheckmarxError
        from app.models.violations import KIND_SETTING_REENABLED

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        real = platform.get_fusion_setting
        calls = {"n": 0}

        def flaky(client_, *, project_id):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2:
                raise CheckmarxError("read-back timed out")
            return real(client_, project_id=project_id)

        monkeypatch.setattr(platform, "get_fusion_setting", flaky)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        monkeypatch.setattr(platform, "get_fusion_setting", real)
        action = actions_by_kind(db)["disable_fusion"]
        assert action.undo_snapshot["lock_unconfirmed"] is True
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = actions_by_kind(db)["disable_fusion"]
        assert "lock_unconfirmed" not in action.undo_snapshot
        assert action.undo_snapshot["lock_applied"] is True
        # Now a real removal is a violation.
        tenant.fusion_setting("proj-api")["allowOverride"] = True
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in outcome.reconciled] == [EnforcementKind.DISABLE_FUSION]
        assert _count(db, PolicyViolation, PolicyViolation.kind == KIND_SETTING_REENABLED) == 1

    def test_unconfirmed_lock_inherited_by_sibling_with_its_doubt(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Limit A writes the lock, the read-back fails (lock_unconfirmed) and the
        tenant does not keep the lock. The lock option is then turned off; limit
        B writes nothing and inherits A's word on the lock - doubt included - so
        neither reports 'lock removed' (nobody removed it)."""
        from app.checkmarx import platform
        from app.checkmarx.errors import CheckmarxError
        from app.models.violations import KIND_SETTING_REENABLED

        tenant = populated_tenant()
        tenant.drop_config_lock = True
        tenant, client = setup_tenant(db, tenant)
        project_limit = make_limit(db, actions=["fusion"])
        group_limit = make_limit(
            db, entity_type=EntityType.GROUP, entity_id="grp-payments", actions=["fusion"]
        )
        real = platform.get_fusion_setting
        calls = {"n": 0}

        def flaky(client_, *, project_id):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 2 and project_id == "proj-api":
                raise CheckmarxError("read-back timed out")
            return real(client_, project_id=project_id)

        monkeypatch.setattr(platform, "get_fusion_setting", flaky)
        enforcement.apply_enforcement(
            db, client, limit=project_limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        monkeypatch.setattr(platform, "get_fusion_setting", real)

        def fusion_action(limit: CreditLimit) -> EnforcementAction:
            db.expire_all()
            return next(
                x
                for x in db.scalars(select(EnforcementAction))
                if x.kind == "disable_fusion"
                and x.target_id == "proj-api"
                and x.limit_id == limit.id
            )

        a = fusion_action(project_limit)
        assert a.undo_snapshot.get("lock_unconfirmed") is True
        assert a.undo_snapshot.get("lock_applied") is True

        settings_store.set_value(db, settings_store.KEY_FUSION_LOCK, False)
        db.commit()
        enforcement.apply_enforcement(db, client, limit=group_limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        b = fusion_action(group_limit)
        assert b.undo_snapshot.get("lock_applied") is True
        assert b.undo_snapshot.get("lock_unconfirmed") is True

        for _ in range(3):
            enforcement.apply_enforcement(
                db, client, limit=project_limit, period_key=PERIOD, actor=ACTOR
            )
            enforcement.apply_enforcement(
                db, client, limit=group_limit, period_key=PERIOD, actor=ACTOR
            )
            db.commit()
        assert _count(db, PolicyViolation, PolicyViolation.kind == KIND_SETTING_REENABLED) == 0
        for limit in (project_limit, group_limit):
            snapshot = fusion_action(limit).undo_snapshot
            assert snapshot["lock_not_kept"] is True and snapshot["lock_applied"] is False
        # Said once for the project, however many limits restrict it.
        assert _count(db, Notification, Notification.title.like("%Fusion lock not kept")) == 1
        patches = len([p for p in tenant.config_patches if p[0] == "proj-api"])
        enforcement.apply_enforcement(
            db, client, limit=project_limit, period_key=PERIOD, actor=ACTOR
        )
        enforcement.apply_enforcement(db, client, limit=group_limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert len([p for p in tenant.config_patches if p[0] == "proj-api"]) == patches

    def test_never_settling_rows_do_not_push_applied_ones_off_the_active_list(
        self, db: Session, admin_client: TestClient
    ) -> None:
        from app.db.base import utcnow

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        applied = actions_by_kind(db)["disable_fusion"]
        assert applied.status == EnforcementStatus.APPLIED
        # Newer rows that never settle and were never in force (a "not
        # applicable" repository half retried every cycle, say).
        for index in range(8):
            db.add(
                EnforcementAction(
                    idempotency_key=f"synthetic-na-{index}",
                    kind="disable_repo_fusion",
                    status=EnforcementStatus.FAILED,
                    entity_type="project",
                    entity_id=f"proj-na-{index}",
                    target_type="cx_project",
                    target_id=f"proj-na-{index}",
                    target_label=f"na-{index}",
                    period_key=PERIOD,
                    created_at=utcnow(),
                    attempts=5,
                    error="nothing to turn off there (not applicable)",
                )
            )
        db.commit()
        listed = admin_client.get("/api/notifications/enforcements", params={"limit": 3})
        assert listed.status_code == 200
        assert applied.id in [row["id"] for row in listed.json()]
        assert all(row["status"] != "failed" for row in listed.json())

    def test_fallback_notification_when_violation_cannot_be_recorded(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import violations

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["auto_triage"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        tenant.auto_triage["proj-api"]["enabled"] = True

        def boom(*a, **k):  # type: ignore[no-untyped-def]
            raise RuntimeError("db hiccup")

        monkeypatch.setattr(violations, "record_reenabled", boom)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        n = db.scalars(select(Notification).where(Notification.title.like("%re-disabled%"))).all()
        assert [x.category for x in n] == ["enforcement"]


class TestDriftCadence:
    """A setting switched back on: notified in the enforcement category as
    before, once per restriction per period (Fusion once a day), with one
    violation row per restriction per period that counts the occurrences."""

    @staticmethod
    def _on_day(monkeypatch: pytest.MonkeyPatch, days: int) -> None:
        from datetime import timedelta

        from app.db.base import utcnow as real_utcnow
        from app.services import violations

        moment = real_utcnow() + timedelta(days=days)
        monkeypatch.setattr(violations, "utcnow", lambda: moment)

    def test_roles_or_auto_triage_back_every_day_notify_once_a_period(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.models.violations import KIND_SETTING_REENABLED

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["auto_triage"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        for day in range(3):
            self._on_day(monkeypatch, day)
            tenant.auto_triage["proj-api"]["enabled"] = True  # e.g. a daily sync
            enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
            db.commit()
            assert tenant.auto_triage["proj-api"]["enabled"] is False
        found = db.scalars(
            select(PolicyViolation).where(PolicyViolation.kind == KIND_SETTING_REENABLED)
        ).all()
        assert len(found) == 1
        assert found[0].evidence["occurrences"] == 3
        assert found[0].evidence["period"] == PERIOD
        assert found[0].evidence["last_seen"] > found[0].evidence["first_seen"]
        notes = db.scalars(
            select(Notification).where(Notification.title.like("%re-disabled%"))
        ).all()
        assert [n.category for n in notes] == ["enforcement"]
        assert notes[0].dedupe_key == f"reconciled:{found[0].enforcement_action_id}:{PERIOD}"
        assert _count(db, Notification, Notification.category == "policy") == 0
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "violation.detected") == 1

    def test_fusion_back_on_notifies_once_a_day_on_one_row(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.models.violations import KIND_SETTING_REENABLED

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        for day in (0, 0, 1):
            self._on_day(monkeypatch, day)
            tenant.fusion_setting("proj-api")["value"] = "true"
            enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
            db.commit()
        found = db.scalars(
            select(PolicyViolation).where(PolicyViolation.kind == KIND_SETTING_REENABLED)
        ).all()
        assert len(found) == 1 and found[0].evidence["occurrences"] == 3
        notes = db.scalars(
            select(Notification).where(Notification.title.like("%Fusion turned off again%"))
        ).all()
        assert [n.category for n in notes] == ["enforcement", "enforcement"]

    def test_resolved_then_found_again_reopens_the_row(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.models.violations import KIND_SETTING_REENABLED, STATUS_OPEN, STATUS_RESOLVED

        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["auto_triage"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        self._on_day(monkeypatch, 0)
        tenant.auto_triage["proj-api"]["enabled"] = True
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        row = db.scalar(
            select(PolicyViolation).where(PolicyViolation.kind == KIND_SETTING_REENABLED)
        )
        assert row is not None
        row.status = STATUS_RESOLVED
        row.resolved_by = "admin"
        row.resolved_at = row.detected_at
        db.commit()
        # Found again later in the same period: open again, audited, not silently counted.
        self._on_day(monkeypatch, 1)
        tenant.auto_triage["proj-api"]["enabled"] = True
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        db.refresh(row)
        assert row.status == STATUS_OPEN
        assert row.resolved_by is None and row.resolved_at is None
        assert row.evidence["occurrences"] == 2 and row.evidence.get("reopened_at")
        assert _count(db, AuditLogEntry, AuditLogEntry.action == "violation.reopened") == 1


class TestPricesAndNames:
    def test_inactive_rate_does_not_shadow_the_active_one(self, db: Session) -> None:
        settings_store.set_value(
            db,
            settings_store.KEY_ACTION_RATES,
            {
                "rates": [
                    {
                        "action_type": "fusion_scan_-_opus_5.5",
                        "credits_per_action": "1",
                        "display_name": "Fusion Scan - Opus 5.5",
                        "is_active": False,
                    },
                    {
                        "action_type": "fusion_scan_-_opus_5.5",
                        "credits_per_action": "2",
                        "display_name": "Fusion Scan - Opus 5.5",
                        "is_active": True,
                    },
                ]
            },
        )
        db.commit()
        table = usage_mix.rate_table(db)
        assert table["fusion_scan___opus_5.5"][0] == 2

    def test_a_scan_model_is_priced_by_an_exact_match_only(self) -> None:
        from app.services import violations

        rates = {
            "fusion_scan___claude_opus_5.5": (Decimal("9"), "Fusion Scan - Claude Opus 5.5"),
            "fusion_scan___haiku_4.5": (Decimal("1.5"), "Fusion Scan - Haiku 4.5"),
        }
        assert violations._fusion_price("opus-5.5", rates) is None
        assert violations._fusion_price("5.5", rates) is None
        assert violations._fusion_price("claude-opus-5.5", rates) == Decimal("9")
        assert violations._fusion_price("Haiku 4.5", rates) == Decimal("1.5")

    @pytest.mark.parametrize("raw", ["fusion_sast", "fusionsomething", "Fusion Report"])
    def test_other_fusion_types_stay_visible(self, raw: str) -> None:
        assert usage_api.normalise_action_type(raw) != ActionType.FUSION
        assert usage_api.normalise_action_type(raw) == usage_api.action_key(raw)


class TestNeededPermissions:
    def test_turning_fusion_off_needs_the_repository_read_and_the_scans(
        self, db: Session, monkeypatch
    ) -> None:
        tenant = _connected(db, monkeypatch)
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        make_limit(db, entity_id="proj-api", actions=["fusion"])
        assessed = key_permissions.current_report(db) or key_permissions.run_check(
            db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR
        )
        checks = {check["id"]: check for check in assessed["checks"]}
        assert checks["repo_read"]["required"] is True
        assert checks["repo_fusion_write"]["required"] is True
        assert checks["scans"]["required"] is True

    def test_without_a_fusion_limit_they_are_not_needed_for_it(
        self, db: Session, monkeypatch
    ) -> None:
        tenant = _connected(db, monkeypatch)
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        make_limit(db, entity_id="proj-api", actions=["auto_triage"])
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        checks = {check["id"]: check for check in report["checks"]}
        assert checks["repo_fusion_write"]["required"] is False
        assert checks["scans"]["required"] is False
