"""Fusion: recognising its usage, pricing it, and turning it off per limit.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from app.checkmarx import credits as credits_api
from app.checkmarx import usage as usage_api
from app.db.migrate import alembic_config
from app.models import EnforcementAction, Notification
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
        tenant, client = setup_tenant(db)
        limit = make_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        repo = actions_by_kind(db)["disable_repo_fusion"]
        assert repo.status == EnforcementStatus.FAILED
        assert "do not include a Fusion setting" in repo.error
        assert not db.scalar(
            select(Notification).where(Notification.title.like("%no repository Fusion setting"))
        )
        assert "repo-1" not in tenant.repo_fusion  # nothing invented

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
