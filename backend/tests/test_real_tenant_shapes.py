"""Payload shapes a live tenant showed, and the writes that must follow them.

Synthetic data only, in the shapes observed (tests/fake_tenant.py):

* ``remediationSeverities`` wrapped as ``{"value": [...], "isEditable": true}``;
* the Auto Triage configuration listing ``auto_remediation`` and every
  ``allowOverride`` next to ``auto_triage``;
* an unset project configuration entry reporting ``originLevel`` ``Project``
  with ``isPersisted`` false.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import platform
from app.checkmarx.errors import CheckmarxError
from app.models import CreditLimit, EnforcementAction, Notification
from app.models.enums import EnforcementKind, EnforcementStatus, EntityType
from app.services import enforcement, org_sync
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


def project_limit(db: Session, entity_id: str = "proj-api", actions=None) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.PROJECT,
        entity_id=entity_id,
        entity_label=entity_id,
        credit_limit=10,
        period_type="monthly",
        enforce=True,
        project_actions=actions,
    )
    db.add(limit)
    db.commit()
    return limit


def action_of(db: Session, kind: str) -> EnforcementAction:
    found = db.scalar(select(EnforcementAction).where(EnforcementAction.kind == kind))
    assert found is not None, kind
    return found


# ------------------------------------------------------------ PR severities


class TestPrSeverityShapes:
    def test_both_shapes_parse(self) -> None:
        wrapped = platform.parse_pr_severities({"value": ["CRITICAL", "HIGH"], "isEditable": True})
        assert wrapped.severities == ["CRITICAL", "HIGH"]
        assert wrapped.shape == platform.PR_SHAPE_WRAPPED
        assert wrapped.fields == {"isEditable": True}
        bare = platform.parse_pr_severities(["CRITICAL"])
        assert bare.severities == ["CRITICAL"] and bare.shape == platform.PR_SHAPE_LIST
        assert platform.parse_pr_severities({"value": [], "isEditable": False}).severities == []

    @pytest.mark.parametrize(
        "value",
        ["CRITICAL,HIGH", {"isEditable": True}, {"value": "CRITICAL"}, [1, 2], None, 3],
    )
    def test_unknown_shapes_are_refused(self, value) -> None:
        with pytest.raises(platform.PrSeveritiesShapeError):
            platform.parse_pr_severities(value)

    def test_the_body_goes_back_in_the_shape_read(self) -> None:
        wrapped = platform.parse_pr_severities({"value": ["HIGH"], "isEditable": True})
        assert platform.pr_severities_body([], form=wrapped) == {"value": [], "isEditable": True}
        assert platform.pr_severities_body(["LOW"], form=wrapped.form()) == {
            "value": ["LOW"],
            "isEditable": True,
        }
        bare = platform.parse_pr_severities(["HIGH"])
        assert platform.pr_severities_body([], form=bare.form()) == []
        with pytest.raises(platform.PrSeveritiesShapeError):
            platform.pr_severities_body([], form={"shape": "csv"})

    def test_no_write_without_a_known_shape(self) -> None:
        tenant = populated_tenant()
        with pytest.raises(platform.PrSeveritiesShapeError):
            platform.set_pr_remediation_severities(
                tenant.client(), repo_id="repo-1", project_id="proj-api", severities=[], form=None
            )
        assert tenant.repo_patches == []

    @pytest.mark.parametrize("shape", ["wrapped", "list"])
    def test_capture_restrict_verify_and_restore(self, db: Session, shape: str) -> None:
        tenant = populated_tenant()
        tenant.repo_severities_shape = shape
        tenant, client = setup_tenant(db, tenant)
        tenant.repo_severities["repo-1"] = ["CRITICAL", "HIGH", "MEDIUM"]
        limit = project_limit(db)

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert EnforcementKind.DISABLE_PR_REMEDIATION in {a.kind for a in outcome.applied}
        assert tenant.repo_severities["repo-1"] == []
        sent = tenant.repo_patches[-1][1]["remediationSeverities"]
        if shape == "wrapped":
            assert sent == {"value": [], "isEditable": True}
        else:
            assert sent == []
        action = action_of(db, EnforcementKind.DISABLE_PR_REMEDIATION)
        assert action.undo_snapshot["severities_before"] == ["CRITICAL", "HIGH", "MEDIUM"]
        assert action.undo_snapshot["severities_form"]["shape"] == shape
        # Read back as the app reads it.
        read = platform.read_pr_remediation(client, repo_id="repo-1", project_id="proj-api")
        assert read is not None and read.severities == [] and read.shape == shape

        # Verified: someone turns it back on; the next pass re-asserts it, in
        # the same shape.
        tenant.repo_severities["repo-1"] = ["CRITICAL"]
        again = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in again.reconciled] == [EnforcementKind.DISABLE_PR_REMEDIATION]
        assert tenant.repo_severities["repo-1"] == []
        resent = tenant.repo_patches[-1][1]["remediationSeverities"]
        assert resent == sent

        assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH", "MEDIUM"]
        restored = tenant.repo_patches[-1][1]["remediationSeverities"]
        if shape == "wrapped":
            assert restored == {"value": ["CRITICAL", "HIGH", "MEDIUM"], "isEditable": True}
        else:
            assert restored == ["CRITICAL", "HIGH", "MEDIUM"]

    def test_an_unknown_shape_is_left_alone_and_reported(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.repo_severities_shape = "string"
        tenant, client = setup_tenant(db, tenant)
        limit = project_limit(db)

        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in outcome.applied] == [EnforcementKind.DISABLE_AUTO_TRIAGE]
        assert tenant.repo_patches == []
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]
        assert any("a str" in note for note in outcome.skipped), outcome.skipped
        notice = db.scalar(select(Notification).where(Notification.title.like("%left unchanged")))
        assert notice is not None and "neither a list" in notice.body

    def test_a_restriction_recorded_before_the_shape_was_kept_reads_it_on_restore(
        self, db: Session
    ) -> None:
        tenant, client = setup_tenant(db)
        limit = project_limit(db)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = action_of(db, EnforcementKind.DISABLE_PR_REMEDIATION)
        legacy = dict(action.undo_snapshot)
        legacy.pop("severities_form")
        action.undo_snapshot = legacy
        db.commit()

        assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]
        assert tenant.repo_patches[-1][1]["remediationSeverities"] == {
            "value": ["CRITICAL", "HIGH"],
            "isEditable": True,
        }

    def test_legacy_restore_with_an_unreadable_setting_writes_nothing(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = project_limit(db)
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = action_of(db, EnforcementKind.DISABLE_PR_REMEDIATION)
        legacy = dict(action.undo_snapshot)
        legacy.pop("severities_form")
        action.undo_snapshot = legacy
        db.commit()
        tenant.fail_requests[("GET", "/repos-manager/")] = 500
        patches = len(tenant.repo_patches)

        with pytest.raises(CheckmarxError, match="shape to restore it in is not known"):
            enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.rollback()
        assert len(tenant.repo_patches) == patches
        assert tenant.repo_severities["repo-1"] == []
        assert action.status != EnforcementStatus.REVERSED


# ------------------------------------------------------------ Auto Triage


def _features(body: dict) -> dict[str, str]:
    return {entry["feature"]: json.dumps(entry, sort_keys=True) for entry in body["configurations"]}


class TestAutoTriageRoundTrip:
    def test_the_put_keeps_everything_else_byte_for_byte(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        before = client.get_json(platform.AUTO_TRIAGE_PATH.format(project_id="proj-api"))
        limit = project_limit(db, actions=["auto_triage"])

        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

        assert tenant.auto_triage["proj-api"]["enabled"] is False
        (project_id, body) = tenant.auto_triage_puts[-1]
        assert project_id == "proj-api"
        # Top level fields as read.
        assert {k: v for k, v in body.items() if k != "configurations"} == {
            k: v for k, v in before.items() if k != "configurations"
        }
        sent, read = _features(body), _features(before)
        assert set(sent) == {"auto_triage", "auto_remediation"}
        assert sent["auto_remediation"] == read["auto_remediation"]
        triage = next(e for e in body["configurations"] if e["feature"] == "auto_triage")
        original = next(e for e in before["configurations"] if e["feature"] == "auto_triage")
        assert triage["enabled"] is False
        assert triage["config"] == original["config"]
        assert json.dumps(triage["allowOverride"], sort_keys=True) == json.dumps(
            original["allowOverride"], sort_keys=True
        )
        # The tenant (which resets what a PUT leaves out) kept auto_remediation.
        assert tenant.auto_remediation["proj-api"]["enabled"] is True
        action = action_of(db, EnforcementKind.DISABLE_AUTO_TRIAGE)
        assert action.undo_snapshot["payload_before"] == before

    def test_restore_changes_only_auto_triage(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = project_limit(db, actions=["auto_triage"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        # Someone changes auto_remediation while the restriction is in force:
        # Restore must neither reset nor revert it.
        tenant.auto_remediation["proj-api"]["enabled"] = False
        tenant.auto_remediation["proj-api"]["config"]["aggregationLimit"] = 7
        changed = json.dumps(tenant.auto_remediation["proj-api"], sort_keys=True)

        action = action_of(db, EnforcementKind.DISABLE_AUTO_TRIAGE)
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-api"]["enabled"] is True
        assert json.dumps(tenant.auto_remediation["proj-api"], sort_keys=True) == changed
        body = tenant.auto_triage_puts[-1][1]
        assert _features(body)["auto_remediation"] == changed

    def test_a_reassert_keeps_auto_remediation(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = project_limit(db, actions=["auto_triage"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        tenant.auto_triage["proj-api"]["enabled"] = True
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        db.commit()
        assert [a.kind for a in outcome.reconciled] == [EnforcementKind.DISABLE_AUTO_TRIAGE]
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert tenant.auto_remediation["proj-api"]["enabled"] is True

    def test_no_put_when_the_configuration_shape_is_unknown(self) -> None:
        tenant = populated_tenant()
        client = tenant.client()
        state = platform.AutoTriageState(enabled=True, raw={"scope": "project"})
        with pytest.raises(platform.CheckmarxResponseError):
            platform.set_auto_triage(
                client, project_id="proj-api", enabled=False, config={}, current=state
            )
        assert tenant.auto_triage_puts == []


# ------------------------------------------------------------ isPersisted


class TestIsPersisted:
    @pytest.mark.parametrize(
        ("origin", "persisted", "inherited"),
        [
            ("Project", True, False),
            ("Project", False, True),  # unset: no value of its own
            ("Project", None, False),
            ("Tenant", True, True),  # the tenant's value
            ("Environment", None, True),
            (None, None, False),
        ],
    )
    def test_inherited(self, origin, persisted, inherited) -> None:
        entry = {"key": platform.FUSION_SETTING_KEY, "value": "", "originLevel": origin}
        if persisted is not None:
            entry["isPersisted"] = persisted
        setting = platform.parse_project_setting([entry], key=platform.FUSION_SETTING_KEY)
        assert setting is not None
        assert setting.is_persisted is persisted
        assert setting.inherited is inherited

    def test_an_unset_entry_is_recorded_and_shown_as_inherited(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.set_fusion_setting(
            "proj-web", value="true", origin="Project", allow_override=True, is_persisted=False
        )
        tenant, client = setup_tenant(db, tenant)
        limit = project_limit(db, entity_id="proj-web", actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = action_of(db, EnforcementKind.DISABLE_FUSION)
        assert action.undo_snapshot["origin_level_before"] == "Project"
        assert action.undo_snapshot["is_persisted_before"] is False
        assert action.undo_snapshot["inherited_before"] is True
        applied = db.scalar(
            select(Notification).where(Notification.title.like("%Fusion turned off"))
        )
        assert "the project had no value of its own" in applied.body

        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        # Still written back (no per-key delete is known), and said so.
        entry = tenant.fusion_setting("proj-web")
        assert entry["value"] == "true" and entry["isPersisted"] is True
        restored = db.scalar(
            select(Notification).where(Notification.title.like("%Fusion setting restored"))
        )
        assert "the project had no value of its own" in restored.body
        assert "now set on the project" in restored.body

    def test_an_own_value_is_not_called_inherited(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        limit = project_limit(db, actions=["fusion"])
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        action = action_of(db, EnforcementKind.DISABLE_FUSION)
        assert action.undo_snapshot["inherited_before"] is False
        enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        restored = db.scalar(
            select(Notification).where(Notification.title.like("%Fusion setting restored"))
        )
        assert "inherited" not in restored.body
