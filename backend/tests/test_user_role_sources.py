"""Precise user restrictions and confirmed project switches.

* The roles a user restriction removes are a setting; each restriction keeps
  going by the list it recorded.
* Where a user's AI roles come from (directly, a group, a composite role) is
  read best effort; a role that stays effective is reported once, never drift.
* The Simulation says exactly what a person would lose and keep.
* Auto Triage and PR triage and remediation writes are read back, with a quiet
  retry and a once-only conclusion.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx import iam
from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
from app.models import AuditLogEntry, EnforcementAction, Notification, PolicyViolation
from app.models.enums import EnforcementKind, EnforcementStatus, EntityType, PeriodType
from app.models.limits import CreditLimit
from app.services import connection as connection_service
from app.services import (
    enforcement,
    key_permissions,
    limits_service,
    org_sync,
    preview_service,
    role_sources,
    settings_store,
)
from app.services.audit import AuditActor
from tests.conftest import USING_SQLITE, make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
PERIOD = "2026-08"
RM, RM_DASH, RM_TAB = DEFAULT_AI_ROLE_NAMES


def setup_tenant(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    db.commit()
    return tenant, client


def user_limit(db: Session, user_id: str = "user-harsh") -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id=user_id,
        entity_label=user_id,
        credit_limit=10,
        period_type="monthly",
        enforce=True,
    )
    db.add(limit)
    db.commit()
    return limit


def project_limit(db: Session, actions: list[str], entity_id: str = "proj-api") -> CreditLimit:
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id=entity_id,
            credit_limit=10,
            period_type=PeriodType.MONTHLY,
            enforce=True,
            project_actions=actions,
        ),
        actor=ACTOR,
    )
    db.commit()
    return limit


def apply(db: Session, client, limit: CreditLimit) -> enforcement.EnforcementOutcome:
    outcome = enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()
    return outcome


def set_ai_roles(db: Session, names: list[str]) -> None:
    settings_store.set_value(db, settings_store.KEY_AI_ROLES, names)
    db.commit()


def count(db: Session, model, *where) -> int:  # type: ignore[no-untyped-def]
    db.expire_all()
    return int(db.scalar(select(func.count()).select_from(model).where(*where)) or 0)


def only_action(db: Session, kind: str | None = None) -> EnforcementAction:
    db.expire_all()
    query = select(EnforcementAction)
    if kind is not None:
        query = query.where(EnforcementAction.kind == kind)
    rows = list(db.scalars(query))
    assert len(rows) == 1
    return rows[0]


def requests(tenant: FakeTenant, method: str, fragment: str) -> int:
    return len([1 for m, path in tenant.requests if m == method and fragment in path])


# ------------------------------------------------------------- the role list


class TestConfigurableRoleList:
    def test_default_list_is_the_legacy_three(self, db: Session) -> None:
        assert settings_store.ai_role_names(db) == DEFAULT_AI_ROLE_NAMES
        tenant, client = setup_tenant(db)
        apply(db, client, user_limit(db))
        action = only_action(db)
        assert {r["name"] for r in action.undo_snapshot["removed_roles"]} == set(
            DEFAULT_AI_ROLE_NAMES
        )
        assert action.undo_snapshot["ai_roles"] == list(DEFAULT_AI_ROLE_NAMES)
        assert action.undo_snapshot["kept_effective"] == []
        assert "view-scans" in tenant.role_mappings["user-harsh"]
        # Nothing about groups or composites to report for an ordinary user.
        assert count(db, Notification, Notification.title.like("%keeps AI access%")) == 0

    def test_an_unusable_stored_value_falls_back_to_the_default(self, db: Session) -> None:
        set_ai_roles(db, [])
        assert settings_store.ai_role_names(db) == DEFAULT_AI_ROLE_NAMES
        settings_store.set_value(db, settings_store.KEY_AI_ROLES, "a, b ;a")
        assert settings_store.ai_role_names(db) == ("a", "b")

    def test_a_custom_list_removes_only_those_roles(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        set_ai_roles(db, [RM_TAB, "view-projects"])
        apply(db, client, user_limit(db))
        held = tenant.role_mappings["user-harsh"]
        assert RM_TAB not in held and "view-projects" not in held
        assert RM in held and RM_DASH in held and "view-scans" in held
        action = only_action(db)
        assert {r["name"] for r in action.undo_snapshot["removed_roles"]} == {
            RM_TAB,
            "view-projects",
        }
        assert action.undo_snapshot["ai_roles"] == [RM_TAB, "view-projects"]

    def test_restore_returns_exactly_the_snapshot_after_the_list_changes(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        set_ai_roles(db, [RM_TAB, "view-projects"])
        limit = user_limit(db)
        apply(db, client, limit)
        # The admin changes the list while the restriction is in force.
        set_ai_roles(db, [RM, RM_DASH])
        # The cycle's pass for roles outside a restriction goes by the record:
        # nothing this restriction took is handed back early.
        assert enforcement.return_roles_outside_the_restriction(db, client, actor=ACTOR) == 0
        # Re-granted directly, a role of the *recorded* list is drift...
        tenant.role_mappings["user-harsh"].append("view-projects")
        outcome = apply(db, client, limit)
        assert [a.kind for a in outcome.reconciled] == [EnforcementKind.REMOVE_USER_ROLES]
        assert "view-projects" not in tenant.role_mappings["user-harsh"]
        # ...one only on the new list is not this restriction's business.
        assert RM in tenant.role_mappings["user-harsh"]
        held = apply(db, client, limit)
        assert held.reconciled == []
        assert RM in tenant.role_mappings["user-harsh"]

        action = only_action(db)
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        held_roles = set(tenant.role_mappings["user-harsh"])
        assert {RM_TAB, "view-projects", RM, RM_DASH, "view-scans"} <= held_roles

    def test_view_scans_from_an_old_restriction_is_still_returned_once(self, db: Session) -> None:
        """A restriction made before the list was a setting has no recorded list:
        the default three count as its AI roles, so view-scans goes back."""
        tenant, client = setup_tenant(db)
        set_ai_roles(db, [RM_TAB])
        limit = user_limit(db)
        apply(db, client, limit)
        action = only_action(db)
        legacy = {
            key: value
            for key, value in action.undo_snapshot.items()
            if key not in ("ai_roles", "kept_effective", "role_sources_unread")
        }
        legacy["removed_roles"] = [
            {"id": iam_id, "name": name}
            for name, iam_id in tenant.client_roles.items()
            if name in (*DEFAULT_AI_ROLE_NAMES, "view-scans")
        ]
        action.undo_snapshot = legacy
        db.commit()
        tenant.role_mappings["user-harsh"] = ["view-projects"]
        assert enforcement.return_roles_outside_the_restriction(db, client, actor=ACTOR) == 1
        assert tenant.role_mappings["user-harsh"] == ["view-projects", "view-scans"]
        # Once only: it is out of the snapshot now.
        assert enforcement.return_roles_outside_the_restriction(db, client, actor=ACTOR) == 0
        enforcement.restore_action(db, client, action=only_action(db), actor=ACTOR)
        db.commit()
        assert set(tenant.role_mappings["user-harsh"]) == {
            "view-projects",
            "view-scans",
            *DEFAULT_AI_ROLE_NAMES,
        }

    def test_merged_snapshots_keep_every_list(self) -> None:
        merged = enforcement._merge_snapshots(
            {"kind": "remove_user_roles", "removed_roles": [], "ai_roles": ["x"]},
            {"kind": "remove_user_roles", "removed_roles": [], "ai_roles": ["y"]},
        )
        assert merged["ai_roles"] == ["x", "y"]
        legacy = enforcement._merge_snapshots(
            {"kind": "remove_user_roles", "removed_roles": []},
            {"kind": "remove_user_roles", "removed_roles": [], "ai_roles": ["y"]},
        )
        assert set(legacy["ai_roles"]) == {*DEFAULT_AI_ROLE_NAMES, "y"}


# -------------------------------------------------- where roles come from


def _assert_reported_once(db: Session) -> None:
    assert count(db, Notification, Notification.title.like("%keeps AI access%")) == 1
    assert count(db, AuditLogEntry, AuditLogEntry.action == "enforcement.not_effective") == 1


class TestRoleSources:
    def test_a_role_held_through_a_group_is_reported_once_and_is_not_drift(
        self, db: Session
    ) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        limit = user_limit(db)

        outcome = apply(db, client, limit)
        assert len(outcome.applied) == 1
        # Only the direct mappings are removed; the group is left alone.
        assert not any(r in tenant.role_mappings["user-harsh"] for r in DEFAULT_AI_ROLE_NAMES)
        assert tenant.group_role_mappings["grp-ai"] == [RM]
        assert RM in tenant.effective_roles("user-harsh")
        action = only_action(db)
        kept = action.undo_snapshot["kept_effective"]
        assert kept == [
            {
                "role": RM,
                "sources": [{"kind": "group", "group": "/AI Users"}],
                "direct_removed": True,
            }
        ]
        _assert_reported_once(db)
        note = db.scalar(select(Notification).where(Notification.title.like("%keeps AI access%")))
        assert note is not None
        assert f"keeps {RM} through group /AI Users" in note.body
        assert "CreditGuard removed only the direct mapping" in note.body
        assert "Remove it from the group or role in Checkmarx One" in note.body
        assert "exemption" in note.body
        restricted = db.scalar(select(Notification).where(Notification.title.like("% restricted")))
        assert restricted is not None and "not effective" in restricted.body

        # Cycles go on: verified, never drift, never said again.
        for _ in range(3):
            again = apply(db, client, limit)
            assert again.reconciled == [] and again.failed == []
        _assert_reported_once(db)
        assert count(db, PolicyViolation) == 0
        # Restore gives back exactly the direct mappings it took.
        enforcement.restore_action(db, client, action=only_action(db), actor=ACTOR)
        db.commit()
        assert all(r in tenant.role_mappings["user-harsh"] for r in DEFAULT_AI_ROLE_NAMES)

    def test_a_role_held_through_a_parent_group(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-parent", name="Engineering", roles=[RM_DASH])
        tenant.add_group(group_id="grp-child", name="Backend", path="/Engineering/Backend")
        tenant.join_group("user-harsh", "grp-child")
        tenant, client = setup_tenant(db, tenant)
        apply(db, client, user_limit(db))
        kept = role_sources.kept_from_entries(only_action(db).undo_snapshot["kept_effective"])
        assert list(kept) == [RM_DASH]
        assert kept[RM_DASH][0].describe() == "group /Engineering"
        _assert_reported_once(db)

    def test_a_role_held_through_a_composite_role(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_client_role("ai-bundle", contains=["view-projects", RM_TAB])
        tenant.role_mappings["user-harsh"].append("ai-bundle")
        tenant, client = setup_tenant(db, tenant)
        limit = user_limit(db)
        apply(db, client, limit)
        assert "ai-bundle" in tenant.role_mappings["user-harsh"]  # composites untouched
        kept = role_sources.kept_from_entries(only_action(db).undo_snapshot["kept_effective"])
        assert list(kept) == [RM_TAB]
        assert kept[RM_TAB][0].describe() == "role ai-bundle"
        _assert_reported_once(db)
        for _ in range(2):
            assert apply(db, client, limit).reconciled == []
        _assert_reported_once(db)

    def test_a_composite_role_mapped_to_a_group(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_client_role("ai-bundle", contains=[RM])
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=["ai-bundle"])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        apply(db, client, user_limit(db))
        kept = role_sources.kept_from_entries(only_action(db).undo_snapshot["kept_effective"])
        assert kept[RM][0].describe() == "role ai-bundle (through group /AI Users)"

    def test_a_role_held_only_through_a_group_removes_nothing_and_says_so(
        self, db: Session
    ) -> None:
        tenant = FakeTenant()
        tenant.add_user(user_id="u1", username="u1@example.com", roles=["view-projects"])
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("u1", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        outcome = apply(db, client, user_limit(db, "u1"))
        assert len(outcome.applied) == 1
        assert requests(tenant, "DELETE", "/role-mappings/") == 0
        entry = only_action(db).undo_snapshot["kept_effective"][0]
        assert entry["role"] == RM and entry["direct_removed"] is False
        _assert_reported_once(db)

    def test_refused_source_reads_never_stop_the_restriction(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        key_permissions.discard_pending_denials()
        tenant.fail_requests[("GET", "/role-mappings/clients/" + tenant_uuid() + "/composite")] = (
            403
        )
        tenant.fail_requests[("GET", "/users/user-harsh/groups")] = 403
        outcome = apply(db, client, user_limit(db))
        assert len(outcome.applied) == 1 and outcome.failed == []
        assert not any(r in tenant.role_mappings["user-harsh"] for r in DEFAULT_AI_ROLE_NAMES)
        snapshot = only_action(db).undo_snapshot
        assert "the user's effective roles" in snapshot["role_sources_unread"]
        assert "the user's groups" in snapshot["role_sources_unread"]
        # The optional reads are not part of the key permission check.
        assert key_permissions.pending_denials() == 0
        assert count(db, Notification, Notification.title.like("%keeps AI access%")) == 0

    def test_a_role_effective_from_an_unreadable_source_is_source_unknown(
        self, db: Session
    ) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        tenant.fail_requests[("GET", "/groups/grp-ai/role-mappings/")] = 404
        limit = user_limit(db)
        # Held directly and through the unreadable group: still held after the
        # direct mapping goes, for no reason that can be seen. Once is a quiet
        # retry (the read may be behind); the next attempt concludes.
        first = apply(db, client, limit)
        assert first.applied == [] and first.failed == []
        assert count(db, Notification, Notification.severity == "error") == 0
        second = apply(db, client, limit)
        assert len(second.applied) == 1
        snapshot = only_action(db).undo_snapshot
        assert {r["name"] for r in snapshot["removed_roles"]} == set(DEFAULT_AI_ROLE_NAMES)
        kept = role_sources.kept_from_entries(snapshot["kept_effective"])
        assert kept[RM][0].kind == role_sources.SOURCE_UNKNOWN
        assert "the roles of group /AI Users" in snapshot["role_sources_unread"]
        note = db.scalar(select(Notification).where(Notification.title.like("%keeps AI access%")))
        assert note is not None and "source unknown" in note.body

    def test_a_stale_effective_read_is_a_quiet_retry(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)
        real = iam.fetch_user_effective_client_roles
        calls = {"n": 0}

        def stale(client_, *, user_id, client_uuid):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            roles = real(client_, user_id=user_id, client_uuid=client_uuid)
            if calls["n"] == 2:  # straight after the write: still shows the role
                return [*roles, iam.RoleRef(id="x", name=RM)]
            return roles

        monkeypatch.setattr(iam, "fetch_user_effective_client_roles", stale)
        limit = user_limit(db)
        first = apply(db, client, limit)
        assert first.failed == [] and first.applied == []
        action = only_action(db)
        assert action.status == EnforcementStatus.FAILED
        assert enforcement.may_be_in_force(action)  # the roles may be gone: kept for Restore
        assert count(db, Notification, Notification.severity == "error") == 0
        second = apply(db, client, limit)
        assert len(second.applied) == 1
        action = only_action(db)
        assert {r["name"] for r in action.undo_snapshot["removed_roles"]} == set(
            DEFAULT_AI_ROLE_NAMES
        )
        assert action.undo_snapshot["kept_effective"] == []

    def test_a_removal_the_tenant_does_not_keep_is_concluded_once(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)
        monkeypatch.setattr(iam, "remove_user_client_roles", lambda *a, **k: None)
        limit = user_limit(db)
        for _ in range(4):
            outcome = apply(db, client, limit)
            assert outcome.failed == []
        action = only_action(db)
        assert action.status == EnforcementStatus.FAILED
        assert "did not keep it" in (action.error or "")
        assert action.undo_snapshot["roles_read_back"] == sorted(DEFAULT_AI_ROLE_NAMES)
        assert count(db, Notification, Notification.title.like("%AI role removal not kept%")) == 1
        assert count(db, Notification, Notification.severity == "error") == 0


def tenant_uuid() -> str:
    from tests.fake_tenant import CLIENT_UUID

    return CLIENT_UUID


# ---------------------------------------------------------------- simulation


class TestSimulation:
    def test_blast_radius_lists_removed_and_kept_roles(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_client_role(
            "ai-bundle", contains=["view-projects", RM_DASH], description="AI power users"
        )
        tenant.role_mappings["user-harsh"].append("ai-bundle")
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        set_ai_roles(db, [*DEFAULT_AI_ROLE_NAMES, "ai-bundle"])

        blast = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="user-harsh", client=client
        )
        assert blast.ai_roles == [*DEFAULT_AI_ROLE_NAMES, "ai-bundle"]
        [user] = blast.user_roles
        assert user.read is True
        removed = {role.name: role for role in user.removed}
        assert set(removed) == {*DEFAULT_AI_ROLE_NAMES, "ai-bundle"}
        assert removed["ai-bundle"].grants == ["view-projects", RM_DASH]
        assert removed["ai-bundle"].description == "AI power users"
        assert removed[RM].grants == []
        assert "AI Triage/Remediation are reached from here" in (removed[RM].description or "")
        kept = {role.name: role.sources for role in user.kept}
        # The group still grants RM. RM_DASH comes with ai-bundle, which this
        # restriction removes as well, so it is not kept (Keycloak would drop it).
        assert kept[RM] == ["group /AI Users"]
        assert blast.user_roles_truncated is False

    def test_without_a_client_the_roles_are_not_read(self, db: Session) -> None:
        setup_tenant(db)
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="user-harsh"
        )
        [user] = blast.user_roles
        assert user.read is False
        assert "not connected" in (user.note or "")

    def test_the_number_of_users_read_is_capped(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        roles = preview_service.RolePreviewer(db, client, max_users=1)
        first = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="user-harsh", roles=roles
        )
        second = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="user-sean", roles=roles
        )
        assert first.user_roles[0].read is True
        assert second.user_roles[0].read is False
        assert second.user_roles_truncated is True
        assert "first 1 users" in (second.user_roles_note or "")
        assert "at most 1" in (second.user_roles[0].note or "")

    def test_the_api_returns_the_role_preview(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        db.commit()
        monkeypatch.setattr(connection_service, "get_client", lambda _s: tenant.client())
        response = admin_client.get(
            "/api/preview/blast-radius", params={"entity_type": "user", "entity_id": "user-harsh"}
        )
        assert response.status_code == 200
        body = response.json()
        [user] = body["user_roles"]
        assert user["read"] is True
        assert {role["name"] for role in user["removed"]} == set(DEFAULT_AI_ROLE_NAMES)
        assert user["kept"] == [{"name": RM, "sources": ["group /AI Users"]}]
        dry = admin_client.get("/api/preview/dry-run")
        assert dry.status_code == 200
        assert dry.json()["user_roles_truncated"] is False


# --------------------------------------------------- project read-backs


def at_puts(tenant: FakeTenant) -> int:
    return requests(tenant, "PUT", "/ai-agents-coordinator/projects/proj-api/configuration")


class TestAutoTriageReadBack:
    def test_stale_once_is_a_quiet_retry(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.ignore_auto_triage_writes = True
        limit = project_limit(db, ["auto_triage"])
        first = apply(db, client, limit)
        assert first.failed == [] and first.applied == []
        action = only_action(db, "disable_auto_triage")
        assert action.status == EnforcementStatus.FAILED
        assert "checked again on the next cycle" in (action.error or "")
        assert enforcement.may_be_in_force(action)
        assert count(db, Notification, Notification.severity == "error") == 0
        tenant.ignore_auto_triage_writes = False
        second = apply(db, client, limit)
        assert len(second.applied) == 1
        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert only_action(db, "disable_auto_triage").undo_snapshot["enabled_before"] is True

    def test_ignored_twice_is_concluded_account_wide_once(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.ignore_auto_triage_writes = True
        override = {"projects": False, "branches": True, "severities": True}
        tenant.auto_triage_allow_override["proj-api"] = override
        limit = project_limit(db, ["auto_triage"])
        sent = []
        for _ in range(4):
            outcome = apply(db, client, limit)
            assert outcome.failed == []
            sent.append(at_puts(tenant))
        assert sent == [1, 2, 2, 2]
        action = only_action(db, "disable_auto_triage")
        assert action.status == EnforcementStatus.FAILED
        assert "set account-wide" in (action.error or "")
        snapshot = action.undo_snapshot
        assert snapshot["auto_triage_account_wide"] is True
        assert snapshot["auto_triage_allow_override_read_back"] == override
        assert snapshot["auto_triage_allow_override"] == override
        assert enforcement.may_be_in_force(action)
        assert (
            count(db, Notification, Notification.title.like("%Auto Triage is set account-wide%"))
            == 1
        )
        assert (
            count(
                db,
                AuditLogEntry,
                AuditLogEntry.action == "enforcement.not_restricted",
                AuditLogEntry.target_id == "proj-api",
            )
            == 1
        )
        assert count(db, Notification, Notification.severity == "error") == 0
        assert count(db, PolicyViolation) == 0
        # Still restorable: what was there before is put back.
        tenant.ignore_auto_triage_writes = False
        tenant.auto_triage["proj-api"]["enabled"] = False
        assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-api"]["enabled"] is True

    def test_simulation_warns_it_may_not_hold(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.ignore_auto_triage_writes = True
        limit = project_limit(db, ["auto_triage"])
        for _ in range(2):
            apply(db, client, limit)
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.PROJECT, entity_id="proj-api"
        )
        [warning] = blast.warnings
        assert warning.project_id == "proj-api"
        assert "may not hold" in warning.message and "account-wide" in warning.message

    def test_simulation_warns_on_a_recorded_allow_override(self, db: Session) -> None:
        """allowOverride.projects false is the ordinary shape: applied and read
        back off, it is no reason to warn."""
        tenant, client = setup_tenant(db)
        tenant.auto_triage_allow_override["proj-api"] = {"projects": False}
        limit = project_limit(db, ["auto_triage"])
        apply(db, client, limit)
        assert only_action(db, "disable_auto_triage").status == EnforcementStatus.APPLIED
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.APPLICATION, entity_id="app-payments"
        )
        assert blast.warnings == []

    def test_simulation_warns_softly_before_anything_was_read_back(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.auto_triage_allow_override["proj-api"] = {"projects": False}
        tenant.fail_requests[("PUT", "/ai-agents-coordinator/projects/proj-api")] = 400
        limit = project_limit(db, ["auto_triage"])
        apply(db, client, limit)
        action = only_action(db, "disable_auto_triage")
        assert action.status == EnforcementStatus.FAILED
        assert "auto_triage_allow_override_read_back" not in action.undo_snapshot
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.APPLICATION, entity_id="app-payments"
        )
        [warning] = blast.warnings
        assert warning.project_id == "proj-api"
        assert "not verified yet" in warning.message
        assert '{"projects": false}' in warning.message

    def test_a_later_read_that_holds_clears_the_conclusion(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.ignore_auto_triage_writes = True
        limit = project_limit(db, ["auto_triage"])
        for _ in range(2):
            apply(db, client, limit)
        concluded = only_action(db, "disable_auto_triage")
        assert concluded.undo_snapshot["auto_triage_account_wide"] is True
        # The next period: the account setting was changed, the switch holds.
        tenant.ignore_auto_triage_writes = False
        tenant.auto_triage["proj-api"]["enabled"] = True
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key="2026-09", actor=ACTOR
        )
        db.commit()
        assert len(outcome.applied) == 1
        db.expire_all()
        db.refresh(concluded)
        assert concluded.undo_snapshot["auto_triage_account_wide"] is False
        # Restore still has what was there before.
        assert concluded.undo_snapshot["enabled_before"] is True
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.PROJECT, entity_id="proj-api"
        )
        assert blast.warnings == []

    def test_the_warning_goes_by_the_latest_action_in_the_current_period(self, db: Session) -> None:
        from app.db.base import utcnow
        from app.services.periods import current_window

        tenant, client = setup_tenant(db)
        limit = project_limit(db, ["auto_triage"])
        current = current_window(limit, utcnow()).key
        # This period's restriction applied and held ...
        enforcement.apply_enforcement(db, client, limit=limit, period_key=current, actor=ACTOR)
        db.commit()
        # ... and a row of an older period, written later, records a conclusion.
        db.add(
            EnforcementAction(
                idempotency_key="old-period-conclusion",
                kind=EnforcementKind.DISABLE_AUTO_TRIAGE,
                status=EnforcementStatus.FAILED,
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                target_type=enforcement.TARGET_PROJECT,
                target_id="proj-api",
                limit_id=limit.id,
                period_key="2020-01",
                created_at=utcnow(),
                attempts=2,
                undo_snapshot={"kind": "disable_auto_triage", "auto_triage_account_wide": True},
            )
        )
        db.commit()
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.PROJECT, entity_id="proj-api"
        )
        assert blast.warnings == []


class TestPrRemediationReadBack:
    def test_stale_once_then_kept(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.drop_pr_remediation_writes = True
        limit = project_limit(db, ["pr_remediation"])
        first = apply(db, client, limit)
        assert first.failed == [] and first.applied == []
        assert count(db, Notification, Notification.severity == "error") == 0
        tenant.drop_pr_remediation_writes = False
        second = apply(db, client, limit)
        assert len(second.applied) == 1
        assert tenant.repo_severities["repo-1"] == []

    def test_ignored_twice_is_concluded_once(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.drop_pr_remediation_writes = True
        limit = project_limit(db, ["pr_remediation"])
        sent = []
        for _ in range(4):
            assert apply(db, client, limit).failed == []
            sent.append(requests(tenant, "PATCH", "/repos-manager/repo/repo-1"))
        assert sent == [1, 2, 2, 2]
        action = only_action(db, "disable_pr_remediation")
        assert action.status == EnforcementStatus.FAILED
        assert "did not keep it" in (action.error or "")
        assert action.undo_snapshot["severities_before"] == ["CRITICAL", "HIGH"]
        assert action.undo_snapshot["severities_read_back"] == ["CRITICAL", "HIGH"]
        assert enforcement.may_be_in_force(action)
        assert count(db, Notification, Notification.title.like("%change not kept%")) == 1
        assert count(db, PolicyViolation) == 0


# -------------------------------------------------------- no lock held


@pytest.mark.skipif(not USING_SQLITE, reason="SQLite lock probe")
class TestNoWriteLockAcrossCalls:
    def test_role_sources_and_the_report(self, db: Session) -> None:
        from tests.test_cycle_transactions import _watch_for_write_locks

        tenant = populated_tenant()
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        limit = user_limit(db)
        held = _watch_for_write_locks(tenant)
        for _ in range(2):
            apply(db, client, limit)
        assert held == []
        _assert_reported_once(db)

    def test_auto_triage_conclusion(self, db: Session) -> None:
        from tests.test_cycle_transactions import _watch_for_write_locks

        tenant, client = setup_tenant(db)
        tenant.ignore_auto_triage_writes = True
        limit = project_limit(db, ["auto_triage", "pr_remediation"])
        held = _watch_for_write_locks(tenant)
        for _ in range(3):
            apply(db, client, limit)
        assert held == []


# ---------------------------------------------------------------- settings


@pytest.fixture
def connected(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    fake.add_client_role("ai-triage", description="AI Triage (dedicated)")
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _s: fake.client())
    return fake


class TestSettingsApi:
    def test_default_and_change(self, admin_client: TestClient, connected: FakeTenant) -> None:
        current = admin_client.get("/api/settings").json()
        assert current["ai_roles"] == list(DEFAULT_AI_ROLE_NAMES)
        assert current["default_ai_roles"] == list(DEFAULT_AI_ROLE_NAMES)
        saved = admin_client.put("/api/settings", json={"ai_roles": [" ai-triage ", RM]})
        assert saved.status_code == 200, saved.text
        assert saved.json()["ai_roles"] == ["ai-triage", RM]

    def test_unknown_or_empty_lists_are_refused(
        self, admin_client: TestClient, connected: FakeTenant
    ) -> None:
        unknown = admin_client.put("/api/settings", json={"ai_roles": ["no-such-role"]})
        assert unknown.status_code == 400
        assert unknown.json()["detail"]["code"] == "unknown_ai_roles"
        empty = admin_client.put("/api/settings", json={"ai_roles": []})
        assert empty.status_code in (400, 422)

    def test_unreadable_tenant_accepts_only_known_names(
        self, admin_client: TestClient, connected: FakeTenant
    ) -> None:
        connected.fail_requests[("GET", "/clients")] = 403
        refused = admin_client.put("/api/settings", json={"ai_roles": ["ai-triage"]})
        assert refused.status_code == 400
        assert refused.json()["detail"]["code"] == "ai_roles_unverifiable"
        narrowed = admin_client.put("/api/settings", json={"ai_roles": [RM]})
        assert narrowed.status_code == 200
        assert narrowed.json()["ai_roles"] == [RM]

    def test_client_role_listing(self, admin_client: TestClient, connected: FakeTenant) -> None:
        listing = admin_client.get("/api/settings/client-roles")
        assert listing.status_code == 200
        body = listing.json()
        assert body["available"] is True
        names = {role["name"]: role for role in body["roles"]}
        assert names["ai-triage"]["description"] == "AI Triage (dedicated)"
        assert "reached from here" in names[RM]["known_description"]
        # Cached briefly: a second ask does not read the tenant again.
        before = requests(connected, "GET", "/roles")
        admin_client.get("/api/settings/client-roles")
        assert requests(connected, "GET", "/roles") == before

    def test_client_role_listing_never_breaks(
        self, admin_client: TestClient, connected: FakeTenant
    ) -> None:
        connected.fail_requests[("GET", "/roles")] = 500
        listing = admin_client.get("/api/settings/client-roles")
        assert listing.status_code == 200
        assert listing.json()["available"] is False
        assert listing.json()["message"]

    def test_viewers_cannot_list_roles(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/settings/client-roles").status_code == 403

    @pytest.mark.parametrize(
        "role", ["manage-users", "ast-admin-reports", "iam-admin-x", "realm-x"]
    )
    def test_admin_like_roles_need_a_confirmation(
        self, admin_client: TestClient, connected: FakeTenant, role: str
    ) -> None:
        connected.add_client_role(role)
        refused = admin_client.put("/api/settings", json={"ai_roles": [role]})
        assert refused.status_code == 400, refused.text
        detail = refused.json()["detail"]
        assert detail["code"] == "admin_ai_roles_unconfirmed"
        assert "administration role" in detail["message"]
        assert admin_client.get("/api/settings").json()["ai_roles"] == list(DEFAULT_AI_ROLE_NAMES)
        confirmed = admin_client.put(
            "/api/settings", json={"ai_roles": [role, RM], "confirm_admin_roles": True}
        )
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["ai_roles"] == [role, RM]
        assert "confirm_admin_roles" not in confirmed.json()

    @pytest.mark.parametrize("role", ["ast-admin", "iam-admin"])
    def test_a_protected_role_is_refused_even_when_confirmed(
        self, admin_client: TestClient, connected: FakeTenant, role: str
    ) -> None:
        connected.add_client_role(role)
        refused = admin_client.put(
            "/api/settings", json={"ai_roles": [role, RM], "confirm_admin_roles": True}
        )
        assert refused.status_code == 400, refused.text
        detail = refused.json()["detail"]
        assert detail["code"] == "protected_ai_roles"
        assert "never restricted" in detail["message"]

    def test_protecting_an_ai_role_is_refused(
        self, admin_client: TestClient, connected: FakeTenant
    ) -> None:
        both = admin_client.put(
            "/api/settings", json={"ai_roles": ["ai-triage"], "protected_roles": "ai-triage"}
        )
        assert both.status_code == 400
        assert both.json()["detail"]["code"] == "protected_ai_roles"
        later = admin_client.put("/api/settings", json={"protected_roles": f"ast-admin, {RM}"})
        assert later.status_code == 400
        assert later.json()["detail"]["code"] == "protected_ai_roles"
        fine = admin_client.put("/api/settings", json={"protected_roles": "ast-admin, owner"})
        assert fine.status_code == 200

    def test_the_listing_marks_admin_like_and_protected_roles(
        self, admin_client: TestClient, connected: FakeTenant
    ) -> None:
        connected.add_client_role("manage-users")
        connected.add_client_role("ast-admin")
        roles = {
            role["name"]: role
            for role in admin_client.get("/api/settings/client-roles").json()["roles"]
        }
        assert roles["manage-users"]["admin_like"] is True
        assert roles["manage-users"]["protected"] is False
        assert roles["ast-admin"]["protected"] is True
        assert roles[RM]["admin_like"] is False and roles[RM]["protected"] is False


# ------------------------------------------------ review: role reads and previews


def connect(db: Session, monkeypatch: pytest.MonkeyPatch, tenant: FakeTenant) -> None:
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _s: tenant.client())


class TestPreviewAccess:
    def test_viewer_sees_no_group_names_and_makes_no_iam_reads(
        self, viewer_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-secret", name="Secret Team", roles=[RM])
        tenant.join_group("user-harsh", "grp-secret")
        tenant, _client = setup_tenant(db, tenant)
        connect(db, monkeypatch, tenant)
        built: list[object] = []
        real = connection_service.optional_client
        monkeypatch.setattr(
            connection_service, "optional_client", lambda s: built.append(s) or real(s)
        )
        before = len(tenant.requests)
        response = viewer_client.get(
            "/api/preview/blast-radius", params={"entity_type": "user", "entity_id": "user-harsh"}
        )
        assert response.status_code == 200
        [user] = response.json()["user_roles"]
        assert user["read"] is False
        assert user["kept"] == [] and user["removed"] == []
        assert "admins only" in user["note"]
        assert "Secret Team" not in response.text
        dry = viewer_client.get("/api/preview/dry-run")
        assert dry.status_code == 200
        assert len(tenant.requests) == before
        assert built == []

    def test_admin_still_gets_the_details(
        self, admin_client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-secret", name="Secret Team", roles=[RM])
        tenant.join_group("user-harsh", "grp-secret")
        tenant, _client = setup_tenant(db, tenant)
        connect(db, monkeypatch, tenant)
        response = admin_client.get(
            "/api/preview/blast-radius", params={"entity_type": "user", "entity_id": "user-harsh"}
        )
        assert response.json()["user_roles"][0]["kept"] == [
            {"name": RM, "sources": ["group /Secret Team"]}
        ]


class TestPreviewBudget:
    def test_preview_against_unavailable_iam_stops_at_once(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        slept: list[float] = []
        client._sleep = lambda seconds: slept.append(seconds)
        tenant.fail_requests[("GET", "/auth/admin/")] = 503
        before = len(tenant.requests)
        roles = preview_service.RolePreviewer(db, client)
        users = [roles.user(uid, uid) for uid in ("user-harsh", "user-sean")]
        assert len(tenant.requests) - before <= 1
        assert slept == []
        for user in users:
            assert user.read is False
            assert "Checkmarx IAM did not answer" in (user.note or "")

    def test_a_time_budget_bounds_the_reads(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        before = len(tenant.requests)
        roles = preview_service.RolePreviewer(db, client, budget_seconds=0)
        user = roles.user("user-harsh", "Harsh")
        assert user.read is False
        assert "ran out" in (user.note or "")
        assert len(tenant.requests) == before

    def test_reads_are_tried_once_with_a_short_timeout(self, db: Session) -> None:
        from app.checkmarx.client import single_attempt
        from app.checkmarx.errors import CheckmarxUnavailableError

        tenant, client = setup_tenant(db)
        slept: list[float] = []
        client._sleep = lambda seconds: slept.append(seconds)
        tenant.fail_requests[("GET", "/users/user-harsh/groups")] = 503
        before = requests(tenant, "GET", "/users/user-harsh/groups")
        with single_attempt(2.0), pytest.raises(CheckmarxUnavailableError):
            iam.fetch_user_groups(client, user_id="user-harsh")
        assert requests(tenant, "GET", "/users/user-harsh/groups") == before + 1
        assert slept == []
        # Outside it (enforcement), the full retry policy is unchanged.
        with pytest.raises(CheckmarxUnavailableError):
            iam.fetch_user_groups(client, user_id="user-harsh")
        assert requests(tenant, "GET", "/users/user-harsh/groups") > before + 2
        assert slept

    def test_a_failed_client_lookup_is_not_repeated_per_user(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        tenant.fail_requests[("GET", f"/auth/admin/realms/{tenant_name()}/clients")] = 403
        roles = preview_service.RolePreviewer(db, client)
        roles.user("user-harsh", None)
        after_first = requests(tenant, "GET", "/clients")
        second = roles.user("user-sean", None)
        assert requests(tenant, "GET", "/clients") == after_first
        assert second.read is True and "the user's effective roles" in second.unread

    def test_readings_are_reused_briefly_across_requests(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        first = preview_service.RolePreviewer(db, client).user("user-harsh", "Harsh")
        assert first.read is True
        before = len(tenant.requests)
        again = preview_service.RolePreviewer(db, client).user("user-harsh", "Harsh G.")
        assert len(tenant.requests) == before
        assert again.read is True and again.user_label == "Harsh G."
        # A connection change drops them.
        connection_service.reset_client_cache()
        preview_service.RolePreviewer(db, client).user("user-harsh", "Harsh")
        assert len(tenant.requests) > before

    def test_an_already_restricted_user_is_not_read_again(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        apply(db, client, user_limit(db))
        before = len(tenant.requests)
        user = preview_service.RolePreviewer(db, client).user("user-harsh", "Harsh")
        assert len(tenant.requests) == before
        assert user.read is False and user.already_restricted is True
        assert "Already restricted" in (user.note or "")
        assert "holds none" not in (user.note or "")
        assert user.not_held == []


def tenant_name() -> str:
    from tests.fake_tenant import TENANT

    return TENANT


class TestRoleSourceAccuracy:
    def test_a_child_of_a_removed_composite_is_not_kept(self, db: Session) -> None:
        tenant = FakeTenant()
        tenant.add_client_role("ai-bundle", contains=[RM_DASH])
        tenant.add_user(user_id="u1", username="u1@example.com", roles=["ai-bundle"])
        tenant, client = setup_tenant(db, tenant)
        set_ai_roles(db, [*DEFAULT_AI_ROLE_NAMES, "ai-bundle"])
        blast = preview_service.blast_radius(
            db, entity_type=EntityType.USER, entity_id="u1", client=client
        )
        [user] = blast.user_roles
        assert user.kept == []
        assert [role.name for role in user.removed] == ["ai-bundle"]
        apply(db, client, user_limit(db, "u1"))
        assert only_action(db).undo_snapshot["kept_effective"] == []

    def test_an_unreadable_read_back_reports_no_kept_roles_from_the_guess(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.checkmarx.errors import CheckmarxUnavailableError

        tenant = populated_tenant()
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[RM])
        tenant.join_group("user-harsh", "grp-ai")
        tenant, client = setup_tenant(db, tenant)
        real = iam.fetch_user_effective_client_roles
        calls = {"n": 0}

        def second_fails(client_, *, user_id, client_uuid):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] >= 2:
                raise CheckmarxUnavailableError("synthetic outage")
            return real(client_, user_id=user_id, client_uuid=client_uuid)

        monkeypatch.setattr(iam, "fetch_user_effective_client_roles", second_fails)
        outcome = apply(db, client, user_limit(db))
        assert len(outcome.applied) == 1
        snapshot = only_action(db).undo_snapshot
        assert snapshot["kept_effective"] == []
        assert "the user's effective roles after the removal" in snapshot["role_sources_unread"]
        assert count(db, Notification, Notification.title.like("%keeps AI access%")) == 0

    def test_hidden_source_wording_counts_the_earlier_removal(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant, client = setup_tenant(db)
        real = tenant.effective_roles

        def with_hidden(user_id: str) -> set[str]:
            return real(user_id) | ({RM} if user_id == "user-harsh" else set())

        monkeypatch.setattr(tenant, "effective_roles", with_hidden)
        limit = user_limit(db)
        assert apply(db, client, limit).applied == []
        assert len(apply(db, client, limit).applied) == 1
        snapshot = only_action(db).undo_snapshot
        [entry] = [e for e in snapshot["kept_effective"] if e["role"] == RM]
        assert RM in {r["name"] for r in snapshot["removed_roles"]}
        assert entry["direct_removed"] is True
        note = db.scalar(select(Notification).where(Notification.title.like("%keeps AI access%")))
        assert note is not None
        assert "CreditGuard removed only the direct mapping" in note.body
        assert "the user has none for it" not in note.body

    def test_groups_beyond_the_cap_are_reported_unread(self, db: Session) -> None:
        tenant = populated_tenant()
        for i in range(role_sources.MAX_GROUPS_PER_USER + 10):
            tenant.add_group(group_id=f"g{i}", name=f"G{i}", roles=[])
            tenant.join_group("user-harsh", f"g{i}")
        tenant, client = setup_tenant(db, tenant)
        found = enforcement.RoleResolver(client).sources.read_user(
            "user-harsh", ai_roles=DEFAULT_AI_ROLE_NAMES
        )
        [note] = [u for u in found.unread if "group" in u]
        assert f"beyond the first {role_sources.MAX_GROUPS_PER_USER}" in note
        assert f"in {role_sources.MAX_GROUPS_PER_USER + 10} groups" in note

    def test_composites_nested_too_deep_are_reported_unread(self, db: Session) -> None:
        tenant = populated_tenant()
        depth = role_sources.MAX_COMPOSITE_DEPTH + 2
        for level in range(depth):
            tenant.add_client_role(f"nest-{level}", contains=[f"nest-{level + 1}"])
        tenant.add_client_role(f"nest-{depth}", contains=[RM])
        tenant.role_mappings["user-harsh"].append("nest-0")
        tenant, client = setup_tenant(db, tenant)
        found = enforcement.RoleResolver(client).sources.read_user(
            "user-harsh", ai_roles=DEFAULT_AI_ROLE_NAMES
        )
        assert any("nest-0" in u and "levels deep" in u for u in found.unread), found.unread

    def test_a_composite_child_of_another_client_is_not_an_ai_role(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tenant = populated_tenant()
        tenant.add_client_role("ext-bundle", contains=[])
        tenant.role_mappings["user-harsh"].append("ext-bundle")
        tenant, client = setup_tenant(db, tenant)
        real = iam.fetch_client_role_composites

        def other_client(client_, *, client_uuid, role_name):  # type: ignore[no-untyped-def]
            if role_name == "ext-bundle":
                return [
                    iam.RoleRef(id="other-id", name=RM, container_id="another-client"),
                    iam.RoleRef(id="other-id-2", name=RM_TAB),  # no container: by id
                ]
            return real(client_, client_uuid=client_uuid, role_name=role_name)

        monkeypatch.setattr(iam, "fetch_client_role_composites", other_client)
        found = enforcement.RoleResolver(client).sources.read_user(
            "user-harsh", ai_roles=DEFAULT_AI_ROLE_NAMES
        )
        assert found.indirect == {}

    def test_tracked_reads_stay_on_the_key_permission_report(self, db: Session) -> None:
        tenant, client = setup_tenant(db)
        key_permissions.discard_pending_denials()
        tenant.fail_requests[("GET", f"/clients/{tenant_uuid()}/roles")] = 403
        preview_service.RolePreviewer(db, client).user("user-harsh", None)
        assert key_permissions.pending_denials() >= 1
        key_permissions.discard_pending_denials()
        # The optional source reads stay off it.
        tenant.fail_requests.clear()
        tenant.fail_requests[("GET", "/users/user-harsh/groups")] = 403
        preview_service.reset_role_cache()
        preview_service.RolePreviewer(db, client).user("user-harsh", None)
        assert key_permissions.pending_denials() == 0
