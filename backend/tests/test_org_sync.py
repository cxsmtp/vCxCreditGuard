"""Mirroring the Checkmarx organisation model."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    AuditLogEntry,
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.services import org_sync
from tests.fake_tenant import FakeTenant, populated_tenant


def test_syncs_every_entity_type(db: Session) -> None:
    tenant = populated_tenant()
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()

    assert result.users == 3
    assert result.groups == 2
    assert result.projects == 3
    assert result.applications == 1
    assert db.scalar(select(CxUser).where(CxUser.id == "user-harsh")) is not None


def test_user_fields_are_stored(db: Session) -> None:
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    user = db.get(CxUser, "user-harsh")
    assert user is not None
    assert user.username == "harsh.gokani@checkmarx.com"
    assert user.email == "harsh.gokani@checkmarx.com"
    assert user.display_name == "Harsh Gokani"
    assert user.auth_provider == "saml"
    assert "view-risk-management" in (user.role_names or [])
    assert user.group_names == ["AA-Platform"]


def test_emails_are_lowercased_for_matching(db: Session) -> None:
    tenant = FakeTenant()
    tenant.add_user(user_id="u1", username="Mixed.Case@Example.COM", email="Mixed.Case@Example.COM")
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert db.get(CxUser, "u1").email == "mixed.case@example.com"


def test_group_membership_is_resolved_from_names_to_ids(db: Session) -> None:
    """Users report groups by name; projects report them by id. This is the join."""
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    memberships = {(row.group_id, row.user_id) for row in db.scalars(select(CxGroupMembership))}
    assert ("grp-platform", "user-harsh") in memberships
    assert ("grp-payments", "user-sean") in memberships
    # A user in two groups gets two rows.
    assert ("grp-platform", "user-akash") in memberships
    assert ("grp-payments", "user-akash") in memberships


def test_duplicate_group_names_are_reported_not_guessed(db: Session) -> None:
    tenant = FakeTenant()
    tenant.add_group(group_id="g1", name="Platform", path="/eng/Platform")
    tenant.add_group(group_id="g2", name="Platform", path="/ops/Platform")
    tenant.add_user(user_id="u1", username="a@example.com", groups=["Platform"])

    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()

    assert any("not unique" in warning for warning in result.warnings)
    # The ambiguous membership is not invented.
    assert db.scalar(select(CxGroupMembership)) is None


def test_group_paths_resolve_when_names_are_ambiguous(db: Session) -> None:
    tenant = FakeTenant()
    tenant.add_group(group_id="g1", name="Platform", path="/eng/Platform")
    tenant.add_group(group_id="g2", name="Platform", path="/ops/Platform")
    tenant.add_user(user_id="u1", username="a@example.com", groups=["/eng/Platform"])

    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    membership = db.scalar(select(CxGroupMembership))
    assert membership is not None
    assert membership.group_id == "g1"


def test_unknown_group_names_are_warned_about(db: Session) -> None:
    tenant = FakeTenant()
    tenant.add_user(user_id="u1", username="a@example.com", groups=["Ghost Group"])
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert any("Ghost Group" in warning for warning in result.warnings)


def test_nested_groups_are_flattened_with_parents(db: Session) -> None:
    tenant = FakeTenant()
    tenant.groups = [
        {
            "id": "parent",
            "name": "Engineering",
            "path": "/Engineering",
            "subGroupCount": 1,
            "subGroups": [
                {
                    "id": "child",
                    "name": "Platform",
                    "path": "/Engineering/Platform",
                    "subGroups": [],
                }
            ],
        }
    ]
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    child = db.get(CxGroup, "child")
    assert child is not None
    assert child.parent_id == "parent"


def test_project_group_and_application_links_are_stored(db: Session) -> None:
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    project_groups = {(row.project_id, row.group_id) for row in db.scalars(select(CxProjectGroup))}
    assert ("proj-api", "grp-payments") in project_groups

    app_projects = {
        (row.application_id, row.project_id) for row in db.scalars(select(CxApplicationProject))
    }
    assert ("app-payments", "proj-api") in app_projects
    assert ("app-payments", "proj-web") in app_projects


def test_repo_id_is_captured_when_the_payload_carries_it(db: Session) -> None:
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert db.get(CxProject, "proj-api").repo_id == "repo-1"
    assert db.get(CxProject, "proj-web").repo_id is None


def test_integer_repo_id_is_captured_and_normalised(db: Session) -> None:
    """Checkmarx reports repoId as an integer; it must still be captured."""
    tenant = FakeTenant()
    tenant.add_project(project_id="proj-api", name="singakash/CxHybrid", repo_id=228481)
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    # Normalised to a string so it can be stored and used in the repos-manager URL.
    assert db.get(CxProject, "proj-api").repo_id == "228481"


def test_projects_paginate(db: Session) -> None:
    tenant = FakeTenant()
    for index in range(250):
        tenant.add_project(project_id=f"p{index}", name=f"project {index}")
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert result.projects == 250


def test_removed_entities_are_soft_deleted_not_erased(db: Session) -> None:
    """History has to stay readable, so nothing is hard deleted."""
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    tenant.projects = [row for row in tenant.projects if row["id"] != "proj-web"]
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()

    project = db.get(CxProject, "proj-web")
    assert project is not None
    assert project.is_deleted is True
    assert result.soft_deleted >= 1


def test_a_returning_entity_is_undeleted(db: Session) -> None:
    tenant = populated_tenant()
    removed = [row for row in tenant.projects if row["id"] == "proj-web"]
    tenant.projects = [row for row in tenant.projects if row["id"] != "proj-web"]
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    tenant.projects.extend(removed)
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert db.get(CxProject, "proj-web").is_deleted is False


def test_memberships_are_rebuilt_so_removals_take_effect(db: Session) -> None:
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    for user in tenant.users:
        if user["id"] == "user-akash":
            user["groups"] = ["AA-Platform"]
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    memberships = {(row.group_id, row.user_id) for row in db.scalars(select(CxGroupMembership))}
    assert ("grp-payments", "user-akash") not in memberships
    assert ("grp-platform", "user-akash") in memberships


def test_application_links_to_invisible_projects_are_warned_about(db: Session) -> None:
    tenant = populated_tenant()
    tenant.applications[0]["projectIds"].append("proj-invisible")
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert any("not visible to this API key" in warning for warning in result.warnings)


def test_users_endpoint_pagination_fallback(db: Session) -> None:
    """The unpaginated response is short of filteredCount, so paging kicks in."""
    tenant = FakeTenant()
    for index in range(5):
        tenant.add_user(user_id=f"u{index}", username=f"user{index}@example.com")
    tenant.users_requires_paging = True

    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert result.users == 5
    assert not any("only" in warning for warning in result.warnings)


def test_sync_is_audited(db: Session) -> None:
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "org.synced"))
    assert entry is not None
    assert entry.after["users"] == 3


def test_sync_is_idempotent(db: Session) -> None:
    tenant = populated_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()

    assert len(list(db.scalars(select(CxUser)))) == 3
    assert len(list(db.scalars(select(CxApplication)))) == 1
    assert len(list(db.scalars(select(CxGroupMembership)))) == 4
