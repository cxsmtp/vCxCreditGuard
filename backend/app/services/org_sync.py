"""Mirror the Checkmarx One organisation model locally.

Why mirror at all: limit evaluation, the GUI entity pickers and enforcement fan
out all need the user, group, project and application graph, and re-reading it on
every two minute cycle would be both slow and rude to the API.

Rows are soft deleted rather than removed. A project that disappears from the
tenant still has to render in last month's audit log and in historical usage.

One awkward seam worth knowing about: ``/users/v2`` reports a user's groups by
**name**, while ``/projects`` reports a project's groups by **id**. Groups are
joined through the groups listing, which has both. Duplicate group names are
resolved by path where possible, and reported as a warning where not, because
guessing which "Platform" a user belongs to could attribute usage to the wrong
budget.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import iam, platform
from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.org import (
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)


@dataclass
class OrgSyncResult:
    users: int = 0
    groups: int = 0
    memberships: int = 0
    projects: int = 0
    project_groups: int = 0
    applications: int = 0
    application_projects: int = 0
    soft_deleted: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.warnings

    def as_stats(self) -> dict[str, object]:
        return {
            "users": self.users,
            "groups": self.groups,
            "memberships": self.memberships,
            "projects": self.projects,
            "applications": self.applications,
            "soft_deleted": self.soft_deleted,
            "warnings": self.warnings,
        }


def sync_org_model(
    session: Session,
    client: CheckmarxClient,
    *,
    actor: AuditActor | None = None,
) -> OrgSyncResult:
    """Refresh users, groups, projects, applications and the links between them."""
    result = OrgSyncResult()
    now = utcnow()

    group_index = _sync_groups(session, client, result, now)
    _sync_users(session, client, result, now, group_index)
    project_ids = _sync_projects(session, client, result, now)
    _sync_applications(session, client, result, now, project_ids)

    record_audit(
        session,
        action="org.synced",
        actor=actor or AuditActor.system("org_sync"),
        target_type="org_model",
        after=result.as_stats(),
        detail="Organisation model refreshed from Checkmarx One.",
    )
    session.flush()
    return result


# ---------------------------------------------------------------------- groups


@dataclass(frozen=True, slots=True)
class GroupIndex:
    """Lookups from what /users/v2 gives us (names) to group ids."""

    by_name: dict[str, str]
    by_path: dict[str, str]
    ambiguous_names: frozenset[str]

    def resolve(self, name: str) -> str | None:
        candidate = name.strip()
        if not candidate:
            return None
        # A leading slash means it is already a path.
        if candidate.startswith("/"):
            return self.by_path.get(candidate.lower())
        group_id = self.by_name.get(candidate.lower())
        if group_id is not None:
            return group_id
        return self.by_path.get(f"/{candidate}".lower())


def _sync_groups(
    session: Session, client: CheckmarxClient, result: OrgSyncResult, now
) -> GroupIndex:
    groups = iam.fetch_groups(client)
    existing = {row.id: row for row in session.scalars(select(CxGroup))}
    seen: set[str] = set()

    by_name: dict[str, str] = {}
    by_path: dict[str, str] = {}
    duplicates: set[str] = set()

    for group in groups:
        seen.add(group.id)
        row = existing.get(group.id)
        if row is None:
            row = CxGroup(id=group.id)
            session.add(row)
        row.name = group.name
        row.path = group.path
        row.parent_id = group.parent_id
        row.is_deleted = False
        row.last_synced_at = now
        row.raw = group.raw
        result.groups += 1

        key = group.name.strip().lower()
        if key in by_name and by_name[key] != group.id:
            duplicates.add(key)
        by_name[key] = group.id
        if group.path:
            by_path[group.path.strip().lower()] = group.id

    for name in duplicates:
        by_name.pop(name, None)
    if duplicates:
        result.warnings.append(
            f"{len(duplicates)} group name(s) are not unique in this tenant "
            f"({', '.join(sorted(duplicates)[:5])}). Memberships reported by name alone "
            "cannot be attributed for those groups, so their group limits may undercount."
        )

    result.soft_deleted += _soft_delete_missing(session, existing, seen, now)
    session.flush()
    return GroupIndex(by_name=by_name, by_path=by_path, ambiguous_names=frozenset(duplicates))


# ----------------------------------------------------------------------- users


def _sync_users(
    session: Session,
    client: CheckmarxClient,
    result: OrgSyncResult,
    now,
    group_index: GroupIndex,
) -> None:
    users, reported_total, warning = iam.fetch_users(client)
    if warning:
        result.warnings.append(warning)
    if reported_total is not None:
        logger.info("IAM reported %d users, read %d", reported_total, len(users))

    existing = {row.id: row for row in session.scalars(select(CxUser))}
    seen: set[str] = set()

    # Rebuild memberships from scratch each sync: a removal has to be reflected,
    # and the volumes here (hundreds of users) make diffing not worth the code.
    session.query(CxGroupMembership).delete(synchronize_session=False)

    unresolved_group_names: set[str] = set()
    # Memberships are collected and inserted after the users are flushed, because
    # cx_group_membership has a foreign key onto cx_user and the session does not
    # autoflush.
    pending_memberships: list[tuple[str, str]] = []

    for user in users:
        seen.add(user.id)
        row = existing.get(user.id)
        if row is None:
            row = CxUser(id=user.id)
            session.add(row)
        row.username = user.username
        row.email = user.email.lower() if user.email else None
        row.first_name = user.first_name
        row.last_name = user.last_name
        row.enabled = user.enabled
        row.auth_provider = user.auth_provider
        row.role_names = list(user.role_names)
        row.group_names = list(user.group_names)
        row.is_deleted = False
        row.last_synced_at = now
        row.raw = user.raw
        result.users += 1

        for group_name in user.group_names:
            group_id = group_index.resolve(group_name)
            if group_id is None:
                unresolved_group_names.add(group_name)
                continue
            pending_memberships.append((group_id, user.id))

    session.flush()
    for group_id, user_id in pending_memberships:
        session.add(
            CxGroupMembership(
                group_id=group_id, user_id=user_id, inherited=False, last_synced_at=now
            )
        )
        result.memberships += 1

    if unresolved_group_names:
        result.warnings.append(
            f"{len(unresolved_group_names)} group name(s) on users did not match any known "
            f"group ({', '.join(sorted(unresolved_group_names)[:5])}). Those memberships "
            "are not counted towards group limits."
        )

    result.soft_deleted += _soft_delete_missing(session, existing, seen, now)
    session.flush()


# -------------------------------------------------------------------- projects


def _sync_projects(
    session: Session, client: CheckmarxClient, result: OrgSyncResult, now
) -> set[str]:
    projects = platform.fetch_projects(client)
    existing = {row.id: row for row in session.scalars(select(CxProject))}
    seen: set[str] = set()

    session.query(CxProjectGroup).delete(synchronize_session=False)

    for project in projects:
        seen.add(project.id)
        row = existing.get(project.id)
        if row is None:
            row = CxProject(id=project.id)
            session.add(row)
        row.name = project.name
        row.repo_url = project.repo_url
        # Only overwrite a known repo id; an admin may have supplied one manually.
        if project.repo_id:
            row.repo_id = project.repo_id
        row.is_deleted = False
        row.last_synced_at = now
        row.raw = project.raw
        result.projects += 1

        for group_id in project.group_ids:
            session.add(
                CxProjectGroup(project_id=project.id, group_id=group_id, last_synced_at=now)
            )
            result.project_groups += 1

    result.soft_deleted += _soft_delete_missing(session, existing, seen, now)
    session.flush()
    return seen


# ---------------------------------------------------------------- applications


def _sync_applications(
    session: Session,
    client: CheckmarxClient,
    result: OrgSyncResult,
    now,
    known_project_ids: set[str],
) -> None:
    applications = platform.fetch_applications(client)
    existing = {row.id: row for row in session.scalars(select(CxApplication))}
    seen: set[str] = set()

    session.query(CxApplicationProject).delete(synchronize_session=False)

    unknown_links = 0
    for application in applications:
        seen.add(application.id)
        row = existing.get(application.id)
        if row is None:
            row = CxApplication(id=application.id)
            session.add(row)
        row.name = application.name
        row.description = application.description
        row.is_deleted = False
        row.last_synced_at = now
        row.raw = application.raw
        result.applications += 1

        for project_id in application.project_ids:
            if project_id not in known_project_ids:
                # A project the projects listing did not return, for example one
                # the service account cannot see. Recorded, not silently dropped.
                unknown_links += 1
            session.add(
                CxApplicationProject(
                    application_id=application.id, project_id=project_id, last_synced_at=now
                )
            )
            result.application_projects += 1

    if unknown_links:
        result.warnings.append(
            f"{unknown_links} application to project link(s) reference projects that are not "
            "visible to this API key. Application limits may undercount. Check the service "
            "account's project permissions."
        )

    result.soft_deleted += _soft_delete_missing(session, existing, seen, now)
    session.flush()


def _soft_delete_missing(session: Session, existing: dict, seen: set[str], now) -> int:
    """Flag rows the tenant no longer reports, without deleting history."""
    count = 0
    for row_id, row in existing.items():
        if row_id in seen or row.is_deleted:
            continue
        row.is_deleted = True
        row.last_synced_at = now
        count += 1
    return count
