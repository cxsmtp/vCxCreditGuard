"""Read-only previews: enforcement blast radius and a dry-run of the next cycle.

Neither function writes anything. They answer two questions an admin wants
settled *before* turning enforcement on:

* **Blast radius** - if this entity's limit were enforced right now, exactly what
  would be restricted, and how much of it? One user's AI roles, or N projects'
  Auto Triage (and PR remediation where a repo is wired up).
* **Dry run** - across every active limit, what would the next cycle decide with
  the usage on hand, and which breaches would actually enforce? The same
  evaluation arithmetic, with the writes left out.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import iam
from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.enums import (
    LEGACY_PROJECT_ACTIONS,
    PROJECT_ACTION_ORDER,
    EnforcementKind,
    EntityType,
    LimitStatus,
)
from app.models.limits import CreditLimit, EnforcementAction, effective_project_actions
from app.services import enforcement, evaluation, settings_store
from app.services.periods import PeriodError, current_window


@dataclass(frozen=True, slots=True)
class TargetPreview:
    kind: str
    target_type: str
    target_id: str
    target_label: str | None


# How many users' roles one preview reads from Checkmarx One at most.
MAX_USERS_READ = 50


@dataclass(slots=True)
class RemovedRolePreview:
    """A role the restriction would remove, and what holding it gives."""

    name: str
    description: str | None = None
    # The roles it contains when it is a composite role; [] when it is not one,
    # None when that could not be read.
    grants: list[str] | None = None


@dataclass(slots=True)
class KeptRolePreview:
    """An AI role the user would keep, through a group or a composite role."""

    name: str
    sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class UserRolesPreview:
    """Exactly what one person would lose, as far as it could be read."""

    user_id: str
    user_label: str | None
    # Whether the user's roles were read from Checkmarx One at all.
    read: bool
    removed: list[RemovedRolePreview] = field(default_factory=list)
    kept: list[KeptRolePreview] = field(default_factory=list)
    # AI roles the user does not hold in any way that was seen.
    not_held: list[str] = field(default_factory=list)
    # What could not be read (so where a role comes from is not known).
    unread: list[str] = field(default_factory=list)
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ProjectWarning:
    project_id: str
    project_label: str | None
    message: str


class RolePreviewer:
    """Reads users' roles for previews: best effort, cached for the request,
    and at most ``max_users`` users per request."""

    def __init__(
        self,
        session: Session,
        client: CheckmarxClient | None,
        *,
        max_users: int = MAX_USERS_READ,
        why_not_read: str | None = None,
    ) -> None:
        self.ai_roles = settings_store.ai_role_names(session)
        self._resolver = enforcement.RoleResolver(client) if client is not None else None
        self._why_not_read = why_not_read or (
            "Checkmarx One is not connected, so the user's roles were not read."
        )
        self._max_users = max_users
        self._read: dict[str, UserRolesPreview] = {}
        self.truncated = False

    @property
    def truncation_note(self) -> str | None:
        if not self.truncated:
            return None
        return (
            f"Roles were read for the first {self._max_users} users only; the others show "
            "which roles a restriction would remove, not what they hold."
        )

    def user(self, user_id: str, label: str | None) -> UserRolesPreview:
        if user_id in self._read:
            return self._read[user_id]
        listed = ", ".join(self.ai_roles)
        if self._resolver is None:
            return UserRolesPreview(
                user_id=user_id,
                user_label=label,
                read=False,
                note=f"{self._why_not_read} A restriction removes whichever of {listed} "
                "the user holds directly.",
            )
        if len(self._read) >= self._max_users:
            self.truncated = True
            return UserRolesPreview(
                user_id=user_id,
                user_label=label,
                read=False,
                note=f"Not read: a preview reads at most {self._max_users} users' roles. A "
                f"restriction removes whichever of {listed} the user holds directly.",
            )
        reader = self._resolver.sources
        found = reader.read_user(user_id, ai_roles=self.ai_roles)
        known = reader.roles()
        removed = []
        for role in found.direct_ai():
            children = reader.children(role.name)
            tenant = known.get(role.name)
            removed.append(
                RemovedRolePreview(
                    name=role.name,
                    description=iam.ROLE_DESCRIPTIONS.get(role.name)
                    or (tenant.description if tenant else None),
                    grants=None if children is None else sorted(c.name for c in children),
                )
            )
        kept = [
            KeptRolePreview(name=name, sources=[source.describe() for source in sources])
            for name, sources in found.stays_effective().items()
        ]
        held = {role.name for role in removed} | {role.name for role in kept}
        preview = UserRolesPreview(
            user_id=user_id,
            user_label=label,
            read=True,
            removed=removed,
            kept=kept,
            not_held=[name for name in self.ai_roles if name not in held],
            unread=list(found.unread),
            note=(
                "Some of where these roles come from could not be read, so a role held "
                "through a group or a composite role may be missing here."
                if found.unread
                else None
            ),
        )
        self._read[user_id] = preview
        return preview


def auto_triage_warnings(session: Session, projects: dict[str, str | None]) -> list[ProjectWarning]:
    """Projects where turning Auto Triage off may not hold, by what was last read.

    Best effort, from what earlier restrictions recorded: one concluded set
    account-wide, or a configuration read with ``allowOverride.projects`` false.
    """
    if not projects:
        return []
    latest: dict[str, EnforcementAction] = {}
    for action in session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.kind == EnforcementKind.DISABLE_AUTO_TRIAGE,
            EnforcementAction.target_id.in_(list(projects)),
        )
        .order_by(EnforcementAction.id.desc())
    ):
        latest.setdefault(action.target_id, action)
    warnings: list[ProjectWarning] = []
    for project_id, action in latest.items():
        snapshot = action.undo_snapshot or {}
        label = projects.get(project_id) or project_id
        if snapshot.get("auto_triage_account_wide"):
            message = (
                f"Turning Auto Triage off for {label} may not hold: an earlier restriction found "
                "it still on after turning it off, twice, so it appears to be set account-wide "
                "with no project override."
            )
        else:
            seen: Any = snapshot.get("auto_triage_allow_override_read_back")
            if seen is None:
                seen = snapshot.get("auto_triage_allow_override")
            if not (isinstance(seen, dict) and seen.get("projects") is False):
                continue
            message = (
                f"Turning Auto Triage off for {label} may not hold: its configuration was last "
                f"read with allowOverride {json.dumps(seen, sort_keys=True)[:200]}, which "
                "suggests the project cannot override the account's Auto Triage setting."
            )
        warnings.append(ProjectWarning(project_id=project_id, project_label=label, message=message))
    return warnings


@dataclass(slots=True)
class BlastRadius:
    entity_type: str
    entity_id: str
    entity_label: str | None
    exempt: bool
    affected_users: int
    affected_projects: int
    remove_user_roles: int
    disable_auto_triage: int
    disable_pr_remediation: int
    total_actions: int
    targets: list[TargetPreview] = field(default_factory=list)
    # Fusion turned off in the project's scan settings, and in the repository's
    # settings (projects with a repository; skipped when it has no such setting).
    disable_fusion: int = 0
    disable_repo_fusion: int = 0
    # What the limit turns off on its projects ([] for a user limit).
    project_actions: list[str] = field(default_factory=list)
    # The roles a user restriction removes (the setting), and per user target
    # what they would lose and keep.
    ai_roles: list[str] = field(default_factory=list)
    user_roles: list[UserRolesPreview] = field(default_factory=list)
    user_roles_truncated: bool = False
    user_roles_note: str | None = None
    # Projects where turning Auto Triage off may not hold.
    warnings: list[ProjectWarning] = field(default_factory=list)


def blast_radius(
    session: Session,
    *,
    entity_type: str,
    entity_id: str,
    project_actions: list[str] | None = None,
    client: CheckmarxClient | None = None,
    roles: RolePreviewer | None = None,
) -> BlastRadius:
    """What enforcing this entity's limit would change, computed read-only.

    ``project_actions`` previews a choice that is not saved yet (the limit
    form); without it the entity's limit's own choice is used, or the legacy
    pair when it has no limit.
    """
    exempt = enforcement.is_exempt(session, entity_type=entity_type, entity_id=entity_id)
    if entity_type == EntityType.USER:
        actions: tuple[str, ...] = ()
    elif project_actions is not None:
        actions = tuple(a for a in PROJECT_ACTION_ORDER if a in set(project_actions))
    else:
        limit = session.scalar(
            select(CreditLimit).where(
                CreditLimit.entity_type == entity_type, CreditLimit.entity_id == entity_id
            )
        )
        actions = effective_project_actions(limit) if limit is not None else LEGACY_PROJECT_ACTIONS
    targets = enforcement.plan_targets(
        session, entity_type=entity_type, entity_id=entity_id, project_actions=actions
    )

    projects: set[str] = set()
    users: set[str] = set()
    counts = dict.fromkeys(EnforcementKind, 0)
    previews: list[TargetPreview] = []
    for target in targets:
        counts[target.kind] = counts.get(target.kind, 0) + 1
        if target.kind == EnforcementKind.REMOVE_USER_ROLES:
            users.add(target.target_id)
        else:
            projects.add(target.target_id)
        previews.append(
            TargetPreview(
                kind=str(target.kind),
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
            )
        )

    roles = roles or RolePreviewer(session, client)
    user_roles = [
        roles.user(target.target_id, target.target_label)
        for target in targets
        if target.kind == EnforcementKind.REMOVE_USER_ROLES
    ]
    auto_triage_projects = {
        target.target_id: target.target_label
        for target in targets
        if target.kind == EnforcementKind.DISABLE_AUTO_TRIAGE
    }

    label = enforcement_entity_label(session, entity_type=entity_type, entity_id=entity_id)
    return BlastRadius(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=label,
        exempt=exempt,
        affected_users=len(users),
        affected_projects=len(projects),
        remove_user_roles=counts[EnforcementKind.REMOVE_USER_ROLES],
        disable_auto_triage=counts[EnforcementKind.DISABLE_AUTO_TRIAGE],
        disable_pr_remediation=counts[EnforcementKind.DISABLE_PR_REMEDIATION],
        disable_fusion=counts[EnforcementKind.DISABLE_FUSION],
        disable_repo_fusion=counts[EnforcementKind.DISABLE_REPO_FUSION],
        total_actions=len(previews),
        targets=previews,
        project_actions=list(actions),
        ai_roles=list(roles.ai_roles),
        user_roles=user_roles,
        user_roles_truncated=roles.truncated,
        user_roles_note=roles.truncation_note,
        warnings=auto_triage_warnings(session, auto_triage_projects),
    )


def enforcement_entity_label(session: Session, *, entity_type: str, entity_id: str) -> str | None:
    from app.services import limits_service

    return limits_service.resolve_entity_label(
        session, entity_type=entity_type, entity_id=entity_id
    )


@dataclass(slots=True)
class DryRunRow:
    limit_id: int
    entity_type: str
    entity_id: str
    entity_label: str | None
    credit_limit: int
    enforce: bool
    exempt: bool
    usage_available: bool
    credits_used: Decimal
    percent_used: float | None
    projected_status: str
    would_enforce: bool
    blast: BlastRadius | None
    note: str | None = None
    # The budget period the projection is for (None when the period is misconfigured).
    period_key: str | None = None
    # How much of credits_used is auto-triage charged from scans; None when that
    # setting is off or the limit is not fed by a person's usage.
    auto_triage_attributed: Decimal | None = None


@dataclass(slots=True)
class DryRunResult:
    generated_at: datetime
    rows: list[DryRunRow] = field(default_factory=list)
    would_enforce_count: int = 0
    would_warn_count: int = 0
    affected_projects: int = 0
    affected_users: int = 0
    # Set when more users would be restricted than one preview reads roles for.
    user_roles_truncated: bool = False
    user_roles_note: str | None = None


def dry_run(
    session: Session,
    *,
    now: datetime | None = None,
    client: CheckmarxClient | None = None,
    roles: RolePreviewer | None = None,
) -> DryRunResult:
    """Project what the next evaluation cycle would decide, writing nothing.

    With a ``client``, the roles of users who would be restricted are read
    (best effort, at most ``MAX_USERS_READ`` of them).
    """
    moment = now or utcnow()
    roles = roles or RolePreviewer(session, client)
    index = evaluation.UsageIndex(session)
    result = DryRunResult(generated_at=moment)
    all_projects: set[str] = set()
    all_users: set[str] = set()

    # The real cycle defers every restriction when no tenant connection is
    # configured, so a dry run should say so rather than promise enforcement that
    # could not run.
    from app.services import connection as connection_service

    connection_configured = connection_service.get_connection(session) is not None

    limits = list(session.scalars(select(CreditLimit).where(CreditLimit.is_active.is_(True))))
    for limit in limits:
        row = _project_one(
            session,
            limit=limit,
            index=index,
            moment=moment,
            connection_configured=connection_configured,
            roles=roles,
        )
        result.rows.append(row)
        if row.projected_status == LimitStatus.WARNED:
            result.would_warn_count += 1
        if row.would_enforce:
            result.would_enforce_count += 1
            if row.blast is not None:
                for target in row.blast.targets:
                    if target.kind == str(EnforcementKind.REMOVE_USER_ROLES):
                        all_users.add(target.target_id)
                    else:
                        all_projects.add(target.target_id)

    result.affected_projects = len(all_projects)
    result.affected_users = len(all_users)
    result.user_roles_truncated = roles.truncated
    result.user_roles_note = roles.truncation_note
    result.rows.sort(key=lambda r: (not r.would_enforce, -(r.percent_used or 0.0)))
    return result


def _project_one(
    session: Session,
    *,
    limit: CreditLimit,
    index: evaluation.UsageIndex,
    moment: datetime,
    connection_configured: bool = True,
    roles: RolePreviewer | None = None,
) -> DryRunRow:
    exempt = enforcement.is_exempt(
        session, entity_type=limit.entity_type, entity_id=limit.entity_id
    )

    try:
        window = current_window(limit, moment)
    except PeriodError as exc:
        return DryRunRow(
            limit_id=limit.id,
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            credit_limit=limit.credit_limit,
            enforce=limit.enforce,
            exempt=exempt,
            usage_available=False,
            credits_used=Decimal("0"),
            percent_used=None,
            projected_status=LimitStatus.OK,
            would_enforce=False,
            blast=None,
            note=f"Misconfigured period: {exc}",
        )

    # Read the stored baseline without creating or mutating any state. When no
    # state exists yet, use the exact baseline the first real cycle would pick
    # (evaluation.baseline_for) rather than assuming the current reading: for a
    # lifetime, custom or count_existing_usage limit that baseline is 0, so the
    # first cycle counts the whole reported total and can breach immediately. A
    # naive "baseline = reported_total" would make the simulation claim such a
    # limit is within budget right up until it restricts someone. Auto-triage
    # credits charged to a person from their scans are included exactly as the
    # evaluation includes them.
    credits_used, available, attributed = evaluation.period_usage(
        session, limit=limit, window=window, index=index, moment=moment
    )
    auto_triage = attributed.counted if attributed is not None else None

    if not available or not window.is_active:
        return DryRunRow(
            limit_id=limit.id,
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            credit_limit=limit.credit_limit,
            enforce=limit.enforce,
            exempt=exempt,
            usage_available=available,
            credits_used=Decimal("0"),
            percent_used=None,
            projected_status=LimitStatus.OK,
            would_enforce=False,
            blast=None,
            note=(
                "No consumption reported for this level on this tenant."
                if not available
                else "The custom period is not currently open."
            ),
        )

    percent = float(credits_used) / limit.credit_limit * 100 if limit.credit_limit > 0 else 100.0
    threshold = Decimal(limit.credit_limit) * Decimal(limit.warning_threshold_pct) / 100

    if credits_used >= Decimal(limit.credit_limit):
        projected = LimitStatus.BREACHED
    elif credits_used >= threshold:
        projected = LimitStatus.WARNED
    else:
        projected = LimitStatus.OK

    blast: BlastRadius | None = None
    would_enforce = False
    note: str | None = None
    if projected == LimitStatus.BREACHED:
        if exempt:
            note = "Would breach, but the entity is exempt."
        elif not limit.enforce:
            note = "Would breach, but the limit is monitor only."
        else:
            blast = blast_radius(
                session,
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                project_actions=list(effective_project_actions(limit)),
                roles=roles,
            )
            would_enforce = blast.total_actions > 0
            if not would_enforce:
                protected = (
                    enforcement.protection_reason(session, limit.entity_id)
                    if limit.entity_type == "user"
                    else None
                )
                note = (
                    f"Would breach, but this user is not restricted because {protected}."
                    if protected
                    else "Would breach, but there is nothing to restrict (no linked projects)."
                )
            elif not connection_configured:
                note = (
                    "Would breach and enforce, but no Checkmarx connection is configured, "
                    "so the restriction would be deferred until one is."
                )

    return DryRunRow(
        limit_id=limit.id,
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        credit_limit=limit.credit_limit,
        enforce=limit.enforce,
        exempt=exempt,
        usage_available=True,
        credits_used=credits_used,
        percent_used=percent,
        projected_status=projected,
        would_enforce=would_enforce,
        blast=blast,
        note=note,
        period_key=window.key,
        auto_triage_attributed=auto_triage,
    )
