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
import threading
import time
from dataclasses import dataclass, field, replace
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
    EnforcementStatus,
    EntityType,
    LimitStatus,
)
from app.models.limits import CreditLimit, EnforcementAction, effective_project_actions
from app.services import enforcement, evaluation, role_sources, settings_store
from app.services.periods import PeriodError, current_window


@dataclass(frozen=True, slots=True)
class TargetPreview:
    kind: str
    target_type: str
    target_id: str
    target_label: str | None


# How many users' roles one preview reads from Checkmarx One at most.
MAX_USERS_READ = 50
# How long one preview may spend reading roles in all, and each read at most.
# Every read is tried once: a page someone waits on does not retry with backoff.
ROLE_READ_BUDGET_SECONDS = 10.0
ROLE_READ_TIMEOUT_SECONDS = 5.0
# How long one user's role reading is reused by later previews (per connection,
# user and AI role list; dropped when the connection changes).
ROLE_PREVIEW_CACHE_SECONDS = 60.0

_cache_lock = threading.Lock()
_role_cache: dict[tuple[str, ...], tuple[float, UserRolesPreview]] = {}


def reset_role_cache() -> None:
    """Forget every cached role reading (the connection changed)."""
    with _cache_lock:
        _role_cache.clear()


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
    # A restriction already holds: the roles are not read again.
    already_restricted: bool = False


@dataclass(frozen=True, slots=True)
class ProjectWarning:
    project_id: str
    project_label: str | None
    message: str


class RolePreviewer:
    """Reads users' roles for previews: best effort, at most ``max_users`` users
    and ``ROLE_READ_BUDGET_SECONDS`` per request, each read tried once.

    Once Checkmarx IAM does not answer (unavailable, rate limited, timed out),
    nothing more is read in this request: the remaining users say so. A user
    already restricted is not read again. A reading is reused by later
    previews for ``ROLE_PREVIEW_CACHE_SECONDS``.
    """

    def __init__(
        self,
        session: Session,
        client: CheckmarxClient | None,
        *,
        max_users: int = MAX_USERS_READ,
        why_not_read: str | None = None,
        budget_seconds: float = ROLE_READ_BUDGET_SECONDS,
    ) -> None:
        self._session = session
        self.ai_roles = settings_store.ai_role_names(session)
        self._why_not_read = why_not_read or (
            "Checkmarx One is not connected, so the user's roles were not read."
        )
        self._max_users = max_users
        self._read: dict[str, UserRolesPreview] = {}
        self._reads = 0
        self._restricted: dict[str, EnforcementAction] | None = None
        self.truncated = False
        self._reader: role_sources.RoleSourceReader | None = None
        self._cache_key: tuple[str, ...] = ()
        if client is not None:
            resolver = enforcement.RoleResolver(client)
            self._reader = role_sources.RoleSourceReader(
                client,
                client_uuid=lambda: resolver.client_uuid,
                client_roles=resolver.all_roles,
                budget=role_sources.ReadBudget(
                    seconds=budget_seconds, call_timeout_seconds=ROLE_READ_TIMEOUT_SECONDS
                ),
            )
            self._cache_key = (
                str(client.key_fingerprint or ""),
                str(client.tenant_name or ""),
                str(client.iam_base_url or ""),
                *self.ai_roles,
            )

    @property
    def truncation_note(self) -> str | None:
        if not self.truncated:
            return None
        return (
            f"Roles were read for the first {self._max_users} users only; the others show "
            "which roles a restriction would remove, not what they hold."
        )

    def _removes(self) -> str:
        return (
            f"A restriction removes whichever of {', '.join(self.ai_roles)} the user holds "
            "directly."
        )

    def _not_read(self, user_id: str, label: str | None, note: str) -> UserRolesPreview:
        return UserRolesPreview(
            user_id=user_id, user_label=label, read=False, note=f"{note} {self._removes()}"
        )

    def _restriction_of(self, user_id: str) -> EnforcementAction | None:
        if self._restricted is None:
            self._restricted = {}
            for action in self._session.scalars(
                select(EnforcementAction)
                .where(
                    EnforcementAction.kind == EnforcementKind.REMOVE_USER_ROLES,
                    EnforcementAction.status == EnforcementStatus.APPLIED,
                )
                .order_by(EnforcementAction.id)
            ):
                self._restricted.setdefault(action.target_id, action)
        return self._restricted.get(user_id)

    def user(self, user_id: str, label: str | None) -> UserRolesPreview:
        if user_id in self._read:
            return self._read[user_id]
        preview = self._preview(user_id, label)
        self._read[user_id] = preview
        return preview

    def _preview(self, user_id: str, label: str | None) -> UserRolesPreview:
        if self._reader is None:
            return self._not_read(user_id, label, self._why_not_read)
        restriction = self._restriction_of(user_id)
        if restriction is not None:
            taken = sorted(
                {
                    str(entry.get("name"))
                    for entry in (restriction.undo_snapshot or {}).get("removed_roles") or []
                    if isinstance(entry, dict) and entry.get("name")
                }
            )
            return UserRolesPreview(
                user_id=user_id,
                user_label=label,
                read=False,
                already_restricted=True,
                note="Already restricted"
                + (
                    f" since {restriction.applied_at:%Y-%m-%d %H:%M} UTC"
                    if restriction.applied_at
                    else ""
                )
                + (f" ({', '.join(taken)} removed)" if taken else "")
                + ", so the roles were not read again.",
            )
        now = time.monotonic()
        key = (*self._cache_key, user_id)
        with _cache_lock:
            cached = _role_cache.get(key)
        if cached is not None and cached[0] > now:
            return replace(cached[1], user_label=label)
        if self._reader.stopped:
            return self._not_read(user_id, label, f"Not read: {self._reader.stopped}.")
        if self._reads >= self._max_users:
            self.truncated = True
            return self._not_read(
                user_id,
                label,
                f"Not read: a preview reads at most {self._max_users} users' roles.",
            )
        self._reads += 1
        preview = self._read_user(user_id, label)
        if preview.read:
            with _cache_lock:
                _role_cache[key] = (now + ROLE_PREVIEW_CACHE_SECONDS, preview)
        return preview

    def _read_user(self, user_id: str, label: str | None) -> UserRolesPreview:
        reader = self._reader
        assert reader is not None
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
        if reader.stopped:
            # Cut short: what was read is incomplete, so none of it is shown.
            return self._not_read(user_id, label, f"Not read: {reader.stopped}.")
        kept = [
            KeptRolePreview(name=name, sources=[source.describe() for source in sources])
            for name, sources in found.stays_effective().items()
        ]
        held = {role.name for role in removed} | {role.name for role in kept}
        return UserRolesPreview(
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


def auto_triage_warnings(
    session: Session, projects: dict[str, str | None], *, now: datetime | None = None
) -> list[ProjectWarning]:
    """Projects where turning Auto Triage off may not hold, by what was recorded.

    Goes by the latest restriction of each project in its limit's current
    period (the latest one of any period when there is none yet), and warns
    only on evidence:

    * it concluded that Auto Triage is set account-wide (still on after being
      turned off, twice), and no later read showed it off; or
    * it is not applied, its write was not read back yet, and the
      configuration read before it had ``allowOverride.projects`` false: a
      soft "may not hold, not verified yet". That shape is common and does not
      by itself mean the switch is ignored, so an applied restriction (read
      back off) never warns because of it.
    """
    if not projects:
        return []
    moment = now or utcnow()
    period_keys: dict[int | None, str | None] = {}

    def current_key(limit_id: int | None) -> str | None:
        if limit_id not in period_keys:
            limit = session.get(CreditLimit, limit_id) if limit_id else None
            try:
                period_keys[limit_id] = (
                    current_window(limit, moment).key if limit is not None else None
                )
            except PeriodError:
                period_keys[limit_id] = None
        return period_keys[limit_id]

    latest_now: dict[str, EnforcementAction] = {}
    latest_any: dict[str, EnforcementAction] = {}
    for action in session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.kind == EnforcementKind.DISABLE_AUTO_TRIAGE,
            EnforcementAction.target_id.in_(list(projects)),
        )
        .order_by(EnforcementAction.id.desc())
    ):
        latest_any.setdefault(action.target_id, action)
        if action.target_id not in latest_now and action.period_key == current_key(action.limit_id):
            latest_now[action.target_id] = action
    warnings: list[ProjectWarning] = []
    for project_id in projects:
        action = latest_now.get(project_id) or latest_any.get(project_id)
        if action is None:
            continue
        snapshot = action.undo_snapshot or {}
        label = projects.get(project_id) or project_id
        if snapshot.get("auto_triage_account_wide"):
            message = (
                f"Turning Auto Triage off for {label} may not hold: an earlier restriction found "
                "it still on after turning it off, twice, so it appears to be set account-wide "
                "with no project override."
            )
        elif action.status == EnforcementStatus.APPLIED:
            continue
        else:
            seen: Any = snapshot.get("auto_triage_allow_override")
            if "auto_triage_allow_override_read_back" in snapshot or not (
                isinstance(seen, dict) and seen.get("projects") is False
            ):
                continue
            recorded = json.dumps(seen, sort_keys=True)[:200]
            message = (
                f"Turning Auto Triage off for {label} may not hold (not verified yet): its "
                f"configuration was read with allowOverride {recorded}, "
                "which may mean the project cannot override the account's Auto Triage setting. "
                "Whether it holds is known once a restriction has been read back."
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
    warnings: bool = True,
) -> BlastRadius:
    """What enforcing this entity's limit would change, computed read-only.

    ``warnings`` False leaves out the Auto Triage warnings (the cycle's safety
    check needs only the targets).

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
        warnings=auto_triage_warnings(session, auto_triage_projects) if warnings else [],
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
    light: bool = False,
) -> DryRunResult:
    """Project what the next evaluation cycle would decide, writing nothing.

    ``light``: targets only, without the Auto Triage warnings (the cycle's
    safety check, every cycle).

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
            light=light,
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
    light: bool = False,
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
                warnings=not light,
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
