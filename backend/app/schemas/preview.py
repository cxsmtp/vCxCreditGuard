"""Schemas for enforcement previews (blast radius and dry run)."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel

from app.models.enums import EntityType, LimitStatus


class TargetPreviewResponse(BaseModel):
    kind: str
    target_type: str
    target_id: str
    target_label: str | None


class RemovedRolePreviewResponse(BaseModel):
    name: str
    description: str | None = None
    # The roles it contains when composite; [] when not; null when unreadable.
    grants: list[str] | None = None


class KeptRolePreviewResponse(BaseModel):
    name: str
    sources: list[str] = []


class UserRolesPreviewResponse(BaseModel):
    user_id: str
    user_label: str | None
    read: bool
    removed: list[RemovedRolePreviewResponse] = []
    kept: list[KeptRolePreviewResponse] = []
    not_held: list[str] = []
    unread: list[str] = []
    note: str | None = None
    # A restriction already holds, so the roles were not read again.
    already_restricted: bool = False


class ProjectWarningResponse(BaseModel):
    project_id: str
    project_label: str | None
    message: str


class BlastRadiusResponse(BaseModel):
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    exempt: bool
    affected_users: int
    affected_projects: int
    remove_user_roles: int
    disable_auto_triage: int
    disable_pr_remediation: int
    # Fusion off in the project's scan settings / in its repository's settings.
    disable_fusion: int = 0
    disable_repo_fusion: int = 0
    total_actions: int
    # The first targets only, for a large group or application: ``targets_total``
    # says how many there are in all (the counts above are always complete).
    targets: list[TargetPreviewResponse]
    targets_total: int = 0
    targets_truncated: bool = False
    # What the limit turns off on its projects ([] for a user limit).
    project_actions: list[str] = []
    # The roles a user restriction removes, and per user what they would lose.
    ai_roles: list[str] = []
    user_roles: list[UserRolesPreviewResponse] = []
    user_roles_truncated: bool = False
    user_roles_note: str | None = None
    # Projects where turning Auto Triage off may not hold (the first ones;
    # ``warnings_total`` in all).
    warnings: list[ProjectWarningResponse] = []
    warnings_total: int = 0


class DryRunRowResponse(BaseModel):
    limit_id: int
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    credit_limit: int
    enforce: bool
    exempt: bool
    usage_available: bool
    credits_used: Decimal
    percent_used: float | None
    projected_status: LimitStatus
    would_enforce: bool
    blast: BlastRadiusResponse | None
    note: str | None
    # How much of credits_used is auto-triage charged to the person from their
    # scans. Null when that setting is off or the limit is not fed by a person.
    auto_triage_attributed: Decimal | None = None
    # A new restriction of a monthly or quarterly budget: it starts only if a
    # direct recount of the activity log agrees (not run by the preview).
    recount_required: bool = False


class DryRunResponse(BaseModel):
    generated_at: datetime
    would_enforce_count: int
    would_warn_count: int
    affected_projects: int
    affected_users: int
    rows: list[DryRunRowResponse]
    user_roles_truncated: bool = False
    user_roles_note: str | None = None


class EnforcementCoverageResponse(BaseModel):
    """How many of the users who hold an AI role a user restriction can reach.

    See app/services/coverage.py. ``available`` false: computed without
    reading the tenant's composite roles and groups.
    """

    computed_at: datetime
    ai_roles: list[str]
    protected_roles: list[str]
    users: int
    ai_holders: int
    restrictable: int
    share: float | None = None
    via_composite: int
    via_group: int
    via_composite_or_group: int
    protected: int
    unknown: int
    composites: dict[str, list[str]] = {}
    composite_holders: dict[str, int] = {}
    groups_granting: list[str] = []
    dedicated_roles: list[str] = []
    notes: list[str] = []
    available: bool = True
    low: bool = False
    warning: str | None = None
    # False when no AI holder's role sources could be read: no verdict.
    determined: bool = True
    undetermined: str | None = None
