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
    targets: list[TargetPreviewResponse]
    # What the limit turns off on its projects ([] for a user limit).
    project_actions: list[str] = []
    # The roles a user restriction removes, and per user what they would lose.
    ai_roles: list[str] = []
    user_roles: list[UserRolesPreviewResponse] = []
    user_roles_truncated: bool = False
    user_roles_note: str | None = None
    # Projects where turning Auto Triage off may not hold.
    warnings: list[ProjectWarningResponse] = []


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


class DryRunResponse(BaseModel):
    generated_at: datetime
    would_enforce_count: int
    would_warn_count: int
    affected_projects: int
    affected_users: int
    rows: list[DryRunRowResponse]
    user_roles_truncated: bool = False
    user_roles_note: str | None = None
