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
    total_actions: int
    targets: list[TargetPreviewResponse]


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


class DryRunResponse(BaseModel):
    generated_at: datetime
    would_enforce_count: int
    would_warn_count: int
    affected_projects: int
    affected_users: int
    rows: list[DryRunRowResponse]
