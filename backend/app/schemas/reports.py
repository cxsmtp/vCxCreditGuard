"""Schemas for forward projection, impact, and the exportable report."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel

from app.models.enums import EntityType


class ProjectionResponse(BaseModel):
    limit_id: int
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    credit_limit: int
    enforce: bool
    period_key: str
    credits_used: Decimal
    burn_per_day: Decimal
    projected_period_end: Decimal
    percent_at_period_end: float | None
    days_to_exhaustion: float | None
    exhaustion_at: datetime | None
    will_breach: bool


class ImpactResponse(BaseModel):
    enforced_limits: int
    active_restrictions: int
    entities_restricted: int
    credits_over_budget: Decimal
    warnings_active: int
    monitor_only_breaches: int


class ReportResponse(BaseModel):
    generated_at: datetime
    limits_total: int
    limits_enforcing: int
    breaching_soon: int
    impact: ImpactResponse
    projections: list[ProjectionResponse]


class ReportEmailResult(BaseModel):
    sent: bool
    recipients: int
    message: str


class ChargebackRowResponse(BaseModel):
    business_unit: str
    limits: int
    credits_used: Decimal
    estimated_cost: Decimal | None


class ChargebackResponse(BaseModel):
    generated_at: datetime
    unit_cost: float
    currency_known: bool
    unassigned_limits: int
    rows: list[ChargebackRowResponse]
