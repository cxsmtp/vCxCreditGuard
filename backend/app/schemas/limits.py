"""Schemas for limits, exemptions, notifications and operations."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field, model_validator

from app.models.enums import (
    EntityType,
    LimitStatus,
    PeriodType,
    Severity,
)
from app.schemas.auth import StrictModel


class LimitCreateRequest(StrictModel):
    entity_type: EntityType
    entity_id: str = Field(min_length=1, max_length=64)
    credit_limit: int = Field(ge=0, le=100_000_000)
    period_type: PeriodType = PeriodType.MONTHLY
    warning_threshold_pct: int = Field(default=80, ge=1, le=100)
    # Defaults to monitor only. Enforcement is always an explicit choice.
    enforce: bool = False
    include_member_usage: bool = False
    hold_until_released: bool = False
    # Count consumption already reported when the period opens. Ignored for lifetime
    # and custom periods, which always count everything.
    count_existing_usage: bool = False
    custom_period_start: datetime | None = None
    custom_period_end: datetime | None = None
    notes: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def _check_custom_period(self) -> LimitCreateRequest:
        if self.period_type == PeriodType.CUSTOM and self.custom_period_start is None:
            raise ValueError("A custom period needs a start date.")
        if (
            self.custom_period_start is not None
            and self.custom_period_end is not None
            and self.custom_period_end <= self.custom_period_start
        ):
            raise ValueError("The custom period's end date must be after its start date.")
        return self


class LimitUpdateRequest(StrictModel):
    credit_limit: int | None = Field(default=None, ge=0, le=100_000_000)
    period_type: PeriodType | None = None
    warning_threshold_pct: int | None = Field(default=None, ge=1, le=100)
    enforce: bool | None = None
    is_active: bool | None = None
    include_member_usage: bool | None = None
    hold_until_released: bool | None = None
    count_existing_usage: bool | None = None
    custom_period_start: datetime | None = None
    custom_period_end: datetime | None = None
    notes: str | None = Field(default=None, max_length=1024)


class LimitPeriodStateResponse(BaseModel):
    period_key: str
    period_start: datetime
    period_end: datetime | None
    credits_used: Decimal
    baseline_credits: Decimal
    reported_total: Decimal
    usage_available: bool
    status: LimitStatus
    percent_used: float | None = None
    last_evaluated_at: datetime | None = None
    warned_at: datetime | None = None
    breached_at: datetime | None = None
    restricted_at: datetime | None = None


class LimitResponse(BaseModel):
    id: int
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    credit_limit: int
    period_type: PeriodType
    custom_period_start: datetime | None
    custom_period_end: datetime | None
    warning_threshold_pct: int
    enforce: bool
    is_active: bool
    include_member_usage: bool
    hold_until_released: bool
    count_existing_usage: bool
    exempt: bool
    notes: str | None
    created_at: datetime
    updated_at: datetime
    current_period: LimitPeriodStateResponse | None = None
    active_restrictions: int = 0


class ExemptionCreateRequest(StrictModel):
    entity_type: EntityType
    entity_id: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=512)


class ExemptionResponse(BaseModel):
    id: int
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    reason: str | None
    created_at: datetime


class NotificationResponse(BaseModel):
    id: int
    created_at: datetime
    severity: Severity
    category: str
    entity_type: str | None
    entity_id: str | None
    entity_label: str | None
    title: str
    body: str | None
    read_at: datetime | None
    enforcement_action_id: int | None
    # Present when this notification refers to a reversible enforcement action.
    can_restore: bool = False


class NotificationListResponse(BaseModel):
    items: list[NotificationResponse]
    total: int
    unread: int


class MarkReadRequest(StrictModel):
    notification_ids: list[int] | None = Field(default=None, max_length=500)


class EnforcementActionResponse(BaseModel):
    id: int
    kind: str
    status: str
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    target_type: str
    target_id: str
    target_label: str | None
    period_key: str | None
    created_at: datetime
    applied_at: datetime | None
    reversed_at: datetime | None
    reversal_reason: str | None
    error: str | None


class CycleRunResponse(BaseModel):
    run_id: int | None
    status: str
    steps: dict
    errors: list[str]
    skipped_reason: str | None = None


class SchedulerStatusResponse(BaseModel):
    schedule: str
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_run_status: str | None
    last_success_at: datetime | None
    entities_in_warning: int
    entities_restricted: int
    unread_notifications: int
    unresolved_subjects: int
