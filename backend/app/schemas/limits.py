"""Schemas for limits, exemptions, notifications and operations."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field, model_validator

from app.models.enums import (
    EntityType,
    LimitStatus,
    PeriodType,
    ProjectAction,
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
    business_unit: str | None = Field(default=None, max_length=128)
    # What a project, group or application limit turns off on its projects.
    # Omitted or null: Auto Triage and PR triage and remediation (what every
    # limit did before the choice existed). Not allowed on user limits.
    project_actions: list[ProjectAction] | None = Field(default=None, max_length=3)

    @model_validator(mode="after")
    def _check_custom_period(self) -> LimitCreateRequest:
        if self.period_type == PeriodType.CUSTOM and self.custom_period_start is None:
            raise ValueError("A custom period needs a start date.")
        if self.project_actions is not None:
            if self.entity_type == EntityType.USER:
                raise ValueError(
                    "What to turn off for projects can only be chosen for project, group and "
                    "application limits."
                )
            if not self.project_actions:
                raise ValueError("Choose at least one thing to turn off for projects.")
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
    business_unit: str | None = Field(default=None, max_length=128)
    # null puts the limit back on the legacy pair; an empty list is refused.
    project_actions: list[ProjectAction] | None = Field(default=None, max_length=3)


class AutoTriagePartResponse(BaseModel):
    """One person's share of one project's auto-triage credits behind a figure."""

    user_id: str
    user_label: str | None = None
    project_id: str
    project_label: str | None = None
    # "observed": traced to scans this person started, when the credits were
    # spent. "estimated": credits from before observation began, split by how
    # many scans each person ran on the auto-triage branches.
    basis: str
    # Attributed inside the consumption lookback window.
    credits: Decimal
    # Of which counts towards this period (see counts_existing_usage).
    counted: Decimal


class AutoTriageAttributionResponse(BaseModel):
    """The auto-triage credits charged from scans that are part of a figure.

    Present only while the setting "charge auto-triage credits to the person who
    started the scan" is on, and only for user limits and group limits that
    include member usage.
    """

    # Every figure below is as it would be counted now, from the same live
    # rebuild, so counted + not_counted == window_total and the parts add up.
    # The amount that counts towards this period.
    counted: Decimal
    # What the period's credits_used included at its last evaluation (null
    # before the first). Differs from ``counted`` only between cycles, for
    # example right after an initiator was mapped; the next cycle catches up.
    evaluated_counted: Decimal | None = None
    # Everything attributed to the person (or the group's members) inside the
    # consumption window, counted or not.
    window_total: Decimal
    # window_total - counted: attributed, but from before this period's
    # baseline, so it does not count against it.
    not_counted: Decimal
    # True for lifetime, custom and count_existing_usage limits, which count
    # usage already reported. Otherwise only charges observed after
    # counted_since count.
    counts_existing_usage: bool
    counted_since: datetime | None = None
    parts: list[AutoTriagePartResponse] = Field(default_factory=list)


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
    # Null unless auto-triage credits are being charged to scan initiators.
    auto_triage_attributed: AutoTriageAttributionResponse | None = None
    # Set when the limit's restriction is spread over several cycles (more
    # targets than one cycle's write budget): users or projects it restricts,
    # and how many have been dealt with so far.
    rollout_total: int | None = None
    rollout_done: int | None = None


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
    business_unit: str | None = None
    # As stored: null for a limit that predates the choice (and for users).
    project_actions: list[str] | None = None
    # What the limit actually turns off on its projects ([] for user limits).
    effective_project_actions: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
    current_period: LimitPeriodStateResponse | None = None
    active_restrictions: int = 0


class ExemptionCreateRequest(StrictModel):
    entity_type: EntityType
    entity_id: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=512)
    # When set, this is a time-boxed override that auto-expires.
    expires_at: datetime | None = None


class ExemptionResponse(BaseModel):
    id: int
    entity_type: EntityType
    entity_id: str
    entity_label: str | None
    reason: str | None
    expires_at: datetime | None = None
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


class EnforcementActionPage(BaseModel):
    """One page of restrictions, with how many match in all."""

    items: list[EnforcementActionResponse]
    total: int
    offset: int
    limit: int
    # Restrictions in force per kind, over everything that matches.
    by_kind: dict[str, int] = Field(default_factory=dict)


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


class DiagnosticCheckResponse(BaseModel):
    key: str
    label: str
    status: str
    detail: str
    remediation: str | None = None


class DiagnosticsResponse(BaseModel):
    generated_at: datetime
    overall: str
    checks: list[DiagnosticCheckResponse]


class AuditChainResponse(BaseModel):
    """Result of re-walking the audit hash chain to prove it is intact."""

    ok: bool
    entries_checked: int
    tip: str | None
    broken_at_id: int | None = None
    reason: str | None = None


class UpdateStatusResponse(BaseModel):
    current: str
    latest: str | None = None
    update_available: bool = False


class AttestationResponse(BaseModel):
    version: str
    migration_head: str | None
    config_digest: str
    generated_at: datetime
    update: UpdateStatusResponse


class WatchdogResponse(BaseModel):
    state: str
    enabled: bool
    seconds_since_last_run: int | None
    last_run_at: datetime | None
    last_status: str | None
    tolerance_seconds: int
    detail: str


class RestoreResultResponse(BaseModel):
    settings: int
    limits_created: int
    limits_updated: int
    exemptions: int
