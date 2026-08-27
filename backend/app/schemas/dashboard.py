"""Schemas for the dashboard, entity pickers, audit log and settings."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.enums import ActorType, EntityType, LimitStatus, Severity, UtilityRole
from app.schemas.auth import StrictModel


class ActionBreakdownItem(BaseModel):
    action_type: str
    credits: Decimal
    transactions: int | None = None
    percent_of_total: float | None = None


class TrendPoint(BaseModel):
    collected_at: datetime
    # The cumulative figure Checkmarx reported for its lookback window.
    cumulative_credits: Decimal
    # Credits consumed since the previous poll. Null for the first point, since
    # there is nothing to compare it against.
    delta_credits: Decimal | None = None


class TopConsumerItem(BaseModel):
    entity_type: EntityType
    entity_id: str | None
    label: str
    credits: Decimal
    percent_of_total: float | None = None
    # Present when a limit is configured for this entity, so the dashboard can
    # show headroom next to consumption.
    limit: int | None = None
    limit_id: int | None = None
    credits_used_in_period: Decimal | None = None
    status: LimitStatus | None = None
    resolved: bool = True


class StatusTiles(BaseModel):
    entities_in_warning: int
    entities_restricted: int
    active_restrictions: int
    unresolved_subjects: int
    unread_notifications: int
    limits_configured: int
    limits_enforcing: int
    next_run_at: datetime | None = None
    last_success_at: datetime | None = None
    last_run_status: str | None = None
    schedule: str


class DashboardResponse(BaseModel):
    generated_at: datetime
    period_label: str
    lookback_window: str
    # Null when no snapshot has been collected yet, which the GUI shows as
    # "no data yet" rather than as zero.
    tenant_total_credits: Decimal | None
    collected_at: datetime | None
    breakdown: list[ActionBreakdownItem]
    trend: list[TrendPoint]
    top_users: list[TopConsumerItem]
    top_projects: list[TopConsumerItem]
    top_groups: list[TopConsumerItem]
    top_applications: list[TopConsumerItem]
    tiles: StatusTiles
    unavailable_dimensions: list[str]


class OrgEntity(BaseModel):
    entity_type: EntityType
    entity_id: str
    label: str
    secondary: str | None = None
    has_limit: bool = False
    is_exempt: bool = False
    is_deleted: bool = False


class AuditEntryResponse(BaseModel):
    id: int
    occurred_at: datetime
    actor_type: ActorType
    actor_name: str | None
    action: str
    target_type: str | None
    target_id: str | None
    target_label: str | None
    before: dict | None
    after: dict | None
    detail: str | None
    ip_address: str | None


class AuditListResponse(BaseModel):
    items: list[AuditEntryResponse]
    total: int
    actions: list[str]


class SubjectSuggestion(BaseModel):
    """A ranked guess at which user a consumption subject belongs to."""

    user_id: str
    label: str
    # 0..1 similarity between the reported handle and this user.
    score: float


class UnresolvedSubjectResponse(BaseModel):
    id: int
    subject_key: str
    subject_name: str | None
    subject_email: str | None
    credits_used: Decimal
    first_seen_at: datetime
    last_seen_at: datetime
    times_seen: int
    mapped_user_id: str | None
    mapped_user_label: str | None = None
    # Fuzzy-match triage: "unmatched" | "disputed" | "auto_matched".
    status: str = "unmatched"
    is_bot: bool = False
    match_score: float | None = None
    suggested_user_id: str | None = None
    suggested_user_label: str | None = None
    suggestions: list[SubjectSuggestion] = Field(default_factory=list)
    # The user this subject's credits currently count towards (a manual mapping,
    # or the auto-match), with a label for display. Null when nothing counts.
    counts_towards_user_id: str | None = None
    counts_towards_label: str | None = None


class MapSubjectRequest(StrictModel):
    # Null clears an existing mapping.
    user_id: str | None = Field(default=None, max_length=64)


class SettingsResponse(BaseModel):
    scheduler_enabled: bool
    schedule_mode: str
    schedule_interval_minutes: int
    schedule_cron: str | None
    org_refresh_minutes: int
    usage_period_param: str
    usage_page_size: int
    retention_days: int
    notify_min_severity: Severity
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_use_tls: bool
    smtp_from: str | None
    smtp_recipients: str | None
    smtp_password_configured: bool
    webhook_url: str | None
    webhook_secret_configured: bool
    allowed_interval_minutes: list[int]
    # The lookback windows the consumption endpoint accepts. Anything else is a 400.
    allowed_usage_periods: list[str]
    current_schedule_description: str


class SettingsUpdateRequest(StrictModel):
    scheduler_enabled: bool | None = None
    schedule_mode: str | None = None
    schedule_interval_minutes: int | None = Field(default=None, ge=1, le=10080)
    schedule_cron: str | None = Field(default=None, max_length=128)
    org_refresh_minutes: int | None = Field(default=None, ge=1, le=10080)
    usage_period_param: str | None = Field(default=None, max_length=32)
    usage_page_size: int | None = Field(default=None, ge=1, le=1000)
    retention_days: int | None = Field(default=None, ge=7, le=3650)
    notify_min_severity: Severity | None = None
    smtp_host: str | None = Field(default=None, max_length=256)
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = Field(default=None, max_length=256)
    # Write only. An empty string clears it.
    smtp_password: str | None = Field(default=None, max_length=512)
    smtp_use_tls: bool | None = None
    smtp_from: str | None = Field(default=None, max_length=320)
    smtp_recipients: str | None = Field(default=None, max_length=2048)
    webhook_url: str | None = Field(default=None, max_length=1024)
    webhook_secret: str | None = Field(default=None, max_length=512)

    @field_validator("schedule_mode")
    @classmethod
    def _check_mode(cls, value: str | None) -> str | None:
        if value is not None and value not in {"interval", "cron"}:
            raise ValueError("Schedule mode must be interval or cron.")
        return value

    @field_validator("webhook_url")
    @classmethod
    def _check_webhook(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return value
        candidate = value.strip()
        if not candidate.startswith(("https://", "http://")):
            raise ValueError("Webhook URL must start with https:// or http://")
        return candidate


class BulkLimitUpdateRequest(StrictModel):
    limit_ids: list[int] = Field(min_length=1, max_length=500)
    credit_limit: int | None = Field(default=None, ge=0, le=100_000_000)
    warning_threshold_pct: int | None = Field(default=None, ge=1, le=100)
    enforce: bool | None = None
    is_active: bool | None = None
    period_type: str | None = None
    hold_until_released: bool | None = None


class BulkLimitResultResponse(BaseModel):
    updated: int
    restrictions_lifted: int
    errors: list[str]


class CsvImportResultResponse(BaseModel):
    created: int
    updated: int
    skipped: int
    errors: list[str]
    # True when nothing was written, which is what dry_run produces.
    dry_run: bool


class MeResponse(BaseModel):
    """Everything the SPA needs on load to decide what to render."""

    username: str
    role: UtilityRole
    totp_enabled: bool
    must_change_password: bool
    connection_configured: bool
    connection_status: str
    tenant_name: str | None
    version: str
    setup_required: bool
    extra: dict[str, Any] = Field(default_factory=dict)
