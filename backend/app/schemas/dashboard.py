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
    # Users only, and only while auto-triage credits are charged to scan
    # initiators: what this person is charged for auto triage inside the
    # lookback window, on top of ``credits``.
    auto_triage_attributed: Decimal | None = None


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
    # Scan initiators whose share of auto-triage credits counts towards nobody
    # (only ever non-zero while that attribution setting is on).
    unresolved_scan_initiators: int = 0


class CreditPoolInfo(BaseModel):
    """Tenant AI credit pool vs. what the utility's budgets have claimed.

    total/used/available are null when the pool has never been read - unknown,
    not zero.
    """

    total: Decimal | None = None
    used: Decimal | None = None
    available: Decimal | None = None
    collected_at: datetime | None = None
    assigned: Decimal = Decimal("0")
    over_allocation: Decimal | None = None


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
    credit_pool: CreditPoolInfo | None = None


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
    entry_hash: str | None = None


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
    # "consumption": a subject of the credit consumption feed. "scan_initiator":
    # who started scans whose auto triage is charged to people (only raised
    # while that setting is on). Both are mapped the same way.
    source: str = "consumption"


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
    # The URL itself is a credential and is never returned: only whether one is
    # set, and which host it points at.
    webhook_url_configured: bool = False
    webhook_host: str | None = None
    webhook_secret_configured: bool
    allowed_interval_minutes: list[int]
    # The lookback windows the consumption endpoint accepts. Anything else is a 400.
    allowed_usage_periods: list[str]
    # The organisation accent theme and the set an admin may choose from.
    ui_accent: str = "default"
    allowed_accents: list[str] = Field(default_factory=list)
    # Whether viewers may submit credit requests for an admin to decide.
    self_service_requests: bool = False
    # Whether a weekly summary report is emailed to the notification recipients.
    report_email_enabled: bool = False
    # Monetary cost of one credit for chargeback (0 means cost unknown).
    credit_unit_cost: float = 0.0
    # Demo mode: synthetic data, enforcement suppressed, UI marked as demo.
    demo_mode: bool = False
    # Hands-off automation: auto-approve pending credit requests within a cap.
    automation_enabled: bool = False
    auto_approve_max_increase: int = 0
    auto_approve_expiry_days: int = 0
    # Enforcement safety: paused (by an admin or by the ceiling), the ceiling on
    # limits that may start restricting in one cycle (0 = none), and tenant
    # roles whose holders are never restricted.
    enforcement_paused: bool = False
    enforcement_pause_reason: str | None = None
    max_new_enforcements_per_cycle: int = 25
    max_new_targets_per_cycle: int = 100
    protected_roles: str = ""
    # Charge each project's auto-triage credits also to the person whose scan
    # triggered it. Off by default.
    charge_auto_triage_to_scan_initiator: bool = False
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
    ui_accent: str | None = Field(default=None, max_length=16)
    self_service_requests: bool | None = None
    report_email_enabled: bool | None = None
    credit_unit_cost: float | None = Field(default=None, ge=0, le=1_000_000)
    demo_mode: bool | None = None
    automation_enabled: bool | None = None
    auto_approve_max_increase: int | None = Field(default=None, ge=0, le=10_000_000)
    auto_approve_expiry_days: int | None = Field(default=None, ge=0, le=3650)
    enforcement_paused: bool | None = None
    max_new_enforcements_per_cycle: int | None = Field(default=None, ge=0, le=100_000)
    max_new_targets_per_cycle: int | None = Field(default=None, ge=0, le=1_000_000)
    protected_roles: str | None = Field(default=None, max_length=1024)
    charge_auto_triage_to_scan_initiator: bool | None = None

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
    # The organisation accent theme, so the SPA can apply it on load.
    ui_accent: str = "default"
    # Whether this user may submit credit requests: always true for an admin,
    # and for a viewer only when self-service is enabled.
    can_request_credits: bool = False
    # Demo mode, so the SPA can show the demo banner.
    demo_mode: bool = False
    # Why new restrictions are not being applied, when they are not (paused by
    # an admin or by the safety ceiling). None when enforcement is running.
    enforcement_paused: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class AutoTriageUserPart(BaseModel):
    project_id: str
    project_label: str | None = None
    basis: str
    credits: Decimal


class AutoTriageUserAttribution(BaseModel):
    user_id: str
    user_label: str | None = None
    # Everything charged to this person inside the lookback window.
    total: Decimal
    observed: Decimal
    estimated: Decimal
    parts: list[AutoTriageUserPart] = Field(default_factory=list)


class AutoTriageProjectAttribution(BaseModel):
    project_id: str
    project_label: str | None = None
    # The project's auto-triage credits in the newest project reading. Always
    # counted against the project; the split below never changes that.
    auto_triage_credits: Decimal
    observed: Decimal
    estimated: Decimal
    # Recorded as untraceable, or with no earlier scan to estimate against.
    unattributed: Decimal
    # Held by initiators that are not a synced user yet.
    unresolved: Decimal
    # The part also charged to people (observed + estimated).
    charged_to_people: Decimal
    # Below 1 when charges recorded earlier add up to more than the project now
    # reports, and were scaled down to fit.
    scale: float = 1.0
    # "pending" | "done" | "truncated" | "none": the sample of scans from before
    # observation began that estimates are made against.
    history_status: str | None = None
    observing_since: datetime | None = None


class AutoTriageInitiator(BaseModel):
    initiator: str
    credits: Decimal
    status: str
    counts_towards_user_id: str | None = None
    counts_towards_label: str | None = None
    # The unresolved_subject row to map, when there is one.
    subject_id: int | None = None


class AutoTriageChargeResponse(BaseModel):
    id: int
    project_id: str
    basis: str
    initiator: str | None
    # At most the first 50 (scan_count has them all).
    scan_ids: list[str] = Field(default_factory=list)
    scan_count: int
    credits: Decimal
    window_start: datetime
    window_end: datetime
    detail: str | None = None


class AutoTriageAttributionOverview(BaseModel):
    enabled: bool
    # False until a project consumption reading exists (or the tenant does not
    # report consumption by project).
    available: bool
    reference_at: datetime | None = None
    window_start: datetime | None = None
    projects: list[AutoTriageProjectAttribution] = Field(default_factory=list)
    users: list[AutoTriageUserAttribution] = Field(default_factory=list)
    initiators: list[AutoTriageInitiator] = Field(default_factory=list)
    # The newest recorded charges (filtered like the rest), newest first.
    recent_charges: list[AutoTriageChargeResponse] = Field(default_factory=list)
