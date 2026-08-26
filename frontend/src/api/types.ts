/** Response shapes mirrored from the backend Pydantic schemas. */

export type UtilityRole = "admin" | "viewer";
export type EntityType = "user" | "group" | "project" | "application";
export type PeriodType = "monthly" | "quarterly" | "custom" | "lifetime";
export type Severity = "info" | "warning" | "critical" | "error";
export type LimitStatus = "ok" | "warned" | "breached" | "restricted" | "restored";
export type ConnectionStatus = "unconfigured" | "healthy" | "degraded" | "failed";

export interface SessionInfo {
  username: string;
  role: UtilityRole;
  email: string | null;
  totp_enabled: boolean;
  must_change_password: boolean;
  idle_expires_at: string;
  absolute_expires_at: string;
  last_login_at: string | null;
}

export interface Me {
  username: string;
  role: UtilityRole;
  totp_enabled: boolean;
  must_change_password: boolean;
  connection_configured: boolean;
  connection_status: ConnectionStatus;
  tenant_name: string | null;
  version: string;
  setup_required: boolean;
}

export interface ConnectionPreview {
  iam_base_url: string;
  tenant_name: string;
  derived_api_base_url: string | null;
  region_label: string;
  derivation_confident: boolean;
  api_key_fingerprint: string;
  key_expires_at: string | null;
  client_id: string | null;
}

export interface ConnectionStatusResponse {
  configured: boolean;
  status: ConnectionStatus;
  tenant_name: string | null;
  iam_base_url: string | null;
  api_base_url: string | null;
  api_base_url_overridden: boolean;
  api_key_fingerprint: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error: string | null;
}

export interface ConnectionTestResult {
  ok: boolean;
  token_acquired: boolean;
  api_reachable: boolean;
  message: string;
  tenant_name: string | null;
  iam_base_url: string | null;
  api_base_url: string | null;
  token_seconds_remaining: number | null;
  projects_visible: number | null;
}

export interface ActionBreakdownItem {
  action_type: string;
  credits: string;
  transactions: number | null;
  percent_of_total: number | null;
}

export interface TrendPoint {
  collected_at: string;
  cumulative_credits: string;
  delta_credits: string | null;
}

export interface TopConsumer {
  entity_type: EntityType;
  entity_id: string | null;
  label: string;
  credits: string;
  percent_of_total: number | null;
  limit: number | null;
  limit_id: number | null;
  credits_used_in_period: string | null;
  status: LimitStatus | null;
  resolved: boolean;
}

export interface StatusTiles {
  entities_in_warning: number;
  entities_restricted: number;
  active_restrictions: number;
  unresolved_subjects: number;
  unread_notifications: number;
  limits_configured: number;
  limits_enforcing: number;
  next_run_at: string | null;
  last_success_at: string | null;
  last_run_status: string | null;
  schedule: string;
}

export interface Dashboard {
  generated_at: string;
  period_label: string;
  lookback_window: string;
  tenant_total_credits: string | null;
  collected_at: string | null;
  breakdown: ActionBreakdownItem[];
  trend: TrendPoint[];
  top_users: TopConsumer[];
  top_projects: TopConsumer[];
  top_groups: TopConsumer[];
  top_applications: TopConsumer[];
  tiles: StatusTiles;
  unavailable_dimensions: string[];
}

export interface LimitPeriodState {
  period_key: string;
  period_start: string;
  period_end: string | null;
  credits_used: string;
  baseline_credits: string;
  reported_total: string;
  usage_available: boolean;
  status: LimitStatus;
  percent_used: number | null;
  last_evaluated_at: string | null;
  warned_at: string | null;
  breached_at: string | null;
  restricted_at: string | null;
}

export interface Limit {
  id: number;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  credit_limit: number;
  period_type: PeriodType;
  custom_period_start: string | null;
  custom_period_end: string | null;
  warning_threshold_pct: number;
  enforce: boolean;
  is_active: boolean;
  include_member_usage: boolean;
  hold_until_released: boolean;
  count_existing_usage: boolean;
  exempt: boolean;
  notes: string | null;
  created_at: string;
  updated_at: string;
  current_period: LimitPeriodState | null;
  active_restrictions: number;
}

export interface Exemption {
  id: number;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  reason: string | null;
  created_at: string;
}

export interface OrgEntity {
  entity_type: EntityType;
  entity_id: string;
  label: string;
  secondary: string | null;
  has_limit: boolean;
  is_exempt: boolean;
  is_deleted: boolean;
}

export interface NotificationItem {
  id: number;
  created_at: string;
  severity: Severity;
  category: string;
  entity_type: string | null;
  entity_id: string | null;
  entity_label: string | null;
  title: string;
  body: string | null;
  read_at: string | null;
  enforcement_action_id: number | null;
  can_restore: boolean;
}

export interface NotificationList {
  items: NotificationItem[];
  total: number;
  unread: number;
}

export interface EnforcementActionItem {
  id: number;
  kind: string;
  status: string;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  target_type: string;
  target_id: string;
  target_label: string | null;
  period_key: string | null;
  created_at: string;
  applied_at: string | null;
  reversed_at: string | null;
  reversal_reason: string | null;
  error: string | null;
}

export interface AuditEntry {
  id: number;
  occurred_at: string;
  actor_type: "admin" | "system";
  actor_name: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  target_label: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  detail: string | null;
  ip_address: string | null;
}

export interface AuditList {
  items: AuditEntry[];
  total: number;
  actions: string[];
}

export interface AppSettings {
  scheduler_enabled: boolean;
  schedule_mode: "interval" | "cron";
  schedule_interval_minutes: number;
  schedule_cron: string | null;
  org_refresh_minutes: number;
  usage_period_param: string;
  usage_page_size: number;
  retention_days: number;
  notify_min_severity: Severity;
  smtp_host: string | null;
  smtp_port: number;
  smtp_username: string | null;
  smtp_use_tls: boolean;
  smtp_from: string | null;
  smtp_recipients: string | null;
  smtp_password_configured: boolean;
  webhook_url: string | null;
  webhook_secret_configured: boolean;
  allowed_interval_minutes: number[];
  allowed_usage_periods: string[];
  current_schedule_description: string;
}

export interface SchedulerStatus {
  schedule: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  last_success_at: string | null;
  entities_in_warning: number;
  entities_restricted: number;
  unread_notifications: number;
  unresolved_subjects: number;
}

export interface CycleRun {
  run_id: number | null;
  status: string;
  steps: Record<string, unknown>;
  errors: string[];
  skipped_reason: string | null;
}

export interface UnresolvedSubject {
  id: number;
  subject_key: string;
  subject_name: string | null;
  subject_email: string | null;
  credits_used: string;
  first_seen_at: string;
  last_seen_at: string;
  times_seen: number;
  mapped_user_id: string | null;
  mapped_user_label: string | null;
}

export interface UtilityAccount {
  id: number;
  username: string;
  email: string | null;
  role: UtilityRole;
  is_active: boolean;
  totp_enabled: boolean;
  last_login_at: string | null;
  locked_until: string | null;
  created_at: string;
}

export interface CsvImportResult {
  created: number;
  updated: number;
  skipped: number;
  errors: string[];
  dry_run: boolean;
}

export interface BulkResult {
  updated: number;
  restrictions_lifted: number;
  errors: string[];
}
