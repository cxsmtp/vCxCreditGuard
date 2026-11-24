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
  ui_accent: string;
  can_request_credits: boolean;
  demo_mode: boolean;
  /** Why new restrictions are not being applied, or null when they are. */
  enforcement_paused: string | null;
  /** The last API key permission check, compact. Null until one has run. */
  key_permissions?: KeyPermissionSummary | null;
  /** Open policy violations (admins only; null for a viewer). */
  open_violations?: number | null;
}

export type KeyPermissionVerdict = "ok" | "limited" | "insufficient" | "unknown";
export type KeyPermissionStatus = "ok" | "denied" | "not_found" | "error" | "skipped" | "not_tested";

export interface KeyPermissionSummary {
  verdict: KeyPermissionVerdict;
  /** True only when something needed with the current setup is confirmed missing. */
  attention?: boolean;
  summary: string;
  /** "CreditGuard can't ..." phrases, most serious first. */
  missing: string[];
  checked_at: string | null;
  /** Changes whenever the set of missing permissions changes. */
  problem_key: string | null;
}

export interface KeyPermissionCheck {
  id: string;
  label: string;
  purpose: string;
  method: string;
  path: string;
  kind: "read" | "write";
  status: KeyPermissionStatus;
  detail: string | null;
  expectation: "will_fail" | "probably_denied" | null;
  runtime_denied_at: string | null;
  needed_for: string[];
  required: boolean;
  required_reason: string;
  breaks: string;
  problem: boolean;
  severe: boolean;
}

export interface KeyPermissionReport extends KeyPermissionSummary {
  /** False for a viewer: checks, roles and run-time refusals are admin only. */
  details_visible: boolean;
  trigger: string | null;
  key_fingerprint: string | null;
  enforce_users: boolean;
  enforce_projects: boolean;
  enforce_fusion?: boolean;
  auto_triage_charging: boolean;
  checks: KeyPermissionCheck[];
  runtime_denials: {
    method: string;
    path: string;
    check_id: string | null;
    first_seen: string | null;
    last_seen: string | null;
    count: number;
  }[];
  token: {
    readable: boolean;
    realm_roles: string[];
    client_roles: Record<string, string[]>;
    roles: string[];
    groups: string[];
  } | null;
  explanation: { why: string[]; missing: string[]; roles: string[]; what_to_do: string[] };
}

export interface KeyPermissionsResponse {
  available: boolean;
  report: KeyPermissionReport | null;
}

export type RequestStatus = "pending" | "approved" | "denied";

export interface CreditRequest {
  id: number;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  requested_limit: number;
  reason: string | null;
  status: RequestStatus;
  requested_by_name: string | null;
  requested_at: string;
  decided_by_name: string | null;
  decided_at: string | null;
  decision_note: string | null;
  approved_limit: number | null;
  previous_limit: number | null;
  expires_at: string | null;
  reverted: boolean;
  created_at: string;
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
  /** What the key may do, checked right after a successful token exchange. */
  permissions?: KeyPermissionReport | null;
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
  /** Auto-triage credits charged to this person from scans they started (setting on). */
  auto_triage_attributed?: string | null;
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
  /** Scan initiators whose auto-triage share is waiting to be mapped to a person. */
  unresolved_scan_initiators?: number;
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
  credit_pool: CreditPoolInfo | null;
}

export interface CreditPoolInfo {
  total: string | null;
  used: string | null;
  available: string | null;
  collected_at: string | null;
  assigned: string;
  over_allocation: string | null;
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
  /** The auto-triage part of credits_used, when it is charged to the scan's initiator. */
  auto_triage_attributed?: AutoTriageAttributed | null;
}

export type AttributionBasis = "observed" | "estimated" | "unattributed";

export interface AutoTriagePart {
  user_id: string;
  user_label: string | null;
  project_id: string;
  project_label: string | null;
  basis: AttributionBasis;
  credits: string;
  counted: string;
}

export interface AutoTriageAttributed {
  /** As it would be counted now; parts, window_total and not_counted agree with it. */
  counted: string;
  /** What credits_used included at the last evaluation (catches up next cycle). */
  evaluated_counted: string | null;
  window_total: string;
  not_counted: string;
  counts_existing_usage: boolean;
  counted_since: string | null;
  parts: AutoTriagePart[];
}

export interface AutoTriageOverview {
  enabled: boolean;
  available: boolean;
  reference_at: string | null;
  window_start: string | null;
  projects: {
    project_id: string;
    project_label: string | null;
    auto_triage_credits: string;
    observed: string;
    estimated: string;
    unattributed: string;
    unresolved: string;
    charged_to_people: string;
    scale: number;
    history_status: string | null;
    observing_since: string | null;
  }[];
  users: {
    user_id: string;
    user_label: string | null;
    total: string;
    observed: string;
    estimated: string;
    parts: { project_id: string; project_label: string | null; basis: AttributionBasis; credits: string }[];
  }[];
  initiators: {
    initiator: string;
    credits: string;
    status: string;
    counts_towards_user_id: string | null;
    counts_towards_label: string | null;
    subject_id: number | null;
  }[];
  recent_charges: {
    id: number;
    project_id: string;
    basis: AttributionBasis;
    initiator: string | null;
    scan_ids: string[];
    scan_count: number;
    credits: string;
    window_start: string;
    window_end: string;
    detail: string | null;
  }[];
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
  business_unit: string | null;
  /** As stored: null for a limit that predates the choice (and for users). */
  project_actions: ProjectAction[] | null;
  /** What the limit turns off on its projects ([] for a user limit). */
  effective_project_actions: ProjectAction[];
  created_at: string;
  updated_at: string;
  current_period: LimitPeriodState | null;
  active_restrictions: number;
}

export type ProjectAction = "auto_triage" | "pr_remediation" | "fusion";

export interface Exemption {
  id: number;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  reason: string | null;
  expires_at: string | null;
  created_at: string;
}

export interface ChargebackRow {
  business_unit: string;
  limits: number;
  credits_used: string;
  estimated_cost: string | null;
}

export interface Chargeback {
  generated_at: string;
  unit_cost: number;
  currency_known: boolean;
  unassigned_limits: number;
  rows: ChargebackRow[];
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
  entry_hash: string | null;
}

export interface AuditList {
  items: AuditEntry[];
  total: number;
  actions: string[];
}

export interface AuditChainResult {
  ok: boolean;
  entries_checked: number;
  tip: string | null;
  broken_at_id: number | null;
  reason: string | null;
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
  /** The URL itself is a credential and is never sent back: only whether one
   * is set and which host it points at. */
  webhook_url_configured: boolean;
  webhook_host: string | null;
  webhook_secret_configured: boolean;
  allowed_interval_minutes: number[];
  allowed_usage_periods: string[];
  ui_accent: string;
  allowed_accents: string[];
  self_service_requests: boolean;
  charge_auto_triage_to_scan_initiator: boolean;
  report_email_enabled: boolean;
  credit_unit_cost: number;
  demo_mode: boolean;
  automation_enabled: boolean;
  auto_approve_max_increase: number;
  auto_approve_expiry_days: number;
  enforcement_paused: boolean;
  enforcement_pause_reason: string | null;
  /** Limits that may start restricting in one cycle before enforcement stops itself. 0 = no ceiling. */
  max_new_enforcements_per_cycle: number;
  /** The same ceiling counted in users and projects. 0 = no ceiling. */
  max_new_targets_per_cycle: number;
  /** Comma separated tenant role names whose holders are never restricted. */
  protected_roles: string;
  /** Turning Fusion off also tries to lock it against per-scan override (unverified). */
  fusion_lock_override: boolean;
  /** The client roles a user restriction removes (from now on), and the built-in default. */
  ai_roles: string[];
  default_ai_roles: string[];
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

export interface SubjectSuggestion {
  user_id: string;
  label: string;
  score: number;
}

export type SubjectStatus = "unmatched" | "disputed" | "auto_matched";

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
  status: SubjectStatus;
  is_bot: boolean;
  match_score: number | null;
  suggested_user_id: string | null;
  suggested_user_label: string | null;
  suggestions: SubjectSuggestion[];
  counts_towards_user_id: string | null;
  counts_towards_label: string | null;
  /** Where the handle came from: a consumption row, or a scan's initiator. */
  source?: "consumption" | "scan_initiator";
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

export interface MessageResponse {
  message: string;
}

export interface TotpEnrollResult {
  secret: string;
  otpauth_uri: string;
}

export interface TotpConfirmResult {
  message: string;
  /** Shown once. Each signs in a single time in place of an authenticator code. */
  recovery_codes: string[];
}

export interface AdminResetResult {
  reset_token: string;
  expires_at: string;
}

export interface Attestation {
  version: string;
  migration_head: string | null;
  config_digest: string;
  generated_at: string;
  update: { current: string; latest: string | null; update_available: boolean };
}

export interface WatchdogStatus {
  state: "ok" | "stale" | "down" | "disabled";
  enabled: boolean;
  seconds_since_last_run: number | null;
  last_run_at: string | null;
  last_status: string | null;
  tolerance_seconds: number;
  detail: string;
}

export interface RestoreResult {
  settings: number;
  limits_created: number;
  limits_updated: number;
  exemptions: number;
}

export interface Projection {
  limit_id: number;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  credit_limit: number;
  enforce: boolean;
  period_key: string;
  credits_used: string;
  burn_per_day: string;
  projected_period_end: string;
  percent_at_period_end: number | null;
  days_to_exhaustion: number | null;
  exhaustion_at: string | null;
  will_breach: boolean;
}

export interface ReportImpact {
  enforced_limits: number;
  active_restrictions: number;
  entities_restricted: number;
  credits_over_budget: string;
  warnings_active: number;
  monitor_only_breaches: number;
}

export interface ReportSummary {
  generated_at: string;
  limits_total: number;
  limits_enforcing: number;
  breaching_soon: number;
  impact: ReportImpact;
  projections: Projection[];
}

export type DiagnosticStatus = "ok" | "warn" | "fail";

export interface DiagnosticCheck {
  key: string;
  label: string;
  status: DiagnosticStatus;
  detail: string;
  remediation: string | null;
}

export interface Diagnostics {
  generated_at: string;
  overall: DiagnosticStatus;
  checks: DiagnosticCheck[];
}

export interface TargetPreview {
  kind: string;
  target_type: string;
  target_id: string;
  target_label: string | null;
}

export interface ClientRole {
  name: string;
  description: string | null;
  composite: boolean;
  /** A short description CreditGuard knows for this role (the default AI roles). */
  known_description: string | null;
  /** Looks like an administration role: choosing it needs a confirmation. */
  admin_like?: boolean;
  /** A protected role (Settings -> Enforcement): it cannot be an AI role. */
  protected?: boolean;
}

export interface ClientRoles {
  available: boolean;
  message: string | null;
  roles: ClientRole[];
  ai_roles: string[];
  default_ai_roles: string[];
}

export interface RemovedRolePreview {
  name: string;
  description: string | null;
  /** The roles it contains when composite; [] when not; null when unreadable. */
  grants: string[] | null;
}

export interface KeptRolePreview {
  name: string;
  sources: string[];
}

export interface UserRolesPreview {
  user_id: string;
  user_label: string | null;
  /** Whether the user's roles were read from Checkmarx One at all. */
  read: boolean;
  removed: RemovedRolePreview[];
  kept: KeptRolePreview[];
  not_held: string[];
  unread: string[];
  note: string | null;
  /** A restriction already holds, so the roles were not read again. */
  already_restricted?: boolean;
}

export interface ProjectWarning {
  project_id: string;
  project_label: string | null;
  message: string;
}

export interface BlastRadius {
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  exempt: boolean;
  affected_users: number;
  affected_projects: number;
  remove_user_roles: number;
  disable_auto_triage: number;
  disable_pr_remediation: number;
  disable_fusion?: number;
  disable_repo_fusion?: number;
  total_actions: number;
  targets: TargetPreview[];
  project_actions?: ProjectAction[];
  /** The roles a user restriction removes, and per user what they would lose. */
  ai_roles?: string[];
  user_roles?: UserRolesPreview[];
  user_roles_truncated?: boolean;
  user_roles_note?: string | null;
  /** Projects where turning Auto Triage off may not hold. */
  warnings?: ProjectWarning[];
}

export interface DryRunRow {
  limit_id: number;
  entity_type: EntityType;
  entity_id: string;
  entity_label: string | null;
  credit_limit: number;
  enforce: boolean;
  exempt: boolean;
  usage_available: boolean;
  credits_used: string;
  percent_used: number | null;
  projected_status: LimitStatus;
  would_enforce: boolean;
  blast: BlastRadius | null;
  note: string | null;
  /** The auto-triage part of credits_used, when charged to scan initiators. */
  auto_triage_attributed?: string | null;
}

export interface DryRunResult {
  generated_at: string;
  would_enforce_count: number;
  would_warn_count: number;
  affected_projects: number;
  affected_users: number;
  rows: DryRunRow[];
  user_roles_truncated?: boolean;
  user_roles_note?: string | null;
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

export type ViolationStatus = "open" | "acknowledged" | "resolved";

export interface PolicyViolation {
  id: number;
  kind: string;
  kind_label: string;
  /** Information, not a violation: nothing to follow up, never counted as open. */
  information?: boolean;
  detected_at: string;
  updated_at: string | null;
  limit_id: number | null;
  limit_label: string | null;
  limit_entity_type: string | null;
  limit_entity_id: string | null;
  enforcement_action_id: number | null;
  target_type: string;
  target_id: string;
  target_label: string | null;
  actor: string | null;
  source: string | null;
  detail: string;
  evidence: Record<string, unknown> | null;
  credits: string | null;
  severity: string;
  status: ViolationStatus;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  resolved_by: string | null;
  resolved_at: string | null;
  note: string | null;
}

export interface ViolationList {
  items: PolicyViolation[];
  total: number;
  /** Open violations to follow up (information rows are never counted). */
  open: number;
}
