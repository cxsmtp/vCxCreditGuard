import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type {
  AdminResetResult,
  AppSettings,
  Attestation,
  AutoTriageOverview,
  ClientRoles,
  CycleRun,
  OrgEntity,
  RestoreResult,
  SchedulerStatus,
  UnresolvedSubject,
  UtilityAccount,
  WatchdogStatus,
} from "../api/types";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  KeyValue,
  Modal,
  PageHeader,
  Select,
  Spinner,
  Table,
  Td,
  Th,
  Toggle,
} from "../components/ui";
import { FilterNote, useTableView, type ViewColumn } from "../components/tableView";
import { useResource } from "../hooks/useResource";
import { downloadText, timestampedName } from "../lib/export";
import { formatCredits, formatDateTime, formatRelative } from "../lib/format";
import { applyAccent, useToast } from "../lib/ui-context";
import { LookPicker } from "../components/AppShell";
import { StatTile } from "../components/StatTile";
import { UpdatesPanel } from "../components/UpdatesPanel";
import { settingsDraft, useSettingsDraft, useWarnBeforeUnload } from "../lib/settingsDraft";

/** Unsaved edits. The last three are write only: the server never sends the
 * stored value back, so they exist here only while being typed. */
type SettingsDraft = Partial<AppSettings> & {
  smtp_password?: string;
  webhook_secret?: string;
  webhook_url?: string;
};

export type SettingsSection =
  | "general"
  | "enforcement"
  | "requests"
  | "notifications"
  | "attribution"
  | "accounts"
  | "appearance"
  | "operations"
  | "updates";

const SECTION_HEAD: Record<SettingsSection, { title: string; description: string }> = {
  general: {
    title: "Schedule & data",
    description: "When cycles run, how usage is read from Checkmarx One, and how long history is kept.",
  },
  enforcement: {
    title: "Enforcement",
    description:
      "Guard rails around restricting access in Checkmarx One. They apply to every budget set to enforce.",
  },
  requests: {
    title: "Credit requests",
    description: "Who may ask for more budget, and what may be approved without an admin.",
  },
  notifications: {
    title: "Notifications & reports",
    description: "Where alerts and the weekly report are delivered. The Notification Center always keeps everything.",
  },
  attribution: {
    title: "Attribution",
    description: "Who the credits Checkmarx One reports are counted against.",
  },
  accounts: {
    title: "Accounts",
    description: "The people who can sign in to CxCreditGuard, and their roles.",
  },
  appearance: {
    title: "Appearance",
    description: "Your look on this device, and the organisation's accent colour.",
  },
  operations: {
    title: "Backups & health",
    description: "Configuration backup and restore, the scheduler watchdog and the release attestation.",
  },
  updates: {
    title: "Updates",
    description:
      "New releases, installed in place from the private registry. Automatic by default, with a rollback.",
  },
};

type PacingKey =
  | "verify_interval_minutes"
  | "max_verifications_per_cycle"
  | "max_writes_per_cycle"
  | "violation_projects_per_cycle"
  | "attribution_projects_per_cycle"
  | "attribution_requests_per_cycle"
  | "read_concurrency"
  | "cycle_time_budget_pct";

/** The per-cycle budgets (pacing.py), with what each one means. */
const PACING_FIELDS: {
  key: PacingKey;
  label: string;
  hint: string;
  min: number;
  max: number;
  fallback: number;
}[] = [
  {
    key: "verify_interval_minutes",
    label: "Verify each restriction every (minutes)",
    hint: "How often each restriction in force is read back from Checkmarx One, at most, spread over the cycles: including those kept in force outside a limit's current plan (a project that left the group, a held earlier period), not those being lifted. A new restriction is always read back at once, and one whose limit changed what it turns off is next. 0 reads every one back every cycle.",
    min: 0,
    max: 10080,
    fallback: 60,
  },
  {
    key: "max_verifications_per_cycle",
    label: "Read-backs per cycle (most)",
    hint: "The oldest-verified first. If more are in force than this covers within the interval above, each is verified less often; the cycle record says how often, and a notification says when any goes unverified for more than twice the interval. 0: no cap.",
    min: 0,
    max: 1000000,
    fallback: 2000,
  },
  {
    key: "max_writes_per_cycle",
    label: "Restriction changes per cycle (most)",
    hint: "Changes made in one cycle: lifts first, then drift re-asserted, then new restrictions (small limits first), so giving access back is never held up. A larger group or application is restricted (or lifted) over several cycles, resuming where it stopped, with its progress on the Budgets page. The safety ceilings judge each target of such a rollout once. 0: no cap.",
    min: 0,
    max: 1000000,
    fallback: 1000,
  },
  {
    key: "violation_projects_per_cycle",
    label: "Projects checked for violations per cycle",
    hint: "Restricted projects whose scans are listed, the least recently checked first: each is checked at least every (restricted projects / this) cycles.",
    min: 0,
    max: 1000000,
    fallback: 150,
  },
  {
    key: "attribution_projects_per_cycle",
    label: "Auto-triage projects per cycle",
    hint: "Projects whose new Auto Triage is traced to a scan per cycle, the longest waiting first. Credits not traced yet stay on the project meanwhile.",
    min: 0,
    max: 1000000,
    fallback: 150,
  },
  {
    key: "attribution_requests_per_cycle",
    label: "Auto-triage scan requests per cycle",
    hint: "Scan listings auto-triage attribution may make in one cycle.",
    min: 0,
    max: 1000000,
    fallback: 600,
  },
  {
    key: "read_concurrency",
    label: "Parallel reads",
    hint: "Independent read-only calls (read-backs, scan listings) made at the same time. Writes are always one at a time. 1 makes every call one after another.",
    min: 1,
    max: 16,
    fallback: 4,
  },
  {
    key: "cycle_time_budget_pct",
    label: "Cycle time budget (% of interval)",
    hint: "Once a cycle has run this long, it stops starting new per-project work and leaves the rest to the next cycle instead of overrunning. 0 removes the budget.",
    min: 0,
    max: 100,
    fallback: 80,
  },
];

export function SettingsPage({
  isAdmin,
  onSettingsSaved,
  section,
}: {
  isAdmin: boolean;
  onSettingsSaved?: () => Promise<unknown>;
  section: SettingsSection;
}) {
  const toast = useToast();
  const location = useLocation();

  const settings = useResource<AppSettings>((signal) => api.get("/api/settings", undefined, signal), []);
  const status = useResource<SchedulerStatus>((signal) => api.get("/api/ops/status", undefined, signal), []);
  const unresolved = useResource<UnresolvedSubject[]>(
    (signal) => api.get("/api/usage/unresolved", undefined, signal),
    [],
  );

  const { draft, removeWebhook } = useSettingsDraft<SettingsDraft>();
  const setRemoveWebhook = settingsDraft.setRemoveWebhook;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [testing, setTesting] = useState(false);
  // Administration-like AI roles the admin confirmed in the picker's dialog.
  const [confirmedAdminRoles, setConfirmedAdminRoles] = useState<string[]>([]);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    channels: Record<string, string>;
  } | null>(null);

  useEffect(() => {
    if (location.hash === "#unmatched") {
      document.getElementById("attribution")?.scrollIntoView({ behavior: "smooth" });
    }
  }, [location.hash, unresolved.data]);

  const current = settings.data;
  const value = <K extends keyof AppSettings>(key: K): AppSettings[K] | undefined =>
    (draft[key] as AppSettings[K] | undefined) ?? current?.[key];

  function set(patch: SettingsDraft) {
    settingsDraft.patch(patch);
  }

  // Keys cleared back to undefined are not changes.
  const changes = Object.fromEntries(
    Object.entries(draft).filter(([, fieldValue]) => fieldValue !== undefined),
  ) as SettingsDraft;
  if (removeWebhook && changes.webhook_url === undefined) changes.webhook_url = "";
  const dirty = Object.keys(changes).length > 0;
  useWarnBeforeUnload(dirty);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      // An administration-like AI role is saved only with an explicit
      // confirmation: one given in the picker's dialog, or one already saved.
      const adminLike = (changes.ai_roles ?? []).filter(isAdminLikeRole);
      const confirmed =
        adminLike.length > 0 &&
        adminLike.every(
          (name) => confirmedAdminRoles.includes(name) || (current?.ai_roles ?? []).includes(name),
        );
      const updated = await api.put<AppSettings>(
        "/api/settings",
        confirmed ? { ...changes, confirm_admin_roles: true } : changes,
      );
      settings.setData(updated);
      applyAccent(updated.ui_accent);
      settingsDraft.clear();
      setConfirmedAdminRoles([]);
      toast.success(`Settings saved. Schedule is now ${updated.current_schedule_description}.`);
      await status.reload();
      // Refresh the bootstrap profile so shell-level state (the demo banner,
      // the accent) reflects the save without a manual reload.
      await onSettingsSaved?.();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not save the settings.");
    } finally {
      setBusy(false);
    }
  }

  async function sendTest() {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.post<{ ok: boolean; channels: Record<string, string> }>(
        "/api/settings/test-notification",
      );
      setTestResult(result);
      if (result.ok) toast.success("Test notification delivered.");
      else toast.error("The test could not be delivered on every channel.");
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "The test could not run.");
    } finally {
      setTesting(false);
    }
  }

  async function runCycle(forceOrgSync: boolean) {
    setRunning(true);
    try {
      const result = await api.post<CycleRun>("/api/ops/run-cycle", undefined, {
        force_org_sync: forceOrgSync,
      });
      if (result.status === "success") toast.success("Cycle finished.");
      else if (result.status === "skipped")
        toast.info(`Cycle skipped: ${result.skipped_reason ?? "unknown reason"}`);
      else toast.error(`Cycle status ${result.status}. ${result.errors.join("; ")}`);
      await Promise.all([status.reload(), unresolved.reload()]);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "The cycle could not be started.");
    } finally {
      setRunning(false);
    }
  }

  if (settings.initialLoading) {
    return (
      <div className="flex items-center gap-2 py-16" style={{ color: "var(--text-secondary)" }}>
        <Spinner /> Loading settings
      </div>
    );
  }

  if (!current) {
    return <ErrorNote>{settings.error ?? "Settings could not be loaded."}</ErrorNote>;
  }

  return (
    <>
      <PageHeader
        title={SECTION_HEAD[section].title}
        description={SECTION_HEAD[section].description}
        actions={
          isAdmin &&
          (section === "general" || section === "operations") && (
            <>
              <Button size="sm" onClick={() => runCycle(false)} loading={running}>
                Run a cycle now
              </Button>
              <Button size="sm" onClick={() => runCycle(true)} loading={running}>
                Sync organisation model
              </Button>
            </>
          )
        }
      />

      {error && (
        <div className="mb-5">
          <ErrorNote>{error}</ErrorNote>
        </div>
      )}

      <div className="flex max-w-[1000px] flex-col gap-6">
        {section === "general" && (
        <Card title="Scheduler" description={`Currently ${current.current_schedule_description}.`}>
          <div className="flex flex-col gap-5">
            <Toggle
              checked={Boolean(value("scheduler_enabled"))}
              onChange={(next) => set({ scheduler_enabled: next })}
              disabled={!isAdmin}
              label="Run cycles automatically"
              description="When off, cycles only run when you trigger one by hand. Nothing is evaluated or enforced in between."
            />

            <Field label="Schedule mode">
              <Select
                value={value("schedule_mode") ?? "interval"}
                disabled={!isAdmin}
                onChange={(event) => set({ schedule_mode: event.target.value as "interval" | "cron" })}
              >
                <option value="interval">Fixed interval</option>
                <option value="cron">Cron expression</option>
              </Select>
            </Field>

            {(value("schedule_mode") ?? "interval") === "interval" ? (
              <Field label="Interval" hint="How often to poll Checkmarx and evaluate limits.">
                <Select
                  value={String(value("schedule_interval_minutes") ?? 15)}
                  disabled={!isAdmin}
                  onChange={(event) => set({ schedule_interval_minutes: Number(event.target.value) })}
                >
                  {current.allowed_interval_minutes.map((minutes) => (
                    <option key={minutes} value={minutes}>
                      {minutes < 60 ? `Every ${minutes} minutes` : "Every hour"}
                    </option>
                  ))}
                  {!current.allowed_interval_minutes.includes(
                    Number(value("schedule_interval_minutes") ?? 15),
                  ) && (
                    <option value={String(value("schedule_interval_minutes"))}>
                      Every {value("schedule_interval_minutes")} minutes (custom)
                    </option>
                  )}
                </Select>
              </Field>
            ) : (
              <Field
                label="Cron expression"
                hint="Five fields, evaluated in UTC. For example */10 * * * * runs every ten minutes."
              >
                <Input
                  value={value("schedule_cron") ?? ""}
                  disabled={!isAdmin}
                  onChange={(event) => set({ schedule_cron: event.target.value })}
                  placeholder="*/15 * * * *"
                  spellCheck={false}
                />
              </Field>
            )}

            <Field
              label="Organisation model refresh (minutes)"
              hint="How often to re-read users, groups, projects and applications."
            >
              <Input
                type="number"
                min={1}
                value={String(value("org_refresh_minutes") ?? 30)}
                disabled={!isAdmin}
                onChange={(event) => set({ org_refresh_minutes: Number(event.target.value) })}
              />
            </Field>

            <div className="grid grid-cols-2 gap-3 border-t border-hairline pt-4">
              <KeyValue label="Next run">
                {status.data?.next_run_at ? formatRelative(status.data.next_run_at) : "Not scheduled"}
              </KeyValue>
              <KeyValue label="Last run">
                {status.data?.last_run_at ? formatDateTime(status.data.last_run_at) : "Never"}
              </KeyValue>
              <KeyValue label="Last run status">
                {status.data?.last_run_status ? (
                  <Badge
                    tone={
                      status.data.last_run_status === "success"
                        ? "good"
                        : status.data.last_run_status === "failed"
                          ? "critical"
                          : "warning"
                    }
                  >
                    {status.data.last_run_status}
                  </Badge>
                ) : (
                  "Never run"
                )}
              </KeyValue>
              <KeyValue label="Last success">
                {status.data?.last_success_at ? formatRelative(status.data.last_success_at) : "Never"}
              </KeyValue>
            </div>
          </div>
        </Card>
        )}

        {section === "general" && (
        <Card
          title="Usage ingestion"
          description="How the consumption endpoint is queried. Budget periods are derived from a baseline, so this window only has to be at least as wide as your widest budget period."
        >
          <div className="flex flex-col gap-5">
            <Field
              label="Lookback window"
              hint="How far back the consumption endpoint reports. It must be at least as wide as your widest budget period, or consumption inside a period but outside the window is invisible."
            >
              <Select
                value={value("usage_period_param") ?? "last_year"}
                disabled={!isAdmin}
                onChange={(event) => set({ usage_period_param: event.target.value })}
              >
                {(current.allowed_usage_periods ?? ["last_year"]).map((window) => (
                  <option key={window} value={window}>
                    {window.replace(/_/g, " ")}
                  </option>
                ))}
              </Select>
            </Field>

            <Field label="Page size" hint="Records per request when paging through consumption.">
              <Input
                type="number"
                min={1}
                max={1000}
                value={String(value("usage_page_size") ?? 100)}
                disabled={!isAdmin}
                onChange={(event) => set({ usage_page_size: Number(event.target.value) })}
              />
            </Field>

            <Field
              label="Data retention (days)"
              hint="How long snapshots, notifications and audit entries are kept."
            >
              <Input
                type="number"
                min={7}
                max={3650}
                value={String(value("retention_days") ?? 365)}
                disabled={!isAdmin}
                onChange={(event) => set({ retention_days: Number(event.target.value) })}
              />
            </Field>
          </div>
          <div className="mt-4 border-t border-hairline pt-4">
            <Toggle
              checked={value("retention_thin_snapshots") ?? true}
              disabled={!isAdmin}
              onChange={(next) => set({ retention_thin_snapshots: next })}
              label="Thin old consumption readings"
              description="Keep every reading of the last 3 days, one an hour for each dimension up to 40 days, and one a day after that. A reading anything refers to (a restriction's baseline, a budget period's usage breakdown, the latest) is always kept. Off: every reading is kept for the whole retention period."
            />
          </div>
        </Card>
        )}

        {section === "notifications" && (
        <Card
          title="Notification delivery"
          description="The Notification Center always records everything. These channels push copies out."
          actions={
            isAdmin && (
              <Button size="sm" onClick={sendTest} loading={testing}>
                Send a test
              </Button>
            )
          }
        >
          <div className="flex flex-col gap-5">
            {testResult && (
              <InfoNote tone={testResult.ok ? "good" : "critical"}>
                {Object.entries(testResult.channels).map(([channel, outcome]) => (
                  <span key={channel} className="block">
                    {channel}: {String(outcome)}
                  </span>
                ))}
              </InfoNote>
            )}
            <Field label="Minimum severity to deliver">
              <Select
                value={value("notify_min_severity") ?? "warning"}
                disabled={!isAdmin}
                onChange={(event) =>
                  set({ notify_min_severity: event.target.value as AppSettings["notify_min_severity"] })
                }
              >
                <option value="info">Info and above</option>
                <option value="warning">Warning and above</option>
                <option value="error">Error and above</option>
                <option value="critical">Critical only</option>
              </Select>
            </Field>

            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="SMTP host">
                <Input
                  value={value("smtp_host") ?? ""}
                  disabled={!isAdmin}
                  onChange={(event) => set({ smtp_host: event.target.value })}
                  placeholder="smtp.example.com"
                />
              </Field>
              <Field label="SMTP port">
                <Input
                  type="number"
                  value={String(value("smtp_port") ?? 587)}
                  disabled={!isAdmin}
                  onChange={(event) => set({ smtp_port: Number(event.target.value) })}
                />
              </Field>
              <Field label="SMTP username">
                <Input
                  value={value("smtp_username") ?? ""}
                  disabled={!isAdmin}
                  onChange={(event) => set({ smtp_username: event.target.value })}
                  autoComplete="off"
                />
              </Field>
              <Field
                label="SMTP password"
                hint={
                  current.smtp_password_configured
                    ? "A password is stored. Type a new one to replace it, or clear the field and save to remove it."
                    : "Stored encrypted. Never displayed again."
                }
              >
                <Input
                  type="password"
                  value={draft.smtp_password ?? ""}
                  disabled={!isAdmin}
                  onChange={(event) => set({ smtp_password: event.target.value })}
                  placeholder={current.smtp_password_configured ? "••••••••" : ""}
                  autoComplete="new-password"
                />
              </Field>
            </div>

            <Toggle
              checked={Boolean(value("smtp_use_tls"))}
              onChange={(next) => set({ smtp_use_tls: next })}
              disabled={!isAdmin}
              label="Use STARTTLS"
            />

            <Field label="From address">
              <Input
                value={value("smtp_from") ?? ""}
                disabled={!isAdmin}
                onChange={(event) => set({ smtp_from: event.target.value })}
                placeholder="cxcreditguard@example.com"
              />
            </Field>

            <Field label="Recipients" hint="Comma separated.">
              <Input
                value={value("smtp_recipients") ?? ""}
                disabled={!isAdmin}
                onChange={(event) => set({ smtp_recipients: event.target.value })}
                placeholder="security@example.com, platform@example.com"
              />
            </Field>

            <div className="grid gap-4 border-t border-hairline pt-4 sm:grid-cols-2">
              <Field
                label="Webhook URL"
                fold={false}
                hint={
                  current.webhook_url_configured
                    ? `A webhook to ${current.webhook_host ?? "a stored URL"} is configured. The URL is not shown again; type a new one to replace it, or clear the box and save to remove it.`
                    : "A JSON payload is posted for each delivered notification."
                }
              >
                <Input
                  type="text"
                  name="cxcg-webhook-url"
                  value={draft.webhook_url ?? ""}
                  disabled={!isAdmin}
                  // Emptying the box is "leave it as it is", not "remove it":
                  // removal is the explicit control below.
                  onChange={(event) => set({ webhook_url: event.target.value || undefined })}
                  placeholder={
                    current.webhook_url_configured
                      ? `•••••••• (${current.webhook_host ?? "configured"})`
                      : "https://hooks.example.com/cxcreditguard"
                  }
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>
              {isAdmin && current.webhook_url_configured && (
                <div className="sm:col-span-2">
                  <Toggle
                    checked={removeWebhook}
                    onChange={setRemoveWebhook}
                    label="Remove the stored webhook when saving"
                    description="Stops posting notifications to it. Leave off to keep it, or type a new URL above to replace it."
                  />
                </div>
              )}
              <Field
                label="Webhook signing secret"
                hint={
                  current.webhook_secret_configured
                    ? "A secret is stored. Type a new one to replace it."
                    : "Optional. Used to sign the payload."
                }
              >
                <Input
                  type="password"
                  value={draft.webhook_secret ?? ""}
                  disabled={!isAdmin}
                  onChange={(event) => set({ webhook_secret: event.target.value })}
                  placeholder={current.webhook_secret_configured ? "••••••••" : ""}
                  autoComplete="new-password"
                />
              </Field>
            </div>
          </div>
        </Card>
        )}

        <>
          {section === "appearance" && (
            <>
              <Card
                title="Your look"
                description="Standard or Command Center, light or dark. Remembered on this device."
              >
                <LookPicker />
              </Card>
              <AppearanceCard
                isAdmin={isAdmin}
                value={value("ui_accent") ?? "default"}
                options={current.allowed_accents ?? ["default"]}
                onPick={(accent) => {
                  // Picking what is stored (or the swatch a legacy accent shows as) is no change.
                  const stored = current.ui_accent ?? "default";
                  set({ ui_accent: accent === (LEGACY_ACCENT[stored] ?? stored) ? undefined : accent });
                }}
              />
            </>
          )}
          {section === "requests" && (
          <Card
            title="Self-service credit requests"
            description="Let viewers submit requests to raise an entity's budget for you to approve or deny."
          >
            <Toggle
              checked={value("self_service_requests") ?? false}
              disabled={!isAdmin}
              onChange={(next) => set({ self_service_requests: next })}
              label="Allow viewers to request credits"
              description={
                (value("self_service_requests") ?? false)
                  ? "Viewers see a Requests page where they can ask for more budget. Admins always decide every request."
                  : "Only admins can file credit requests. Turn this on to open it to viewers."
              }
            />
          </Card>
          )}
          {section === "enforcement" && (
          <div id="enforcement-safety">
            <Card
              title="Enforcement safety"
              description="Guard rails around restricting access in Checkmarx One. They apply to every budget set to enforce."
            >
              {current.enforcement_paused && (
                <div className="mb-4">
                  <InfoNote tone="warning">
                    Enforcement is paused. {current.enforcement_pause_reason} Limits are still
                    monitored and access that is no longer restricted for a reason is still given
                    back, but nobody new is restricted until you resume.
                  </InfoNote>
                </div>
              )}
              <Toggle
                checked={value("enforcement_paused") ?? false}
                disabled={!isAdmin}
                onChange={(next) => set({ enforcement_paused: next })}
                label="Pause enforcement"
                description="Stops new restrictions straight away without changing any limit. Existing restrictions stay as they are; restores continue. Turning it off resumes enforcement: whatever was held back is applied on the next cycle, so check the Simulation page first."
              />
              <div className="mt-4 grid gap-4 sm:grid-cols-3">
                <Field
                  label="Safety ceiling (limits per cycle)"
                  fold={false}
                  hint="If more limits than this would start restricting in a single cycle, none are restricted and enforcement pauses itself until an admin resumes it. That many breaches at once usually means bad data, not real spending. 0 removes the ceiling."
                >
                  <Input
                    type="number"
                    min={0}
                    step="1"
                    disabled={!isAdmin}
                    value={String(value("max_new_enforcements_per_cycle") ?? 25)}
                    onChange={(event) =>
                      set({
                        max_new_enforcements_per_cycle: Math.max(
                          0,
                          Math.floor(Number(event.target.value)),
                        ),
                      })
                    }
                  />
                </Field>
                <Field
                  label="Safety ceiling (users and projects)"
                  fold={false}
                  hint="The same safeguard counted in what would be restricted: one application or group limit can take many projects with it. 0 removes the ceiling."
                >
                  <Input
                    type="number"
                    min={0}
                    step="1"
                    disabled={!isAdmin}
                    value={String(value("max_new_targets_per_cycle") ?? 100)}
                    onChange={(event) =>
                      set({
                        max_new_targets_per_cycle: Math.max(
                          0,
                          Math.floor(Number(event.target.value)),
                        ),
                      })
                    }
                  />
                </Field>
                <Field
                  label="Protected roles"
                  hint="Comma separated Checkmarx One role names. A user holding any of them is never restricted automatically; an admin is told instead. The account your API key belongs to is always protected."
                >
                  <Input
                    disabled={!isAdmin}
                    value={value("protected_roles") ?? ""}
                    onChange={(event) => set({ protected_roles: event.target.value })}
                    placeholder="ast-admin, iam-admin"
                    spellCheck={false}
                  />
                </Field>
              </div>
              <div className="mt-4 border-t border-hairline pt-4">
                <p className="text-sm font-medium">Pacing for large tenants</p>
                <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
                  How much one cycle does, so a tenant of thousands of projects is worked through
                  over several cycles and every cycle finishes well within its interval. 0 means no
                  budget: everything, every cycle (for the violation check and auto-triage
                  attribution that is no cap at all, where they had fixed caps before pacing).
                </p>
                <div className="mt-3 grid gap-4 sm:grid-cols-3">
                  {PACING_FIELDS.map((field) => (
                    <Field key={field.key} label={field.label} fold={false} hint={field.hint}>
                      <Input
                        type="number"
                        min={field.min}
                        max={field.max}
                        step="1"
                        disabled={!isAdmin}
                        value={String(value(field.key) ?? field.fallback)}
                        onChange={(event) =>
                          set({
                            [field.key]: Math.min(
                              field.max,
                              Math.max(field.min, Math.floor(Number(event.target.value) || 0)),
                            ),
                          })
                        }
                      />
                    </Field>
                  ))}
                </div>
              </div>
              <div className="mt-4 border-t border-hairline pt-4">
                <AiRolesPicker
                  isAdmin={isAdmin}
                  value={value("ai_roles") ?? current.ai_roles ?? []}
                  defaults={current.default_ai_roles ?? []}
                  protectedRoles={(value("protected_roles") ?? "")
                    .split(/[,;]/)
                    .map((name) => name.trim().toLowerCase())
                    .filter(Boolean)}
                  onChange={(next) => set({ ai_roles: next })}
                  onConfirmAdmin={(name) =>
                    setConfirmedAdminRoles((previous) => [...previous, name])
                  }
                />
              </div>
              <div className="mt-4 border-t border-hairline pt-4">
                <Toggle
                  checked={value("fusion_lock_override") ?? true}
                  disabled={!isAdmin}
                  onChange={(next) => set({ fusion_lock_override: next })}
                  label="Lock Fusion against per-scan override"
                  description="When a limit turns Fusion off, also try to stop a scan started with its own settings from turning it back on (allowOverride off). Not verified that Checkmarx One honours this; a tenant that refuses the lock still gets Fusion turned off without it. CreditGuard re-applies its restrictions every cycle and records any scan that ran Fusion anyway under Policy violations, so this is optional."
                />
              </div>
            </Card>
          </div>
          )}
          {section === "requests" && (
          <Card
            title="Hands-off automation"
            description="Let the governance cycle approve routine credit requests on its own, so small, safe raises do not wait for an admin."
          >
            <Toggle
              checked={value("automation_enabled") ?? false}
              disabled={!isAdmin}
              onChange={(next) => set({ automation_enabled: next })}
              label="Auto-approve credit requests within a cap"
              description="When on, each cycle approves pending requests whose increase over the current budget is within the cap below. Requests above the cap always wait for an admin."
            />
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <Field
                label="Auto-approve cap (credits)"
                fold={false}
                hint="The most that is approved automatically for one entity, and at one requester's asking, in any 30 days - in total, not per request. A request that would go over it waits for an admin. 0 approves nothing, even when the switch is on."
              >
                <Input
                  type="number"
                  min={0}
                  step="1"
                  disabled={!isAdmin || !(value("automation_enabled") ?? false)}
                  value={String(value("auto_approve_max_increase") ?? 0)}
                  onChange={(event) =>
                    set({ auto_approve_max_increase: Math.max(0, Math.floor(Number(event.target.value))) })
                  }
                />
              </Field>
              <Field
                label="Auto-grant expiry (days)"
                hint="0 makes auto-approvals permanent. A positive value makes each a temporary grant that self-reverts, so the mode is safe to leave on."
              >
                <Input
                  type="number"
                  min={0}
                  step="1"
                  disabled={!isAdmin || !(value("automation_enabled") ?? false)}
                  value={String(value("auto_approve_expiry_days") ?? 0)}
                  onChange={(event) =>
                    set({ auto_approve_expiry_days: Math.max(0, Math.floor(Number(event.target.value))) })
                  }
                />
              </Field>
            </div>
          </Card>
          )}
          {section === "notifications" && (
          <Card
            title="Scheduled report"
            description="Email a weekly summary report to the notification recipients."
          >
            <Toggle
              checked={value("report_email_enabled") ?? false}
              disabled={!isAdmin}
              onChange={(next) => set({ report_email_enabled: next })}
              label="Email the weekly report"
              description="Sends the Reports summary to the configured notification recipients once a week. Needs the mail server set up above. Admins can also send it on demand from the Reports page."
            />
            <div className="mt-4">
              <Field
                label="Credit unit cost (for chargeback)"
                hint="Monetary cost of one credit. 0 shows chargeback in credits only, with no currency amount."
              >
                <Input
                  type="number"
                  min={0}
                  step="0.0001"
                  disabled={!isAdmin}
                  value={String(value("credit_unit_cost") ?? 0)}
                  onChange={(event) => set({ credit_unit_cost: Number(event.target.value) })}
                />
              </Field>
            </div>
          </Card>
          )}
          {isAdmin && section === "general" && (
            <DemoCard
              enabled={value("demo_mode") ?? false}
              onToggle={(next) => set({ demo_mode: next })}
              onChanged={async () => {
                await settings.reload();
                await onSettingsSaved?.();
              }}
            />
          )}
          {section === "attribution" && (
            <AutoTriageCard
              isAdmin={isAdmin}
              checked={value("charge_auto_triage_to_scan_initiator") ?? false}
              saved={current.charge_auto_triage_to_scan_initiator ?? false}
              demo={current.demo_mode ?? false}
              onChange={(next) => set({ charge_auto_triage_to_scan_initiator: next })}
            />
          )}
          {section === "attribution" && (
            <AttributionCard
              isAdmin={isAdmin}
              subjects={unresolved.data ?? []}
              loading={unresolved.initialLoading}
              onChanged={() => unresolved.reload()}
            />
          )}
          {isAdmin && section === "operations" && <OperationsCard />}
          {isAdmin && section === "updates" && <UpdatesPanel onChanged={onSettingsSaved} />}
          {isAdmin && section === "accounts" && <AccountsCard />}
        </>
      </div>

      {dirty && isAdmin && (
        <div className="sticky bottom-4 mt-6 flex justify-end">
          <div
            className="cg-panel flex items-center gap-3 px-4 py-3"
            style={{ background: "var(--surface-raised)", boxShadow: "var(--shadow-pop)" }}
          >
            <span className="text-sm">
              You have unsaved settings. They are kept while you move between settings pages and
              saved together.
            </span>
            <Button variant="secondary" size="sm" onClick={() => settingsDraft.clear()} disabled={busy}>
              Discard
            </Button>
            <Button variant="primary" size="sm" onClick={save} loading={busy}>
              Save changes
            </Button>
          </div>
        </div>
      )}
    </>
  );
}

/* ------------------------------------------------------ auto-triage charging */

const BASIS_LABEL: Record<string, string> = {
  observed: "Observed",
  estimated: "Estimated",
  unattributed: "Unattributed",
};

type OverviewUser = AutoTriageOverview["users"][number];
type OverviewProject = AutoTriageOverview["projects"][number];
type OverviewCharge = AutoTriageOverview["recent_charges"][number];

const AT_USER_VIEW: ViewColumn<OverviewUser>[] = [
  { key: "person", value: (u) => u.user_label ?? u.user_id, filter: false },
  { key: "total", value: (u) => Number(u.total), filter: false },
  { key: "observed", value: (u) => Number(u.observed), filter: false },
  { key: "estimated", value: (u) => Number(u.estimated), filter: false },
];

const AT_PROJECT_VIEW: ViewColumn<OverviewProject>[] = [
  { key: "project", value: (p) => p.project_label ?? p.project_id, filter: false },
  { key: "credits", value: (p) => Number(p.auto_triage_credits), filter: false },
  { key: "people", value: (p) => Number(p.charged_to_people), filter: false },
  { key: "waiting", value: (p) => Number(p.unresolved), filter: false },
  { key: "unattributed", value: (p) => Number(p.unattributed), filter: false },
];

const AT_CHARGE_VIEW: ViewColumn<OverviewCharge>[] = [
  { key: "when", value: (c) => c.window_end, filter: false },
  { key: "project", value: (c) => c.project_id },
  { key: "initiator", value: (c) => c.initiator ?? "" },
  { key: "basis", value: (c) => BASIS_LABEL[c.basis] ?? c.basis },
  { key: "credits", value: (c) => Number(c.credits), filter: false },
];

function AutoTriageCard({
  isAdmin,
  checked,
  saved,
  demo,
  onChange,
}: {
  isAdmin: boolean;
  checked: boolean;
  saved: boolean;
  demo: boolean;
  onChange: (next: boolean) => void;
}) {
  const overview = useResource<AutoTriageOverview>(
    (signal) => api.get("/api/usage/auto-triage-attribution", { charges: 25 }, signal),
    [saved],
  );
  const data = overview.data;
  const users = useTableView(data?.users ?? [], AT_USER_VIEW);
  const projects = useTableView(data?.projects ?? [], AT_PROJECT_VIEW);
  const charges = useTableView(data?.recent_charges ?? [], AT_CHARGE_VIEW);
  const projectName = new Map((data?.projects ?? []).map((p) => [p.project_id, p.project_label ?? p.project_id]));
  const sum = (key: "auto_triage_credits" | "charged_to_people" | "unresolved" | "unattributed") =>
    (data?.projects ?? []).reduce((total, p) => total + Number(p[key]), 0);
  const waitingInitiators = (data?.initiators ?? []).filter((i) => !i.counts_towards_user_id);

  return (
    <Card
      title="Auto triage: charge the person who started the scan"
      description="Checkmarx One reports Auto Triage credits against the project. This also counts them against the person whose scan the auto triage ran after."
      help={
        <>
          For each project, CxCreditGuard watches its Auto Triage credits rise and lists the
          completed scans on the project's auto-triage branches in between: the rise is split
          equally between those scans, so per person by number of scans (<b>observed</b>). Credits
          from before it was watching are split by how many such scans each person ran in the
          lookback window (<b>estimated</b>). A monthly or quarterly budget counts only credits
          observed after it opened, unless it is set to count consumption that predates the period:
          then, like a lifetime or custom budget, it counts everything attributed in the window,
          estimated credits included. A scan started by an integration (a webhook bot) has no person behind it: map it
          below, under Unmatched, to the person it acts for. Until then its share stays on the
          project only. Project and tenant totals never change: people are only ever charged a
          split of what the project reports.
        </>
      }
    >
      <Toggle
        checked={checked}
        disabled={!isAdmin || demo}
        onChange={onChange}
        label="Charge auto-triage credits to the person who started the scan"
        description={
          checked
            ? "On: auto triage counts against the scan starter's own budget, and a group budget that includes its members' usage. With many people near their budget, turning this on can restrict several at once: the enforcement safety ceiling still applies, and the Simulation shows the effect first."
            : "Off: auto triage counts against the project, its application and the tenant only, as Checkmarx One reports it."
        }
      />
      {demo && (
        <p className="mt-2 text-xs" style={{ color: "var(--text-muted)" }}>
          Not available in demo mode.
        </p>
      )}
      {checked !== saved && (
        <div className="mt-3">
          <InfoNote tone="warning">
            Saved with the other settings. Check the Simulation page after saving to see who would
            be restricted.
          </InfoNote>
        </div>
      )}

      {saved && overview.error && (
        <div className="mt-4">
          <ErrorNote>{overview.error}</ErrorNote>
        </div>
      )}
      {saved && data && !data.available && (
        <div className="mt-4">
          <InfoNote>
            Nothing to show yet: the first cycle after a project consumption reading fills this in.
          </InfoNote>
        </div>
      )}
      {saved && data?.available && (
        <div className="mt-5 flex flex-col gap-5">
          <div className="grid gap-3 sm:grid-cols-4">
            <StatTile label="Auto-triage credits" value={formatCredits(sum("auto_triage_credits"))} detail="In the lookback window" />
            <StatTile label="Charged to people" value={formatCredits(sum("charged_to_people"))} tone="good" detail="Observed and estimated" />
            <StatTile
              label="Waiting for mapping"
              value={formatCredits(sum("unresolved"))}
              tone={sum("unresolved") > 0 ? "warning" : "neutral"}
              detail={`${waitingInitiators.length} scan initiator${waitingInitiators.length === 1 ? "" : "s"} not matched to a person`}
            />
            <StatTile label="Stays on the project" value={formatCredits(sum("unattributed"))} detail="No scan to charge it to" />
          </div>

          <div>
            <h3 className="cg-panel-title mb-2">People charged</h3>
            {users.total === 0 ? (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                No one has been charged yet.
              </p>
            ) : (
              <Table before={<FilterNote shown={users.rows.length} total={users.total} filtered={users.filtered} onClear={users.clearFilters} />}>
                <thead>
                  <tr>
                    {users.th("person", "Person")}
                    {users.th("total", "Charged", "right")}
                    {users.th("observed", "Observed", "right")}
                    {users.th("estimated", "Estimated", "right")}
                    <Th>From projects</Th>
                  </tr>
                </thead>
                <tbody>
                  {users.rows.map((u) => (
                    <tr key={u.user_id}>
                      <Td>{u.user_label ?? u.user_id}</Td>
                      <Td align="right" className="tabular">{formatCredits(u.total)}</Td>
                      <Td align="right" className="tabular">{formatCredits(u.observed)}</Td>
                      <Td align="right" className="tabular">{formatCredits(u.estimated)}</Td>
                      <Td>
                        <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                          {u.parts
                            .map((part) => `${part.project_label ?? part.project_id} ${formatCredits(part.credits)} (${(BASIS_LABEL[part.basis] ?? part.basis).toLowerCase()})`)
                            .join(" · ")}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </div>

          {projects.total > 0 && (
            <div>
              <h3 className="cg-panel-title mb-2">By project</h3>
              <Table before={<FilterNote shown={projects.rows.length} total={projects.total} filtered={projects.filtered} onClear={projects.clearFilters} />}>
                <thead>
                  <tr>
                    {projects.th("project", "Project")}
                    {projects.th("credits", "Auto-triage credits", "right")}
                    {projects.th("people", "Charged to people", "right")}
                    {projects.th("waiting", "Waiting for mapping", "right")}
                    {projects.th("unattributed", "Stays on project", "right")}
                  </tr>
                </thead>
                <tbody>
                  {projects.rows.map((p) => (
                    <tr key={p.project_id}>
                      <Td>
                        {p.project_label ?? p.project_id}
                        {p.observing_since && (
                          <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                            Observed since {formatDateTime(p.observing_since)}
                          </span>
                        )}
                      </Td>
                      <Td align="right" className="tabular">{formatCredits(p.auto_triage_credits)}</Td>
                      <Td align="right" className="tabular">{formatCredits(p.charged_to_people)}</Td>
                      <Td align="right" className="tabular">{formatCredits(p.unresolved)}</Td>
                      <Td align="right" className="tabular">{formatCredits(p.unattributed)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}

          {charges.total > 0 && (
            <div>
              <h3 className="cg-panel-title mb-2">Latest charges</h3>
              <Table before={<FilterNote shown={charges.rows.length} total={charges.total} filtered={charges.filtered} onClear={charges.clearFilters} />}>
                <thead>
                  <tr>
                    {charges.th("when", "Seen")}
                    {charges.th("project", "Project")}
                    {charges.th("initiator", "Scan started by")}
                    {charges.th("basis", "Basis")}
                    {charges.th("credits", "Credits", "right")}
                  </tr>
                </thead>
                <tbody>
                  {charges.rows.map((c) => (
                    <tr key={c.id}>
                      <Td>
                        <span className="text-xs tabular" title={c.detail ?? undefined}>
                          {formatDateTime(c.window_end)}
                        </span>
                      </Td>
                      <Td>{projectName.get(c.project_id) ?? c.project_id}</Td>
                      <Td>
                        {c.initiator ?? "—"}
                        {c.scan_count > 0 && (
                          <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                            {c.scan_count} scan{c.scan_count === 1 ? "" : "s"}
                          </span>
                        )}
                      </Td>
                      <Td>
                        <Badge tone={c.basis === "observed" ? "good" : c.basis === "estimated" ? "info" : "neutral"}>
                          {BASIS_LABEL[c.basis] ?? c.basis}
                        </Badge>
                      </Td>
                      <Td align="right" className="tabular">{formatCredits(c.credits)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------- attribution */

type AttributionTab = "disputed" | "matched" | "unmatched";

const TAB_LABELS: Record<AttributionTab, string> = {
  disputed: "Disputes",
  matched: "Matched",
  unmatched: "Unmatched",
};

const TAB_BLURB: Record<AttributionTab, string> = {
  disputed:
    "A likely user was found but the match is not certain. Confirm one of the suggestions, or map it yourself. Nothing is counted until you do.",
  matched:
    "Counted towards a user's limits — either matched automatically at high confidence, or mapped by you. Change any that look wrong.",
  unmatched:
    "No user resembled the reported handle closely enough to suggest. Map these by hand. Automation accounts (bots) are listed here too and are never counted.",
};

const SUBJECT_VIEW: ViewColumn<UnresolvedSubject>[] = [
  { key: "reported", value: (s) => s.subject_email ?? s.subject_name ?? s.subject_key, filter: false },
  { key: "credits", value: (s) => Number(s.credits_used), filter: false },
];

const ACCOUNT_VIEW: ViewColumn<UtilityAccount>[] = [
  { key: "username", value: (a) => a.username, filter: false },
  { key: "role", value: (a) => (a.role === "admin" ? "Admin" : "Viewer") },
  { key: "totp", value: (a) => (a.totp_enabled ? "On" : "Off") },
  { key: "last", value: (a) => a.last_login_at, filter: false },
];

function confidence(score: number | null | undefined): string {
  return score == null ? "" : `${Math.round(score * 100)}%`;
}

// A subject is counted when its credits currently reach a user's budget — an
// admin mapping or a high-confidence auto-match. This, not the raw status, is
// what decides which tab a row belongs in, so a manual mapping is reflected the
// instant it is saved.
function isCounted(s: UnresolvedSubject): boolean {
  return Boolean(s.counts_towards_user_id);
}

/* ------------------------------------------------------------- appearance */

// The five earth accents of the Standard look, in the order the picker shows them,
// with their light-mode colour for the swatch. The real tokens live in index.css
// under [data-accent]. The keys are the stored values the API accepts.
const ACCENTS: { key: string; name: string; swatch: string }[] = [
  { key: "default", name: "Ink", swatch: "#34507a" },
  { key: "teal", name: "Lagoon", swatch: "#1f6b68" },
  { key: "sage", name: "Sage", swatch: "#3e6a46" },
  { key: "violet", name: "Plum", swatch: "#6c4265" },
  { key: "amber", name: "Ochre", swatch: "#8f5716" },
];

// Accents from before the earth colours, still accepted and shown as their nearest.
const LEGACY_ACCENT: Record<string, string> = { rose: "violet", slate: "default" };

function AppearanceCard({
  isAdmin,
  value,
  options,
  onPick,
}: {
  isAdmin: boolean;
  value: string;
  options: string[];
  onPick: (accent: string) => void;
}) {
  const shown = LEGACY_ACCENT[value] ?? value;
  return (
    <Card
      title="Organisation accent"
      description="The one accent colour of the Standard look, for everyone in this organisation. Command Center uses each person's phosphor colour instead."
    >
      <div className="flex flex-wrap gap-2.5">
        {ACCENTS.filter((accent) => options.includes(accent.key)).map((accent) => {
          const selected = accent.key === shown;
          return (
            <button
              key={accent.key}
              type="button"
              disabled={!isAdmin}
              aria-pressed={selected}
              onClick={() => onPick(accent.key)}
              title={accent.name}
              className="flex items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-60"
              style={{
                borderColor: selected ? "var(--accent)" : "var(--border)",
                background: selected ? "var(--hover)" : "transparent",
                color: "var(--text-primary)",
                fontWeight: selected ? 600 : 400,
              }}
            >
              <span
                className="inline-block size-4 rounded-full"
                style={{
                  background: accent.swatch,
                  outline: selected ? "2px solid var(--accent)" : "none",
                  outlineOffset: "1px",
                }}
              />
              {accent.name}
            </button>
          );
        })}
      </div>
      {!isAdmin && (
        <p className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>
          Only an admin can change the organisation accent.
        </p>
      )}
    </Card>
  );
}

function AttributionCard({
  isAdmin,
  subjects,
  loading,
  onChanged,
}: {
  isAdmin: boolean;
  subjects: UnresolvedSubject[];
  loading: boolean;
  onChanged: () => Promise<void>;
}) {
  const toast = useToast();
  // Opened from "map them" on the Overview: start on the unmatched usage.
  const [tab, setTab] = useState<AttributionTab>(() =>
    window.location.hash === "#unmatched" ? "unmatched" : "disputed",
  );
  const [mapping, setMapping] = useState<UnresolvedSubject | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OrgEntity[]>([]);
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);

  const groups: Record<AttributionTab, UnresolvedSubject[]> = {
    // Grouped by effective attribution, not raw status: a mapped subject counts,
    // so it belongs in "Matched" whatever the matcher last labelled it.
    disputed: subjects.filter((s) => s.status === "disputed" && !isCounted(s)),
    matched: subjects.filter(isCounted),
    unmatched: subjects.filter((s) => !isCounted(s) && s.status !== "disputed"),
  };
  const rows = groups[tab];
  const view = useTableView(rows, SUBJECT_VIEW);

  useEffect(() => {
    if (!mapping) return;
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      try {
        const found = await api.get<OrgEntity[]>(
          "/api/org/entities",
          { entity_type: "user", q: query, limit: 15 },
          controller.signal,
        );
        setResults(found);
      } catch {
        // The dialog shows an empty list rather than an error toast per keystroke.
      }
    }, 200);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [mapping, query]);

  // Map a subject directly, e.g. by accepting a suggestion, without the dialog.
  async function mapSubject(subject: UnresolvedSubject, userId: string | null) {
    setBusyId(subject.id);
    try {
      await api.post(`/api/usage/unresolved/${subject.id}/map`, { user_id: userId });
      toast.success(
        userId
          ? "Confirmed. This usage now counts towards that user."
          : "Mapping cleared.",
      );
      await onChanged();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not save the mapping.");
    } finally {
      setBusyId(null);
    }
  }

  // Map via the free-form search dialog.
  async function assign(userId: string | null) {
    if (!mapping) return;
    setBusy(true);
    try {
      await api.post(`/api/usage/unresolved/${mapping.id}/map`, { user_id: userId });
      toast.success(
        userId
          ? "Mapped. This usage now counts towards that user."
          : "Mapping cleared.",
      );
      setMapping(null);
      setQuery("");
      await onChanged();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not save the mapping.");
    } finally {
      setBusy(false);
    }
  }

  function openDialog(subject: UnresolvedSubject) {
    setMapping(subject);
    setQuery(subject.subject_email ?? subject.subject_name ?? "");
  }

  return (
    <Card
      title="Consumption attribution"
      description="How Checkmarx-reported usage maps to synced users. Handles it cannot match exactly are matched by similarity, then triaged into the tabs below."
    >
      <div id="attribution" />

      <div className="mb-4 flex gap-1 border-b border-hairline">
        {(Object.keys(TAB_LABELS) as AttributionTab[]).map((key) => (
          <button
            key={key}
            type="button"
            onClick={() => setTab(key)}
            className="-mb-px border-b-2 px-3 py-2 text-sm"
            style={{
              borderColor: tab === key ? "var(--focus)" : "transparent",
              color: tab === key ? "var(--text-primary)" : "var(--text-secondary)",
              fontWeight: tab === key ? 600 : 400,
            }}
          >
            {TAB_LABELS[key]}
            {groups[key].length > 0 && (
              <span className="ml-1.5">
                <Badge tone={key === "disputed" ? "warning" : "neutral"}>
                  {groups[key].length}
                </Badge>
              </span>
            )}
          </button>
        ))}
      </div>

      <p className="mb-4 text-xs" style={{ color: "var(--text-secondary)" }}>
        {TAB_BLURB[tab]}
      </p>

      {loading ? (
        <Spinner />
      ) : rows.length === 0 ? (
        <EmptyState
          title={
            tab === "disputed"
              ? "No disputes to resolve"
              : tab === "matched"
                ? "Nothing is matched yet"
                : "Nothing is unmatched"
          }
          description={
            tab === "matched"
              ? "Confirmed mappings and high-confidence auto-matches appear here."
              : "Every consumption row in this state is clear."
          }
        />
      ) : (
        <Table before={<FilterNote shown={view.rows.length} total={view.total} filtered={view.filtered} onClear={view.clearFilters} />}>
          <thead>
            <tr>
              {view.th("reported", "Reported as")}
              {view.th("credits", "Credits", "right")}
              <Th>{tab === "matched" ? "Counts towards" : "Suggestion"}</Th>
              <Th align="right" />
            </tr>
          </thead>
          <tbody>
            {view.rows.map((subject) => (
              <tr key={subject.id}>
                <Td>
                  <span className="text-sm">{subject.subject_name ?? subject.subject_key}</span>
                  {subject.is_bot && (
                    <span className="ml-1.5">
                      <Badge tone="neutral">Bot</Badge>
                    </span>
                  )}
                  {subject.source === "scan_initiator" && (
                    <span className="ml-1.5" title="Started scans that auto triage ran after. Map it to the person it acts for to charge them.">
                      <Badge tone="info">Scan initiator</Badge>
                    </span>
                  )}
                  {subject.subject_email && subject.subject_email !== subject.subject_name && (
                    <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                      {subject.subject_email}
                    </span>
                  )}
                  <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                    Seen {subject.times_seen} times, last {formatRelative(subject.last_seen_at)}
                  </span>
                </Td>
                <Td align="right">
                  <span className="tabular">{formatCredits(subject.credits_used)}</span>
                </Td>
                <Td>
                  {isCounted(subject) ? (
                    <span className="flex items-center gap-2">
                      <Badge tone="good">{subject.counts_towards_label ?? "—"}</Badge>
                      <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                        {subject.mapped_user_id
                          ? "mapped by you"
                          : subject.match_score != null
                            ? `${confidence(subject.match_score)} auto`
                            : ""}
                      </span>
                    </span>
                  ) : subject.suggestions.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {subject.suggestions.map((suggestion) => (
                        <button
                          key={suggestion.user_id}
                          type="button"
                          disabled={!isAdmin || busyId === subject.id}
                          onClick={() => mapSubject(subject, suggestion.user_id)}
                          title={`Confirm ${suggestion.label} (${confidence(suggestion.score)} match)`}
                          className="rounded-full border px-2.5 py-1 text-xs"
                          style={{ borderColor: "var(--border)", color: "var(--text-secondary)" }}
                        >
                          {suggestion.label}{" "}
                          <span style={{ color: "var(--text-muted)" }}>
                            {confidence(suggestion.score)}
                          </span>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <Badge tone="warning">Not counted</Badge>
                  )}
                </Td>
                <Td align="right">
                  {isAdmin && (
                    <button
                      type="button"
                      className="text-xs underline"
                      style={{ color: "var(--text-secondary)" }}
                      onClick={() => openDialog(subject)}
                    >
                      {isCounted(subject) ? "Change" : "Map to a user"}
                    </button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Modal
        open={mapping !== null}
        title="Map this usage to a user"
        description={mapping ? `Reported as ${mapping.subject_key}` : ""}
        onClose={() => setMapping(null)}
      >
        <div className="flex flex-col gap-3">
          <Field label="Search users">
            <Input value={query} onChange={(event) => setQuery(event.target.value)} autoFocus />
          </Field>
          <ul className="max-h-64 overflow-y-auto rounded-md border border-hairline">
            {results.map((entity) => (
              <li key={entity.entity_id}>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => assign(entity.entity_id)}
                  className="w-full px-3 py-2 text-left"
                  style={{ borderTop: "1px solid var(--border)" }}
                >
                  <span className="block text-sm">{entity.label}</span>
                  {entity.secondary && (
                    <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                      {entity.secondary}
                    </span>
                  )}
                </button>
              </li>
            ))}
            {results.length === 0 && (
              <li className="px-3 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                No users matched.
              </li>
            )}
          </ul>
          {mapping && isCounted(mapping) && (
            <Button variant="secondary" onClick={() => assign(null)} loading={busy}>
              {mapping.mapped_user_id
                ? "Clear the current mapping"
                : "Reject the auto-match (leave uncounted)"}
            </Button>
          )}
        </div>
      </Modal>
    </Card>
  );
}

/* ---------------------------------------------------------------- accounts */

const WATCHDOG_TONE: Record<WatchdogStatus["state"], "good" | "neutral" | "warning" | "critical"> = {
  ok: "good",
  disabled: "neutral",
  stale: "warning",
  down: "critical",
};

function OperationsCard() {
  const toast = useToast();
  const attestation = useResource<Attestation>(
    (signal) => api.get("/api/ops/attestation", undefined, signal),
    [],
  );
  const watchdog = useResource<WatchdogStatus>(
    (signal) => api.get("/api/ops/watchdog", undefined, signal),
    [],
  );
  const [busy, setBusy] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  async function downloadBackup() {
    setBusy(true);
    try {
      const data = await api.get<Record<string, unknown>>("/api/ops/backup");
      downloadText(
        JSON.stringify(data, null, 2),
        timestampedName("cxcreditguard-config", "json"),
        "application/json",
      );
      toast.success("Backup downloaded.");
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not export the backup.");
    } finally {
      setBusy(false);
    }
  }

  async function emailBackup() {
    setBusy(true);
    try {
      await api.post("/api/ops/backup/email");
      toast.success("Backup emailed to the notification recipients.");
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not email the backup.");
    } finally {
      setBusy(false);
    }
  }

  async function restore(file: File) {
    setBusy(true);
    try {
      const parsed = JSON.parse(await file.text());
      const result = await api.post<RestoreResult>("/api/ops/restore", parsed);
      toast.success(
        `Restored ${result.limits_created + result.limits_updated} limit(s), ` +
          `${result.settings} setting(s), ${result.exemptions} override(s).`,
      );
      await Promise.all([attestation.reload(), watchdog.reload()]);
    } catch (caught) {
      if (caught instanceof SyntaxError) toast.error("That file is not valid JSON.");
      else toast.error(caught instanceof ApiError ? caught.message : "Restore failed.");
    } finally {
      setBusy(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  const att = attestation.data;
  const watch = watchdog.data;

  return (
    <Card
      title="Operations"
      description="Version and integrity, scheduler liveness, and configuration backup and restore."
    >
      <div className="flex flex-col gap-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Version &amp; integrity
            </p>
            {att ? (
              <div className="mt-1 text-sm">
                <div>
                  v{att.version}
                  {att.update.update_available && (
                    <Link to="/settings/updates" className="ml-2">
                      <Badge tone="warning">Update to {att.update.latest}</Badge>
                    </Link>
                  )}
                </div>
                <code className="text-xs break-all" style={{ color: "var(--text-muted)" }}>
                  {att.config_digest.slice(0, 16)}…
                </code>
              </div>
            ) : (
              <Spinner />
            )}
          </div>
          <div>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Scheduler watchdog
            </p>
            {watch ? (
              <div className="mt-1 flex items-center gap-2">
                <Badge tone={WATCHDOG_TONE[watch.state]}>{watch.state}</Badge>
                <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {watch.detail}
                </span>
              </div>
            ) : (
              <Spinner />
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-hairline pt-4">
          <Button size="sm" onClick={downloadBackup} disabled={busy}>
            Download backup
          </Button>
          <Button size="sm" variant="secondary" onClick={emailBackup} disabled={busy}>
            Email backup
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => fileInput.current?.click()}
            disabled={busy}
          >
            Restore from file…
          </Button>
          <input
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void restore(file);
            }}
          />
        </div>
        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
          Backups hold settings, limits and overrides only. Secrets, passwords and the audit log
          are never exported. Restoring overwrites matching configuration.
        </p>
      </div>
    </Card>
  );
}

function AccountsCard() {
  const toast = useToast();
  const accounts = useResource<UtilityAccount[]>(
    (signal) => api.get("/api/accounts", undefined, signal),
    [],
  );
  const view = useTableView(accounts.data ?? [], ACCOUNT_VIEW);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<UtilityAccount | null>(null);
  const [resettingTotp, setResettingTotp] = useState<UtilityAccount | null>(null);
  const [resetFor, setResetFor] = useState<
    (AdminResetResult & { username: string }) | null
  >(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"admin" | "viewer">("viewer");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/accounts", {
        username: username.trim(),
        password,
        role,
        must_change_password: true,
      });
      toast.success(`Account ${username.trim()} created.`);
      setCreating(false);
      setUsername("");
      setPassword("");
      await accounts.reload();
    } catch (caught) {
      if (caught instanceof ApiError) {
        setError(
          caught.problems.length > 0
            ? `${caught.message} ${caught.problems.join(", ")}`
            : caught.message,
        );
      } else {
        setError("Could not create the account.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      await api.delete(`/api/accounts/${deleting.id}`);
      toast.success(`Account ${deleting.username} deleted.`);
      setDeleting(null);
      await accounts.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not delete the account.");
    } finally {
      setBusy(false);
    }
  }

  async function toggleRole(account: UtilityAccount) {
    try {
      await api.patch(`/api/accounts/${account.id}`, {
        role: account.role === "admin" ? "viewer" : "admin",
      });
      await accounts.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not change the role.");
    }
  }

  async function unlock(account: UtilityAccount) {
    try {
      await api.post(`/api/accounts/${account.id}/unlock`);
      toast.success(`${account.username} unlocked.`);
      await accounts.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not unlock the account.");
    }
  }

  async function resetTwoFactor() {
    if (!resettingTotp) return;
    setBusy(true);
    try {
      await api.post(`/api/accounts/${resettingTotp.id}/totp/reset`);
      toast.success(`Two factor reset for ${resettingTotp.username}.`);
      setResettingTotp(null);
      await accounts.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not reset two factor.");
    } finally {
      setBusy(false);
    }
  }

  async function issueReset(account: UtilityAccount) {
    try {
      const result = await api.post<AdminResetResult>(
        `/api/accounts/${account.id}/reset-password`,
      );
      setResetFor({ username: account.username, ...result });
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not issue a reset code.");
    }
  }

  return (
    <Card
      title="Utility accounts"
      description="Who can sign in to CxCreditGuard. Admin has full control, Viewer is read only."
      actions={
        <Button size="sm" onClick={() => setCreating(true)}>
          New account
        </Button>
      }
    >
      {accounts.initialLoading ? (
        <Spinner />
      ) : (
        <Table before={<FilterNote shown={view.rows.length} total={view.total} filtered={view.filtered} onClear={view.clearFilters} />}>
          <thead>
            <tr>
              {view.th("username", "Username")}
              {view.th("role", "Role")}
              {view.th("totp", "Two factor")}
              {view.th("last", "Last sign in")}
              <Th align="right" />
            </tr>
          </thead>
          <tbody>
            {view.rows.map((account) => (
              <tr key={account.id}>
                <Td>
                  <span className="text-sm font-medium">{account.username}</span>
                  {!account.is_active && (
                    <span className="ml-2">
                      <Badge tone="neutral">Disabled</Badge>
                    </span>
                  )}
                  {account.locked_until && (
                    <span className="ml-2">
                      <Badge tone="warning">Locked</Badge>
                    </span>
                  )}
                </Td>
                <Td>
                  <button
                    type="button"
                    className="text-xs underline"
                    style={{ color: "var(--text-secondary)" }}
                    onClick={() => toggleRole(account)}
                  >
                    {account.role === "admin" ? "Admin" : "Viewer"}
                  </button>
                </Td>
                <Td>
                  {account.totp_enabled ? (
                    <Badge tone="good">Enabled</Badge>
                  ) : (
                    <Badge tone="neutral">Not set up</Badge>
                  )}
                </Td>
                <Td>
                  <span className="text-xs">{formatRelative(account.last_login_at)}</span>
                </Td>
                <Td align="right">
                  <div className="flex justify-end gap-2 text-xs">
                    {account.locked_until && (
                      <button
                        type="button"
                        className="underline"
                        style={{ color: "var(--text-secondary)" }}
                        onClick={() => unlock(account)}
                      >
                        Unlock
                      </button>
                    )}
                    {account.is_active && (
                      <button
                        type="button"
                        className="underline"
                        style={{ color: "var(--text-secondary)" }}
                        onClick={() => issueReset(account)}
                      >
                        Reset password
                      </button>
                    )}
                    {account.totp_enabled && (
                      <button
                        type="button"
                        className="underline"
                        style={{ color: "var(--text-secondary)" }}
                        onClick={() => setResettingTotp(account)}
                      >
                        Reset two factor
                      </button>
                    )}
                    <button
                      type="button"
                      className="underline"
                      style={{ color: "var(--status-critical)" }}
                      onClick={() => setDeleting(account)}
                    >
                      Delete
                    </button>
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Modal
        open={creating}
        title="New utility account"
        description="This is an account for CxCreditGuard itself, not a Checkmarx One user."
        onClose={() => setCreating(false)}
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreating(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={create} loading={busy} disabled={!username || !password}>
              Create account
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          {error && <ErrorNote>{error}</ErrorNote>}
          <Field label="Username" required>
            <Input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" />
          </Field>
          <Field
            label="Initial password"
            required
            hint="At least 12 characters with mixed case, a digit and a symbol. The user is asked to change it."
          >
            <Input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
            />
          </Field>
          <Field label="Role">
            <Select value={role} onChange={(event) => setRole(event.target.value as "admin" | "viewer")}>
              <option value="viewer">Viewer (read only)</option>
              <option value="admin">Admin (full control)</option>
            </Select>
          </Field>
          <InfoNote>
            Viewers can read dashboards, notifications and the audit log, but cannot change limits,
            settings or the connection.
          </InfoNote>
        </div>
      </Modal>

      <ConfirmDialog
        open={deleting !== null}
        title="Delete this account?"
        destructive
        confirmLabel="Delete account"
        busy={busy}
        message={
          deleting
            ? `${deleting.username} will no longer be able to sign in. Their entries stay in the audit log.`
            : ""
        }
        onConfirm={remove}
        onCancel={() => setDeleting(null)}
      />

      <ConfirmDialog
        open={resettingTotp !== null}
        title="Reset two factor for this account?"
        destructive
        confirmLabel="Reset two factor"
        busy={busy}
        message={
          resettingTotp
            ? `Use this when ${resettingTotp.username} has lost their authenticator. Two factor is turned off for the account, its recovery codes are discarded and it is signed out everywhere. They sign in with their password and should set two factor up again straight away.`
            : ""
        }
        onConfirm={resetTwoFactor}
        onCancel={() => setResettingTotp(null)}
      />

      <Modal
        open={resetFor !== null}
        title="One-time reset code"
        description={
          resetFor
            ? `Give this code to ${resetFor.username}. They redeem it on the sign-in page under "I have a reset code". It is shown once.`
            : ""
        }
        onClose={() => setResetFor(null)}
        footer={
          <Button variant="primary" onClick={() => setResetFor(null)}>
            Done
          </Button>
        }
      >
        {resetFor && (
          <div className="flex flex-col gap-3">
            <code
              className="block rounded-md px-3 py-2 text-sm break-all"
              style={{ background: "var(--hover)" }}
            >
              {resetFor.reset_token}
            </code>
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              Expires {formatDateTime(resetFor.expires_at)}. Issuing a new code invalidates this one.
            </p>
          </div>
        )}
      </Modal>
    </Card>
  );
}

/* -------------------------------------------------------------------- demo */

function DemoCard({
  enabled,
  onToggle,
  onChanged,
}: {
  enabled: boolean;
  onToggle: (next: boolean) => void;
  onChanged: () => Promise<unknown>;
}) {
  const toast = useToast();
  const status = useResource<{ demo_mode: boolean; seeded: boolean }>(
    (signal) => api.get("/api/ops/demo", undefined, signal),
    [],
  );
  const [running, setRunning] = useState<"seed" | "clear" | null>(null);

  async function run(path: "seed" | "clear") {
    setRunning(path);
    try {
      await api.post(`/api/ops/demo/${path}`);
      toast.success(
        path === "seed"
          ? "Demo data seeded and demo mode turned on."
          : "Demo data cleared and demo mode turned off.",
      );
      await status.reload();
      // Seeding/clearing flips demo mode server-side; refresh the toggle and the
      // app banner so they match.
      await onChanged();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "The demo action failed.");
    } finally {
      setRunning(null);
    }
  }

  const busy = running !== null;

  return (
    <Card
      title="Demo mode"
      description="Explore CxCreditGuard with synthetic data. In demo mode the scheduler makes no change in Checkmarx, and demo data is never read as live."
    >
      <div className="flex flex-col gap-4">
        <Toggle
          checked={enabled}
          onChange={onToggle}
          label="Demo mode"
          description={
            enabled
              ? "On. The app is marked as demo and automated cycles touch no live tenant. Save to apply."
              : "Off. Live data and normal enforcement. Save after changing."
          }
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" onClick={() => run("seed")} loading={running === "seed"} disabled={busy}>
            Seed demo data
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => run("clear")}
            loading={running === "clear"}
            disabled={busy}
          >
            Clear demo data
          </Button>
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            {status.data?.seeded ? "Demo data is present." : "No demo data seeded."}
          </span>
        </div>
      </div>
    </Card>
  );
}

/** Role names that look like administration roles (as the server checks:
 * `*admin*`, `manage-*`, `realm-*`, `iam-*`). */
function isAdminLikeRole(name: string): boolean {
  const lowered = name.trim().toLowerCase();
  return (
    lowered.includes("admin") ||
    lowered.startsWith("manage-") ||
    lowered.startsWith("realm-") ||
    lowered.startsWith("iam-")
  );
}

/** The client roles a user restriction removes, picked from the tenant's own roles. */
function AiRolesPicker({
  isAdmin,
  value,
  defaults,
  protectedRoles,
  onChange,
  onConfirmAdmin,
}: {
  isAdmin: boolean;
  value: string[];
  defaults: string[];
  /** Protected role names, lowercase: they cannot be AI roles. */
  protectedRoles: string[];
  onChange: (next: string[]) => void;
  onConfirmAdmin: (name: string) => void;
}) {
  const roles = useResource<ClientRoles | null>(
    (signal) =>
      isAdmin ? api.get<ClientRoles>("/api/settings/client-roles", undefined, signal) : Promise.resolve(null),
    [isAdmin],
  );
  const [choice, setChoice] = useState("");
  const [confirming, setConfirming] = useState<string | null>(null);
  const listing = roles.data;
  const isProtected = (name: string) => protectedRoles.includes(name.toLowerCase());
  const adminLike = (name: string) => byName.get(name)?.admin_like ?? isAdminLikeRole(name);

  function add(name: string) {
    if (isProtected(name)) return;
    if (adminLike(name)) {
      setConfirming(name);
      return;
    }
    onChange([...value, name]);
  }
  const byName = new Map((listing?.roles ?? []).map((role) => [role.name, role]));
  const addable = (listing?.roles ?? []).filter((role) => !value.includes(role.name));
  const isDefault =
    value.length === defaults.length && value.every((name) => defaults.includes(name));

  function remove(name: string) {
    const next = value.filter((entry) => entry !== name);
    if (next.length > 0) onChange(next);
  }

  return (
    <div>
      <p className="text-sm font-medium">Roles a user restriction removes</p>
      <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
        The client roles (on <code>ast-app</code>) taken from a person who goes over a user
        budget. The default is the three general Risk Management roles AI Triage and AI
        Remediation are reached through, so a restricted person also loses the Risk Management
        pages. When Checkmarx One ships dedicated AI Triage and Remediation roles (announced for
        10 January), add them here and remove the general ones. A change applies only to
        restrictions made from then on: a restriction in force keeps, and gives back, exactly
        the roles it recorded. A role a person holds through a group or a composite role is not
        taken away by removing their direct mapping; CreditGuard says so when it happens.
      </p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {value.map((name) => {
          const role = byName.get(name);
          const title = role?.known_description ?? role?.description ?? undefined;
          return (
            <span
              key={name}
              title={title}
              className="inline-flex items-center gap-1 rounded border border-hairline px-2 py-0.5 text-xs"
            >
              <code>{name}</code>
              {role?.composite && <Badge tone="neutral">composite</Badge>}
              {adminLike(name) && <Badge tone="warning">admin role</Badge>}
              {isProtected(name) && <Badge tone="warning">protected</Badge>}
              {listing?.available && !role && <Badge tone="warning">not on the tenant</Badge>}
              {isAdmin && value.length > 1 && (
                <button
                  type="button"
                  className="ml-0.5"
                  aria-label={`Remove ${name}`}
                  onClick={() => remove(name)}
                  style={{ color: "var(--text-muted)" }}
                >
                  ×
                </button>
              )}
            </span>
          );
        })}
      </div>
      {isAdmin && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          {roles.loading ? (
            <span className="flex items-center gap-2 text-xs" style={{ color: "var(--text-secondary)" }}>
              <Spinner size={12} /> Reading the tenant's roles
            </span>
          ) : listing?.available ? (
            <>
              <Select
                value={choice}
                onChange={(event) => setChoice(event.target.value)}
                aria-label="Role to add"
                className="max-w-xs"
              >
                <option value="">Add a role…</option>
                {addable.map((role) => (
                  <option
                    key={role.name}
                    value={role.name}
                    disabled={isProtected(role.name)}
                  >
                    {role.name}
                    {role.composite ? " (composite)" : ""}
                    {isProtected(role.name)
                      ? " (protected: cannot be an AI role)"
                      : adminLike(role.name)
                        ? " ⚠ admin role"
                        : ""}
                  </option>
                ))}
              </Select>
              <Button
                size="sm"
                disabled={!choice}
                onClick={() => {
                  if (choice) add(choice);
                  setChoice("");
                }}
              >
                Add
              </Button>
            </>
          ) : (
            <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
              {listing?.message ?? roles.error ?? "The tenant's roles could not be listed."} Only
              roles already in the list (or the defaults) can be kept until they can be read.
            </span>
          )}
          {!isDefault && (
            <Button size="sm" onClick={() => onChange([...defaults])}>
              Back to the default
            </Button>
          )}
        </div>
      )}
      <ConfirmDialog
        open={confirming !== null}
        title="Remove an administration role from people over budget?"
        destructive
        confirmLabel="Add it anyway"
        message={
          confirming
            ? `${confirming} looks like an administration role. A user restriction would take it from anyone who goes over a user budget, along with everything it allows besides AI features (managing users, the tenant or its settings). Add it only if that is what you want.`
            : ""
        }
        onConfirm={() => {
          if (confirming) {
            onConfirmAdmin(confirming);
            onChange([...value, confirming]);
          }
          setConfirming(null);
        }}
        onCancel={() => setConfirming(null)}
      />
    </div>
  );
}
