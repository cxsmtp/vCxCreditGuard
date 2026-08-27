import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type {
  AppSettings,
  CycleRun,
  OrgEntity,
  SchedulerStatus,
  UnresolvedSubject,
  UtilityAccount,
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
import { useResource } from "../hooks/useResource";
import { formatCredits, formatDateTime, formatRelative } from "../lib/format";
import { useToast } from "../lib/ui-context";

export function SettingsPage({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const location = useLocation();

  const settings = useResource<AppSettings>((signal) => api.get("/api/settings", undefined, signal), []);
  const status = useResource<SchedulerStatus>((signal) => api.get("/api/ops/status", undefined, signal), []);
  const unresolved = useResource<UnresolvedSubject[]>(
    (signal) => api.get("/api/usage/unresolved", undefined, signal),
    [],
  );

  const [draft, setDraft] = useState<Partial<AppSettings> & { smtp_password?: string; webhook_secret?: string }>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    channels: Record<string, string>;
  } | null>(null);

  useEffect(() => {
    if (location.hash === "#attribution") {
      document.getElementById("attribution")?.scrollIntoView({ behavior: "smooth" });
    }
  }, [location.hash, unresolved.data]);

  const current = settings.data;
  const value = <K extends keyof AppSettings>(key: K): AppSettings[K] | undefined =>
    (draft[key] as AppSettings[K] | undefined) ?? current?.[key];

  function set(patch: Partial<AppSettings> & { smtp_password?: string; webhook_secret?: string }) {
    setDraft((existing) => ({ ...existing, ...patch }));
  }

  const dirty = Object.keys(draft).length > 0;

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.put<AppSettings>("/api/settings", draft);
      settings.setData(updated);
      setDraft({});
      toast.success(`Settings saved. Schedule is now ${updated.current_schedule_description}.`);
      await status.reload();
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
        title="Settings"
        description="Scheduling, ingestion, notification delivery, attribution fixes and utility accounts."
        actions={
          isAdmin && (
            <>
              <Button size="sm" onClick={() => runCycle(false)} loading={running}>
                Run a cycle now
              </Button>
              <Button size="sm" onClick={() => runCycle(true)} loading={running}>
                Sync organisation model
              </Button>
              <Button variant="primary" size="sm" onClick={save} disabled={!dirty} loading={busy}>
                Save changes
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

      <div className="grid gap-6 lg:grid-cols-2">
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
        </Card>

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
              <Field label="Webhook URL" hint="A JSON payload is posted for each delivered notification.">
                <Input
                  value={value("webhook_url") ?? ""}
                  disabled={!isAdmin}
                  onChange={(event) => set({ webhook_url: event.target.value })}
                  placeholder="https://hooks.example.com/cxcreditguard"
                  spellCheck={false}
                />
              </Field>
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

        <div className="flex flex-col gap-6">
          <AttributionCard
            isAdmin={isAdmin}
            subjects={unresolved.data ?? []}
            loading={unresolved.initialLoading}
            onChanged={() => unresolved.reload()}
          />
          {isAdmin && <AccountsCard />}
        </div>
      </div>

      {dirty && isAdmin && (
        <div className="sticky bottom-4 mt-6 flex justify-end">
          <div
            className="flex items-center gap-3 rounded-lg border border-hairline px-4 py-3 shadow-lg"
            style={{ background: "var(--surface-raised)" }}
          >
            <span className="text-sm">You have unsaved changes.</span>
            <Button variant="secondary" size="sm" onClick={() => setDraft({})} disabled={busy}>
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

/* ------------------------------------------------------------- attribution */

type AttributionTab = "disputed" | "auto_matched" | "unmatched";

const TAB_LABELS: Record<AttributionTab, string> = {
  disputed: "Disputes",
  auto_matched: "Auto-matched",
  unmatched: "Unmatched",
};

const TAB_BLURB: Record<AttributionTab, string> = {
  disputed:
    "A likely user was found but the match is not certain. Confirm one of the suggestions, or map it yourself. Nothing is counted until you do.",
  auto_matched:
    "Matched to a user automatically at high confidence, and counted towards their limits from the next poll. Override any that look wrong.",
  unmatched:
    "No user resembled the reported handle closely enough to suggest. Map these by hand. Automation accounts (bots) are listed here too and are never counted.",
};

function confidence(score: number | null | undefined): string {
  return score == null ? "" : `${Math.round(score * 100)}%`;
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
  const [tab, setTab] = useState<AttributionTab>("disputed");
  const [mapping, setMapping] = useState<UnresolvedSubject | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OrgEntity[]>([]);
  const [busy, setBusy] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);

  const groups: Record<AttributionTab, UnresolvedSubject[]> = {
    disputed: subjects.filter((s) => s.status === "disputed"),
    auto_matched: subjects.filter((s) => s.status === "auto_matched"),
    unmatched: subjects.filter((s) => s.status === "unmatched"),
  };
  const rows = groups[tab];

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
          ? "Confirmed. From the next poll onwards this usage counts towards that user."
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
          ? "Mapped. From the next poll onwards this usage counts towards that user."
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
              : tab === "auto_matched"
                ? "Nothing was auto-matched"
                : "Nothing is unmatched"
          }
          description={
            tab === "auto_matched"
              ? "When a handle is matched to a user by similarity it will appear here to review."
              : "Every consumption row in this state is clear."
          }
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Reported as</Th>
              <Th align="right">Credits</Th>
              <Th>{tab === "auto_matched" ? "Matched to" : "Suggestion"}</Th>
              <Th align="right" />
            </tr>
          </thead>
          <tbody>
            {rows.map((subject) => (
              <tr key={subject.id}>
                <Td>
                  <span className="text-sm">{subject.subject_name ?? subject.subject_key}</span>
                  {subject.is_bot && (
                    <span className="ml-1.5">
                      <Badge tone="neutral">Bot</Badge>
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
                  {tab === "auto_matched" ? (
                    <span className="flex items-center gap-2">
                      <Badge tone="good">{subject.counts_towards_label ?? "—"}</Badge>
                      {subject.match_score != null && (
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                          {confidence(subject.match_score)} confidence
                        </span>
                      )}
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
                      {tab === "auto_matched" ? "Override" : "Map to a user"}
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
          {(mapping?.mapped_user_id || mapping?.status === "auto_matched") && (
            <Button variant="secondary" onClick={() => assign(null)} loading={busy}>
              {mapping?.mapped_user_id
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

function AccountsCard() {
  const toast = useToast();
  const accounts = useResource<UtilityAccount[]>(
    (signal) => api.get("/api/accounts", undefined, signal),
    [],
  );
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<UtilityAccount | null>(null);
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
        <Table>
          <thead>
            <tr>
              <Th>Username</Th>
              <Th>Role</Th>
              <Th>Two factor</Th>
              <Th>Last sign in</Th>
              <Th align="right" />
            </tr>
          </thead>
          <tbody>
            {(accounts.data ?? []).map((account) => (
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
    </Card>
  );
}
