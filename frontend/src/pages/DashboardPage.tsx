import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type {
  AttributionSummary,
  CreditPoolInfo,
  CycleRun,
  Dashboard,
  UnresolvedSubject,
} from "../api/types";
import { BarList } from "../components/charts/BarList";
import { BreakdownChart } from "../components/charts/BreakdownChart";
import { TrendChart } from "../components/charts/TrendChart";
import { StatTile } from "../components/StatTile";
import { DiagnosticsPanel } from "../components/DiagnosticsPanel";
import { Button, Card, ErrorNote, InfoNote, PageHeader, Spinner, Tabs } from "../components/ui";
import { useInterval, useResource } from "../hooks/useResource";
import { UsageSourceBanner } from "../components/UsageSourceBanner";
import {
  formatCredits,
  formatDateTime,
  formatNumber,
  formatPercent,
  formatRelative,
  runStatusLabel,
  thresholdsPhrase,
} from "../lib/format";
import { useToast } from "../lib/ui-context";

type ConsumerTab = "users" | "projects" | "groups" | "applications";

export function DashboardPage({
  isAdmin,
  needsTwoFactor = false,
}: {
  isAdmin: boolean;
  needsTwoFactor?: boolean;
}) {
  const toast = useToast();
  const [tab, setTab] = useState<ConsumerTab>("users");
  const [running, setRunning] = useState(false);

  const dashboard = useResource<Dashboard>(
    (signal) => api.get("/api/dashboard", { top: 10, trend_points: 60 }, signal),
    [],
  );
  const unresolved = useResource<UnresolvedSubject[]>(
    (signal) => api.get("/api/usage/unresolved", undefined, signal),
    [],
  );

  // Refresh while the tab is visible so a cycle that lands is reflected without a
  // manual reload. The previous render stays on screen during the refetch.
  useInterval(() => {
    void dashboard.reload();
  }, 60_000);

  async function runCycle() {
    setRunning(true);
    try {
      const result = await api.post<CycleRun>("/api/ops/run-cycle", undefined, {
        force_org_sync: true,
      });
      if (result.status === "success") {
        toast.success("Cycle finished.");
      } else if (result.status === "skipped") {
        toast.info(`Cycle skipped: ${result.skipped_reason ?? "unknown reason"}`);
      } else {
        toast.error(
          `Cycle finished: ${runStatusLabel(result.status).toLowerCase()}. ${result.errors.join("; ") || "See the notifications."}`,
        );
      }
      await Promise.all([dashboard.reload(), unresolved.reload()]);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "The cycle could not be started.");
    } finally {
      setRunning(false);
    }
  }

  if (dashboard.initialLoading) {
    return (
      <div className="flex items-center gap-2 py-16" style={{ color: "var(--text-secondary)" }}>
        <Spinner /> Loading the dashboard
      </div>
    );
  }

  if (!dashboard.data) {
    return <ErrorNote>{dashboard.error ?? "The dashboard could not be loaded."}</ErrorNote>;
  }

  const data = dashboard.data;
  const tiles = data.tiles;
  // Not counted towards anyone: no manual mapping, no auto-match, and not a bot.
  // The count is the server's (the same on every page); the list only adds credits
  // when the summary is not there.
  const unmatched = (unresolved.data ?? []).filter(
    (row) => !row.counts_towards_user_id && !row.is_bot && row.source !== "scan_initiator",
  );
  const unmatchedPeople = data.attribution?.unmatched_people ?? tiles.unresolved_subjects;
  const unmatchedCredits =
    data.attribution?.unmatched_people_credits ??
    unmatched.reduce((sum, row) => sum + Number(row.credits_used), 0);

  const consumers = {
    users: data.top_users,
    projects: data.top_projects,
    groups: data.top_groups,
    applications: data.top_applications,
  } as const;

  return (
    <div className={dashboard.loading ? "opacity-70 transition-opacity" : "transition-opacity"}>
      <PageHeader
        title="Overview"
        description={
          <>
            AI credits used in the {data.lookback_window.replace(/_/g, " ")} window, as Checkmarx One
            reports them. Each budget counts from when its period opened: see Budgets.
          </>
        }
        actions={
          isAdmin && (
            <Button variant="primary" onClick={runCycle} loading={running}>
              Run a cycle now
            </Button>
          )
        }
      />
      <UsageSourceBanner />

      <div className="mb-5">
        <DiagnosticsPanel needsTwoFactor={needsTwoFactor} />
      </div>

      {data.unavailable_dimensions.length > 0 && (
        <div className="mb-5">
          <InfoNote tone="warning">
            Checkmarx does not report consumption by{" "}
            {data.unavailable_dimensions.join(", ")} on this tenant. Limits at{" "}
            {data.unavailable_dimensions.length === 1 ? "that level" : "those levels"} are not
            evaluated, and nothing is assumed to be zero.
          </InfoNote>
        </div>
      )}

      {(tiles.unresolved_scan_initiators ?? 0) > 0 && (
        <div className="mb-5">
          <InfoNote tone="warning">
            {formatNumber(tiles.unresolved_scan_initiators ?? 0)} scan{" "}
            {tiles.unresolved_scan_initiators === 1 ? "initiator is" : "initiators are"} not matched to
            a person, so their share of auto-triage credits stays on the project.{" "}
            <Link to="/settings/attribution#unmatched" className="underline">
              Map them under Settings → Attribution
            </Link>
            .
          </InfoNote>
        </div>
      )}
      {unmatchedPeople > 0 && (
        <div className="mb-5">
          <InfoNote tone="warning">
            {formatNumber(unmatchedPeople)} {unmatchedPeople === 1 ? "person" : "people"} in the
            consumption feed could not be matched to a Checkmarx user, so{" "}
            {formatCredits(unmatchedCredits)} credits are not counted towards any user limit.{" "}
            <Link to="/settings/attribution#unmatched" className="underline">
              Map them under Settings → Attribution
            </Link>
            .
          </InfoNote>
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label={`Credits reported (${data.lookback_window.replace(/_/g, " ")})`}
          value={
            data.tenant_total_credits === null ? "No data" : formatCredits(data.tenant_total_credits)
          }
          detail={
            data.collected_at
              ? `Consumption feed, rolling window. Collected ${formatRelative(data.collected_at)}`
              : "No poll yet"
          }
        />
        <StatTile
          label="Entities near a limit"
          value={formatNumber(tiles.entities_in_warning)}
          tone={tiles.entities_in_warning > 0 ? "warning" : "neutral"}
          detail="Past their warning threshold"
          to="/limits"
        />
        <StatTile
          label="Entities restricted"
          value={formatNumber(tiles.entities_restricted)}
          tone={tiles.entities_restricted > 0 ? "critical" : "good"}
          detail={`${formatNumber(tiles.active_restrictions)} active ${
            tiles.active_restrictions === 1 ? "restriction" : "restrictions"
          }`}
          to="/notifications"
        />
        <StatTile
          label="Next scheduled run"
          value={tiles.next_run_at ? formatRelative(tiles.next_run_at) : "Not scheduled"}
          detail={`${tiles.schedule}. Last success ${formatRelative(tiles.last_success_at)}`}
          tone={tiles.last_run_status === "failed" ? "critical" : "neutral"}
          to="/settings"
        />
      </div>

      <CreditPoolCard pool={data.credit_pool} />

      {data.attribution && <AttributionCard summary={data.attribution} isAdmin={isAdmin} />}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card
          title="Credits consumed over time"
          description="Difference between consecutive polls"
          className="min-w-0 lg:col-span-2"
        >
          <TrendChart points={data.trend} />
        </Card>

        {/* min-w-0: a grid item may otherwise grow to its table's width on a phone. */}
        <Card title="By action type" description="What the credits were spent on" className="min-w-0">
          <BreakdownChart items={data.breakdown} />
        </Card>
      </div>

      <div className="mt-6">
        <Card
          title="Top consumers"
          description={`Ranked by credits in the reported window. Limits are shown where configured.`}
          padded={false}
        >
          <div className="px-5 pt-4">
            <Tabs
              tabs={[
                { id: "users", label: "Users", count: data.top_users.length },
                { id: "projects", label: "Projects", count: data.top_projects.length },
                { id: "groups", label: "Groups", count: data.top_groups.length },
                { id: "applications", label: "Applications", count: data.top_applications.length },
              ]}
              active={tab}
              onChange={setTab}
            />
          </div>
          <div className="p-5">
            <BarList
              items={consumers[tab]}
              unavailable={
                (tab === "projects" && data.unavailable_dimensions.includes("project")) ||
                (tab === "applications" && data.unavailable_dimensions.includes("application"))
              }
              emptyTitle={`No ${tab} consumption recorded yet`}
              emptyDescription="Run a cycle, or wait for the scheduler to poll Checkmarx."
            />
          </div>
        </Card>
      </div>

      <p className="mt-4 text-xs" style={{ color: "var(--text-muted)" }}>
        Generated {formatDateTime(data.generated_at)}. Limits configured:{" "}
        {formatNumber(tiles.limits_configured)}, of which {formatNumber(tiles.limits_enforcing)}{" "}
        {tiles.limits_enforcing === 1 ? "enforces" : "enforce"}.
      </p>
    </div>
  );
}

function CreditPoolCard({ pool }: { pool: CreditPoolInfo | null }) {
  if (!pool) return null;

  const known = pool.total !== null;
  const total = known ? Number(pool.total) : 0;
  const used = pool.used !== null ? Number(pool.used) : null;
  const assigned = Number(pool.assigned);
  const over = pool.over_allocation !== null;

  // Bar segments as a share of the pool. Floor the scale at 1 so a genuine
  // total of 0 (a real zero, not "unknown") can never produce 0/0 = NaN widths.
  const scale = Math.max(known ? total : Math.max(assigned, used ?? 0), 1);
  const pct = (value: number) => `${Math.min(100, Math.max(0, (value / scale) * 100))}%`;

  const figure = (v: string | null) => (v === null ? "—" : formatCredits(v));
  const thresholds = thresholdsPhrase(
    pool.checkmarx_enforcement?.warningThresholdPct,
    pool.checkmarx_enforcement?.cutoffThresholdPct,
  );

  return (
    <div className="mb-6">
      <Card
        title="Credit pool"
        description="The tenant's AI credit balance against what your budgets have claimed. Granted, Used and Available are Checkmarx One's balance for the current grant (its credit info), shown as it reports them. “Credits reported” above comes from the consumption feed over a rolling window, which can reach back past the start of this grant, so it can be higher than Granted."
      >
        <div className="mb-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <PoolFigure label="Total granted" value={figure(pool.total)} />
          <PoolFigure label="Used" value={figure(pool.used)} />
          <PoolFigure label="Available" value={figure(pool.available)} />
          <PoolFigure
            label="Assigned to budgets"
            value={formatCredits(pool.assigned)}
            tone={over ? "critical" : "neutral"}
          />
        </div>

        <div
          className="relative h-3 w-full overflow-hidden rounded-full"
          style={{ background: "var(--surface-raised)" }}
          role="img"
          aria-label={`Used ${figure(pool.used)}, assigned ${formatCredits(pool.assigned)}${
            known ? `, of ${figure(pool.total)} total` : ""
          }`}
        >
          {used !== null && (
            <div
              className="absolute inset-y-0 left-0"
              style={{ width: pct(used), background: "var(--status-good)" }}
            />
          )}
          {/* Assigned marker: where the sum of budgets sits on the pool. */}
          <div
            className="absolute inset-y-0"
            style={{
              left: pct(assigned),
              width: "2px",
              background: over ? "var(--status-critical)" : "var(--text-secondary)",
            }}
          />
        </div>

        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs" style={{ color: "var(--text-muted)" }}>
          <span>
            <span className="mr-1 inline-block h-2 w-2 rounded-full align-middle" style={{ background: "var(--status-good)" }} />
            Used
          </span>
          <span>
            <span className="mr-1 inline-block h-2 w-2 rounded-full align-middle" style={{ background: "var(--text-secondary)" }} />
            Assigned to budgets
          </span>
          {pool.collected_at && <span>Balance read {formatRelative(pool.collected_at)}</span>}
          {!known && <span>Tenant balance not read yet — showing budget allocation only.</span>}
        </div>

        {pool.checkmarx_enforcement && (
          <div className="mt-3">
            <InfoNote tone={pool.checkmarx_enforcement.state === "normal" ? "info" : "warning"}>
              Checkmarx One's own credit enforcement (read only):{" "}
              {pool.checkmarx_enforcement.state ? (
                <strong>{pool.checkmarx_enforcement.state}</strong>
              ) : (
                "state not reported"
              )}
              {pool.checkmarx_enforcement.consumptionPct !== undefined &&
                `, ${formatPercent(pool.checkmarx_enforcement.consumptionPct)} consumed`}
              {thresholds && `; ${thresholds}`}
              . CreditGuard does not change it.
            </InfoNote>
          </div>
        )}

        {pool.unexplained !== null && pool.unexplained !== undefined && (
          <div className="mt-3">
            <InfoNote tone="info">
              Checkmarx One&apos;s own figures do not add up: Granted − Used is{" "}
              {formatCredits(Number(pool.total) - Number(pool.used))}, but it reports{" "}
              {figure(pool.available)} available ({formatCredits(Math.abs(Number(pool.unexplained)))}{" "}
              {Number(pool.unexplained) > 0 ? "less" : "more"}). Its credit info does not say why
              {Object.keys(pool.other_figures ?? {}).length > 0
                ? `; it also reports ${Object.entries(pool.other_figures ?? {})
                    .map(([key, value]) => `${key} ${formatCredits(value)}`)
                    .join(", ")}`
                : ""}
              . CreditGuard shows each figure as reported and does not fill the gap in.
            </InfoNote>
          </div>
        )}

        {over && (
          <div className="mt-3">
            <InfoNote tone="warning">
              Your budgets assign {formatCredits(pool.assigned)} credits, which is{" "}
              {formatCredits(pool.over_allocation)} more than the {figure(pool.total)} the tenant
              was granted. Reduce a budget or raise the tenant's credit pool.
            </InfoNote>
          </div>
        )}
      </Card>
    </div>
  );
}

/**
 * Usage that counts towards no limit, and why. Automation and unmatched
 * project or application names are shown, never silently dropped.
 */
function AttributionCard({ summary, isAdmin }: { summary: AttributionSummary; isAdmin: boolean }) {
  const rows: { key: string; label: string; count: number; credits: string; total: string; note: string }[] = [];
  if (summary.automation > 0) {
    rows.push({
      key: "automation",
      label: summary.automation === 1 ? "Automation identity" : "Automation identities",
      count: summary.automation,
      credits: summary.automation_credits,
      total: summary.user_total_credits,
      note:
        "Auto Triage, bots and integrations without an email. Counted tenant wide and on projects, towards no user limit; not a person to chase." +
        ((summary.automation_builtin ?? 0) > 0
          ? ` ${formatNumber(summary.automation_builtin ?? 0)} of them ${
              summary.automation_builtin === 1 ? "is" : "are"
            } Checkmarx One's own (such as Auto-triage), which Settings → Attribution does not list; the rest are listed there under Unmatched, marked Automation.`
          : " Listed under Settings → Attribution → Unmatched, marked Automation."),
    });
  }
  if (summary.unmatched_people > 0) {
    rows.push({
      key: "people",
      label: summary.unmatched_people === 1 ? "Person not matched" : "People not matched",
      count: summary.unmatched_people,
      credits: summary.unmatched_people_credits,
      total: summary.user_total_credits,
      note:
        "Reported under a name or address that matches no synced user." +
        ((summary.unmatched_people_disputed ?? 0) > 0
          ? ` Under Settings → Attribution: ${formatNumber(summary.unmatched_people_disputed ?? 0)} under Disputes (a likely match to confirm), the rest under Unmatched.`
          : " Listed under Settings → Attribution → Unmatched."),
    });
  }
  for (const [key, label, found] of [
    ["projects", "project", summary.projects],
    ["applications", "application", summary.applications],
  ] as const) {
    if (found.count > 0) {
      const names = found.top.slice(0, 3).map((entry) => entry.name).join(", ");
      rows.push({
        key,
        label: `${label[0]!.toUpperCase()}${label.slice(1)} ${found.count === 1 ? "name" : "names"} not matched`,
        count: found.count,
        credits: found.credits,
        total: found.total_credits,
        note: `Usage under a repository name that matches no ${label} in Checkmarx One (such as ${names}). It counts towards no ${
          key === "projects" ? "project, group or application" : "application"
        } limit.`,
      });
    }
  }
  if (Number(summary.projects_unreported ?? 0) > 0 && summary.tenant_total_credits) {
    rows.push({
      key: "unreported",
      label: "Not under any project",
      count: 0,
      credits: summary.projects_unreported ?? "0",
      total: summary.tenant_total_credits,
      note: "Checkmarx One reports this much more usage tenant wide than its project rows add up to: usage it files under no project, a project row with no name, or a row the last read did not return. It counts towards no project, group or application limit and cannot be mapped here; it is still counted tenant wide.",
    });
  }
  if (rows.length === 0) return null;
  return (
    <div className="mb-6">
      <Card
        title="Usage counted towards no limit"
        description="From the latest readings. Shown so nothing is dropped silently."
        actions={
          isAdmin && (
            <Link to="/settings/attribution#unmatched" className="text-xs underline">
              Map under Settings → Attribution
            </Link>
          )
        }
      >
        <ul className="flex flex-col gap-3">
          {rows.map((row) => {
            const share = Number(row.total) > 0 ? (Number(row.credits) / Number(row.total)) * 100 : null;
            return (
              <li key={row.key} className="text-[13px]">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="font-medium">
                    {row.key === "unreported"
                      ? row.label
                      : `${formatNumber(row.count)} ${row.label.toLowerCase()}`}
                  </span>
                  <span className="tabular" style={{ color: "var(--text-secondary)" }}>
                    {formatCredits(row.credits)} credits
                    {share !== null && ` (${formatPercent(share)} of ${formatCredits(row.total)})`}
                  </span>
                </div>
                <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                  {row.note}
                </p>
              </li>
            );
          })}
        </ul>
      </Card>
    </div>
  );
}

function PoolFigure({
  label,
  value,
  tone = "neutral",
}: {
  label: string;
  value: string;
  tone?: "neutral" | "critical";
}) {
  return (
    <div>
      <div className="text-xs" style={{ color: "var(--text-muted)" }}>
        {label}
      </div>
      <div
        className="text-lg font-semibold tabular"
        style={{ color: tone === "critical" ? "var(--status-critical)" : "var(--text-primary)" }}
      >
        {value}
      </div>
    </div>
  );
}
