import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { CycleRun, Dashboard, UnresolvedSubject } from "../api/types";
import { BarList } from "../components/charts/BarList";
import { BreakdownChart } from "../components/charts/BreakdownChart";
import { TrendChart } from "../components/charts/TrendChart";
import { StatTile } from "../components/StatTile";
import { Button, Card, ErrorNote, InfoNote, PageHeader, Spinner, Tabs } from "../components/ui";
import { useInterval, useResource } from "../hooks/useResource";
import { formatCredits, formatDateTime, formatNumber, formatRelative } from "../lib/format";
import { useToast } from "../lib/ui-context";

type ConsumerTab = "users" | "projects" | "groups" | "applications";

export function DashboardPage({ isAdmin }: { isAdmin: boolean }) {
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
          `Cycle finished with status ${result.status}. ${result.errors.join("; ") || "See the notifications."}`,
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
  const unmatched = (unresolved.data ?? []).filter(
    (row) => !row.counts_towards_user_id && !row.is_bot,
  );

  const consumers = {
    users: data.top_users,
    projects: data.top_projects,
    groups: data.top_groups,
    applications: data.top_applications,
  } as const;

  return (
    <div className={dashboard.loading ? "opacity-70 transition-opacity" : "transition-opacity"}>
      <PageHeader
        title="Dashboard"
        description={
          <>
            Credit consumption for the {data.lookback_window.replace(/_/g, " ")} window as Checkmarx
            reports it. Budget periods are measured from a baseline taken when each period opened,
            which is what the Limits page shows.
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

      {unmatched.length > 0 && (
        <div className="mb-5">
          <InfoNote tone="warning">
            {formatNumber(unmatched.length)} consumption{" "}
            {unmatched.length === 1 ? "row" : "rows"} could not be matched to a Checkmarx user, so{" "}
            {formatCredits(
              unmatched.reduce((sum, row) => sum + Number(row.credits_used), 0),
            )}{" "}
            credits are not counted towards any user limit.{" "}
            <Link to="/settings#attribution" className="underline">
              Map them on the Settings page
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
            data.collected_at ? `Collected ${formatRelative(data.collected_at)}` : "No poll yet"
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

      <div className="grid gap-6 lg:grid-cols-3">
        <Card
          title="Credits consumed over time"
          description="Difference between consecutive polls"
          className="lg:col-span-2"
        >
          <TrendChart points={data.trend} />
        </Card>

        <Card title="By action type" description="What the credits were spent on">
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
