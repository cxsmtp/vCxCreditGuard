import { useCallback } from "react";
import { api } from "../api/client";
import type { BlastRadius, DryRunResult, DryRunRow } from "../api/types";
import { ExportMenu } from "../components/ExportMenu";
import { StatTile } from "../components/StatTile";
import type { ExportColumn } from "../lib/export";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  PageHeader,
  Spinner,
  Table,
  Td,
  Th,
  type BadgeTone,
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { entityLabel, formatCredits, formatDateTime, formatPercent } from "../lib/format";

const STATUS_TONE: Record<string, BadgeTone> = {
  ok: "good",
  warned: "warning",
  breached: "critical",
  restricted: "critical",
  restored: "good",
};

export function PreviewPage() {
  const dryRun = useResource<DryRunResult>(
    (signal) => api.get("/api/preview/dry-run", undefined, signal),
    [],
  );

  const reload = useCallback(() => void dryRun.reload(), [dryRun]);
  const data = dryRun.data;
  const rows = data?.rows ?? [];

  const exportColumns: ExportColumn<DryRunRow>[] = [
    { key: "entity", header: "Entity", value: (r) => r.entity_label ?? r.entity_id },
    { key: "type", header: "Level", value: (r) => r.entity_type },
    {
      key: "used",
      header: "Credits used",
      value: (r) => (r.usage_available ? Number(r.credits_used) : ""),
    },
    { key: "limit", header: "Credit limit", value: (r) => r.credit_limit },
    { key: "percent", header: "Percent used", value: (r) => (r.percent_used == null ? "" : r.percent_used.toFixed(1)) },
    { key: "status", header: "Projected status", value: (r) => r.projected_status },
    { key: "enforce", header: "Would enforce", value: (r) => (r.would_enforce ? "yes" : "no") },
    { key: "projects", header: "Projects affected", value: (r) => r.blast?.affected_projects ?? 0 },
    { key: "users", header: "Users affected", value: (r) => r.blast?.affected_users ?? 0 },
    { key: "note", header: "Note", value: (r) => r.note ?? "" },
  ];

  return (
    <div>
      <PageHeader
        title="Simulation"
        description="A dry run of the next governance cycle against the usage on hand. Nothing here is applied: it shows what would warn, breach and (for enforced limits) be restricted, so you can see the blast radius before it happens."
        actions={
          <>
            <ExportMenu
              rows={rows}
              columns={exportColumns}
              filenameBase="cxcreditguard-simulation"
              title="CxCreditGuard simulation"
            />
            <button
              type="button"
              onClick={reload}
              className="rounded-md border border-hairline px-3 py-1.5 text-sm"
            >
              Refresh
            </button>
          </>
        }
      />

      {dryRun.initialLoading ? (
        <div className="flex items-center gap-2 py-16" style={{ color: "var(--text-secondary)" }}>
          <Spinner /> Running the simulation
        </div>
      ) : dryRun.error ? (
        <ErrorNote>{dryRun.error}</ErrorNote>
      ) : !data ? (
        <ErrorNote>The simulation could not be run.</ErrorNote>
      ) : (
        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Would enforce" value={String(data.would_enforce_count)} tone={data.would_enforce_count > 0 ? "critical" : "neutral"} />
            <StatTile label="Would warn" value={String(data.would_warn_count)} tone={data.would_warn_count > 0 ? "warning" : "neutral"} />
            <StatTile label="Projects affected" value={String(data.affected_projects)} />
            <StatTile label="Users affected" value={String(data.affected_users)} />
          </div>

          <Card
            title="Per-limit projection"
            description={`Generated ${formatDateTime(data.generated_at)}. Sorted so anything that would enforce is at the top.`}
            padded={false}
          >
            {data.rows.length === 0 ? (
              <EmptyState
                title="No active limits"
                description="There are no active limits to simulate yet."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Entity</Th>
                    <Th align="right">Used / limit</Th>
                    <Th align="right">%</Th>
                    <Th>Projected</Th>
                    <Th>Would enforce</Th>
                    <Th>Blast radius</Th>
                  </tr>
                </thead>
                <tbody>
                  {data.rows.map((row) => (
                    <tr key={row.limit_id}>
                      <Td>
                        <span className="font-medium">{row.entity_label ?? row.entity_id}</span>
                        <span className="ml-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
                          {entityLabel(row.entity_type)}
                        </span>
                        {row.note && (
                          <p className="mt-0.5 max-w-sm text-xs" style={{ color: "var(--text-secondary)" }}>
                            {row.note}
                          </p>
                        )}
                      </Td>
                      <Td align="right" className="tabular">
                        {row.usage_available
                          ? `${formatCredits(row.credits_used)} / ${formatCredits(row.credit_limit)}`
                          : "—"}
                      </Td>
                      <Td align="right" className="tabular">
                        {formatPercent(row.percent_used) || "—"}
                      </Td>
                      <Td>
                        <Badge tone={STATUS_TONE[row.projected_status] ?? "neutral"}>
                          {row.projected_status}
                        </Badge>
                      </Td>
                      <Td>
                        {row.would_enforce ? (
                          <Badge tone="critical">Yes</Badge>
                        ) : (
                          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                            No
                          </span>
                        )}
                      </Td>
                      <Td>{row.blast ? <BlastSummary blast={row.blast} /> : <span className="text-xs" style={{ color: "var(--text-muted)" }}>—</span>}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

export function BlastSummary({ blast }: { blast: BlastRadius }) {
  if (blast.exempt) {
    return (
      <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Exempt — nothing restricted
      </span>
    );
  }
  if (blast.total_actions === 0) {
    return (
      <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
        Nothing to restrict
      </span>
    );
  }
  const parts: string[] = [];
  if (blast.remove_user_roles > 0) parts.push(`${blast.remove_user_roles} user`);
  if (blast.disable_auto_triage > 0) parts.push(`${blast.disable_auto_triage} Auto Triage`);
  if (blast.disable_pr_remediation > 0) parts.push(`${blast.disable_pr_remediation} PR remediation`);
  return (
    <span className="text-xs" style={{ color: "var(--text-primary)" }}>
      {parts.join(", ")}
      {blast.affected_projects > 0 && (
        <span style={{ color: "var(--text-muted)" }}>
          {" "}
          across {blast.affected_projects} {blast.affected_projects === 1 ? "project" : "projects"}
        </span>
      )}
    </span>
  );
}
