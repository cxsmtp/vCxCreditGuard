import { useCallback } from "react";
import { api } from "../api/client";
import type { BlastRadius, DryRunResult, DryRunRow, UserRolesPreview } from "../api/types";
import { ExportMenu } from "../components/ExportMenu";
import { StatTile } from "../components/StatTile";
import type { ExportColumn } from "../lib/export";
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  InfoNote,
  PageHeader,
  Spinner,
  Table,
  Td,
  Th,
  type BadgeTone,
} from "../components/ui";
import { FilterNote, Pager, usePaged, useTableView, type ViewColumn } from "../components/tableView";
import { useResource } from "../hooks/useResource";
import { entityLabel, formatCredits, formatDateTime, formatPercent } from "../lib/format";

const STATUS_TONE: Record<string, BadgeTone> = {
  ok: "good",
  warned: "warning",
  breached: "critical",
  restricted: "critical",
  restored: "good",
};

const DRY_RUN_VIEW: ViewColumn<DryRunRow>[] = [
  { key: "entity", value: (r) => r.entity_label ?? r.entity_id, filter: false },
  { key: "used", value: (r) => (r.usage_available ? Number(r.credits_used) : null), filter: false },
  { key: "pct", value: (r) => r.percent_used, filter: false },
  { key: "projected", value: (r) => r.projected_status },
  { key: "enforce", value: (r) => (r.would_enforce ? "Yes" : "No") },
];

export function PreviewPage() {
  const dryRun = useResource<DryRunResult>(
    (signal) => api.get("/api/preview/dry-run", undefined, signal),
    [],
  );

  const reload = useCallback(() => void dryRun.reload(), [dryRun]);
  const data = dryRun.data;
  const view = useTableView(data?.rows ?? [], DRY_RUN_VIEW);
  const paged = usePaged(view.rows, 100);

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
              rows={view.rows}
              columns={exportColumns}
              filenameBase="cxcreditguard-simulation"
              title="CxCreditGuard simulation"
            />
            <button
              type="button"
              onClick={reload}
              className="cg-btn sm"
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

          {data.user_roles_truncated && data.user_roles_note && (
            <InfoNote tone="warning">{data.user_roles_note}</InfoNote>
          )}

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
              <Table
                before={<FilterNote shown={view.rows.length} total={view.total} filtered={view.filtered} onClear={view.clearFilters} />}
                after={<Pager {...paged} noun="limits" />}
              >
                <thead>
                  <tr>
                    {view.th("entity", "Entity")}
                    {view.th("used", "Used / limit", "right")}
                    {view.th("pct", "%", "right")}
                    {view.th("projected", "Projected")}
                    {view.th("enforce", "Would enforce")}
                    <Th>Blast radius</Th>
                  </tr>
                </thead>
                <tbody>
                  {paged.rows.map((row) => (
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
                        {row.auto_triage_attributed && Number(row.auto_triage_attributed) > 0 && (
                          <p className="mt-0.5 text-xs" style={{ color: "var(--text-muted)" }}>
                            incl. {formatCredits(row.auto_triage_attributed)} auto triage from their scans
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
                      <Td>
                        {row.blast ? (
                          <>
                            <BlastSummary blast={row.blast} />
                            <BlastDetails blast={row.blast} />
                          </>
                        ) : (
                          <span className="text-xs" style={{ color: "var(--text-muted)" }}>—</span>
                        )}
                      </Td>
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
  if ((blast.disable_fusion ?? 0) > 0) parts.push(`${blast.disable_fusion} Fusion`);
  if ((blast.disable_repo_fusion ?? 0) > 0)
    parts.push(`${blast.disable_repo_fusion} repository Fusion`);
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

// A large group can have hundreds of projects with a warning: the first few
// are spelled out, the rest counted.
const WARNINGS_SHOWN = 10;

/** What each person would lose and keep, and where a project setting may not hold. */
export function BlastDetails({ blast }: { blast: BlastRadius }) {
  const users = blast.user_roles ?? [];
  const warnings = blast.warnings ?? [];
  if (blast.exempt || (users.length === 0 && warnings.length === 0)) return null;
  return (
    <div className="mt-1.5 flex max-w-md flex-col gap-1.5 text-xs">
      {users.map((user) => (
        <UserRolesDetail key={user.user_id} user={user} aiRoles={blast.ai_roles ?? []} />
      ))}
      {blast.user_roles_truncated && blast.user_roles_note && (
        <p style={{ color: "var(--text-muted)" }}>{blast.user_roles_note}</p>
      )}
      {warnings.slice(0, WARNINGS_SHOWN).map((warning) => (
        <p key={warning.project_id} style={{ color: "var(--status-warning)" }}>
          {warning.message}
        </p>
      ))}
      {(blast.warnings_total ?? warnings.length) > Math.min(warnings.length, WARNINGS_SHOWN) && (
        <p style={{ color: "var(--status-warning)" }}>
          …and {((blast.warnings_total ?? warnings.length) - Math.min(warnings.length, WARNINGS_SHOWN)).toLocaleString()}{" "}
          more projects where turning Auto Triage off may not hold.
        </p>
      )}
    </div>
  );
}

function UserRolesDetail({ user, aiRoles }: { user: UserRolesPreview; aiRoles: string[] }) {
  const name = user.user_label ?? user.user_id;
  if (!user.read) {
    return (
      <p style={{ color: "var(--text-secondary)" }}>
        {name}
        {user.already_restricted && (
          <>
            {" "}
            <Badge tone="neutral">already restricted</Badge>
          </>
        )}
        : {user.note ?? `would lose whichever of ${aiRoles.join(", ")} they hold directly.`}
      </p>
    );
  }
  return (
    <div style={{ color: "var(--text-secondary)" }}>
      <p style={{ color: "var(--text-primary)" }}>{name}</p>
      {user.removed.length > 0 ? (
        <ul className="ml-3 list-disc">
          {user.removed.map((role) => (
            <li key={role.name}>
              Loses <code>{role.name}</code>
              {role.description ? ` (${role.description})` : ""}
              {role.grants && role.grants.length > 0 && (
                <>, which also grants {role.grants.join(", ")}</>
              )}
              {role.grants === null && <>; what else it grants could not be read</>}
            </li>
          ))}
        </ul>
      ) : (
        <p>Holds none of the AI roles directly, so nothing would be removed.</p>
      )}
      {user.kept.length > 0 && (
        <ul className="ml-3 list-disc" style={{ color: "var(--status-warning)" }}>
          {user.kept.map((role) => (
            <li key={role.name}>
              Keeps <code>{role.name}</code> through {role.sources.join(" and ")}: removing the
              direct mapping does not take it away
            </li>
          ))}
        </ul>
      )}
      {user.note && <p style={{ color: "var(--text-muted)" }}>{user.note}</p>}
    </div>
  );
}
