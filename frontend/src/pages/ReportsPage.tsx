import { useCallback, useState } from "react";
import { api, ApiError } from "../api/client";
import type { Chargeback, ChargebackRow, Projection, ReportSummary } from "../api/types";
import { ExportMenu } from "../components/ExportMenu";
import { StatTile } from "../components/StatTile";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  PageHeader,
  Spinner,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import type { ExportColumn } from "../lib/export";
import { entityLabel, formatCredits, formatDate, formatDateTime } from "../lib/format";
import { useToast } from "../lib/ui-context";

const PROJECTION_COLUMNS: ExportColumn<Projection>[] = [
  { key: "entity", header: "Entity", value: (p) => p.entity_label ?? p.entity_id },
  { key: "type", header: "Level", value: (p) => p.entity_type },
  { key: "used", header: "Credits used", value: (p) => Number(p.credits_used) },
  { key: "limit", header: "Credit limit", value: (p) => p.credit_limit },
  { key: "burn", header: "Burn / day", value: (p) => Number(p.burn_per_day).toFixed(1) },
  { key: "projected", header: "Projected period end", value: (p) => Number(p.projected_period_end).toFixed(0) },
  { key: "percent", header: "% at period end", value: (p) => (p.percent_at_period_end == null ? "" : p.percent_at_period_end.toFixed(0)) },
  { key: "exhausts", header: "Exhausts", value: (p) => p.exhaustion_at ?? "" },
  { key: "breach", header: "Will breach", value: (p) => (p.will_breach ? "yes" : "no") },
];

export function ReportsPage({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const report = useResource<ReportSummary>(
    (signal) => api.get("/api/reports/summary", undefined, signal),
    [],
  );
  const chargeback = useResource<Chargeback>(
    (signal) => api.get("/api/reports/chargeback", undefined, signal),
    [],
  );
  const [emailing, setEmailing] = useState(false);

  const emailNow = useCallback(async () => {
    setEmailing(true);
    try {
      const result = await api.post<{ sent: boolean; recipients: number }>("/api/reports/email");
      if (result.sent) toast.success(`Report emailed to ${result.recipients} recipient(s).`);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "The report could not be emailed.");
    } finally {
      setEmailing(false);
    }
  }, [toast]);

  const data = report.data;
  const projections = data?.projections ?? [];

  return (
    <div>
      <PageHeader
        title="Reports"
        description="A forward look at where each budget lands this period, the impact governance is having right now, and a report you can export or email."
        actions={
          <>
            <ExportMenu
              rows={projections}
              columns={PROJECTION_COLUMNS}
              filenameBase="cxcreditguard-projection"
              title="CxCreditGuard projection"
            />
            {isAdmin && (
              <Button size="sm" onClick={emailNow} loading={emailing}>
                Email report
              </Button>
            )}
          </>
        }
      />

      {report.initialLoading ? (
        <div className="flex items-center gap-2 py-16" style={{ color: "var(--text-secondary)" }}>
          <Spinner /> Building the report
        </div>
      ) : report.error ? (
        <ErrorNote>{report.error}</ErrorNote>
      ) : !data ? (
        <ErrorNote>The report could not be built.</ErrorNote>
      ) : (
        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile
              label="Active restrictions"
              value={String(data.impact.active_restrictions)}
              detail={`${data.impact.entities_restricted} entity(ies)`}
              tone={data.impact.active_restrictions > 0 ? "critical" : "neutral"}
            />
            <StatTile
              label="Credits over budget"
              value={formatCredits(data.impact.credits_over_budget)}
              detail="On enforced limits"
              tone={Number(data.impact.credits_over_budget) > 0 ? "warning" : "neutral"}
            />
            <StatTile
              label="Projected to breach"
              value={String(data.breaching_soon)}
              detail="This period, at current burn"
              tone={data.breaching_soon > 0 ? "warning" : "neutral"}
            />
            <StatTile
              label="Enforcing limits"
              value={`${data.limits_enforcing} / ${data.limits_total}`}
              detail="Enforce / total"
            />
          </div>

          {data.impact.monitor_only_breaches > 0 && (
            <Card>
              <p className="text-sm">
                {data.impact.monitor_only_breaches} monitor-only limit(s) are over budget but not
                restricting anything. Turn on enforcement from the Limits page if you want them to
                act.
              </p>
            </Card>
          )}

          <Card
            title="Forward projection"
            description={`Straight-line burn-rate estimate. Generated ${formatDateTime(data.generated_at)}.`}
            padded={false}
          >
            {projections.length === 0 ? (
              <EmptyState
                title="Nothing to project yet"
                description="Projections appear once limits have usage within an open budget period."
              />
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Entity</Th>
                    <Th align="right">Used / limit</Th>
                    <Th align="right">Burn / day</Th>
                    <Th align="right">Projected end</Th>
                    <Th>Exhausts</Th>
                    <Th>Outlook</Th>
                  </tr>
                </thead>
                <tbody>
                  {projections.map((p) => (
                    <tr key={p.limit_id}>
                      <Td>
                        <span className="font-medium">{p.entity_label ?? p.entity_id}</span>
                        <span className="ml-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
                          {entityLabel(p.entity_type)}
                        </span>
                      </Td>
                      <Td align="right" className="tabular">
                        {formatCredits(p.credits_used)} / {formatCredits(p.credit_limit)}
                      </Td>
                      <Td align="right" className="tabular">
                        {formatCredits(Number(p.burn_per_day).toFixed(1))}
                      </Td>
                      <Td align="right" className="tabular">
                        {formatCredits(Number(p.projected_period_end).toFixed(0))}
                        {p.percent_at_period_end != null && (
                          <span className="ml-1 text-xs" style={{ color: "var(--text-muted)" }}>
                            ({p.percent_at_period_end.toFixed(0)}%)
                          </span>
                        )}
                      </Td>
                      <Td className="whitespace-nowrap">
                        {p.exhaustion_at ? formatDate(p.exhaustion_at) : "—"}
                      </Td>
                      <Td>
                        {p.will_breach ? (
                          <Badge tone="critical">Will breach</Badge>
                        ) : (
                          <Badge tone="good">Within budget</Badge>
                        )}
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>

          <ChargebackCard data={chargeback.data} error={chargeback.error} loading={chargeback.initialLoading} />
        </div>
      )}
    </div>
  );
}

const CHARGEBACK_COLUMNS: ExportColumn<ChargebackRow>[] = [
  { key: "bu", header: "Business unit", value: (r) => r.business_unit },
  { key: "limits", header: "Limits", value: (r) => r.limits },
  { key: "credits", header: "Credits used", value: (r) => Number(r.credits_used) },
  { key: "cost", header: "Estimated cost", value: (r) => (r.estimated_cost == null ? "" : Number(r.estimated_cost)) },
];

function ChargebackCard({
  data,
  error,
  loading,
}: {
  data: Chargeback | null;
  error: string | null;
  loading: boolean;
}) {
  return (
    <Card
      title="Chargeback by business unit"
      description="Current-period consumption attributed to the business unit set on each limit."
      padded={false}
      actions={
        data && data.rows.length > 0 ? (
          <ExportMenu
            rows={data.rows}
            columns={CHARGEBACK_COLUMNS}
            filenameBase="cxcreditguard-chargeback"
            title="CxCreditGuard chargeback"
          />
        ) : undefined
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 px-5 py-6 text-sm" style={{ color: "var(--text-secondary)" }}>
          <Spinner size={14} /> Loading
        </div>
      ) : error ? (
        <div className="p-5">
          <ErrorNote>{error}</ErrorNote>
        </div>
      ) : !data || data.rows.length === 0 ? (
        <EmptyState
          title="No business units assigned"
          description="Set a business unit on a limit (on the Limits page) to attribute its consumption here."
        />
      ) : (
        <>
          <Table>
            <thead>
              <tr>
                <Th>Business unit</Th>
                <Th align="right">Limits</Th>
                <Th align="right">Credits used</Th>
                {data.currency_known && <Th align="right">Estimated cost</Th>}
              </tr>
            </thead>
            <tbody>
              {data.rows.map((row) => (
                <tr key={row.business_unit}>
                  <Td className="font-medium">{row.business_unit}</Td>
                  <Td align="right" className="tabular">{row.limits}</Td>
                  <Td align="right" className="tabular">{formatCredits(row.credits_used)}</Td>
                  {data.currency_known && (
                    <Td align="right" className="tabular">
                      {row.estimated_cost == null ? "—" : formatCredits(row.estimated_cost)}
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
          <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 text-xs" style={{ color: "var(--text-muted)" }}>
            <span>
              {data.currency_known
                ? `Estimated at ${data.unit_cost} per credit.`
                : "Set a credit unit cost on the Settings page to show an estimated cost."}
            </span>
            {data.unassigned_limits > 0 && (
              <span>
                {data.unassigned_limits} limit(s) have no business unit and are not attributed.
              </span>
            )}
          </div>
        </>
      )}
    </Card>
  );
}
