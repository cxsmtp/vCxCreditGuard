import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { EnforcementCoverage } from "../api/types";
import { useResource } from "../hooks/useResource";
import { formatNumber, formatRelative } from "../lib/format";
import { useToast } from "../lib/ui-context";
import { Badge, Button, Card, InfoNote, Spinner } from "./ui";

/**
 * Whether a user restriction can bite on this tenant: of the users who hold an
 * AI role, how many a restriction could take AI access from, how many keep it
 * through a composite role or a group, and how many are protected. Read only;
 * the role list is never changed from here.
 */
export function CoveragePanel({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const [refreshing, setRefreshing] = useState(false);
  const coverage = useResource<EnforcementCoverage | null>(
    (signal) =>
      isAdmin ? api.get("/api/preview/coverage", undefined, signal) : Promise.resolve(null),
    [isAdmin],
  );

  if (!isAdmin) return null;

  async function refresh() {
    setRefreshing(true);
    try {
      await api.get("/api/preview/coverage", { refresh: true });
      await coverage.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not check the coverage.");
    } finally {
      setRefreshing(false);
    }
  }

  const data = coverage.data;
  const percent = data?.share === null || data?.share === undefined ? null : Math.round(data.share * 100);

  return (
    <Card
      title="Enforcement coverage"
      description="Whether a user budget can actually take AI access away. A restriction removes the AI roles mapped to the user directly; it cannot take a role held through a composite role or a group, and never touches someone holding a protected role."
      actions={
        <Button variant="secondary" onClick={refresh} loading={refreshing}>
          Check again
        </Button>
      }
    >
      <div id="enforcement-coverage" />
      {coverage.initialLoading ? (
        <Spinner />
      ) : !data ? (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          Not checked yet.
        </p>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Figure
              label="A user restriction can reach"
              value={
                data.determined === false
                  ? "Not determined"
                  : `${formatNumber(data.restrictable)} of ${formatNumber(data.ai_holders - data.unknown)}`
              }
              detail={
                data.determined === false
                  ? "Their roles could not be read"
                  : percent === null
                    ? "No one holds an AI role"
                    : `${percent}% of AI-role holders whose roles were read`
              }
              tone={data.low ? "critical" : "neutral"}
            />
            <Figure
              label="Keep AI through a composite or group"
              value={formatNumber(data.via_composite_or_group)}
              detail={`${formatNumber(data.via_composite)} composite, ${formatNumber(data.via_group)} group`}
            />
            <Figure
              label="Protected (never restricted)"
              value={formatNumber(data.protected)}
              detail={data.protected_roles.join(", ") || "No protected roles"}
            />
            <Figure
              label="Could not be read"
              value={formatNumber(data.unknown)}
              detail="Sources unknown; left out of the share"
            />
          </div>

          {data.determined === false ? (
            <InfoNote tone="info">
              {data.undetermined ?? "Whether user budgets can bite could not be determined."}
            </InfoNote>
          ) : data.warning ? (
            <InfoNote tone="warning">{data.warning}</InfoNote>
          ) : (
            <InfoNote tone="info">
              A user restriction can take AI access from most of the people who have it.
            </InfoNote>
          )}

          {Object.keys(data.composites).length > 0 && (
            <div className="mt-4 text-xs" style={{ color: "var(--text-secondary)" }}>
              <div className="mb-1 font-medium" style={{ color: "var(--text-primary)" }}>
                Composite roles that contain an AI role
              </div>
              <ul className="flex flex-col gap-1">
                {Object.entries(data.composites).map(([name, roles]) => (
                  <li key={name}>
                    <Badge tone={data.protected_roles.includes(name) ? "serious" : "neutral"}>{name}</Badge>{" "}
                    held by {formatNumber(data.composite_holders[name] ?? 0)}, contains {roles.join(", ")}
                    {data.protected_roles.includes(name) && " (protected)"}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {data.groups_granting.length > 0 && (
            <p className="mt-3 text-xs" style={{ color: "var(--text-secondary)" }}>
              Groups that grant an AI role: {data.groups_granting.join(", ")}.
            </p>
          )}
          {data.dedicated_roles.length > 0 && (
            <p className="mt-3 text-xs" style={{ color: "var(--text-secondary)" }}>
              Roles on this tenant that look dedicated to AI features:{" "}
              {data.dedicated_roles.join(", ")}. The roles a restriction removes are{" "}
              {data.ai_roles.join(", ")} (Settings → Enforcement). CreditGuard never changes that list
              itself.
            </p>
          )}
          {data.notes.map((note) => (
            <p key={note} className="mt-2 text-xs" style={{ color: "var(--text-muted)" }}>
              {note}
            </p>
          ))}
          <p className="mt-3 text-xs" style={{ color: "var(--text-muted)" }}>
            Checked {formatRelative(data.computed_at)} from the synced users' roles and groups and the
            tenant's composite roles.
          </p>
        </>
      )}
    </Card>
  );
}

function Figure({
  label,
  value,
  detail,
  tone = "neutral",
}: {
  label: string;
  value: string;
  detail: string;
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
      <div className="text-xs" style={{ color: "var(--text-muted)" }}>
        {detail}
      </div>
    </div>
  );
}
