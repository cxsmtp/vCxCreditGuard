import { useState } from "react";
import type { ActionBreakdownItem } from "../../api/types";
import { actionLabel, formatCredits, formatNumber, formatPercent } from "../../lib/format";
import { EmptyState, Table, Td, Th } from "../ui";

/**
 * Credits by action type.
 *
 * A horizontal bar chart, not a pie: these values are often close together and a
 * pie would make them indistinguishable. Colour carries identity here, so hues are
 * assigned from the validated categorical palette in a fixed order keyed by action
 * type. That order never changes with rank, so "AI Triage is blue" stays true when
 * the ranking moves.
 *
 * Three light-mode series colours sit below 3:1 against the surface, which is why
 * every bar is directly labelled and a table view is always one click away.
 */

// Fixed slot per action type, so colour follows the entity rather than its rank.
const ACTION_SLOTS: Record<string, string> = {
  triage: "var(--series-1)",
  remediation: "var(--series-2)",
  auto_triage: "var(--series-3)",
  dast_correlation: "var(--series-4)",
  fusion: "var(--series-5)",
  unknown: "var(--series-6)",
};
const FALLBACK_SLOTS = [
  "var(--series-1)",
  "var(--series-2)",
  "var(--series-3)",
  "var(--series-4)",
  "var(--series-5)",
  "var(--series-6)",
];
const MAX_SERIES = 6;

function colorFor(actionType: string, index: number): string {
  return ACTION_SLOTS[actionType] ?? FALLBACK_SLOTS[index % FALLBACK_SLOTS.length]!;
}

interface Props {
  items: ActionBreakdownItem[];
  /** True when the API reported transactions but no per action credit split. */
  creditsUnavailable?: boolean;
}

export function BreakdownChart({ items }: Props) {
  const [showTable, setShowTable] = useState(false);
  const [hovered, setHovered] = useState<string | null>(null);

  if (items.length === 0) {
    return (
      <EmptyState
        title="No consumption recorded yet"
        description="Once a cycle has polled Checkmarx, the split by action type appears here."
      />
    );
  }

  // Past six categories, the tail folds into "Other" rather than generating a hue.
  const sorted = [...items].sort((a, b) => Number(b.credits) - Number(a.credits));
  const head = sorted.slice(0, MAX_SERIES);
  const tail = sorted.slice(MAX_SERIES);
  const rows =
    tail.length > 0
      ? [
          ...head,
          {
            action_type: "other",
            credits: String(tail.reduce((sum, item) => sum + Number(item.credits), 0)),
            transactions: tail.reduce((sum, item) => sum + (item.transactions ?? 0), 0),
            percent_of_total: tail.reduce((sum, item) => sum + (item.percent_of_total ?? 0), 0),
          } satisfies ActionBreakdownItem,
        ]
      : head;

  const usesCredits = rows.some((row) => Number(row.credits) > 0);
  const valueOf = (row: ActionBreakdownItem) =>
    usesCredits ? Number(row.credits) : (row.transactions ?? 0);
  const maxValue = Math.max(...rows.map(valueOf), 1);

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
          {usesCredits
            ? "Credits by action type for the reported window."
            : "Actions by type. Checkmarx reports one credit figure per user rather than per action, so this view counts actions."}
        </p>
        <button
          type="button"
          className="text-xs underline"
          style={{ color: "var(--text-secondary)" }}
          onClick={() => setShowTable((value) => !value)}
        >
          {showTable ? "Show chart" : "Show table"}
        </button>
      </div>

      {showTable ? (
        <Table className="tabular">
          <thead>
            <tr>
              <Th>Action type</Th>
              <Th align="right">Credits</Th>
              <Th align="right">Actions</Th>
              <Th align="right">Share</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.action_type}>
                <Td>{row.action_type === "other" ? "Other" : actionLabel(row.action_type)}</Td>
                <Td align="right">{usesCredits ? formatCredits(row.credits) : ""}</Td>
                <Td align="right">{formatNumber(row.transactions)}</Td>
                <Td align="right">{formatPercent(row.percent_of_total, 1)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <>
          <ul className="flex flex-col gap-3">
            {rows.map((row, index) => {
              const value = valueOf(row);
              const share = (value / maxValue) * 100;
              const label = row.action_type === "other" ? "Other" : actionLabel(row.action_type);
              return (
                <li
                  key={row.action_type}
                  onPointerEnter={() => setHovered(row.action_type)}
                  onPointerLeave={() => setHovered(null)}
                  className="group"
                >
                  <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
                    <span className="flex min-w-0 items-center gap-2">
                      <span
                        aria-hidden="true"
                        className="inline-block size-2 shrink-0 rounded-sm"
                        style={{ background: colorFor(row.action_type, index) }}
                      />
                      <span className="truncate font-medium">{label}</span>
                    </span>
                    {/* Direct label, always visible. This is the relief for the
                        light-mode contrast warning on some series colours. */}
                    <span className="tabular whitespace-nowrap" style={{ color: "var(--text-secondary)" }}>
                      {usesCredits ? `${formatCredits(value)} credits` : `${formatNumber(value)} actions`}
                      {row.percent_of_total ? ` (${formatPercent(row.percent_of_total, 1)})` : ""}
                    </span>
                  </div>
                  {/* Track plus a thin mark with 4px rounded data-end. */}
                  <div
                    className="h-2 w-full overflow-hidden rounded-sm"
                    style={{ background: "var(--hover)" }}
                    role="img"
                    aria-label={`${label}: ${formatCredits(value)}`}
                  >
                    <div
                      className="h-full transition-[width] duration-300"
                      style={{
                        width: `${Math.max(share, value > 0 ? 1.5 : 0)}%`,
                        background: colorFor(row.action_type, index),
                        borderTopRightRadius: 4,
                        borderBottomRightRadius: 4,
                        opacity: hovered && hovered !== row.action_type ? 0.55 : 1,
                      }}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
          {/* A legend is present for two or more series, and every series is also
              directly labelled above, so identity is never colour alone. */}
          {rows.length >= 2 && (
            <ul
              className="mt-4 flex flex-wrap gap-x-4 gap-y-1 border-t border-hairline pt-3 text-xs"
              style={{ color: "var(--text-secondary)" }}
            >
              {rows.map((row, index) => (
                <li key={row.action_type} className="flex items-center gap-1.5">
                  <span
                    aria-hidden="true"
                    className="inline-block size-2 rounded-sm"
                    style={{ background: colorFor(row.action_type, index) }}
                  />
                  {row.action_type === "other" ? "Other" : actionLabel(row.action_type)}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
