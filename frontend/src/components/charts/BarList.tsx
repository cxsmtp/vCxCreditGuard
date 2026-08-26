import { useState } from "react";
import { Link } from "react-router-dom";
import type { TopConsumer } from "../../api/types";
import { formatCredits, formatPercent } from "../../lib/format";
import { Badge, EmptyState, Table, Td, Th } from "../ui";

/**
 * Top consumers for one entity level.
 *
 * Identity is carried by the row label, not by colour, so every bar uses a single
 * hue (categorical slot 1). Colouring each bar darker-where-bigger would
 * double-encode the length as hue and burn the only free channel on information
 * the bar already shows.
 *
 * Where a limit is configured, a marker shows the threshold on the same axis, so
 * consumption and headroom are readable together without a second scale.
 */

interface Props {
  items: TopConsumer[];
  emptyTitle: string;
  emptyDescription?: string;
  /** Set when the tenant cannot report this dimension at all. */
  unavailable?: boolean;
}

export function BarList({ items, emptyTitle, emptyDescription, unavailable }: Props) {
  const [showTable, setShowTable] = useState(false);

  if (unavailable) {
    return (
      <EmptyState
        title="Not reported for this tenant"
        description="Checkmarx does not report consumption at this level here, so limits at this level are not evaluated. Nothing is assumed to be zero."
      />
    );
  }

  if (items.length === 0) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />;
  }

  const maxValue = Math.max(...items.map((item) => Number(item.credits)), 1);

  return (
    <div>
      <div className="mb-3 flex justify-end">
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
              <Th>Name</Th>
              <Th align="right">Credits in window</Th>
              <Th align="right">Share</Th>
              <Th align="right">Limit</Th>
              <Th align="right">Used this period</Th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.entity_type}-${item.entity_id ?? item.label}`}>
                <Td>{item.label}</Td>
                <Td align="right">{formatCredits(item.credits)}</Td>
                <Td align="right">{formatPercent(item.percent_of_total, 1)}</Td>
                <Td align="right">{item.limit === null ? "none" : formatCredits(item.limit)}</Td>
                <Td align="right">
                  {item.credits_used_in_period === null
                    ? ""
                    : formatCredits(item.credits_used_in_period)}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <ul className="flex flex-col gap-3.5">
          {items.map((item) => {
            const value = Number(item.credits);
            const share = (value / maxValue) * 100;
            const limitShare =
              item.limit && item.limit > 0 ? Math.min((item.limit / maxValue) * 100, 100) : null;
            return (
              <li key={`${item.entity_type}-${item.entity_id ?? item.label}`}>
                <div className="mb-1 flex items-baseline justify-between gap-3 text-xs">
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-medium" title={item.label}>
                      {item.entity_id ? (
                        <Link
                          to={`/limits?entity_type=${item.entity_type}&entity_id=${encodeURIComponent(item.entity_id)}`}
                          className="hover:underline"
                        >
                          {item.label}
                        </Link>
                      ) : (
                        item.label
                      )}
                    </span>
                    {!item.resolved && (
                      <Badge tone="warning">Not matched to a user</Badge>
                    )}
                    {item.status === "restricted" && <Badge tone="critical">Restricted</Badge>}
                    {item.status === "breached" && <Badge tone="critical">Over limit</Badge>}
                    {item.status === "warned" && <Badge tone="warning">Near limit</Badge>}
                  </span>
                  <span
                    className="tabular whitespace-nowrap"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    {formatCredits(value)}
                    {item.limit !== null && ` of ${formatCredits(item.limit)}`}
                  </span>
                </div>
                <div
                  className="relative h-2 w-full overflow-hidden rounded-sm"
                  style={{ background: "var(--hover)" }}
                  role="img"
                  aria-label={`${item.label}: ${formatCredits(value)} credits${
                    item.limit !== null ? ` against a limit of ${item.limit}` : ""
                  }`}
                >
                  <div
                    className="h-full transition-[width] duration-300"
                    style={{
                      width: `${Math.max(share, value > 0 ? 1.5 : 0)}%`,
                      background: "var(--series-1)",
                      borderTopRightRadius: 4,
                      borderBottomRightRadius: 4,
                    }}
                  />
                  {limitShare !== null && (
                    // Threshold marker on the same axis. 2px surface gap either
                    // side so it reads as a rule rather than as part of the bar.
                    <span
                      aria-hidden="true"
                      className="absolute top-0 h-full"
                      style={{
                        left: `calc(${limitShare}% - 1px)`,
                        width: 2,
                        background: "var(--status-critical)",
                        boxShadow: "0 0 0 2px var(--surface)",
                      }}
                    />
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
