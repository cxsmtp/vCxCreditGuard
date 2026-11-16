import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/**
 * A key figure. The number is the chart, so there is no plot and no hover layer.
 * Any tone is paired with a word in the label or detail, never colour alone.
 */

export type TileTone = "neutral" | "good" | "warning" | "critical";

const TONE_DOT: Record<TileTone, string> = {
  neutral: "var(--axis)",
  good: "var(--status-good)",
  warning: "var(--status-warning)",
  critical: "var(--status-critical)",
};

export function StatTile({
  label,
  value,
  unit,
  detail,
  tone = "neutral",
  to,
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  detail?: ReactNode;
  tone?: TileTone;
  to?: string;
}) {
  const content = (
    <>
      <div className="cg-kpi-label">
        <span
          aria-hidden="true"
          className="inline-block size-1.5 rounded-full"
          style={{ background: TONE_DOT[tone] }}
        />
        {label}
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className="cg-kpi-value">{value}</span>
        {unit && (
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            {unit}
          </span>
        )}
      </div>
      {detail && <p className="cg-kpi-detail">{detail}</p>}
    </>
  );

  const className = `cg-kpi tone-${tone}`;
  if (to) {
    return (
      <Link to={to} className={className}>
        {content}
      </Link>
    );
  }
  return <div className={className}>{content}</div>;
}
