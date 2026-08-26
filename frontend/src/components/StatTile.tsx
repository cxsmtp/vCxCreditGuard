import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/**
 * A stat tile. The number is the chart, so there is no plot and no hover layer.
 *
 * The value uses proportional figures on purpose: tabular figures make a large
 * standalone number look loose. Any tone is paired with a word, never colour alone.
 */

export type TileTone = "neutral" | "good" | "warning" | "critical";

const TONE_COLORS: Record<TileTone, string> = {
  neutral: "var(--text-primary)",
  good: "var(--status-good-text)",
  warning: "var(--text-primary)",
  critical: "var(--status-critical)",
};

const TONE_ACCENTS: Record<TileTone, string> = {
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
      <div className="flex items-center gap-2">
        <span
          aria-hidden="true"
          className="inline-block h-3 w-0.5 rounded-full"
          style={{ background: TONE_ACCENTS[tone] }}
        />
        <span className="text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
          {label}
        </span>
      </div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <span className="text-2xl leading-none font-semibold" style={{ color: TONE_COLORS[tone] }}>
          {value}
        </span>
        {unit && (
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            {unit}
          </span>
        )}
      </div>
      {detail && (
        <p className="mt-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
          {detail}
        </p>
      )}
    </>
  );

  const className =
    "block rounded-lg border border-hairline px-4 py-3.5 transition-colors" +
    (to ? " hover:border-hairline-strong" : "");

  if (to) {
    return (
      <Link to={to} className={className} style={{ background: "var(--surface)" }}>
        {content}
      </Link>
    );
  }
  return (
    <div className={className} style={{ background: "var(--surface)" }}>
      {content}
    </div>
  );
}
