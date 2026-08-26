import { useMemo, useState } from "react";
import type { TrendPoint } from "../../api/types";
import { formatCredits, formatDateTime, formatTime } from "../../lib/format";
import { EmptyState, Table, Td, Th } from "../ui";

/**
 * Credits consumed between consecutive polls, over time.
 *
 * One series, so there is no legend: the title names it. The endpoint is directly
 * labelled and everything else is reachable through the crosshair tooltip and the
 * table view, so no value is tooltip-only.
 *
 * The plotted series is the delta rather than the cumulative figure Checkmarx
 * reports, because the cumulative curve over a sliding lookback window is close to
 * flat and says nothing useful. Two measures on one plot would need two y-scales,
 * which is never correct, so the cumulative figure lives in the table view instead.
 */

const HEIGHT = 220;
const X_AXIS_BAND = 28;
const PADDING = { top: 16, right: 56, bottom: X_AXIS_BAND, left: 44 };

interface Props {
  points: TrendPoint[];
}

export function TrendChart({ points }: Props) {
  const [showTable, setShowTable] = useState(false);
  const [hoverIndex, setHoverIndex] = useState<number | null>(null);
  const [width, setWidth] = useState(720);

  const series = useMemo(
    () =>
      points
        .filter((point) => point.delta_credits !== null)
        .map((point) => ({
          at: point.collected_at,
          value: Number(point.delta_credits),
          cumulative: Number(point.cumulative_credits),
        })),
    [points],
  );

  if (series.length < 2) {
    return (
      <EmptyState
        title="Not enough data for a trend yet"
        description="A trend needs at least two completed polls. Run a cycle from the Settings page, or wait for the scheduler."
      />
    );
  }

  const maxValue = Math.max(...series.map((point) => point.value), 1);
  const plotWidth = width - PADDING.left - PADDING.right;
  const plotHeight = HEIGHT - PADDING.top - PADDING.bottom;

  const xFor = (index: number) =>
    PADDING.left + (series.length === 1 ? 0 : (index / (series.length - 1)) * plotWidth);
  const yFor = (value: number) => PADDING.top + plotHeight - (value / maxValue) * plotHeight;

  const linePath = series
    .map((point, index) => `${index === 0 ? "M" : "L"}${xFor(index)},${yFor(point.value)}`)
    .join(" ");

  const ticks = [0, 0.5, 1].map((fraction) => ({
    value: maxValue * fraction,
    y: PADDING.top + plotHeight - fraction * plotHeight,
  }));

  const last = series[series.length - 1]!;
  const hovered = hoverIndex === null ? null : series[hoverIndex];

  const onPointerMove = (event: React.PointerEvent<SVGSVGElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const scale = bounds.width / width;
    const x = (event.clientX - bounds.left) / scale;
    const ratio = (x - PADDING.left) / plotWidth;
    const index = Math.round(ratio * (series.length - 1));
    setHoverIndex(Math.min(series.length - 1, Math.max(0, index)));
  };

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
          Credits consumed between polls. Peaks show when AI actions were actually run.
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
              <Th>Collected at</Th>
              <Th align="right">Consumed since previous poll</Th>
              <Th align="right">Reported total for the window</Th>
            </tr>
          </thead>
          <tbody>
            {[...series].reverse().map((point) => (
              <tr key={point.at}>
                <Td>{formatDateTime(point.at)}</Td>
                <Td align="right">{formatCredits(point.value)}</Td>
                <Td align="right">{formatCredits(point.cumulative)}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : (
        <div
          ref={(node) => {
            if (node && node.clientWidth && Math.abs(node.clientWidth - width) > 8) {
              setWidth(node.clientWidth);
            }
          }}
          className="relative"
        >
          <svg
            viewBox={`0 0 ${width} ${HEIGHT}`}
            width="100%"
            height={HEIGHT}
            role="img"
            aria-label="Credits consumed between polls over time"
            onPointerMove={onPointerMove}
            onPointerLeave={() => setHoverIndex(null)}
            style={{ touchAction: "none" }}
          >
            {/* Solid hairline gridlines, one shade off the surface. Never dashed. */}
            {ticks.map((tick) => (
              <g key={tick.y}>
                <line
                  x1={PADDING.left}
                  x2={width - PADDING.right}
                  y1={tick.y}
                  y2={tick.y}
                  stroke="var(--grid)"
                  strokeWidth={1}
                />
                <text
                  x={PADDING.left - 8}
                  y={tick.y + 4}
                  textAnchor="end"
                  fontSize={11}
                  fill="var(--text-muted)"
                  className="tabular"
                >
                  {formatCredits(Math.round(tick.value))}
                </text>
              </g>
            ))}

            <line
              x1={PADDING.left}
              x2={width - PADDING.right}
              y1={PADDING.top + plotHeight}
              y2={PADDING.top + plotHeight}
              stroke="var(--axis)"
              strokeWidth={1}
            />

            <path d={linePath} fill="none" stroke="var(--series-1)" strokeWidth={2} strokeLinejoin="round" />

            {hovered && hoverIndex !== null && (
              <>
                <line
                  x1={xFor(hoverIndex)}
                  x2={xFor(hoverIndex)}
                  y1={PADDING.top}
                  y2={PADDING.top + plotHeight}
                  stroke="var(--axis)"
                  strokeWidth={1}
                />
                {/* 2px surface ring so the marker reads against the line. */}
                <circle
                  cx={xFor(hoverIndex)}
                  cy={yFor(hovered.value)}
                  r={5}
                  fill="var(--series-1)"
                  stroke="var(--surface)"
                  strokeWidth={2}
                />
              </>
            )}

            {/* Selective direct label: the endpoint only. */}
            <circle
              cx={xFor(series.length - 1)}
              cy={yFor(last.value)}
              r={4}
              fill="var(--series-1)"
              stroke="var(--surface)"
              strokeWidth={2}
            />
            <text
              x={xFor(series.length - 1) + 8}
              y={yFor(last.value) + 4}
              fontSize={11}
              fill="var(--text-secondary)"
              className="tabular"
            >
              {formatCredits(last.value)}
            </text>

            <text x={PADDING.left} y={HEIGHT - 8} fontSize={11} fill="var(--text-muted)">
              {formatTime(series[0]!.at)}
            </text>
            <text
              x={width - PADDING.right}
              y={HEIGHT - 8}
              textAnchor="end"
              fontSize={11}
              fill="var(--text-muted)"
            >
              {formatTime(last.at)}
            </text>
          </svg>

          {hovered && (
            <div
              className="pointer-events-none absolute rounded-md border border-hairline px-2.5 py-1.5 text-xs shadow-lg"
              style={{
                background: "var(--surface-raised)",
                left: `${(xFor(hoverIndex!) / width) * 100}%`,
                top: 0,
                transform: "translate(-50%, -4px)",
              }}
            >
              <div className="font-medium">{formatCredits(hovered.value)} credits</div>
              <div style={{ color: "var(--text-secondary)" }}>{formatDateTime(hovered.at)}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
