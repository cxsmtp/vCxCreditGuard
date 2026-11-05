import { useState } from "react";
import { api } from "../api/client";
import type { Diagnostics, DiagnosticStatus } from "../api/types";
import { useResource } from "../hooks/useResource";
import { formatRelative } from "../lib/format";
import { Spinner, type BadgeTone } from "./ui";

const STATUS_TONE: Record<DiagnosticStatus, BadgeTone> = {
  ok: "good",
  warn: "warning",
  fail: "critical",
};

const STATUS_DOT: Record<DiagnosticStatus, string> = {
  ok: "var(--status-good)",
  warn: "var(--status-warning)",
  fail: "var(--status-critical)",
};

const OVERALL_LABEL: Record<DiagnosticStatus, string> = {
  ok: "All systems healthy",
  warn: "Needs attention",
  fail: "Action required",
};

/**
 * A self-diagnosis panel. Collapsed by default to a single status line; expand
 * it to see each check. Read-only, so it is safe for viewers too.
 */
export function DiagnosticsPanel() {
  const [open, setOpen] = useState(false);
  const diag = useResource<Diagnostics>(
    (signal) => api.get("/api/ops/diagnostics", undefined, signal),
    [],
  );
  const data = diag.data;
  const overall: DiagnosticStatus = data?.overall ?? "ok";

  return (
    <section
      className="rounded-lg border border-hairline"
      style={{ background: "var(--surface)" }}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-3 px-5 py-3 text-left"
        aria-expanded={open}
      >
        {diag.initialLoading ? (
          <Spinner size={14} />
        ) : (
          <span
            aria-hidden="true"
            className="inline-block size-2.5 rounded-full"
            style={{ background: diag.error ? "var(--text-muted)" : STATUS_DOT[overall] }}
          />
        )}
        <span className="text-sm font-medium">System health</span>
        <span className="text-xs" style={{ color: STATUS_TONE[overall] === "critical" ? "var(--status-critical)" : "var(--text-secondary)" }}>
          {diag.initialLoading ? "Checking…" : diag.error ? "Could not run checks" : OVERALL_LABEL[overall]}
        </span>
        <span className="ml-auto text-xs" style={{ color: "var(--text-muted)" }}>
          {open ? "Hide" : "Show"}
        </span>
      </button>

      {open && (
        <div className="border-t border-hairline px-5 py-4">
          {diag.error ? (
            <p className="text-sm" style={{ color: "var(--status-critical)" }}>
              {diag.error}
            </p>
          ) : !data ? (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Running checks…
            </p>
          ) : (
            <>
              <ul className="flex flex-col gap-3">
                {data.checks.map((check) => (
                  <li key={check.key} className="flex items-start gap-3">
                    <span
                      aria-hidden="true"
                      className="mt-1.5 inline-block size-2 shrink-0 rounded-full"
                      style={{ background: STATUS_DOT[check.status] }}
                    />
                    <div className="min-w-0">
                      <p className="text-sm font-medium">
                        {check.label}
                        <span
                          className="ml-2 text-xs font-normal uppercase"
                          style={{
                            color:
                              check.status === "fail"
                                ? "var(--status-critical)"
                                : check.status === "warn"
                                  ? "var(--text-primary)"
                                  : "var(--status-good-text)",
                          }}
                        >
                          {check.status}
                        </span>
                      </p>
                      <p className="mt-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                        {check.detail}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
              <div className="mt-4 flex items-center justify-between border-t border-hairline pt-3">
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Checked {formatRelative(data.generated_at)}
                </span>
                <button
                  type="button"
                  onClick={() => void diag.reload()}
                  className="text-xs underline"
                  style={{ color: "var(--text-secondary)" }}
                >
                  Re-run
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </section>
  );
}
