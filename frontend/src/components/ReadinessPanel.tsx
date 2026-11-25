import { useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { Readiness, ReadinessStatus } from "../api/types";
import { useResource } from "../hooks/useResource";
import { useToast } from "../lib/ui-context";
import { Button, Card, ErrorNote, InfoNote, Input, Spinner } from "./ui";

const DOT: Record<ReadinessStatus, string> = {
  green: "var(--status-good)",
  amber: "var(--status-warning)",
  red: "var(--status-critical)",
};

const WORD: Record<ReadinessStatus, string> = {
  green: "Ready",
  amber: "Pending",
  red: "Needs a fix",
};

const OVERRIDE_WORD = "ENFORCE";

/**
 * The onboarding readiness checklist. On a new install it gates leaving
 * watch-only: every item green, or an admin types ENFORCE (audited). On an
 * existing install, or once enforcement is on, it is information only.
 * Viewers see it; only admins act.
 */
export function ReadinessPanel({ isAdmin, compact = false }: { isAdmin: boolean; compact?: boolean }) {
  const toast = useToast();
  const readiness = useResource<Readiness>(
    (signal) => api.get("/api/readiness", undefined, signal),
    [],
  );
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const data = readiness.data;

  async function enable() {
    setBusy(true);
    setError(null);
    try {
      const body = data?.all_green ? {} : { confirm: typed };
      readiness.setData(await api.post<Readiness>("/api/readiness/enable", body));
      setTyped("");
      toast.success("Enforcement is on.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  const watching = data?.gate_active ?? false;
  const description = watching
    ? "This install watches only: it warns, but restricts nobody until every item is green (or an admin overrides)."
    : "For information: enforcement is not gated by this checklist here. An item that turns red later raises a warning.";

  return (
    <Card title="Readiness" description={compact ? undefined : description}>
      {readiness.initialLoading ? (
        <Spinner size={14} />
      ) : readiness.error || !data ? (
        <ErrorNote>{readiness.error ?? "Could not read the checklist."}</ErrorNote>
      ) : (
        <div className="flex flex-col gap-3">
          <ul className="flex flex-col gap-2">
            {data.items.map((item) => (
              <li key={item.key} className="flex items-start gap-3">
                <span
                  aria-hidden="true"
                  className="mt-1.5 inline-block size-2.5 shrink-0 rounded-full"
                  style={{ background: DOT[item.status] }}
                />
                <div className="min-w-0 text-sm">
                  <span className="font-medium">{item.label}</span>
                  <span className="ml-2 text-xs" style={{ color: "var(--text-muted)" }}>
                    {WORD[item.status]}
                  </span>
                  <div style={{ color: "var(--text-secondary)" }}>{item.detail}</div>
                  {item.status !== "green" && (
                    <div className="text-xs" style={{ color: "var(--text-muted)" }}>
                      {item.hint}{" "}
                      <Link to={item.link} className="underline">
                        Fix it
                      </Link>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
          {watching && isAdmin && (
            <div className="flex flex-col gap-2 border-t border-hairline pt-3">
              {data.all_green ? (
                <Button variant="primary" loading={busy} onClick={enable}>
                  Turn enforcement on
                </Button>
              ) : (
                <>
                  <InfoNote tone="warning">
                    Not every item is green. To turn enforcement on anyway, type {OVERRIDE_WORD}.
                    The override is audited with the items that were not green.
                  </InfoNote>
                  <div className="flex flex-wrap items-center gap-2">
                    <Input
                      aria-label={`Type ${OVERRIDE_WORD} to override`}
                      placeholder={OVERRIDE_WORD}
                      value={typed}
                      onChange={(event) => setTyped(event.target.value)}
                      className="max-w-40"
                    />
                    <Button
                      variant="danger"
                      loading={busy}
                      disabled={typed.trim() !== OVERRIDE_WORD}
                      onClick={enable}
                    >
                      Override and turn enforcement on
                    </Button>
                  </div>
                </>
              )}
              {error && <ErrorNote>{error}</ErrorNote>}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
