import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type {
  KeyPermissionCheck,
  KeyPermissionReport,
  KeyPermissionsResponse,
  Me,
} from "../api/types";
import { formatDateTime } from "../lib/format";
import { useToast } from "../lib/ui-context";
import { Badge, Button, ErrorNote, InfoNote, Modal, Spinner, Table, Td, Th, type BadgeTone } from "./ui";

/**
 * What the stored Checkmarx API key may do: the banner on every page, the
 * pop-up after sign-in, and the table the Connection page shows.
 */

/**
 * True when something CreditGuard needs with the current setup is confirmed
 * missing: only then the banner, the admin pop-up, the top bar light and the
 * Command Center status show it. Other gaps (optional checks, features not in
 * use, a guess from the token's roles) are shown on the Connection page only.
 */
export function permissionProblem(me: Me): boolean {
  const permissions = me.key_permissions;
  if (!permissions) return false;
  const verdict = permissions.verdict;
  return permissions.attention === true && (verdict === "limited" || verdict === "insufficient");
}

const STATUS_TEXT: Record<string, [string, BadgeTone]> = {
  ok: ["Allowed", "good"],
  denied: ["Refused (403)", "critical"],
  not_found: ["Not found (404)", "warning"],
  error: ["Error", "warning"],
  skipped: ["Skipped", "neutral"],
  not_tested: ["Not tested", "neutral"],
};

function statusOf(check: KeyPermissionCheck): [string, BadgeTone] {
  if (check.runtime_denied_at) return ["Refused when used", "critical"];
  if (check.expectation === "will_fail") return ["Will fail", "critical"];
  if (check.expectation === "probably_denied") return ["Probably refused", "warning"];
  return STATUS_TEXT[check.status] ?? [check.status, "neutral"];
}

export function PermissionChecksTable({ report }: { report: KeyPermissionReport }) {
  return (
    <Table className="cg-perm-table">
      <thead>
        <tr>
          <Th>Capability</Th>
          <Th>Call</Th>
          <Th>Status</Th>
          <Th>If missing</Th>
        </tr>
      </thead>
      <tbody>
        {[...report.checks.filter((c) => c.problem), ...report.checks.filter((c) => !c.problem)].map((check) => {
          const [text, tone] = statusOf(check);
          return (
            <tr key={check.id} className={check.problem ? "cg-perm-problem" : undefined}>
              <Td>
                <span className="font-medium">{check.purpose}</span>
                <small className="block" style={{ color: "var(--text-muted)" }}>
                  {check.required_reason}
                </small>
              </Td>
              <Td>
                <code className="cg-perm-call">
                  {check.method} {check.path}
                </code>
              </Td>
              <Td>
                <Badge tone={tone}>{text}</Badge>
                {check.detail && (
                  <small className="mt-1 block" style={{ color: "var(--text-secondary)" }}>
                    {check.detail}
                  </small>
                )}
              </Td>
              <Td>
                <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {check.breaks}
                </span>
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

function Paragraphs({ lines }: { lines: string[] }) {
  return (
    <>
      {lines.map((line) => (
        <p key={line} className="text-sm" style={{ color: "var(--text-secondary)" }}>
          {line}
        </p>
      ))}
    </>
  );
}

/** Explanation, checks, roles and what to do. Admin details only when visible. */
export function PermissionDetails({ report, isAdmin }: { report: KeyPermissionReport; isAdmin: boolean }) {
  const problem = report.verdict === "limited" || report.verdict === "insufficient";
  return (
    <div className="flex flex-col gap-4">
      {problem ? (
        report.verdict === "insufficient" ? (
          <ErrorNote>{report.summary}</ErrorNote>
        ) : (
          <InfoNote tone="warning">{report.summary}</InfoNote>
        )
      ) : (
        <InfoNote tone={report.verdict === "ok" ? "good" : "neutral"}>{report.summary}</InfoNote>
      )}
      {report.explanation.why.length > 0 && (
        <section className="flex flex-col gap-2">
          <h3 className="cg-field-label">Why this happens</h3>
          <Paragraphs lines={report.explanation.why} />
        </section>
      )}
      {!report.details_visible && report.explanation.missing.length > 0 && (
        <section className="flex flex-col gap-1">
          <h3 className="cg-field-label">What stops working</h3>
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm" style={{ color: "var(--text-secondary)" }}>
            {report.explanation.missing.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      )}
      {report.details_visible && report.checks.length > 0 && (
        <section className="flex flex-col gap-2">
          <h3 className="cg-field-label">What was checked</h3>
          <PermissionChecksTable report={report} />
          {report.runtime_denials.some((entry) => !entry.check_id) && (
            <ul className="text-xs" style={{ color: "var(--text-secondary)" }}>
              {report.runtime_denials
                .filter((entry) => !entry.check_id)
                .map((entry) => (
                  <li key={`${entry.method} ${entry.path}`}>
                    Also refused when used: <code>{entry.method} {entry.path}</code> (
                    {entry.count}×, last {formatDateTime(entry.last_seen)})
                  </li>
                ))}
            </ul>
          )}
        </section>
      )}
      {report.details_visible && report.explanation.roles.length > 0 && (
        <details className="cg-perm-roles">
          <summary>What the key has now (roles in its access token)</summary>
          <ul className="mt-2 flex flex-col gap-1 text-xs" style={{ color: "var(--text-secondary)" }}>
            {report.explanation.roles.map((line) => (
              <li key={line} className="break-words">
                {line}
              </li>
            ))}
          </ul>
        </details>
      )}
      {problem && (
        <section className="flex flex-col gap-1">
          <h3 className="cg-field-label">What to do</h3>
          {isAdmin ? (
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm" style={{ color: "var(--text-secondary)" }}>
              {report.explanation.what_to_do.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          ) : (
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Ask a CreditGuard admin to replace the API key.
            </p>
          )}
        </section>
      )}
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        Last checked {formatDateTime(report.checked_at)}. Only read calls are tried; changes are
        confirmed the first time CreditGuard makes them.
      </p>
    </div>
  );
}

/** Fetches the report, and runs "Check again". */
export function useKeyPermissions(enabled: boolean) {
  const toast = useToast();
  const [report, setReport] = useState<KeyPermissionReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .get<KeyPermissionsResponse>("/api/connection/permissions", undefined, controller.signal)
      .then((response) => setReport(response.report))
      .catch((caught) => {
        if (!controller.signal.aborted) {
          setError(caught instanceof ApiError ? caught.message : "Could not load the report.");
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [enabled]);

  async function checkAgain(): Promise<KeyPermissionReport | null> {
    setChecking(true);
    setError(null);
    try {
      const response = await api.post<KeyPermissionsResponse>("/api/connection/permissions");
      setReport(response.report);
      if (response.report?.verdict === "ok") toast.success("The API key has every permission checked.");
      else if (response.report) toast.info(response.report.summary);
      return response.report;
    } catch (caught) {
      const message = caught instanceof ApiError ? caught.message : "The check could not run.";
      setError(message);
      toast.error(message);
      return null;
    } finally {
      setChecking(false);
    }
  }

  return { report, setReport, loading, checking, error, checkAgain };
}

/** The line under the top bar on every page while the key lacks something. */
export function PermissionBanner({ me, onOpen }: { me: Me; onOpen: () => void }) {
  if (!permissionProblem(me) || !me.key_permissions) return null;
  const insufficient = me.key_permissions.verdict === "insufficient";
  return (
    <div className={`cg-banner ${insufficient ? "bad" : ""}`} role={insufficient ? "alert" : "status"}>
      <span>
        <b>{me.key_permissions.summary}</b>
        {me.role !== "admin" && " Ask a CreditGuard admin to replace the API key."}
      </span>
      <button type="button" className="cg-banner-link" onClick={onOpen}>
        See what's missing
      </button>
    </div>
  );
}

const SEEN_KEY = "cxcg.keyPermissionsSeen";

function readSeen(): string | null {
  try {
    return window.sessionStorage.getItem(SEEN_KEY);
  } catch {
    return null;
  }
}

function writeSeen(value: string): void {
  try {
    window.sessionStorage.setItem(SEEN_KEY, value);
  } catch {
    // Without storage the pop-up may show again; it never blocks anything.
  }
}

export function forgetPermissionPopup(): void {
  try {
    window.sessionStorage.removeItem(SEEN_KEY);
  } catch {
    // Nothing to forget.
  }
}

/**
 * Shown to an admin once per sign-in session per distinct problem, and
 * whenever someone asks for it from the banner or the top bar light. It never
 * blocks anything: closing it is "Remind me later".
 */
export function PermissionPopup({
  me,
  open,
  onOpenChange,
  onChanged,
}: {
  me: Me;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onChanged: () => Promise<unknown> | void;
}) {
  const navigate = useNavigate();
  const isAdmin = me.role === "admin";
  const problemKey = permissionProblem(me) ? me.key_permissions?.problem_key ?? null : null;

  useEffect(() => {
    if (!isAdmin || !problemKey) return;
    if (readSeen() === problemKey) return;
    onOpenChange(true);
    // Only a new problem (or a new sign-in) opens it again.
  }, [isAdmin, problemKey, onOpenChange]);

  const { report, loading, checking, error, checkAgain } = useKeyPermissions(open);

  function close() {
    if (problemKey) writeSeen(problemKey);
    onOpenChange(false);
  }

  const footer = (
    <>
      <Button variant="ghost" onClick={close}>
        {isAdmin ? "Remind me later" : "Close"}
      </Button>
      {isAdmin && (
        <>
          <Button
            onClick={() => {
              close();
              navigate("/setup#key-permissions");
            }}
          >
            Open connection settings
          </Button>
          <Button
            variant="primary"
            loading={checking}
            onClick={async () => {
              const fresh = await checkAgain();
              await onChanged();
              if (fresh && fresh.verdict === "ok") onOpenChange(false);
            }}
          >
            Check again
          </Button>
        </>
      )}
    </>
  );

  return (
    <Modal
      open={open}
      title="The Checkmarx API key is missing permissions"
      description="CreditGuard keeps running. Only what is listed below is affected."
      onClose={close}
      footer={footer}
      width="max-w-4xl"
    >
      {loading && !report ? (
        <div className="flex items-center gap-2 text-sm" style={{ color: "var(--text-secondary)" }}>
          <Spinner /> Loading the last check
        </div>
      ) : error && !report ? (
        <ErrorNote>{error}</ErrorNote>
      ) : report ? (
        <PermissionDetails report={report} isAdmin={isAdmin} />
      ) : (
        <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
          No permission check has run for this key yet.{" "}
          {isAdmin && <Link to="/setup#key-permissions">Open connection settings</Link>}
        </p>
      )}
    </Modal>
  );
}
