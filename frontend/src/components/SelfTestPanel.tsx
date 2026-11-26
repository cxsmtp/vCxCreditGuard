import { useEffect, useState } from "react";
import { ApiError, api } from "../api/client";
import type {
  OrgEntity,
  SelfTestListing,
  SelfTestPlan,
  SelfTestProjectAction,
  SelfTestResult,
  SelfTestStatus,
  SelfTestTargetReport,
} from "../api/types";
import { useResource } from "../hooks/useResource";
import { formatDateTime, formatRelative } from "../lib/format";
import { useToast } from "../lib/ui-context";
import {
  Badge,
  type BadgeTone,
  Button,
  Card,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  Modal,
  Spinner,
  Table,
  Td,
  Th,
} from "./ui";

const STATUS_TONE: Record<SelfTestStatus, BadgeTone> = {
  running: "info",
  passed: "good",
  warning: "warning",
  failed: "serious",
  restore_failed: "critical",
  interrupted: "serious",
};

const STATUS_LABEL: Record<SelfTestStatus, string> = {
  running: "Running",
  passed: "Passed",
  warning: "Passed, with warnings",
  failed: "Failed",
  restore_failed: "Restore failed",
  interrupted: "Interrupted",
};

const ACTIONS: { key: SelfTestProjectAction; label: string }[] = [
  { key: "auto_triage", label: "Auto Triage" },
  { key: "pr_remediation", label: "PR triage and remediation" },
  { key: "fusion", label: "Fusion" },
];

/**
 * Settings → Enforcement → Run self-test. Restricts a chosen user and/or
 * project for real, through the code a budget breach uses, reads it back,
 * restores it and checks it reads exactly as before. Admins only.
 */
export function SelfTestPanel({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const listing = useResource<SelfTestListing | null>(
    (signal) =>
      isAdmin ? api.get("/api/settings/selftest", undefined, signal) : Promise.resolve(null),
    [isAdmin],
  );
  const [user, setUser] = useState<OrgEntity | null>(null);
  const [project, setProject] = useState<OrgEntity | null>(null);
  const [actions, setActions] = useState<SelfTestProjectAction[]>(ACTIONS.map((a) => a.key));
  const [plan, setPlan] = useState<SelfTestPlan | null>(null);
  const [checking, setChecking] = useState(false);
  const [running, setRunning] = useState(false);
  const [typedUser, setTypedUser] = useState("");
  const [typedProject, setTypedProject] = useState("");
  const [error, setError] = useState<{ message: string; problems: string[] } | null>(null);
  const [shown, setShown] = useState<SelfTestResult | null>(null);

  // A changed choice needs a fresh check.
  useEffect(() => {
    setPlan(null);
    setError(null);
  }, [user, project, actions]);

  if (!isAdmin) return null;

  const body = {
    user_id: user?.entity_id ?? null,
    project_id: project?.entity_id ?? null,
    project_actions: actions,
  };

  async function check() {
    setChecking(true);
    setError(null);
    try {
      const result = await api.post<SelfTestPlan>("/api/settings/selftest/check", body);
      setPlan(result);
      setTypedUser("");
      setTypedProject("");
    } catch (caught) {
      setError(describe(caught));
    } finally {
      setChecking(false);
    }
  }

  async function runTest() {
    if (!plan) return;
    setRunning(true);
    setError(null);
    try {
      const response = await api.post<{ result: SelfTestResult }>("/api/settings/selftest/run", {
        ...body,
        confirm_user: user ? typedUser : null,
        confirm_project: project ? typedProject : null,
      });
      setPlan(null);
      setShown(response.result);
      if (response.result.status === "restore_failed") {
        toast.error("The self-test could not restore its target. See the result.");
      } else {
        toast.success(`Self-test ${STATUS_LABEL[response.result.status].toLowerCase()}.`);
      }
      await listing.reload();
    } catch (caught) {
      setError(describe(caught));
      await listing.reload();
    } finally {
      setRunning(false);
    }
  }

  const confirmed =
    plan !== null &&
    plan.targets.every((target) =>
      (target.target_type === "user" ? typedUser : typedProject).trim() === target.label.trim(),
    );
  const data = listing.data;
  const results = data?.results ?? [];

  return (
    <Card
      title="Enforcement self-test"
      description="Proves on the tenant that a budget really restricts: the chosen user or project is restricted through the same code a budget breach uses, read back, restored from its snapshot and read back again. Usually a few seconds."
      help="Refused for a target that is restricted now, is covered by a budget near its limit, is exempt or protected (a protected role, or the API key's own account), or a project with a running scan. The restore always runs, even when a check fails. If the restore itself fails, the target stays a tracked restriction: you are told at once, and the next cycle retries the restore (Restore in the Notification Center does it now). Every step is in the audit log."
    >
      {data?.notes.map((note) => (
        <div key={note} className="mb-3">
          <InfoNote tone={data.demo ? "info" : "warning"}>{note}</InfoNote>
        </div>
      ))}
      {data?.running && (
        <div className="mb-3">
          <InfoNote tone="info">A self-test is running. Wait for it to finish.</InfoNote>
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <OrgPicker kind="user" selected={user} onSelect={setUser} />
        <div className="flex flex-col gap-3">
          <OrgPicker kind="project" selected={project} onSelect={setProject} />
          {project && (
            <div className="flex flex-wrap gap-3 text-sm">
              {ACTIONS.map((action) => (
                <label key={action.key} className="flex items-center gap-1.5">
                  <input
                    type="checkbox"
                    checked={actions.includes(action.key)}
                    onChange={(event) =>
                      setActions((previous) =>
                        event.target.checked
                          ? ACTIONS.map((a) => a.key).filter(
                              (key) => key === action.key || previous.includes(key),
                            )
                          : previous.filter((key) => key !== action.key),
                      )
                    }
                  />
                  {action.label}
                </label>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button
          variant="secondary"
          onClick={check}
          loading={checking}
          disabled={(!user && !project) || (project !== null && actions.length === 0)}
        >
          Check what it would change
        </Button>
      </div>

      {error && (
        <div className="mt-3">
          <ErrorNote>
            {error.message}
            {error.problems.length > 0 && (
              <ul className="mt-1 list-disc pl-5">
                {error.problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            )}
          </ErrorNote>
        </div>
      )}

      {plan && (
        <div className="mt-4 flex flex-col gap-3 rounded-md border border-hairline p-3">
          {plan.refusals.length > 0 ? (
            <ErrorNote>
              Refused. Nothing will be changed:
              <ul className="mt-1 list-disc pl-5">
                {plan.refusals.map((refusal) => (
                  <li key={`${refusal.target_id}-${refusal.code}`}>
                    {refusal.label ? `${refusal.label}: ` : ""}
                    {refusal.reason}
                  </li>
                ))}
              </ul>
            </ErrorNote>
          ) : plan.busy ? (
            <InfoNote tone="warning">Another self-test is running. Try again when it has finished.</InfoNote>
          ) : null}
          {plan.warnings.map((warning) => (
            <InfoNote key={warning} tone="warning">
              {warning}
            </InfoNote>
          ))}
          {plan.targets.map((target) => (
            <div key={target.target_id}>
              <p className="text-sm font-medium">
                What will change on the {target.target_type} {target.label}
              </p>
              <ul className="mt-1 list-disc pl-5 text-sm" style={{ color: "var(--text-secondary)" }}>
                {target.changes.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </div>
          ))}
          <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
            <span className="font-medium">For how long: </span>
            {plan.duration}
          </p>
          {plan.allowed && (
            <div className="grid gap-3 sm:grid-cols-2">
              {plan.targets.map((target) => (
                <Field
                  key={target.target_id}
                  label={`Type the ${target.target_type}'s name to confirm`}
                  hint={target.label}
                  fold={false}
                >
                  <Input
                    value={target.target_type === "user" ? typedUser : typedProject}
                    onChange={(event) =>
                      target.target_type === "user"
                        ? setTypedUser(event.target.value)
                        : setTypedProject(event.target.value)
                    }
                    placeholder={target.label}
                    spellCheck={false}
                    autoComplete="off"
                  />
                </Field>
              ))}
            </div>
          )}
          {plan.allowed && (
            <div>
              <Button variant="danger" onClick={runTest} loading={running} disabled={!confirmed}>
                Run self-test
              </Button>
            </div>
          )}
        </div>
      )}

      <div className="mt-6">
        <p className="text-sm font-medium">Last results</p>
        <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
          The last {data?.keep ?? 20} self-tests are kept. Open one for its steps and the
          per-setting diff.
        </p>
        {listing.initialLoading ? (
          <Spinner />
        ) : results.length === 0 ? (
          <p className="mt-2 text-sm" style={{ color: "var(--text-secondary)" }}>
            No self-test has run yet.
          </p>
        ) : (
          <div className="mt-2">
            <Table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Target</Th>
                  <Th>Result</Th>
                  <Th>By</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {results.map((row) => (
                  <tr key={row.id}>
                    <Td>
                      <span title={formatDateTime(row.started_at)}>{formatRelative(row.started_at)}</span>
                    </Td>
                    <Td>
                      {[row.user_label, row.project_label].filter(Boolean).join(", ") || "—"}
                      {row.demo && (
                        <span className="ml-2">
                          <Badge tone="info">Demo</Badge>
                        </span>
                      )}
                    </Td>
                    <Td>
                      <Badge tone={STATUS_TONE[row.status]}>{STATUS_LABEL[row.status]}</Badge>
                    </Td>
                    <Td>{row.actor_name ?? "—"}</Td>
                    <Td align="right">
                      <Button size="sm" variant="ghost" onClick={() => setShown(row)}>
                        Details
                      </Button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </div>

      <Modal
        open={shown !== null}
        title={shown ? `Self-test #${shown.id}: ${STATUS_LABEL[shown.status]}` : "Self-test"}
        description={shown?.summary ?? undefined}
        onClose={() => setShown(null)}
        width="max-w-4xl"
      >
        {shown && <ResultDetail result={shown} />}
      </Modal>
    </Card>
  );
}

function describe(caught: unknown): { message: string; problems: string[] } {
  if (caught instanceof ApiError) return { message: caught.message, problems: caught.problems };
  return { message: "The self-test could not be started.", problems: [] };
}

function OrgPicker({
  kind,
  selected,
  onSelect,
}: {
  kind: "user" | "project";
  selected: OrgEntity | null;
  onSelect: (entity: OrgEntity | null) => void;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OrgEntity[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (selected || !query.trim()) {
      setResults([]);
      return;
    }
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLoading(true);
      try {
        setResults(
          await api.get<OrgEntity[]>(
            "/api/org/entities",
            { entity_type: kind, q: query, limit: 10 },
            controller.signal,
          ),
        );
      } catch {
        if (!controller.signal.aborted) setResults([]);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 200);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [kind, query, selected]);

  const label = kind === "user" ? "User to test (optional)" : "Project to test (optional)";
  if (selected) {
    return (
      <Field label={label}>
        <div className="flex items-center justify-between gap-2 rounded-md border border-hairline px-3 py-2">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium">{selected.label}</p>
            {selected.secondary && (
              <p className="truncate text-xs" style={{ color: "var(--text-muted)" }}>
                {selected.secondary}
              </p>
            )}
          </div>
          <button
            type="button"
            className="shrink-0 text-xs underline"
            style={{ color: "var(--text-secondary)" }}
            onClick={() => {
              onSelect(null);
              setQuery("");
            }}
          >
            Change
          </button>
        </div>
      </Field>
    );
  }
  return (
    <Field label={label}>
      <div>
        <Input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={kind === "user" ? "Name or email" : "Project name"}
        />
        {(loading || results.length > 0) && (
          <ul className="mt-1 max-h-48 overflow-y-auto rounded-md border border-hairline">
            {loading && (
              <li className="px-3 py-2 text-xs" style={{ color: "var(--text-secondary)" }}>
                Searching…
              </li>
            )}
            {results.map((entity) => (
              <li key={entity.entity_id}>
                <button
                  type="button"
                  className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-sm"
                  style={{ borderTop: "1px solid var(--border)" }}
                  onClick={() => onSelect(entity)}
                >
                  <span className="truncate">{entity.label}</span>
                  <span className="flex shrink-0 gap-1">
                    {entity.has_limit && <Badge tone="info">Has a budget</Badge>}
                    {entity.is_exempt && <Badge tone="neutral">Exempt</Badge>}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Field>
  );
}

function ResultDetail({ result }: { result: SelfTestResult }) {
  const targets = result.result.targets ?? [];
  return (
    <div className="flex flex-col gap-4 text-sm">
      <p style={{ color: "var(--text-secondary)" }}>
        Started {formatDateTime(result.started_at)}
        {result.finished_at ? `, finished ${formatDateTime(result.finished_at)}` : ""}
        {result.actor_name ? ` by ${result.actor_name}` : ""}.
        {result.demo ? " Ran against the built-in demo tenant, not Checkmarx One." : ""}
      </p>
      {(result.result.notes ?? []).map((note) => (
        <InfoNote key={note} tone="warning">
          {note}
        </InfoNote>
      ))}
      {(result.result.warnings ?? []).map((warning) => (
        <InfoNote key={warning} tone="warning">
          {warning}
        </InfoNote>
      ))}
      {targets.length === 0 && <p>No target was tested.</p>}
      {targets.map((target) => (
        <TargetDetail key={`${target.target_type}-${target.target_id}`} target={target} />
      ))}
    </div>
  );
}

function TargetDetail({ target }: { target: SelfTestTargetReport }) {
  const held = target.restore.actions.filter((action) => action.held);
  return (
    <section className="flex flex-col gap-3 border-t border-hairline pt-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="font-medium">
          {target.target_type === "user" ? "User" : "Project"} {target.label}
        </p>
        <Badge tone={STATUS_TONE[target.status]}>{STATUS_LABEL[target.status]}</Badge>
        <span className="text-xs" style={{ color: "var(--text-muted)" }}>
          {(target.ms / 1000).toFixed(1)} s
        </span>
      </div>

      {target.status === "restore_failed" && (
        <ErrorNote>
          <strong>{target.label} may still be restricted.</strong> The restore failed or did not
          read back. It is a tracked restriction: the next cycle retries the restore, and Restore
          in the Notification Center does it now. If it keeps failing, put back exactly this in
          Checkmarx One:
          {held.map((action) => (
            <pre
              key={action.action_id}
              className="mt-2 overflow-x-auto whitespace-pre-wrap text-xs"
              style={{ fontFamily: "var(--font-mono, monospace)" }}
            >
              {action.kind}: {JSON.stringify(action.snapshot ?? {}, null, 2)}
            </pre>
          ))}
        </ErrorNote>
      )}
      {target.cannot_bite.length > 0 && (
        <InfoNote tone="warning">
          The restriction cannot bite:{" "}
          {target.cannot_bite.map((item) => `${item.role} (through ${item.via.join(", ")})`).join("; ")}.
        </InfoNote>
      )}
      {target.warnings
        .filter((warning) => !warning.startsWith("The restriction cannot bite"))
        .map((warning) => (
          <InfoNote key={warning} tone="warning">
            {warning}
          </InfoNote>
        ))}

      <Table>
        <thead>
          <tr>
            <Th>Step</Th>
            <Th>Result</Th>
            <Th align="right">Time</Th>
            <Th>Detail</Th>
          </tr>
        </thead>
        <tbody>
          {target.steps.map((step) => (
            <tr key={step.step}>
              <Td>{step.label}</Td>
              <Td>
                <Badge tone={step.ok ? "good" : "critical"}>{step.ok ? "Pass" : "Fail"}</Badge>
              </Td>
              <Td align="right" className="tabular">
                {step.ms} ms
              </Td>
              <Td>
                <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                  {step.detail}
                </span>
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>

      {target.settings.length > 0 && (
        <Table>
          <thead>
            <tr>
              <Th>Setting</Th>
              <Th>Before</Th>
              <Th>Restricted</Th>
              <Th>Restored</Th>
              <Th>Same as before</Th>
            </tr>
          </thead>
          <tbody>
            {target.settings.map((row) => (
              <tr key={row.setting}>
                <Td>{row.setting}</Td>
                <Td>
                  <Value value={row.before} />
                </Td>
                <Td>
                  <Value value={row.restricted} highlight={row.changed} />
                </Td>
                <Td>
                  <Value value={row.restored} />
                </Td>
                <Td>
                  <Badge tone={row.restored_equal ? "good" : "critical"}>
                    {row.restored_equal ? "Yes" : "No"}
                  </Badge>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  );
}

function Value({ value, highlight = false }: { value: unknown; highlight?: boolean }) {
  let text: string;
  if (Array.isArray(value)) text = value.length ? value.join(", ") : "none";
  else if (typeof value === "boolean") text = value ? "true" : "false";
  else if (value === null || value === undefined) text = "—";
  else if (typeof value === "object") text = JSON.stringify(value);
  else text = String(value);
  return (
    <span
      className="block max-w-xs break-words text-xs"
      style={{ fontWeight: highlight ? 600 : undefined, color: highlight ? "var(--text-primary)" : undefined }}
    >
      {text}
    </span>
  );
}
