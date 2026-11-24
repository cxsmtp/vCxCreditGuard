import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../api/client";
import type { PolicyViolation, ViolationList, ViolationStatus } from "../api/types";
import {
  Badge,
  type BadgeTone,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
  Spinner,
  Table,
  Td,
  Textarea,
} from "../components/ui";
import { FilterNote, useTableView, type ViewColumn } from "../components/tableView";
import { useInterval, useResource } from "../hooks/useResource";
import { formatCredits, formatDateTime, formatRelative, humanise } from "../lib/format";
import { useToast } from "../lib/ui-context";

const STATUS_TONES: Record<ViolationStatus, BadgeTone> = {
  open: "critical",
  acknowledged: "warning",
  resolved: "good",
};

const KINDS = [
  { value: "", label: "Everything" },
  { value: "setting_reenabled", label: "Setting switched back on" },
  { value: "fusion_scan_during_restriction", label: "Fusion scan during a restriction" },
  { value: "ai_scan_during_restriction", label: "AI scan without Fusion" },
  { value: "usage_after_restriction", label: "Usage kept rising" },
];

function targetName(v: PolicyViolation): string {
  const kind = v.target_type === "cx_user" ? "User" : "Project";
  return `${kind} ${v.target_label ?? v.target_id}`;
}

const VIEW: ViewColumn<PolicyViolation>[] = [
  { key: "when", value: (v) => v.detected_at, filter: false },
  { key: "what", value: (v) => v.kind_label },
  { key: "target", value: (v) => targetName(v) },
  { key: "policy", value: (v) => v.limit_label },
  { key: "who", value: (v) => v.actor },
  { key: "source", value: (v) => v.source },
  { key: "credits", value: (v) => (v.credits === null ? null : Number(v.credits)), filter: false },
  { key: "status", value: (v) => v.status, label: (value) => humanise(String(value ?? "")) },
];

export function ViolationsPage({ onChanged }: { onChanged?: () => void }) {
  const [status, setStatus] = useState<string>("");
  const [kind, setKind] = useState("");
  const [target, setTarget] = useState("");
  const [open, setOpen] = useState<PolicyViolation | null>(null);

  const feed = useResource<ViolationList>(
    (signal) =>
      api.get(
        "/api/violations",
        {
          status: status || undefined,
          kind: kind || undefined,
          target: target.trim() || undefined,
          limit: 500,
        },
        signal,
      ),
    [status, kind, target],
  );
  useInterval(() => void feed.reload(), 60_000);
  const rows = useMemo(() => feed.data?.items ?? [], [feed.data]);
  const view = useTableView(rows, VIEW);

  async function changed(updated: PolicyViolation) {
    setOpen(updated);
    await feed.reload();
    onChanged?.();
  }

  return (
    <>
      <PageHeader
        title="Policy violations"
        description="What was done against a restriction in force. CreditGuard re-applies every restriction each cycle; this is the record of what it found, for you to follow up."
      />

      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-2 px-5 py-4">
          <Input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="Project or user"
            className="max-w-xs"
            aria-label="Filter by project or user"
          />
          <Select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className="max-w-40"
            aria-label="Status"
          >
            <option value="">Any status</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </Select>
          <Select
            value={kind}
            onChange={(event) => setKind(event.target.value)}
            className="max-w-64"
            aria-label="What happened"
          >
            {KINDS.map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </Select>
          <span className="ml-auto text-xs tabular" style={{ color: "var(--text-muted)" }}>
            {feed.data?.total ?? 0} shown, {feed.data?.open ?? 0} open
          </span>
        </div>

        {feed.initialLoading ? (
          <div className="px-5 pb-5">
            <Spinner />
          </div>
        ) : feed.error ? (
          <div className="px-5 pb-5">
            <ErrorNote>{feed.error}</ErrorNote>
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No policy violations"
            description="While a restriction is in force, every cycle checks that its settings are still off (Auto Triage, PR triage and remediation, Fusion, a user's AI roles), looks for scans on a project whose Fusion is turned off that ran Fusion or the AI engine anyway, and whether what the restriction is meant to stop kept rising in the consumption feed. Anything found appears here."
          />
        ) : (
          <Table
            before={
              <FilterNote
                shown={view.rows.length}
                total={view.total}
                filtered={view.filtered}
                onClear={view.clearFilters}
              />
            }
          >
            <thead>
              <tr>
                {view.th("when", "When")}
                {view.th("what", "What happened")}
                {view.th("target", "Project or user")}
                {view.th("policy", "Budget")}
                {view.th("who", "Who")}
                {view.th("source", "Source")}
                {view.th("credits", "Credits", "right")}
                {view.th("status", "Status")}
              </tr>
            </thead>
            <tbody>
              {view.rows.map((v) => (
                <tr
                  key={v.id}
                  className="cursor-pointer"
                  onClick={() => setOpen(v)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") setOpen(v);
                  }}
                  tabIndex={0}
                >
                  <Td>
                    <span className="text-xs" title={formatDateTime(v.detected_at)}>
                      {formatRelative(v.detected_at)}
                    </span>
                  </Td>
                  <Td>
                    <span className="font-medium">{v.kind_label}</span>
                  </Td>
                  <Td>{targetName(v)}</Td>
                  <Td>
                    <span className="text-xs">{v.limit_label ?? "—"}</span>
                  </Td>
                  <Td>
                    <span className="text-xs">{v.actor ?? "Not reported"}</span>
                  </Td>
                  <Td>
                    <span className="text-xs">{v.source ?? "—"}</span>
                  </Td>
                  <Td align="right">
                    <span className="tabular">
                      {v.credits === null ? "—" : formatCredits(v.credits)}
                    </span>
                  </Td>
                  <Td>
                    <Badge tone={STATUS_TONES[v.status]}>{humanise(v.status)}</Badge>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      {open && (
        <ViolationDialog violation={open} onClose={() => setOpen(null)} onChanged={changed} />
      )}
    </>
  );
}

function ViolationDialog({
  violation,
  onClose,
  onChanged,
}: {
  violation: PolicyViolation;
  onClose: () => void;
  onChanged: (updated: PolicyViolation) => Promise<void>;
}) {
  const toast = useToast();
  const [note, setNote] = useState(violation.note ?? "");
  const [busy, setBusy] = useState<"" | "acknowledge" | "resolve">("");
  const [error, setError] = useState<string | null>(null);

  async function act(action: "acknowledge" | "resolve") {
    setBusy(action);
    setError(null);
    try {
      const updated = await api.post<PolicyViolation>(
        `/api/violations/${violation.id}/${action}`,
        { note: note.trim() || null },
      );
      toast.success(action === "resolve" ? "Marked as resolved." : "Acknowledged.");
      await onChanged(updated);
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not update the violation.");
    } finally {
      setBusy("");
    }
  }

  const evidence = Object.entries(violation.evidence ?? {}).filter(
    ([, value]) => value !== null && value !== undefined && value !== "",
  );
  const budgetLink =
    violation.limit_entity_type && violation.limit_entity_id
      ? `/limits?entity_type=${encodeURIComponent(violation.limit_entity_type)}&entity_id=${encodeURIComponent(violation.limit_entity_id)}`
      : null;
  const resolved = violation.status === "resolved";

  return (
    <Modal
      open
      title={violation.kind_label}
      description={`${targetName(violation)} · ${formatDateTime(violation.detected_at)}`}
      onClose={onClose}
      width="max-w-2xl"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
          {!resolved && violation.status === "open" && (
            <Button onClick={() => act("acknowledge")} loading={busy === "acknowledge"}>
              Acknowledge
            </Button>
          )}
          {!resolved && (
            <Button variant="primary" onClick={() => act("resolve")} loading={busy === "resolve"}>
              Resolve
            </Button>
          )}
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {error && <ErrorNote>{error}</ErrorNote>}
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={STATUS_TONES[violation.status]}>{humanise(violation.status)}</Badge>
          <Badge tone={violation.severity === "info" ? "info" : "warning"}>
            {humanise(violation.severity)}
          </Badge>
          {violation.credits !== null && (
            <Badge tone="neutral">{formatCredits(violation.credits)} credits</Badge>
          )}
        </div>
        <p className="text-sm whitespace-pre-wrap">{violation.detail}</p>

        <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-[10rem_1fr]">
          <dt style={{ color: "var(--text-muted)" }}>Who</dt>
          <dd>{violation.actor ?? "Not reported by Checkmarx One"}</dd>
          <dt style={{ color: "var(--text-muted)" }}>Source</dt>
          <dd>{violation.source ?? "—"}</dd>
          <dt style={{ color: "var(--text-muted)" }}>Budget</dt>
          <dd>{violation.limit_label ?? "—"}</dd>
          {violation.updated_at && (
            <>
              <dt style={{ color: "var(--text-muted)" }}>Last updated</dt>
              <dd>{formatDateTime(violation.updated_at)}</dd>
            </>
          )}
          {violation.acknowledged_at && (
            <>
              <dt style={{ color: "var(--text-muted)" }}>Acknowledged</dt>
              <dd>
                {formatDateTime(violation.acknowledged_at)} by {violation.acknowledged_by ?? "?"}
              </dd>
            </>
          )}
          {violation.resolved_at && (
            <>
              <dt style={{ color: "var(--text-muted)" }}>Resolved</dt>
              <dd>
                {formatDateTime(violation.resolved_at)} by {violation.resolved_by ?? "?"}
              </dd>
            </>
          )}
        </dl>

        {evidence.length > 0 && (
          <div>
            <p className="text-sm font-medium">Evidence</p>
            <dl className="mt-1 grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-[10rem_1fr]">
              {evidence.map(([key, value]) => (
                <div key={key} className="contents">
                  <dt style={{ color: "var(--text-muted)" }}>{humanise(key)}</dt>
                  <dd className="break-all">
                    {typeof value === "object" ? JSON.stringify(value) : String(value)}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        )}

        <div className="flex flex-wrap gap-3 text-xs">
          {budgetLink && <Link to={budgetLink}>Open the budget</Link>}
          {violation.enforcement_action_id !== null && (
            <Link to="/notifications">Open the restriction (Notification Center)</Link>
          )}
        </div>

        {!resolved ? (
          <Field label="Note" hint="Optional. Saved with the status change and in the audit log.">
            <Textarea
              rows={2}
              value={note}
              maxLength={2000}
              onChange={(event) => setNote(event.target.value)}
            />
          </Field>
        ) : (
          violation.note && (
            <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
              Note: {violation.note}
            </p>
          )
        )}
      </div>
    </Modal>
  );
}
