import { useState } from "react";
import { api } from "../api/client";
import type { AuditEntry, AuditList } from "../api/types";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Input,
  Modal,
  PageHeader,
  Select,
  Spinner,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { formatDateTime, humanise } from "../lib/format";

const PAGE_SIZE = 100;

function DiffView({ before, after }: { before: unknown; after: unknown }) {
  const beforeObject = (before ?? {}) as Record<string, unknown>;
  const afterObject = (after ?? {}) as Record<string, unknown>;
  const keys = [...new Set([...Object.keys(beforeObject), ...Object.keys(afterObject)])];

  if (keys.length === 0) {
    return (
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        No before or after state was recorded for this action.
      </p>
    );
  }

  return (
    <Table className="tabular">
      <thead>
        <tr>
          <Th>Field</Th>
          <Th>Before</Th>
          <Th>After</Th>
        </tr>
      </thead>
      <tbody>
        {keys.map((key) => {
          const from = beforeObject[key];
          const to = afterObject[key];
          const changed = JSON.stringify(from) !== JSON.stringify(to);
          return (
            <tr key={key} style={changed ? { background: "var(--hover)" } : undefined}>
              <Td>{humanise(key)}</Td>
              <Td>
                <code className="text-xs break-all">
                  {from === undefined ? "" : JSON.stringify(from)}
                </code>
              </Td>
              <Td>
                <code className="text-xs break-all">{to === undefined ? "" : JSON.stringify(to)}</code>
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

export function AuditPage() {
  const [action, setAction] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [detail, setDetail] = useState<AuditEntry | null>(null);

  const audit = useResource<AuditList>(
    (signal) =>
      api.get(
        "/api/audit",
        { action: action || undefined, q: query || undefined, limit: PAGE_SIZE, offset: page * PAGE_SIZE },
        signal,
      ),
    [action, query, page],
  );

  const total = audit.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every action the utility took and every change an admin made, with the before and after state. Append only: nothing in the application can rewrite it."
      />

      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-2 px-5 py-4">
          <Input
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(0);
            }}
            placeholder="Search by target or detail"
            className="max-w-xs"
          />
          <Select
            value={action}
            onChange={(event) => {
              setAction(event.target.value);
              setPage(0);
            }}
            className="max-w-64"
          >
            <option value="">All actions</option>
            {(audit.data?.actions ?? []).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </Select>
          <span className="ml-auto text-xs tabular" style={{ color: "var(--text-muted)" }}>
            {total} entries
          </span>
        </div>

        {audit.initialLoading ? (
          <div className="px-5 pb-5">
            <Spinner />
          </div>
        ) : audit.error ? (
          <div className="px-5 pb-5">
            <ErrorNote>{audit.error}</ErrorNote>
          </div>
        ) : (audit.data?.items ?? []).length === 0 ? (
          <EmptyState title="No matching entries" />
        ) : (
          <>
            <Table>
              <thead>
                <tr>
                  <Th>When</Th>
                  <Th>Actor</Th>
                  <Th>Action</Th>
                  <Th>Target</Th>
                  <Th>Detail</Th>
                  <Th align="right" />
                </tr>
              </thead>
              <tbody>
                {(audit.data?.items ?? []).map((entry) => (
                  <tr key={entry.id}>
                    <Td>
                      <span className="text-xs whitespace-nowrap tabular">
                        {formatDateTime(entry.occurred_at)}
                      </span>
                    </Td>
                    <Td>
                      <div className="flex items-center gap-1.5">
                        <Badge tone={entry.actor_type === "system" ? "neutral" : "info"}>
                          {entry.actor_type === "system" ? "System" : "Admin"}
                        </Badge>
                        <span className="text-xs">{entry.actor_name ?? "unknown"}</span>
                      </div>
                    </Td>
                    <Td>
                      <code className="text-xs">{entry.action}</code>
                    </Td>
                    <Td>
                      <span className="text-xs">
                        {entry.target_label ?? entry.target_id ?? ""}
                        {entry.target_type && (
                          <span className="block" style={{ color: "var(--text-muted)" }}>
                            {humanise(entry.target_type)}
                          </span>
                        )}
                      </span>
                    </Td>
                    <Td>
                      <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                        {entry.detail ?? ""}
                      </span>
                    </Td>
                    <Td align="right">
                      <button
                        type="button"
                        className="text-xs underline"
                        style={{ color: "var(--text-secondary)" }}
                        onClick={() => setDetail(entry)}
                      >
                        View
                      </button>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>

            <div className="flex items-center justify-between gap-2 border-t border-hairline px-5 py-3 text-xs">
              <span style={{ color: "var(--text-muted)" }}>
                Page {page + 1} of {pages}
              </span>
              <div className="flex gap-2">
                <Button size="sm" onClick={() => setPage((value) => Math.max(0, value - 1))} disabled={page === 0}>
                  Previous
                </Button>
                <Button
                  size="sm"
                  onClick={() => setPage((value) => value + 1)}
                  disabled={page + 1 >= pages}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>

      <Modal
        open={detail !== null}
        title={detail?.action ?? ""}
        description={detail ? formatDateTime(detail.occurred_at) : ""}
        onClose={() => setDetail(null)}
        width="max-w-3xl"
      >
        {detail && (
          <div className="flex flex-col gap-4">
            <dl className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <dt className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Actor
                </dt>
                <dd>
                  {detail.actor_name ?? "system"} ({detail.actor_type})
                </dd>
              </div>
              <div>
                <dt className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Source address
                </dt>
                <dd>{detail.ip_address ?? "not recorded"}</dd>
              </div>
              <div>
                <dt className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Target
                </dt>
                <dd>
                  {detail.target_label ?? detail.target_id ?? "none"}
                  {detail.target_type ? ` (${detail.target_type})` : ""}
                </dd>
              </div>
              <div>
                <dt className="text-xs" style={{ color: "var(--text-muted)" }}>
                  Entry id
                </dt>
                <dd className="tabular">{detail.id}</dd>
              </div>
            </dl>

            {detail.detail && (
              <p className="text-sm whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
                {detail.detail}
              </p>
            )}

            <div className="border-t border-hairline pt-4">
              <h3 className="mb-2 text-xs font-semibold">State change</h3>
              <DiffView before={detail.before} after={detail.after} />
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}
