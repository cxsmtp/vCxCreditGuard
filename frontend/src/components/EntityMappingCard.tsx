import { useEffect, useState } from "react";
import { ApiError, api } from "../api/client";
import type { OrgEntity, UnmatchedEntity } from "../api/types";
import { useResource } from "../hooks/useResource";
import { formatCredits } from "../lib/format";
import { useToast } from "../lib/ui-context";
import { Badge, Button, Card, EmptyState, Field, Input, Modal, Spinner, Table, Td, Th } from "./ui";

/**
 * Project and application names in the consumption feed that match no synced
 * project or application (a live tenant reported most project credits under
 * "org/repo" names), and the admin's mappings of them.
 */
export function EntityMappingCard({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const rows = useResource<UnmatchedEntity[]>(
    (signal) =>
      isAdmin ? api.get("/api/usage/unmatched-entities", undefined, signal) : Promise.resolve([]),
    [isAdmin],
  );
  const [mapping, setMapping] = useState<UnmatchedEntity | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OrgEntity[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!mapping) return;
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      try {
        setResults(
          await api.get<OrgEntity[]>(
            "/api/org/entities",
            { entity_type: mapping.view, q: query, limit: 15 },
            controller.signal,
          ),
        );
      } catch {
        // An empty list rather than a toast per keystroke.
      }
    }, 200);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [mapping, query]);

  async function assign(entityId: string | null) {
    if (!mapping) return;
    setBusy(true);
    try {
      await api.post("/api/usage/unmatched-entities/map", {
        view: mapping.view,
        subject_key: mapping.subject_key,
        entity_id: entityId,
      });
      toast.success(entityId ? `Mapped. This usage now counts towards that ${mapping.view}.` : "Mapping cleared.");
      setMapping(null);
      await rows.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not save the mapping.");
    } finally {
      setBusy(false);
    }
  }

  if (!isAdmin) return null;
  const data = rows.data ?? [];

  return (
    <Card
      title="Projects and applications not matched"
      description="Usage Checkmarx reports under a repository or application name that matches no project or application synced from /api/projects and /api/applications. It counts towards no project, group or application limit until it is mapped. A name that is no project at all (a repository scanned outside one) can be left: it is still counted tenant wide."
    >
      {rows.initialLoading ? (
        <Spinner />
      ) : data.length === 0 ? (
        <EmptyState
          title="Every project and application name matches"
          description="Names in the latest readings all match a synced project or application."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Reported as</Th>
              <Th>Dimension</Th>
              <Th align="right">Credits</Th>
              <Th>Counts towards</Th>
              <Th align="right" />
            </tr>
          </thead>
          <tbody>
            {data.map((row) => (
              <tr key={`${row.view}:${row.subject_key}`}>
                <Td>
                  <span className="text-sm">{row.name}</span>
                </Td>
                <Td>{row.view === "project" ? "Project" : "Application"}</Td>
                <Td align="right">
                  <span className="tabular">{formatCredits(row.credits)}</span>
                </Td>
                <Td>
                  {row.mapped_entity_id ? (
                    <Badge tone="good">{row.mapped_label ?? row.mapped_entity_id}</Badge>
                  ) : (
                    <Badge tone="warning">Not counted</Badge>
                  )}
                </Td>
                <Td align="right">
                  <button
                    type="button"
                    className="text-xs underline"
                    style={{ color: "var(--text-secondary)" }}
                    onClick={() => {
                      setMapping(row);
                      setQuery(row.name.split("/").pop() ?? "");
                    }}
                  >
                    {row.mapped_entity_id ? "Change" : `Map to a ${row.view}`}
                  </button>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}

      <Modal
        open={mapping !== null}
        title={mapping ? `Map this usage to a ${mapping.view}` : ""}
        description={mapping ? `Reported as ${mapping.name}` : ""}
        onClose={() => setMapping(null)}
      >
        <div className="flex flex-col gap-3">
          <Field label={`Search ${mapping?.view ?? "project"}s`}>
            <Input value={query} onChange={(event) => setQuery(event.target.value)} autoFocus />
          </Field>
          <ul className="max-h-64 overflow-y-auto rounded-md border border-hairline">
            {results.map((entity) => (
              <li key={entity.entity_id}>
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => assign(entity.entity_id)}
                  className="w-full px-3 py-2 text-left"
                  style={{ borderTop: "1px solid var(--border)" }}
                >
                  <span className="block text-sm">{entity.label}</span>
                  {entity.secondary && (
                    <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                      {entity.secondary}
                    </span>
                  )}
                </button>
              </li>
            ))}
            {results.length === 0 && (
              <li className="px-3 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                Nothing matched.
              </li>
            )}
          </ul>
          {mapping?.mapped_entity_id && (
            <Button variant="secondary" onClick={() => assign(null)} loading={busy}>
              Clear the current mapping
            </Button>
          )}
        </div>
      </Modal>
    </Card>
  );
}
