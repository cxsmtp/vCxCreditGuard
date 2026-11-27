import { useEffect, useState } from "react";
import { ApiError, api } from "../api/client";
import type { OrgEntity, UnmatchedEntity } from "../api/types";
import { useResource } from "../hooks/useResource";
import { formatCredits } from "../lib/format";
import { useToast } from "../lib/ui-context";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Field,
  InfoNote,
  Input,
  Modal,
  Spinner,
  Table,
  Td,
  Th,
} from "./ui";

/**
 * Project and application names in the consumption feed that match no synced
 * project or application (a live tenant reported most project credits under
 * "org/repo" names), and the admin's mappings of them.
 */
const PAGE = 200;

export function EntityMappingCard({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  // One page from the server at a time: "Show more" asks for the rows after
  // the last one shown (keyset), from the same readings as the first page, so
  // a cycle that re-ranks the names in between skips or repeats none.
  const rows = useResource<UnmatchedEntity[]>(
    (signal) =>
      isAdmin
        ? api.get("/api/usage/unmatched-entities", { limit: PAGE }, signal)
        : Promise.resolve([]),
    [isAdmin],
  );
  const [more, setMore] = useState<UnmatchedEntity[]>([]);
  const [lastPageFull, setLastPageFull] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);

  async function showMore() {
    setLoadingMore(true);
    try {
      const shown = [...(rows.data ?? []), ...more];
      const last = shown[shown.length - 1];
      const page = await api.get<UnmatchedEntity[]>("/api/usage/unmatched-entities", {
        limit: PAGE,
        after: last?.cursor ?? undefined,
        readings: shown[0]?.readings ?? undefined,
      });
      setMore((current) => [...current, ...page]);
      setLastPageFull(page.length >= PAGE);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not load more names.");
    } finally {
      setLoadingMore(false);
    }
  }
  const [mapping, setMapping] = useState<UnmatchedEntity | null>(null);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OrgEntity[]>([]);
  const [busy, setBusy] = useState(false);
  // Where the last mapped name's usage counts from now on.
  const [confirmation, setConfirmation] = useState<string | null>(null);

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
      const saved = await api.post<UnmatchedEntity>("/api/usage/unmatched-entities/map", {
        view: mapping.view,
        subject_key: mapping.subject_key,
        entity_id: entityId,
      });
      setConfirmation(saved.confirmation ?? null);
      toast.success(
        entityId
          ? `Mapped. Usage reported under this name from now on counts towards that ${mapping.view}.`
          : "Mapping cleared.",
      );
      setMapping(null);
      setMore([]);
      setLastPageFull(true);
      await rows.reload();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not save the mapping.");
    } finally {
      setBusy(false);
    }
  }

  if (!isAdmin) return null;
  const data = [...(rows.data ?? []), ...more];
  const canShowMore = (rows.data?.length ?? 0) >= PAGE && (more.length === 0 || lastPageFull);

  return (
    <Card
      title="Projects and applications not matched"
      description="Usage Checkmarx reports under a repository or application name that matches no project or application synced from /api/projects and /api/applications. It counts towards no project, group or application limit until it is mapped, and a mapping counts forward only: what the name reported before it was mapped is not counted, so no budget period gains past usage. A name that is no project at all (a repository scanned outside one) can be left: it is still counted tenant wide."
    >
      {confirmation && (
        <div className="mb-4">
          <InfoNote tone="info">{confirmation}</InfoNote>
        </div>
      )}
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
                  <span className="text-sm">
                    {row.name}
                    {row.deleted && " (deleted)"}
                  </span>
                  {row.deleted && (
                    <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                      Deleted in Checkmarx One: counted tenant wide, towards no project budget.
                    </span>
                  )}
                </Td>
                <Td>{row.view === "project" ? "Project" : "Application"}</Td>
                <Td align="right">
                  <span className="tabular">{formatCredits(row.credits)}</span>
                </Td>
                <Td>
                  {row.mapping_broken ? (
                    <span title="Mapped to a project or application that is no longer synced, so the mapping is ignored. Map it again.">
                      <Badge tone="critical">Mapping broken: {row.mapped_entity_id} is gone</Badge>
                    </span>
                  ) : row.overridden ? (
                    <span title="This name now matches a synced project or application by itself, and a real name match always wins over a mapping. The mapping applies again if that match goes away, and then only to usage reported from then on.">
                      <Badge tone="warning">Overridden: counts towards {row.overridden_by}</Badge>
                    </span>
                  ) : row.mapped_entity_id ? (
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
      {canShowMore && (
        <div className="mt-3">
          <Button variant="secondary" onClick={showMore} loading={loadingMore}>
            Show more
          </Button>
        </div>
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
