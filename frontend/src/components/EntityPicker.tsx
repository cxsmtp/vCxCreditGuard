import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { EntityType, OrgEntity } from "../api/types";
import { entityLabel } from "../lib/format";
import { Badge, Field, Input, Select, Spinner } from "./ui";

/**
 * Picks an entity from the synced organisation model rather than accepting a free
 * text id, so a limit cannot be created against an id that will never resolve.
 */
export function EntityPicker({
  entityType,
  onEntityTypeChange,
  selected,
  onSelect,
  disabled,
}: {
  entityType: EntityType;
  onEntityTypeChange: (type: EntityType) => void;
  selected: OrgEntity | null;
  onSelect: (entity: OrgEntity | null) => void;
  disabled?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OrgEntity[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const rows = await api.get<OrgEntity[]>(
          "/api/org/entities",
          { entity_type: entityType, q: query, limit: 25 },
          controller.signal,
        );
        setResults(rows);
      } catch (caught) {
        if (!controller.signal.aborted) {
          setError("Could not search the organisation model. Has a sync run yet?");
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, 200);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [entityType, query]);

  return (
    <div className="flex flex-col gap-3">
      <Field label="Level">
        <Select
          value={entityType}
          disabled={disabled}
          onChange={(event) => {
            onEntityTypeChange(event.target.value as EntityType);
            onSelect(null);
          }}
        >
          {(["user", "group", "project", "application"] as EntityType[]).map((type) => (
            <option key={type} value={type}>
              {entityLabel(type)}
            </option>
          ))}
        </Select>
      </Field>

      <Field
        label={`Find a ${entityType}`}
        hint={selected ? undefined : "Type to search the synced organisation model."}
      >
        <Input
          value={query}
          disabled={disabled}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={entityType === "user" ? "Name or email" : "Name"}
        />
      </Field>

      {selected && (
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
            onClick={() => onSelect(null)}
            style={{ color: "var(--text-secondary)" }}
          >
            Change
          </button>
        </div>
      )}

      {!selected && (
        <div className="max-h-56 overflow-y-auto rounded-md border border-hairline">
          {loading && (
            <div className="flex items-center gap-2 px-3 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
              <Spinner size={14} /> Searching
            </div>
          )}
          {error && (
            <p className="px-3 py-3 text-xs" style={{ color: "var(--status-critical)" }}>
              {error}
            </p>
          )}
          {!loading && !error && results.length === 0 && (
            <p className="px-3 py-3 text-xs" style={{ color: "var(--text-secondary)" }}>
              Nothing matched. Run an organisation sync from the Settings page if this entity is new.
            </p>
          )}
          <ul>
            {results.map((entity) => (
              <li key={entity.entity_id}>
                <button
                  type="button"
                  onClick={() => onSelect(entity)}
                  className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left"
                  style={{ borderTop: "1px solid var(--border)" }}
                >
                  <span className="min-w-0">
                    <span className="block truncate text-sm">{entity.label}</span>
                    {entity.secondary && (
                      <span className="block truncate text-xs" style={{ color: "var(--text-muted)" }}>
                        {entity.secondary}
                      </span>
                    )}
                  </span>
                  <span className="flex shrink-0 gap-1">
                    {entity.has_limit && <Badge tone="info">Has a limit</Badge>}
                    {entity.is_exempt && <Badge tone="neutral">Exempt</Badge>}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
