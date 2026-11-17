import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

/**
 * Sorting and per-column filters for any table.
 *
 * Every table can be sorted low to high and back by any column, and filtered
 * by each column with a multi-select of the values it holds. A page keeps its
 * own row rendering: it describes how to read each column's value, renders
 * `view.th(...)` for the header cells and maps over `view.rows`.
 */

export type ColumnValue = string | number | boolean | null | undefined;

export interface ViewColumn<T> {
  key: string;
  /** What the column sorts and filters by (not necessarily what it shows). */
  value: (row: T) => ColumnValue;
  /** Offer a multi-select filter of the values in this column. Default true for text. */
  filter?: boolean;
  /** How a filter value is shown, when the raw value is not friendly. */
  label?: (value: ColumnValue) => string;
}

type Direction = "asc" | "desc";

function text(value: ColumnValue): string {
  if (value === null || value === undefined || value === "") return "(blank)";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function compare(a: ColumnValue, b: ColumnValue): number {
  const aBlank = a === null || a === undefined || a === "";
  const bBlank = b === null || b === undefined || b === "";
  if (aBlank || bBlank) return aBlank === bBlank ? 0 : aBlank ? 1 : -1; // blanks last
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
}

export function useTableView<T>(rows: readonly T[], columns: ViewColumn<T>[]) {
  const [sort, setSort] = useState<{ key: string; dir: Direction } | null>(null);
  const [filters, setFilters] = useState<Record<string, Set<string>>>({});
  const byKey = useMemo(() => new Map(columns.map((c) => [c.key, c])), [columns]);

  const visible = useMemo(() => {
    let out = rows.filter((row) =>
      Object.entries(filters).every(([key, chosen]) => {
        const column = byKey.get(key);
        if (!column || chosen.size === 0) return true;
        return chosen.has(text(column.value(row)));
      }),
    );
    if (sort) {
      const column = byKey.get(sort.key);
      if (column) {
        const sign = sort.dir === "asc" ? 1 : -1;
        out = [...out].sort((a, b) => sign * compare(column.value(a), column.value(b)));
      }
    }
    return out;
  }, [rows, filters, sort, byKey]);

  function cycleSort(key: string) {
    setSort((current) => {
      if (!current || current.key !== key) return { key, dir: "asc" };
      if (current.dir === "asc") return { key, dir: "desc" };
      return null;
    });
  }

  function th(key: string, label: ReactNode, align: "left" | "right" | "center" = "left") {
    const column = byKey.get(key);
    if (!column) return <th style={{ textAlign: align }}>{label}</th>;
    const dir = sort?.key === key ? sort.dir : undefined;
    const filterable = column.filter ?? true;
    return (
      <th
        key={key}
        scope="col"
        style={{ textAlign: align, position: "relative" }}
        aria-sort={dir === "asc" ? "ascending" : dir === "desc" ? "descending" : "none"}
      >
        <span className="inline-flex items-center">
          <button
            type="button"
            className="cg-sort"
            data-dir={dir}
            onClick={() => cycleSort(key)}
            title="Sort low to high, high to low, or back"
          >
            {label}
            <span className="arrow" aria-hidden="true">
              {dir === "asc" ? "▲" : dir === "desc" ? "▼" : "⇅"}
            </span>
          </button>
          {filterable && (
            <ColumnFilter
              name={typeof label === "string" ? label : key}
              values={rows.map((row) => text(column.value(row)))}
              label={column.label ? (v) => (v === "(blank)" ? v : column.label!(v)) : undefined}
              chosen={filters[key] ?? new Set()}
              onChange={(next) => setFilters((current) => ({ ...current, [key]: next }))}
            />
          )}
        </span>
      </th>
    );
  }

  const filtered = Object.values(filters).some((chosen) => chosen.size > 0);
  return {
    rows: visible,
    th,
    filtered,
    clearFilters: () => setFilters({}),
    total: rows.length,
  };
}

function ColumnFilter({
  name,
  values,
  chosen,
  onChange,
  label,
}: {
  name: string;
  values: string[];
  chosen: Set<string>;
  onChange: (next: Set<string>) => void;
  label?: (value: string) => string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [at, setAt] = useState<{ top: number; left: number }>({ top: 0, left: 0 });
  const ref = useRef<HTMLSpanElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const options = useMemo(() => {
    const counts = new Map<string, number>();
    for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
    // A chosen value the current rows no longer hold stays listed (at 0), so it
    // can be seen and unticked rather than filtering everything out unseen.
    for (const value of chosen) if (!counts.has(value)) counts.set(value, 0);
    return [...counts.entries()].sort((a, b) =>
      a[0].localeCompare(b[0], undefined, { numeric: true, sensitivity: "base" }),
    );
  }, [values, chosen]);

  useEffect(() => {
    if (!open) return;
    const inside = (target: EventTarget | null) =>
      ref.current?.contains(target as Node) || popRef.current?.contains(target as Node);
    const onDown = (event: MouseEvent) => {
      if (!inside(event.target)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      setOpen(false);
      buttonRef.current?.focus();
    };
    // Fixed to the viewport so a scrolling table cannot clip it; it closes
    // rather than drift when the page moves under it, but not when its own
    // list of values is scrolled.
    const close = (event: Event) => {
      if (!inside(event.target)) setOpen(false);
    };
    const onResize = () => setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", close, true);
    // Focus moves into the filter, so a keyboard user lands on its first value.
    window.setTimeout(() => popRef.current?.querySelector<HTMLElement>("input")?.focus(), 0);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", close, true);
    };
  }, [open]);

  if (options.length < 2 && chosen.size === 0) return null;
  const shown = options.filter(([value]) =>
    (label ? label(value) : value).toLowerCase().includes(query.trim().toLowerCase()),
  );

  function toggle(value: string) {
    const next = new Set(chosen);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    onChange(next);
  }

  return (
    <span ref={ref} className="relative">
      <button
        ref={buttonRef}
        type="button"
        className={`cg-filter-btn ${chosen.size ? "on" : ""}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        title={chosen.size ? `Filtered: ${chosen.size} chosen` : "Filter this column"}
        aria-label={chosen.size ? `Filter ${name} (${chosen.size} chosen)` : `Filter ${name}`}
        onClick={() => {
          const rect = buttonRef.current?.getBoundingClientRect();
          if (rect) {
            setAt({
              top: Math.min(rect.bottom + 6, window.innerHeight - 340),
              left: Math.max(8, Math.min(rect.left - 8, window.innerWidth - 256)),
            });
          }
          setOpen((v) => !v);
        }}
      >
        ▾
      </button>
      {open &&
        createPortal(
        <div
          ref={popRef}
          className="cg-filter-pop"
          role="dialog"
          aria-label="Filter this column"
          style={{ position: "fixed", top: at.top, left: at.left, marginTop: 0 }}
        >
          {options.length > 8 && (
            <div className="p-2">
              <input
                className="cg-input"
                placeholder="Find a value"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
          )}
          <div className="list">
            {shown.map(([value, count]) => (
              <label key={value}>
                <input type="checkbox" checked={chosen.has(value)} onChange={() => toggle(value)} />
                <span className="min-w-0 flex-1 break-words">{label ? label(value) : value}</span>
                <span className="tabular text-xs" style={{ color: "var(--text-muted)" }}>
                  {count}
                </span>
              </label>
            ))}
          </div>
          <div className="foot">
            <button type="button" className="cg-btn sm ghost" onClick={() => onChange(new Set())}>
              Show all
            </button>
            <button
              type="button"
              className="cg-btn sm"
              onClick={() => {
                setOpen(false);
                buttonRef.current?.focus();
              }}
            >
              Done
            </button>
          </div>
        </div>,
          document.body,
        )}
    </span>
  );
}

/** "Showing 12 of 40 · Clear filters", under a filtered table. */
export function FilterNote({
  shown,
  total,
  filtered,
  onClear,
}: {
  shown: number;
  total: number;
  filtered: boolean;
  onClear: () => void;
}) {
  if (!filtered) return null;
  return (
    <div className="flex items-center gap-3 px-3 py-2 text-xs" style={{ color: "var(--text-secondary)" }}>
      <span>
        Showing {shown} of {total}
      </span>
      <button type="button" className="underline" onClick={onClear}>
        Clear filters
      </button>
    </div>
  );
}
