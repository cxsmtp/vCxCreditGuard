import { useEffect, useRef, useState } from "react";
import {
  downloadText,
  timestampedName,
  toCsv,
  toHtml,
  type ExportColumn,
} from "../lib/export";

/**
 * A small "Export" control: pick which columns to include, then download the
 * rows on screen as CSV or a standalone HTML table. Everything happens in the
 * browser from the data already loaded, so the export matches the view exactly.
 */
export function ExportMenu<T>({
  rows,
  columns,
  filenameBase,
  title,
  disabled,
}: {
  rows: T[];
  columns: ExportColumn<T>[];
  filenameBase: string;
  title: string;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [chosen, setChosen] = useState<Set<string>>(() => new Set(columns.map((c) => c.key)));
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  const selected = columns.filter((c) => chosen.has(c.key));
  const canExport = rows.length > 0 && selected.length > 0;

  function toggle(key: string) {
    setChosen((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function doExport(format: "csv" | "html") {
    if (!canExport) return;
    if (format === "csv") {
      downloadText(toCsv(rows, selected), timestampedName(filenameBase, "csv"), "text/csv");
    } else {
      downloadText(toHtml(rows, selected, title), timestampedName(filenameBase, "html"), "text/html");
    }
    setOpen(false);
  }

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        disabled={disabled || rows.length === 0}
        onClick={() => setOpen((v) => !v)}
        className="rounded-md border border-hairline px-3 py-1.5 text-sm disabled:cursor-not-allowed disabled:opacity-50"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        Export
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 z-20 mt-1 w-64 rounded-md border border-hairline p-3 shadow-lg"
          style={{ background: "var(--surface-raised)" }}
        >
          <p className="mb-2 text-xs font-medium" style={{ color: "var(--text-secondary)" }}>
            Columns
          </p>
          <div className="max-h-56 overflow-y-auto">
            {columns.map((column) => (
              <label key={column.key} className="flex items-center gap-2 py-1 text-sm">
                <input
                  type="checkbox"
                  checked={chosen.has(column.key)}
                  onChange={() => toggle(column.key)}
                />
                {column.header}
              </label>
            ))}
          </div>
          <div className="mt-3 flex gap-2 border-t border-hairline pt-3">
            <button
              type="button"
              disabled={!canExport}
              onClick={() => doExport("csv")}
              className="flex-1 rounded-md px-2.5 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              style={{ background: "var(--accent)", color: "var(--accent-contrast)" }}
            >
              CSV
            </button>
            <button
              type="button"
              disabled={!canExport}
              onClick={() => doExport("html")}
              className="flex-1 rounded-md border border-hairline px-2.5 py-1.5 text-xs font-medium disabled:opacity-50"
            >
              HTML
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
