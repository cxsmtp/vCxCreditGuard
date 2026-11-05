/** Client-side table export: turn the rows already on screen into CSV or HTML.
 *
 * Export reflects exactly what the viewer sees — the chosen columns, in order —
 * so there is no second server render to drift from the table. A column is a
 * header plus a function that reads one cell's text from a row.
 */

export interface ExportColumn<T> {
  key: string;
  header: string;
  value: (row: T) => string | number | null | undefined;
}

function cell(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "";
  return String(value);
}

function csvField(value: string): string {
  // Formula injection: a spreadsheet runs a cell that begins = + - @ (or a
  // control char) as a formula, and CSV-quoting alone does NOT stop that. Prefix
  // such a cell with a single quote so it is read as text - but leave a plain
  // number (including a legitimate negative like "-5") untouched.
  const formulaRisk = /^[=+\-@\t\r]/.test(value) && !/^[+-]?(\d|\.\d)/.test(value);
  let out = formulaRisk ? `'${value}` : value;
  // Then quote for CSV structure: comma, quote, or newline.
  if (/[",\n\r]/.test(out)) {
    out = `"${out.replace(/"/g, '""')}"`;
  }
  return out;
}

export function toCsv<T>(rows: T[], columns: ExportColumn<T>[]): string {
  const header = columns.map((c) => csvField(c.header)).join(",");
  const body = rows.map((row) =>
    columns.map((c) => csvField(cell(c.value(row)))).join(","),
  );
  return [header, ...body].join("\r\n");
}

function htmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function toHtml<T>(rows: T[], columns: ExportColumn<T>[], title: string): string {
  const head = columns.map((c) => `<th>${htmlEscape(c.header)}</th>`).join("");
  const body = rows
    .map(
      (row) =>
        `<tr>${columns.map((c) => `<td>${htmlEscape(cell(c.value(row)))}</td>`).join("")}</tr>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>${htmlEscape(title)}</title>
<style>
  body { font: 14px -apple-system, system-ui, sans-serif; margin: 2rem; color: #111; }
  h1 { font-size: 1.1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
  th { background: #f3f4f6; }
  tr:nth-child(even) td { background: #fafafa; }
  caption { text-align: left; color: #666; font-size: 12px; margin-bottom: 8px; }
</style>
</head>
<body>
<h1>${htmlEscape(title)}</h1>
<table>
<caption>${rows.length} row${rows.length === 1 ? "" : "s"}, exported ${htmlEscape(new Date().toLocaleString())}</caption>
<thead><tr>${head}</tr></thead>
<tbody>
${body}
</tbody>
</table>
</body>
</html>`;
}

export function downloadText(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function timestampedName(base: string, ext: string): string {
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
  return `${base}-${stamp}.${ext}`;
}
