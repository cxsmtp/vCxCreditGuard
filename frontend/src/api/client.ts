/**
 * Thin fetch wrapper.
 *
 * The session lives in an HttpOnly cookie, so there is no token to store or leak
 * into localStorage. The CSRF cookie is readable on purpose and echoed back in the
 * X-CSRF-Token header on every state changing request, which is what the backend
 * compares against the digest on the session row.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  readonly problems: string[];

  constructor(status: number, message: string, code: string | null = null, problems: string[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.problems = problems;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }
}

const CSRF_COOKIE = "cxcg_csrf";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

function readCsrfToken(): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]*)`));
  return match?.[1] ? decodeURIComponent(match[1]) : "";
}

/** Listeners fired when the server says the session is gone, so the app can
 * return to the login screen instead of rendering half-loaded pages. */
type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

export function onUnauthorized(listener: Listener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  /** Set for endpoints that answer with a file rather than JSON. */
  raw?: boolean;
  signal?: AbortSignal;
  formData?: FormData;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  const url = new URL(path.startsWith("/") ? path : `/${path}`, window.location.origin);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") {
        url.searchParams.set(key, String(value));
      }
    }
  }
  return url.pathname + url.search;
}

async function parseError(response: Response): Promise<ApiError> {
  let message = `Request failed with status ${response.status}`;
  let code: string | null = null;
  let problems: string[] = [];
  try {
    const body = await response.json();
    const detail = body?.detail;
    if (typeof detail === "string") {
      message = detail;
    } else if (detail && typeof detail === "object") {
      message = String(detail.message ?? message);
      code = detail.code ? String(detail.code) : null;
      if (Array.isArray(detail.problems)) {
        problems = detail.problems.map(String);
      }
    } else if (Array.isArray(body?.detail)) {
      // FastAPI validation errors.
      message = body.detail
        .map((item: { loc?: unknown[]; msg?: string }) => {
          const field = Array.isArray(item.loc) ? item.loc[item.loc.length - 1] : "";
          return field ? `${String(field)}: ${item.msg ?? ""}` : String(item.msg ?? "");
        })
        .join("; ");
    }
  } catch {
    // Not JSON. Keep the generic message.
  }
  return new ApiError(response.status, message, code, problems);
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { Accept: "application/json" };

  let body: BodyInit | undefined;
  if (options.formData) {
    body = options.formData;
  } else if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }

  if (!SAFE_METHODS.has(method)) {
    headers["X-CSRF-Token"] = readCsrfToken();
  }

  const response = await fetch(buildUrl(path, options.query), {
    method,
    headers,
    body,
    credentials: "same-origin",
    signal: options.signal,
  });

  if (response.status === 401) {
    const error = await parseError(response);
    // A totp_required answer is part of the login flow, not a dead session.
    if (error.code !== "totp_required") {
      for (const listener of unauthorizedListeners) listener();
    }
    throw error;
  }

  if (!response.ok) {
    throw await parseError(response);
  }

  if (options.raw) {
    return (await response.text()) as unknown as T;
  }
  if (response.status === 204 || response.headers.get("Content-Length") === "0") {
    return undefined as unknown as T;
  }
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string, query?: RequestOptions["query"], signal?: AbortSignal) =>
    request<T>(path, { method: "GET", query, signal }),
  post: <T>(path: string, body?: unknown, query?: RequestOptions["query"]) =>
    request<T>(path, { method: "POST", body, query }),
  put: <T>(path: string, body?: unknown) => request<T>(path, { method: "PUT", body }),
  patch: <T>(path: string, body?: unknown) => request<T>(path, { method: "PATCH", body }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  upload: <T>(path: string, formData: FormData, query?: RequestOptions["query"]) =>
    request<T>(path, { method: "POST", formData, query }),
  text: (path: string) => request<string>(path, { method: "GET", raw: true }),
};

/** Triggers a browser download of a CSV export without leaving the SPA. */
export async function downloadCsv(path: string, filename: string): Promise<void> {
  const response = await fetch(buildUrl(path), {
    credentials: "same-origin",
    headers: { Accept: "text/csv" },
  });
  if (!response.ok) {
    throw await parseError(response);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
