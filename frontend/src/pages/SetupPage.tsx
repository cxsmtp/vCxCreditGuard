import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { ConnectionPreview, ConnectionStatusResponse, ConnectionTestResult } from "../api/types";
import { useResource } from "../hooks/useResource";
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  KeyValue,
  PageHeader,
  Spinner,
} from "../components/ui";
import { formatDateTime } from "../lib/format";
import { useToast } from "../lib/ui-context";

/**
 * Connect a tenant.
 *
 * The API key is parsed locally first (Preview), so the admin confirms the tenant
 * and region before anything is stored. The key is write only from here on: it can
 * be replaced but never read back.
 */
export function SetupPage({ isAdmin, onConnected }: { isAdmin: boolean; onConnected: () => void }) {
  const toast = useToast();
  const connection = useResource<ConnectionStatusResponse>(
    (signal) => api.get("/api/connection", undefined, signal),
    [],
  );

  const [apiKey, setApiKey] = useState("");
  const [apiBaseUrl, setApiBaseUrl] = useState("");
  const [preview, setPreview] = useState<ConnectionPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);

  async function runPreview() {
    setBusy(true);
    setError(null);
    setPreview(null);
    try {
      const result = await api.post<ConnectionPreview>("/api/connection/preview", {
        api_key: apiKey.trim(),
      });
      setPreview(result);
      if (result.derived_api_base_url && !apiBaseUrl) {
        setApiBaseUrl(result.derived_api_base_url);
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not read that API key.");
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.put<ConnectionTestResult>("/api/connection", {
        api_key: apiKey.trim(),
        ...(apiBaseUrl.trim() && apiBaseUrl.trim() !== preview?.derived_api_base_url
          ? { api_base_url: apiBaseUrl.trim() }
          : {}),
      });
      setTestResult(result);
      setApiKey("");
      setPreview(null);
      await connection.reload();
      if (result.ok) {
        toast.success(`Connected to ${result.tenant_name ?? "the tenant"}.`);
        onConnected();
      } else {
        toast.error(result.message);
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not save the connection.");
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    try {
      const result = await api.post<ConnectionTestResult>("/api/connection/test");
      setTestResult(result);
      await connection.reload();
      if (result.ok) toast.success(result.message);
      else toast.error(result.message);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "The test could not run.");
    } finally {
      setBusy(false);
    }
  }

  async function saveBaseUrl() {
    setBusy(true);
    try {
      const result = await api.patch<ConnectionTestResult>("/api/connection/api-base-url", {
        api_base_url: apiBaseUrl.trim(),
      });
      setTestResult(result);
      await connection.reload();
      toast.info(result.message);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not update the base URL.");
    } finally {
      setBusy(false);
    }
  }

  const current = connection.data;

  return (
    <>
      <PageHeader
        title="Connection"
        description="Paste a Checkmarx One API key. The tenant name and region are derived from the key itself, and the key is stored encrypted."
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Card
          title="Checkmarx One API key"
          description={
            current?.configured
              ? "Pasting a new key replaces the stored one."
              : "Generate this under Identity and Access Management in your tenant."
          }
        >
          {!isAdmin ? (
            <InfoNote>Only an Admin can change the connection.</InfoNote>
          ) : (
            <div className="flex flex-col gap-4">
              {error && <ErrorNote>{error}</ErrorNote>}

              <Field
                label="API key"
                hint="A long JWT. It is never displayed again after saving."
                required
              >
                <textarea
                  value={apiKey}
                  onChange={(event) => {
                    setApiKey(event.target.value);
                    setPreview(null);
                  }}
                  rows={4}
                  spellCheck={false}
                  autoComplete="off"
                  className="w-full rounded-md border border-hairline-strong px-3 py-2 font-mono text-xs outline-none"
                  style={{ background: "var(--surface-raised)", color: "var(--text-primary)" }}
                  placeholder="eyJhbGciOi..."
                />
              </Field>

              <div className="flex flex-wrap gap-2">
                <Button onClick={runPreview} disabled={apiKey.trim().length < 40} loading={busy}>
                  Check the key
                </Button>
                <Button variant="primary" onClick={save} disabled={!preview} loading={busy}>
                  Save and connect
                </Button>
              </div>

              {preview && (
                <div className="rounded-md border border-hairline p-4">
                  <p className="mb-3 text-xs font-medium">
                    Confirm these details before saving. Nothing has been stored yet.
                  </p>
                  <dl className="grid grid-cols-2 gap-3">
                    <KeyValue label="Tenant">{preview.tenant_name}</KeyValue>
                    <KeyValue label="Region">{preview.region_label}</KeyValue>
                    <KeyValue label="IAM URL">{preview.iam_base_url}</KeyValue>
                    <KeyValue label="Key fingerprint">
                      <span className="font-mono text-xs">{preview.api_key_fingerprint}</span>
                    </KeyValue>
                    <KeyValue label="Key expires">
                      {preview.key_expires_at
                        ? formatDateTime(preview.key_expires_at)
                        : "Does not expire"}
                    </KeyValue>
                    <KeyValue label="OAuth client">{preview.client_id ?? "unknown"}</KeyValue>
                  </dl>

                  <div className="mt-4">
                    <Field
                      label="Platform API base URL"
                      hint={
                        preview.derivation_confident
                          ? "Derived from the tenant region. Change it only for a dedicated deployment."
                          : "This region was not recognised, so please confirm the URL is right."
                      }
                    >
                      <Input
                        value={apiBaseUrl}
                        onChange={(event) => setApiBaseUrl(event.target.value)}
                        placeholder="https://eu.ast.checkmarx.net/api"
                        spellCheck={false}
                      />
                    </Field>
                  </div>

                  {!preview.derivation_confident && (
                    <div className="mt-3">
                      <InfoNote tone="warning">
                        The API base URL was guessed from the IAM hostname. If the connection test
                        fails, correct it here.
                      </InfoNote>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </Card>

        <div className="flex flex-col gap-6">
          <Card
            title="Connection health"
            actions={
              isAdmin &&
              current?.configured && (
                <Button size="sm" onClick={test} loading={busy}>
                  Test connection
                </Button>
              )
            }
          >
            {connection.initialLoading ? (
              <Spinner />
            ) : !current?.configured ? (
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                No connection configured yet.
              </p>
            ) : (
              <div className="flex flex-col gap-4">
                <div className="flex flex-wrap items-center gap-2">
                  {current.status === "healthy" ? (
                    <Badge tone="good">Healthy</Badge>
                  ) : current.status === "failed" ? (
                    <Badge tone="critical">Failing</Badge>
                  ) : (
                    <Badge tone="neutral">Not tested yet</Badge>
                  )}
                  {current.api_base_url_overridden && <Badge tone="info">Base URL overridden</Badge>}
                </div>

                <dl className="grid grid-cols-2 gap-3">
                  <KeyValue label="Tenant">{current.tenant_name}</KeyValue>
                  <KeyValue label="Key fingerprint">
                    <span className="font-mono text-xs">{current.api_key_fingerprint}</span>
                  </KeyValue>
                  <KeyValue label="IAM URL">{current.iam_base_url}</KeyValue>
                  <KeyValue label="API base URL">{current.api_base_url}</KeyValue>
                  <KeyValue label="Last success">{formatDateTime(current.last_success_at)}</KeyValue>
                  <KeyValue label="Last failure">{formatDateTime(current.last_failure_at)}</KeyValue>
                </dl>

                {current.last_error && <ErrorNote>{current.last_error}</ErrorNote>}

                {isAdmin && (
                  <div className="border-t border-hairline pt-4">
                    <Field
                      label="Override the platform API base URL"
                      hint="For a dedicated or newly added region. Saving runs a connection test."
                    >
                      <Input
                        value={apiBaseUrl}
                        onChange={(event) => setApiBaseUrl(event.target.value)}
                        placeholder={current.api_base_url ?? "https://eu.ast.checkmarx.net/api"}
                        spellCheck={false}
                      />
                    </Field>
                    <div className="mt-2">
                      <Button size="sm" onClick={saveBaseUrl} disabled={!apiBaseUrl.trim()} loading={busy}>
                        Save base URL
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </Card>

          {testResult && (
            <Card title="Last test result">
              <ul className="flex flex-col gap-2 text-sm">
                <li className="flex items-center gap-2">
                  {testResult.token_acquired ? (
                    <Badge tone="good">Token acquired</Badge>
                  ) : (
                    <Badge tone="critical">Token exchange failed</Badge>
                  )}
                </li>
                <li className="flex items-center gap-2">
                  {testResult.api_reachable ? (
                    <Badge tone="good">Platform API reachable</Badge>
                  ) : (
                    <Badge tone="critical">Platform API unreachable</Badge>
                  )}
                </li>
                {testResult.projects_visible !== null && (
                  <li style={{ color: "var(--text-secondary)" }}>
                    {testResult.projects_visible} projects visible to this key.
                  </li>
                )}
              </ul>
              <p className="mt-3 text-xs whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
                {testResult.message}
              </p>
            </Card>
          )}

          <Card title="What this key needs access to">
            <ul className="flex flex-col gap-1.5 text-xs" style={{ color: "var(--text-secondary)" }}>
              <li>Read users and groups in IAM, and read projects and applications.</li>
              <li>Read credit consumption.</li>
              <li>
                To use enforce mode, also manage IAM role mappings and project configuration. A read
                only key runs the whole utility in monitor only mode.
              </li>
              <li>Use a dedicated service account rather than a person's key.</li>
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}
