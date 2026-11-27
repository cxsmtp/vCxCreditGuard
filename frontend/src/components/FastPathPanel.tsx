import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { FastPathEntry, FastPathStatus } from "../api/types";
import { useResource } from "../hooks/useResource";
import { formatRelative } from "../lib/format";
import { useToast } from "../lib/ui-context";
import { Button, Card, ErrorNote, Field, InfoNote, Input, KeyValue, Spinner, Toggle } from "./ui";

function entry(value: FastPathEntry | null | undefined): string {
  if (!value) return "Never";
  return `${formatRelative(value.at)}: ${value.result}`;
}

/**
 * Settings → Schedule: the fast check between cycles, and the optional
 * Checkmarx One webhook that asks for one at once when a scan ends.
 */
export function FastPathPanel({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const status = useResource<FastPathStatus>(
    (signal) => api.get("/api/fastpath", undefined, signal),
    [],
  );
  const [seconds, setSeconds] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);

  if (!status.data) {
    return (
      <Card title="Fast check">
        {status.error ? <ErrorNote>Could not load the fast check.</ErrorNote> : <Spinner />}
      </Card>
    );
  }
  const { fast_check: fast, webhook } = status.data;
  const url = `${window.location.origin}${webhook.path}`;

  async function save(body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      await api.put("/api/fastpath", body);
      setSeconds(null);
      void status.reload();
      toast.success("Saved.");
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not save.");
    } finally {
      setBusy(false);
    }
  }

  async function rotate() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<{ secret: string }>("/api/fastpath/webhook-secret");
      setSecret(result.secret);
      void status.reload();
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Could not create a secret.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Fast check"
      description="Between full cycles, the newest rows of the credit activity log are read every few seconds, and a budget they take over its limit (or inside its headroom) is restricted straight away, through the same recount and safety checks as a cycle."
      help={
        <>
          Checkmarx shows credits only once it bills an action, which for a scan is usually
          when it finishes: the scan that crosses a budget normally completes. To stop the
          one that would overrun, give the budget a headroom (Budgets → edit → Restrict
          early). Cost: about {fast.requests_per_hour.toLocaleString()} small requests an
          hour at this interval, and no database writes while nothing changes.
        </>
      }
    >
      <div className="flex flex-col gap-5">
        {error && <ErrorNote>{error}</ErrorNote>}
        <Toggle
          checked={fast.enabled}
          disabled={!isAdmin || busy}
          onChange={(value) => void save({ fast_check_enabled: value })}
          label="Check for new usage every few seconds"
          description="Off: budgets are checked by the full cycle only. Does nothing in demo mode, or while the usage source is the consumption summary."
        />
        <Field
          label="Every (seconds)"
          hint={`Between ${fast.min_seconds} and ${fast.max_seconds}.`}
        >
          <div className="flex items-center gap-2">
            <Input
              type="number"
              min={fast.min_seconds}
              max={fast.max_seconds}
              value={seconds ?? String(fast.interval_seconds)}
              disabled={!isAdmin || busy}
              onChange={(event) => setSeconds(event.target.value)}
              className="max-w-[120px]"
            />
            {isAdmin && seconds !== null && (
              <Button
                size="sm"
                loading={busy}
                onClick={() => void save({ fast_check_interval_seconds: Number(seconds) })}
              >
                Save
              </Button>
            )}
          </div>
        </Field>
        <div className="grid gap-3 sm:grid-cols-2">
          <KeyValue label="Last run">{entry(fast.last_run)}</KeyValue>
          <KeyValue label="Last action">{entry(fast.last_action)}</KeyValue>
        </div>

        <div className="flex flex-col gap-4 border-t border-hairline pt-4">
          <Toggle
            checked={webhook.switched_on}
            disabled={!isAdmin || busy}
            onChange={(value) => void save({ webhook_enabled: value })}
            label="Checkmarx One webhook"
            description="Optional. When a scan ends, Checkmarx One calls CreditGuard, which runs a fast check at once instead of within the next few seconds. It only speeds up detection; the fast check is what counts and restricts."
          />
          {webhook.switched_on && (
            <>
              <KeyValue label="Payload URL to paste into Checkmarx One">
                <code className="break-all">{url}</code>
              </KeyValue>
              <InfoNote>
                In Checkmarx One: Settings → Webhooks (tenant level) → add a webhook with this
                URL, the secret below, and the events Completed Scan, Failed Scan and Partial
                Scan. The URL must be reachable from Checkmarx One.
              </InfoNote>
              {secret && (
                <InfoNote tone="warning">
                  Copy this secret now; it is not shown again:{" "}
                  <code className="break-all">{secret}</code>
                </InfoNote>
              )}
              {isAdmin && (
                <div>
                  <Button size="sm" loading={busy} onClick={() => void rotate()}>
                    {webhook.secret_configured ? "Replace the secret" : "Create a secret"}
                  </Button>
                </div>
              )}
              {!webhook.secret_configured && (
                <ErrorNote>No secret yet: every delivery is refused until one is created.</ErrorNote>
              )}
              <div className="grid gap-3 sm:grid-cols-2">
                <KeyValue label="Last delivery">{entry(webhook.last_delivery)}</KeyValue>
                <KeyValue label="Last refused">{entry(webhook.last_rejected)}</KeyValue>
              </div>
            </>
          )}
        </div>
      </div>
    </Card>
  );
}
