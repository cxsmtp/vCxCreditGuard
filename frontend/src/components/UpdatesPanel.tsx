import { useEffect, useState } from "react";
import { ApiError, api } from "../api/client";
import type { UpdateRelease, UpdatesStatus } from "../api/types";
import { formatDateTime, formatRelative } from "../lib/format";
import { useResource } from "../hooks/useResource";
import { useToast } from "../lib/ui-context";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  KeyValue,
  Select,
  Spinner,
  Table,
  Td,
  Th,
  Toggle,
} from "./ui";

const HOURS = Array.from({ length: 24 }, (_, hour) => hour);

function hourLabel(hour: number): string {
  return `${String(hour).padStart(2, "0")}:00`;
}

function sizeLabel(bytes: number | null): string {
  if (!bytes) return "–";
  return bytes > 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;
}

function tokenBadge(status: UpdatesStatus["token"]["status"]) {
  if (status === "ok") return <Badge tone="good">Accepted by the registry</Badge>;
  if (status === "invalid") return <Badge tone="critical">Refused by the registry</Badge>;
  if (status === "missing") return <Badge tone="warning">Not set</Badge>;
  return <Badge tone="neutral">Saved, not tried yet</Badge>;
}

const EVENT_LABEL: Record<string, string> = {
  switch: "Switched",
  restart: "Restarted",
  started: "Started and healthy",
  rollback: "Rolled back automatically",
  rollback_blocked: "Failed, could not roll back",
  restore: "Database restored",
  restore_failed: "Database restore failed",
  crash: "Stopped unexpectedly",
  selection_ignored: "Selection not used",
};

/** Settings -> Updates: the in-app updater, for admins. */
export function UpdatesPanel({ onChanged }: { onChanged?: () => Promise<unknown> }) {
  const toast = useToast();
  const status = useResource<UpdatesStatus>(
    (signal) => api.get("/api/ops/updates", undefined, signal),
    [],
  );
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [installing, setInstalling] = useState<UpdateRelease | null>(null);
  const [acceptNoBackup, setAcceptNoBackup] = useState(false);
  const [allowUnsigned, setAllowUnsigned] = useState(false);
  const [rollingBack, setRollingBack] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const data = status.data;
  const job = data?.job;
  const switching = job?.state === "running" || job?.state === "switching";

  // While an update runs (and the server restarts into it), follow along.
  const reload = status.reload;
  useEffect(() => {
    if (!switching) return;
    const id = window.setInterval(() => {
      void reload().catch(() => undefined);
    }, 2500);
    return () => window.clearInterval(id);
  }, [switching, reload]);

  async function act(name: string, call: () => Promise<UpdatesStatus | unknown>, done?: string) {
    setBusy(name);
    setError(null);
    try {
      const result = await call();
      if (result && typeof result === "object" && "image" in result) {
        status.setData(result as UpdatesStatus);
      } else {
        await status.reload();
      }
      if (done) toast.success(done);
      await onChanged?.();
      return true;
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The request failed.");
      return false;
    } finally {
      setBusy(null);
    }
  }

  if (status.initialLoading) {
    return (
      <Card title="Updates">
        <Spinner />
      </Card>
    );
  }
  if (!data) {
    return <ErrorNote>{status.error ?? "The update status could not be loaded."}</ErrorNote>;
  }

  const supervised = data.supervised;
  const newer = data.available.filter((release) => release.newer);
  const latest = data.available.find((release) => release.version === data.latest) ?? null;
  const needsToken = data.token.status === "missing";
  const unverifiable = !data.signing.configured;

  return (
    <div className="flex flex-col gap-6">
      {error && <ErrorNote>{error}</ErrorNote>}

      {needsToken && data.settings.auto_enabled && (
        <div className="cg-banner" role="status">
          <span>
            <b>Auto-update is on, but needs a registry token.</b> Releases are published to a private
            registry: enter a read-only token below and updates install by themselves.
          </span>
        </div>
      )}
      {data.signing.auto_waits && supervised && (
        <div className="cg-banner" role="status">
          <span>
            <b>Auto-update waits for the release signing key.</b> {data.signing.message}
          </span>
        </div>
      )}
      {data.image_age.stale && (
        <div className="cg-banner" role="status">
          <span>
            <b>The image is {data.image_age.days} days old.</b> In-app updates replace only the app's
            own files: replace the image to get OS, Python and OpenSSL fixes (the command is below).
          </span>
        </div>
      )}
      {data.token.status === "invalid" && (
        <div className="cg-banner bad" role="alert">
          <span>
            <b>The registry refused the update token.</b> It may have expired or been revoked. Enter a
            new one below.
          </span>
        </div>
      )}

      <Card
        title="This installation"
        description="What runs now, and how this installation is updated."
        actions={
          <Button
            size="sm"
            onClick={() => act("check", () => api.post("/api/ops/updates/check"), "Checked for updates.")}
            loading={busy === "check"}
            disabled={needsToken}
          >
            Check now
          </Button>
        }
      >
        <div className="flex flex-col gap-4">
          <dl className="grid gap-3 sm:grid-cols-4">
            <KeyValue label="Running">
              <span className="tabular">v{data.running.version}</span>{" "}
              <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                {data.running.source === "installed"
                  ? "installed update"
                  : data.running.source === "built-in"
                    ? "the image's own"
                    : "from source"}
              </span>
            </KeyValue>
            <KeyValue label="Image's own version">v{data.built_in}</KeyValue>
            <KeyValue label="Latest release">
              {data.latest ? (
                <span className="flex items-center gap-2">
                  v{data.latest}
                  {data.update_available ? (
                    <Badge tone={data.latest_needs_image ? "serious" : "warning"}>
                      {data.latest_needs_image ? "Needs a new image" : "Update available"}
                    </Badge>
                  ) : (
                    <Badge tone="good">Up to date</Badge>
                  )}
                </span>
              ) : (
                "–"
              )}
            </KeyValue>
            <KeyValue label="Last check">
              {data.last_check ? formatRelative(data.last_check.at) : "Never"}
            </KeyValue>
          </dl>

          {data.last_check?.error && !needsToken && (
            <InfoNote tone="critical">Last check failed: {data.last_check.error}</InfoNote>
          )}
          {data.last_auto && (
            <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
              Auto-update, {formatRelative(data.last_auto.at)}: {data.last_auto.result}
            </p>
          )}

          {job && (
            <InfoNote tone={job.state === "failed" ? "critical" : "info"}>
              {job.state === "failed" ? (
                <>
                  Update to v{job.version} failed: {job.error}
                </>
              ) : (
                <span className="flex items-center gap-2">
                  <Spinner size={14} /> v{job.version}: {job.step}
                </span>
              )}
            </InfoNote>
          )}

          {!supervised && (
            <InfoNote tone="warning">
              {data.deployment === "compose"
                ? "This installation (Compose) is updated by rebuilding its image from a release tag: "
                : data.deployment === "single"
                  ? "This container was started with a custom command, so it cannot switch versions itself. Update it by replacing the image: "
                  : "This server runs from source. Update it with git and restart it: "}
              the steps are below. Checking and notifications still work.
            </InfoNote>
          )}

          {((data.update_available && (data.latest_needs_image || !supervised)) ||
            data.image_age.stale) && (
            <Field label="Update by replacing the image" fold={false} hint="Run on the server.">
              <pre
                className="overflow-x-auto rounded-md px-3 py-2 font-mono text-xs"
                style={{ background: "var(--hover)" }}
              >
                {data.image_command}
              </pre>
            </Field>
          )}
        </div>
      </Card>

      {data.whats_new.length > 0 && (
        <Card title="What's new" description="Release notes of the versions newer than this one.">
          <div className="flex flex-col gap-4">
            {data.whats_new.map((entry) => (
              <div key={entry.version}>
                <p className="text-sm font-medium">v{entry.version}</p>
                <p className="mt-1 whitespace-pre-wrap text-[13px]" style={{ color: "var(--text-secondary)" }}>
                  {entry.notes}
                </p>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card
        title="Automatic updates"
        description="Newer releases install by themselves, at a quiet hour, never during an enforcement cycle."
        help={
          <>
            The registry is checked every 6 hours (and a minute after the server starts). A newer
            release is installed only in the quiet hour, never while an enforcement cycle runs, never
            a version that already failed to start here, and never an older one. The database is
            backed up first; if the new version does not come up, the previous one runs again by
            itself.
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Toggle
            checked={data.settings.auto_enabled}
            disabled={busy !== null}
            onChange={(next) =>
              void act(
                "settings",
                () =>
                  api.put("/api/ops/updates/settings", {
                    auto_enabled: next,
                    quiet_hour: data.settings.quiet_hour,
                  }),
                next ? "Auto-update is on." : "Auto-update is off.",
              )
            }
            label="Install new releases automatically"
            description={
              data.settings.auto_enabled
                ? needsToken
                  ? "On, waiting for a registry token."
                  : unverifiable
                    ? "On, but waiting for the release signing key: nothing is installed automatically until the image has one."
                  : `On: newer releases install at ${hourLabel(data.settings.quiet_hour)} ${data.settings.timezone}.`
                : "Off: you are notified when a release is published, and install it here."
            }
          />
          <div className="max-w-xs">
            <Field label={`Quiet hour (${data.settings.timezone})`} hint="When automatic installs may happen.">
              <Select
                value={data.settings.quiet_hour}
                disabled={busy !== null}
                onChange={(event) =>
                  void act(
                    "settings",
                    () =>
                      api.put("/api/ops/updates/settings", {
                        auto_enabled: data.settings.auto_enabled,
                        quiet_hour: Number(event.target.value),
                      }),
                    "Quiet hour saved.",
                  )
                }
              >
                {HOURS.map((hour) => (
                  <option key={hour} value={hour}>
                    {hourLabel(hour)} – {hourLabel((hour + 1) % 24)}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        </div>
      </Card>

      <Card
        title="Registry token"
        description={`Releases are private images at ${data.image}.`}
        help={
          <>
            Create a GitHub personal access token (classic) with only the <b>read:packages</b> scope, from
            an account that can see the package. It is encrypted with the master key, never shown
            again, never logged. The server needs outbound HTTPS to {data.egress_hosts.join(" and ")}.
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-2 text-sm">
            <span style={{ color: "var(--text-secondary)" }}>Status:</span>
            {tokenBadge(data.token.status)}
          </div>
          <Field
            label={data.token.configured ? "Replace the token" : "Token"}
            hint="Write only: the stored token is never sent back to the browser."
          >
            <Input
              type="password"
              value={token}
              onChange={(event) => setToken(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder={data.token.configured ? "••••••••  (stored)" : "ghp_…"}
              className="font-mono"
            />
          </Field>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="primary"
              disabled={token.trim().length < 20}
              loading={busy === "token"}
              onClick={async () => {
                const ok = await act(
                  "token",
                  () => api.put("/api/ops/updates/token", { token: token.trim() }),
                  "Token saved and tried against the registry.",
                );
                if (ok) setToken("");
              }}
            >
              Save token
            </Button>
            {data.token.configured && (
              <Button
                variant="ghost"
                loading={busy === "token-clear"}
                onClick={() =>
                  void act(
                    "token-clear",
                    () => api.put("/api/ops/updates/token", { token: null }),
                    "Token removed.",
                  )
                }
              >
                Remove
              </Button>
            )}
          </div>
          {unverifiable && (
            <p className="text-xs" style={{ color: "var(--text-muted)" }}>
              This image has no release signing key: nothing proves who published a release, so none
              is installed automatically, and installing one by hand asks for an explicit
              confirmation (audited).
            </p>
          )}
        </div>
      </Card>

      <Card
        title="Versions"
        description="Published releases, and the versions kept on this server (the running one, the one before it, and the image's own)."
        actions={
          supervised && (
            <>
              <Button
                size="sm"
                variant="secondary"
                disabled={!data.rollback.possible || busy !== null || switching}
                title={data.rollback.possible ? undefined : data.rollback.reason}
                onClick={() => setRollingBack(true)}
              >
                Roll back
                {data.rollback.possible && data.rollback.target_version
                  ? ` to v${data.rollback.target_version}`
                  : ""}
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy !== null || switching}
                onClick={() => setRestarting(true)}
              >
                Restart
              </Button>
            </>
          )
        }
      >
        {data.available.length === 0 && data.installed.length === 0 ? (
          <EmptyState
            title={needsToken ? "No registry token yet" : "No releases listed yet"}
            description={
              needsToken
                ? "Enter a registry token to see the published releases."
                : "Check now to read the published releases."
            }
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Version</Th>
                <Th>Published</Th>
                <Th>Status</Th>
                <Th align="right">Action</Th>
              </tr>
            </thead>
            <tbody>
              {data.available.map((release) => (
                <tr key={release.version}>
                  <Td>
                    <span className="tabular font-medium">v{release.version}</span>{" "}
                    {release.revision && (
                      <span className="font-mono text-xs" style={{ color: "var(--text-muted)" }}>
                        {release.revision.slice(0, 7)}
                      </span>
                    )}
                  </Td>
                  <Td>{release.created ? formatDateTime(release.created) : "–"}</Td>
                  <Td>
                    <span className="flex flex-wrap items-center gap-1.5">
                      {release.running && <Badge tone="good">Running</Badge>}
                      {release.installed && !release.running && <Badge tone="info">Installed</Badge>}
                      {release.failed && (
                        <span title={release.failed}>
                          <Badge tone="critical">Failed to start</Badge>
                        </span>
                      )}
                      {release.skipped && (
                        <span title="Rolled back by an admin: auto-update does not install it again until it is installed by hand or a newer release supersedes it.">
                          <Badge tone="warning">Skipped after rollback</Badge>
                        </span>
                      )}
                      {release.needs_image && <Badge tone="serious">Needs a new image</Badge>}
                      {release.schema_change && <Badge tone="info">Changes the database</Badge>}
                      <Badge tone={release.signed ? "good" : "neutral"}>
                        {release.signed ? "Signed" : "Unsigned"}
                      </Badge>
                    </span>
                  </Td>
                  <Td align="right">
                    {release.newer && supervised && !release.needs_image ? (
                      <Button
                        size="sm"
                        variant={release.version === data.latest ? "primary" : "secondary"}
                        disabled={busy !== null || switching}
                        onClick={() => {
                          setAcceptNoBackup(false);
                          setAllowUnsigned(false);
                          setInstalling(release);
                        }}
                      >
                        Install
                      </Button>
                    ) : (
                      <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                        {release.running ? "This version" : release.newer ? "Replace the image" : "Older"}
                      </span>
                    )}
                  </Td>
                </tr>
              ))}
              {data.installed
                .filter((item) => !data.available.some((release) => release.version === item.version))
                .map((item) => (
                  <tr key={`installed-${item.version}`}>
                    <Td>
                      <span className="tabular font-medium">v{item.version}</span>
                    </Td>
                    <Td>{item.installed_at ? formatDateTime(item.installed_at) : "–"}</Td>
                    <Td>
                      <span className="flex flex-wrap items-center gap-1.5">
                        <Badge tone={item.running ? "good" : "info"}>
                          {item.running ? "Running" : "Installed"}
                        </Badge>
                        {item.skipped && <Badge tone="warning">Skipped after rollback</Badge>}
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                          {sizeLabel(item.bytes)}
                        </span>
                      </span>
                    </Td>
                    <Td align="right">–</Td>
                  </tr>
                ))}
            </tbody>
          </Table>
        )}
        {latest === null && newer.length === 0 && data.events.length === 0 ? null : (
          <div className="mt-5 border-t border-hairline pt-4">
            <p className="mb-2 text-xs" style={{ color: "var(--text-muted)" }}>
              Recent switches
            </p>
            {data.events.length === 0 ? (
              <p className="text-xs" style={{ color: "var(--text-secondary)" }}>
                None yet.
              </p>
            ) : (
              <ul className="flex flex-col gap-1 text-[13px]">
                {data.events.slice(0, 6).map((event) => (
                  <li key={event.id}>
                    <span className="tabular" style={{ color: "var(--text-muted)" }}>
                      {formatDateTime(event.at)}
                    </span>{" "}
                    {EVENT_LABEL[event.type] ?? event.type}
                    {event.version ? ` v${event.version}` : ""}
                    {event.from && event.to ? ` (${event.from} → ${event.to})` : ""}
                    {event.reason && event.type !== "started" ? `: ${event.reason}` : ""}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={installing !== null}
        title={installing ? `Install v${installing.version}?` : "Install"}
        confirmLabel={unverifiable ? "Install the unverified release" : "Install and switch"}
        destructive={unverifiable}
        confirmDisabled={unverifiable && !allowUnsigned}
        busy={busy === "install"}
        onCancel={() => setInstalling(null)}
        onConfirm={async () => {
          if (!installing) return;
          const ok = await act(
            "install",
            () =>
              api.post("/api/ops/updates/install", {
                version: installing.version,
                accept_no_backup: acceptNoBackup,
                allow_unsigned: unverifiable && allowUnsigned,
              }),
            `Installing v${installing.version}.`,
          );
          if (ok) setInstalling(null);
        }}
        message={
          <div className="flex flex-col gap-3">
            <span>
              Only the release's own files are downloaded and checked. The database is backed up,
              then the server switches to v{installing?.version}: the page reconnects in a few seconds.
              If it does not come up, v{data.running.version} runs again by itself.
            </span>
            {unverifiable && (
              <div className="cg-banner bad" role="alert">
                <span>
                  <b>This release cannot be verified.</b> This image has no release signing key, so
                  nothing proves that v{installing?.version} was published by the CxCreditGuard
                  release workflow: anyone able to push to the registry could have replaced it, and
                  it would run with access to this server's database and secrets. Install it only if
                  you trust the registry and the people who can publish to it.
                </span>
              </div>
            )}
            {unverifiable && (
              <label className="flex items-start gap-2 text-[13px]">
                <input
                  type="checkbox"
                  checked={allowUnsigned}
                  onChange={(event) => setAllowUnsigned(event.target.checked)}
                />
                <span>
                  I understand that this release is not verified and install it anyway. (This is
                  recorded in the audit log.)
                </span>
              </label>
            )}
            {installing?.notes && (
              <span className="whitespace-pre-wrap text-[13px]" style={{ color: "var(--text-secondary)" }}>
                {installing.notes}
              </span>
            )}
            {!data.database.backups && (
              <label className="flex items-start gap-2 text-[13px]">
                <input
                  type="checkbox"
                  checked={acceptNoBackup}
                  onChange={(event) => setAcceptNoBackup(event.target.checked)}
                />
                <span>
                  This database ({data.database.kind}) is not backed up by the app. I have a current
                  backup of my own, should the release change the schema.
                </span>
              </label>
            )}
          </div>
        }
      />

      <ConfirmDialog
        open={rollingBack}
        title={`Roll back to v${data.rollback.target_version ?? ""}?`}
        confirmLabel={data.rollback.restores_backup ? "Roll back and restore the backup" : "Roll back"}
        destructive={data.rollback.restores_backup}
        busy={busy === "rollback"}
        onCancel={() => setRollingBack(false)}
        onConfirm={async () => {
          const ok = await act(
            "rollback",
            () =>
              api.post("/api/ops/updates/rollback", {
                confirm_data_loss: data.rollback.restores_backup,
              }),
            "Rolling back.",
          );
          if (ok) setRollingBack(false);
        }}
        message={
          data.rollback.restores_backup ? (
            <>
              v{data.running.version} changed the database schema, so the backup taken before the
              update ({data.rollback.since ? formatDateTime(data.rollback.since) : "at the update"}) is
              restored. <b>Everything written since then is lost</b>: usage readings, budget changes,
              requests and audit entries. The replaced database is kept in the backups folder.
            </>
          ) : (
            <>
              The server switches back to v{data.rollback.target_version}. The database is kept as
              it is: its schema did not change since the update.
            </>
          )
        }
      />

      <ConfirmDialog
        open={restarting}
        title="Restart the server?"
        confirmLabel="Restart"
        busy={busy === "restart"}
        onCancel={() => setRestarting(false)}
        onConfirm={async () => {
          const ok = await act("restart", () => api.post("/api/ops/updates/restart"), "Restarting.");
          if (ok) setRestarting(false);
        }}
        message="The server stops cleanly and starts again; the page reconnects in a few seconds."
      />
    </div>
  );
}
