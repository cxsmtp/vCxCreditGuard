import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { EnforcementActionItem, NotificationItem, NotificationList, Severity } from "../api/types";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorNote,
  Input,
  PageHeader,
  Select,
  Spinner,
  Table,
  Td,
  Th,
} from "../components/ui";
import { useInterval, useResource } from "../hooks/useResource";
import { enforcementLabel, formatDateTime, formatRelative, humanise } from "../lib/format";
import { useToast } from "../lib/ui-context";

const SEVERITY_TONES: Record<Severity, "info" | "warning" | "critical" | "serious"> = {
  info: "info",
  warning: "warning",
  critical: "critical",
  error: "serious",
};

const CATEGORIES = [
  { value: "", label: "All categories" },
  { value: "warning", label: "Warnings" },
  { value: "enforcement", label: "Enforcement" },
  { value: "restoration", label: "Restorations" },
  { value: "attribution", label: "Attribution" },
  { value: "sync_error", label: "Sync errors" },
  { value: "auth_failure", label: "Authentication" },
];

export function NotificationsPage({
  isAdmin,
  onUnreadChange,
}: {
  isAdmin: boolean;
  onUnreadChange: (count: number) => void;
}) {
  const toast = useToast();
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [search, setSearch] = useState("");
  const [restoring, setRestoring] = useState<NotificationItem | null>(null);
  const [busy, setBusy] = useState(false);

  const feed = useResource<NotificationList>(
    (signal) =>
      api.get(
        "/api/notifications",
        { severity: severity || undefined, category: category || undefined, unread_only: unreadOnly, limit: 200 },
        signal,
      ),
    [severity, category, unreadOnly],
  );
  const enforcements = useResource<EnforcementActionItem[]>(
    (signal) => api.get("/api/notifications/enforcements", { only_active: true }, signal),
    [],
  );

  useInterval(() => {
    void feed.reload();
  }, 60_000);

  if (feed.data) onUnreadChange(feed.data.unread);

  async function markAllRead() {
    setBusy(true);
    try {
      await api.post("/api/notifications/read", {});
      await feed.reload();
      onUnreadChange(0);
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not mark these as read.");
    } finally {
      setBusy(false);
    }
  }

  async function restore(actionId: number) {
    setBusy(true);
    try {
      const result = await api.post<{ restored: boolean; message: string }>(
        `/api/notifications/enforcements/${actionId}/restore`,
      );
      if (result.restored) toast.success(result.message);
      else toast.info(result.message);
      setRestoring(null);
      await Promise.all([feed.reload(), enforcements.reload()]);
    } catch (caught) {
      toast.error(
        caught instanceof ApiError
          ? caught.message
          : "The restore failed. Check the audit log for the previous state.",
      );
    } finally {
      setBusy(false);
    }
  }

  const items = (feed.data?.items ?? []).filter((item) => {
    const term = search.trim().toLowerCase();
    if (!term) return true;
    return (
      item.title.toLowerCase().includes(term) ||
      (item.body ?? "").toLowerCase().includes(term) ||
      (item.entity_label ?? "").toLowerCase().includes(term)
    );
  });

  return (
    <>
      <PageHeader
        title="Notification Center"
        description="Warnings, enforcement actions, restorations and sync problems. Every enforcement here can be reversed."
        actions={
          <Button size="sm" onClick={markAllRead} loading={busy} disabled={(feed.data?.unread ?? 0) === 0}>
            Mark all as read
          </Button>
        }
      />

      {(enforcements.data ?? []).length > 0 && (
        <div className="mb-6">
          <Card
            title="Active restrictions"
            description="Currently in force in Checkmarx One. Restoring replays the exact state recorded before the change."
            padded={false}
          >
            <Table>
              <thead>
                <tr>
                  <Th>What changed</Th>
                  <Th>Target</Th>
                  <Th>Because of</Th>
                  <Th>Applied</Th>
                  <Th align="right">Action</Th>
                </tr>
              </thead>
              <tbody>
                {(enforcements.data ?? []).map((action) => (
                  <tr key={action.id}>
                    <Td>{enforcementLabel(action.kind)}</Td>
                    <Td>
                      <span className="font-medium">{action.target_label ?? action.target_id}</span>
                    </Td>
                    <Td>
                      <span className="text-xs">
                        {humanise(action.entity_type)} {action.entity_label ?? action.entity_id}
                        {action.period_key ? ` (${action.period_key})` : ""}
                      </span>
                    </Td>
                    <Td>
                      <span className="text-xs" title={formatDateTime(action.applied_at)}>
                        {formatRelative(action.applied_at)}
                      </span>
                    </Td>
                    <Td align="right">
                      {isAdmin && (
                        <Button
                          size="sm"
                          onClick={() =>
                            setRestoring({
                              id: -1,
                              created_at: action.applied_at ?? action.created_at,
                              severity: "critical",
                              category: "enforcement",
                              entity_type: action.entity_type,
                              entity_id: action.entity_id,
                              entity_label: action.entity_label,
                              title: `${enforcementLabel(action.kind)} on ${action.target_label ?? action.target_id}`,
                              body: null,
                              read_at: null,
                              enforcement_action_id: action.id,
                              can_restore: true,
                            })
                          }
                        >
                          Restore access
                        </Button>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
        </div>
      )}

      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-2 px-5 py-4">
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search notifications"
            className="max-w-xs"
          />
          <Select value={severity} onChange={(event) => setSeverity(event.target.value)} className="max-w-40">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="error">Error</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </Select>
          <Select value={category} onChange={(event) => setCategory(event.target.value)} className="max-w-48">
            {CATEGORIES.map((entry) => (
              <option key={entry.value} value={entry.value}>
                {entry.label}
              </option>
            ))}
          </Select>
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={unreadOnly}
              onChange={(event) => setUnreadOnly(event.target.checked)}
            />
            Unread only
          </label>
          <span className="ml-auto text-xs tabular" style={{ color: "var(--text-muted)" }}>
            {feed.data?.total ?? 0} total, {feed.data?.unread ?? 0} unread
          </span>
        </div>

        {feed.initialLoading ? (
          <div className="px-5 pb-5">
            <Spinner />
          </div>
        ) : feed.error ? (
          <div className="px-5 pb-5">
            <ErrorNote>{feed.error}</ErrorNote>
          </div>
        ) : items.length === 0 ? (
          <EmptyState
            title="Nothing to show"
            description="Warnings and enforcement actions appear here as the scheduler runs."
          />
        ) : (
          <ul>
            {items.map((item) => (
              <li
                key={item.id}
                className="flex flex-wrap items-start gap-3 border-t border-hairline px-5 py-4"
                style={{ background: item.read_at ? undefined : "var(--hover)" }}
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={SEVERITY_TONES[item.severity]}>{humanise(item.severity)}</Badge>
                    <Badge tone="neutral">{humanise(item.category)}</Badge>
                    <span className="text-sm font-medium">{item.title}</span>
                  </div>
                  {item.body && (
                    <p className="mt-1.5 text-xs whitespace-pre-wrap" style={{ color: "var(--text-secondary)" }}>
                      {item.body}
                    </p>
                  )}
                  <p className="mt-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
                    {formatDateTime(item.created_at)}
                    {item.entity_label ? ` · ${item.entity_label}` : ""}
                  </p>
                </div>
                {item.can_restore && isAdmin && (
                  <Button size="sm" onClick={() => setRestoring(item)}>
                    Restore access
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <ConfirmDialog
        open={restoring !== null}
        title="Restore access?"
        confirmLabel="Restore access"
        busy={busy}
        message={
          restoring
            ? `${restoring.title}\n\nThis re-applies the exact state recorded before the restriction: the roles the user held, or the project's previous Auto Triage and PR remediation settings.\n\nThe limit itself is not changed, so the next cycle can restrict again. Switch the limit to monitor only, or add an exemption, if that is not what you want.`
            : ""
        }
        onConfirm={() => restoring?.enforcement_action_id && restore(restoring.enforcement_action_id)}
        onCancel={() => setRestoring(null)}
      />
    </>
  );
}
