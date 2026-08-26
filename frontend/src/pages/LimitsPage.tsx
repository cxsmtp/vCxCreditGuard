import { useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError, api, downloadCsv } from "../api/client";
import type {
  BulkResult,
  CsvImportResult,
  EntityType,
  Exemption,
  Limit,
  OrgEntity,
  PeriodType,
} from "../api/types";
import { EntityPicker } from "../components/EntityPicker";
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
  Modal,
  PageHeader,
  Select,
  Spinner,
  Table,
  Tabs,
  Td,
  Textarea,
  Th,
  Toggle,
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { entityLabel, formatCredits, formatPercent, periodLabel } from "../lib/format";
import { useToast } from "../lib/ui-context";

const ENTITY_TABS: { id: EntityType | "all"; label: string }[] = [
  { id: "all", label: "All" },
  { id: "user", label: "Users" },
  { id: "group", label: "Groups" },
  { id: "project", label: "Projects" },
  { id: "application", label: "Applications" },
];

interface LimitForm {
  credit_limit: string;
  period_type: PeriodType;
  warning_threshold_pct: string;
  enforce: boolean;
  is_active: boolean;
  include_member_usage: boolean;
  hold_until_released: boolean;
  count_existing_usage: boolean;
  custom_period_start: string;
  custom_period_end: string;
  notes: string;
}

const EMPTY_FORM: LimitForm = {
  credit_limit: "",
  period_type: "monthly",
  warning_threshold_pct: "80",
  enforce: false,
  is_active: true,
  include_member_usage: false,
  hold_until_released: false,
  count_existing_usage: false,
  custom_period_start: "",
  custom_period_end: "",
  notes: "",
};

function statusBadge(limit: Limit) {
  const state = limit.current_period;
  if (limit.exempt) return <Badge tone="neutral">Exempt</Badge>;
  if (!limit.is_active) return <Badge tone="neutral">Disabled</Badge>;
  if (state && !state.usage_available) return <Badge tone="neutral">Usage not reported</Badge>;
  switch (state?.status) {
    case "restricted":
      return <Badge tone="critical">Restricted</Badge>;
    case "breached":
      return <Badge tone="critical">Over limit</Badge>;
    case "warned":
      return <Badge tone="warning">Near limit</Badge>;
    case "restored":
      return <Badge tone="good">Restored</Badge>;
    default:
      return <Badge tone="good">Within budget</Badge>;
  }
}

function UsageBar({ limit }: { limit: Limit }) {
  const state = limit.current_period;
  if (!state) {
    return (
      <span className="text-xs" style={{ color: "var(--text-muted)" }}>
        Not evaluated yet
      </span>
    );
  }
  if (!state.usage_available) {
    return (
      <span className="text-xs" style={{ color: "var(--text-muted)" }}>
        Not reported for this level
      </span>
    );
  }
  const percent = state.percent_used ?? 0;
  const clamped = Math.min(percent, 100);
  const color =
    percent >= 100
      ? "var(--status-critical)"
      : percent >= limit.warning_threshold_pct
        ? "var(--status-warning)"
        : "var(--series-1)";
  // The reported total is shown whenever it differs from what counts towards the
  // budget. Without it, a project that Checkmarx says used 13 credits reading as 0
  // here looks like a defect rather than a period boundary.
  const discounted = Number(state.baseline_credits) > 0;

  return (
    <div className="min-w-[9rem]">
      <div className="mb-1 flex items-baseline justify-between gap-2 text-xs tabular">
        <span>
          {formatCredits(state.credits_used)} of {formatCredits(limit.credit_limit)}
        </span>
        <span style={{ color: "var(--text-muted)" }}>{formatPercent(percent)}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-sm" style={{ background: "var(--hover)" }}>
        <div
          className="h-full"
          style={{
            width: `${Math.max(clamped, percent > 0 ? 2 : 0)}%`,
            background: color,
            borderTopRightRadius: 4,
            borderBottomRightRadius: 4,
          }}
        />
      </div>
      {discounted && (
        <p
          className="mt-1 text-xs tabular"
          style={{ color: "var(--text-muted)" }}
          title={
            `Checkmarx reports ${formatCredits(state.reported_total)} credits for this entity over its ` +
            `lookback window. ${formatCredits(state.baseline_credits)} of those were already spent when ` +
            `this period opened, so they do not count against this budget. Turn on "count consumption ` +
            `that predates this period" to include them.`
          }
        >
          {formatCredits(state.reported_total)} reported,{" "}
          {formatCredits(state.baseline_credits)} before this period
        </p>
      )}
    </div>
  );
}

export function LimitsPage({ isAdmin }: { isAdmin: boolean }) {
  const toast = useToast();
  const [searchParams, setSearchParams] = useSearchParams();
  const [tab, setTab] = useState<EntityType | "all">(
    (searchParams.get("entity_type") as EntityType) ?? "all",
  );
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Limit | null>(null);
  const [deleting, setDeleting] = useState<Limit | null>(null);
  const [bulkOpen, setBulkOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const limits = useResource<Limit[]>((signal) => api.get("/api/limits", undefined, signal), []);
  const exemptions = useResource<Exemption[]>(
    (signal) => api.get("/api/exemptions", undefined, signal),
    [],
  );

  const highlightId = searchParams.get("entity_id");

  const visible = useMemo(() => {
    const rows = limits.data ?? [];
    const term = search.trim().toLowerCase();
    return rows.filter((limit) => {
      if (tab !== "all" && limit.entity_type !== tab) return false;
      if (!term) return true;
      return (
        (limit.entity_label ?? "").toLowerCase().includes(term) ||
        limit.entity_id.toLowerCase().includes(term)
      );
    });
  }, [limits.data, tab, search]);

  const counts = useMemo(() => {
    const rows = limits.data ?? [];
    return {
      all: rows.length,
      user: rows.filter((row) => row.entity_type === "user").length,
      group: rows.filter((row) => row.entity_type === "group").length,
      project: rows.filter((row) => row.entity_type === "project").length,
      application: rows.filter((row) => row.entity_type === "application").length,
    };
  }, [limits.data]);

  function toggleSelected(id: number) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function reloadAll() {
    await Promise.all([limits.reload(), exemptions.reload()]);
    setSelected(new Set());
  }

  async function toggleEnforce(limit: Limit, enforce: boolean) {
    setBusy(true);
    try {
      await api.patch<Limit>(`/api/limits/${limit.id}`, { enforce });
      toast.success(
        enforce
          ? `${limit.entity_label ?? limit.entity_id} will now be restricted when the limit is reached.`
          : `${limit.entity_label ?? limit.entity_id} is monitor only. Any restriction it caused has been lifted.`,
      );
      await reloadAll();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not update the limit.");
    } finally {
      setBusy(false);
    }
  }

  async function toggleExempt(limit: Limit) {
    setBusy(true);
    try {
      if (limit.exempt) {
        const row = (exemptions.data ?? []).find(
          (item) => item.entity_type === limit.entity_type && item.entity_id === limit.entity_id,
        );
        if (row) await api.delete(`/api/exemptions/${row.id}`);
        toast.info("Exemption removed. This entity can be restricted again.");
      } else {
        await api.post("/api/exemptions", {
          entity_type: limit.entity_type,
          entity_id: limit.entity_id,
        });
        toast.success("Exemption added. Any active restriction has been lifted.");
      }
      await reloadAll();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not change the exemption.");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!deleting) return;
    setBusy(true);
    try {
      const result = await api.delete<{ restrictions_lifted: number }>(`/api/limits/${deleting.id}`);
      toast.success(
        result.restrictions_lifted > 0
          ? `Limit deleted and ${result.restrictions_lifted} restriction(s) lifted.`
          : "Limit deleted.",
      );
      setDeleting(null);
      await reloadAll();
    } catch (caught) {
      toast.error(caught instanceof ApiError ? caught.message : "Could not delete the limit.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Limits"
        description="Budgets for users, groups, projects and applications. A new limit is monitor only until you turn enforcement on."
        actions={
          <>
            <Button
              size="sm"
              onClick={() =>
                downloadCsv("/api/limits/export", "cxcreditguard-limits.csv").catch(() =>
                  toast.error("The export could not be downloaded."),
                )
              }
            >
              Export CSV
            </Button>
            {isAdmin && (
              <>
                <Button size="sm" onClick={() => setImportOpen(true)}>
                  Import CSV
                </Button>
                <Button size="sm" variant="primary" onClick={() => setCreating(true)}>
                  New limit
                </Button>
              </>
            )}
          </>
        }
      />

      <Card padded={false}>
        <div className="flex flex-wrap items-center gap-3 px-5 pt-4">
          <Tabs
            tabs={ENTITY_TABS.map((entry) => ({
              id: entry.id,
              label: entry.label,
              count: counts[entry.id as keyof typeof counts],
            }))}
            active={tab}
            onChange={(id) => {
              setTab(id);
              const next = new URLSearchParams(searchParams);
              if (id === "all") next.delete("entity_type");
              else next.set("entity_type", id);
              setSearchParams(next, { replace: true });
            }}
          />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3">
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter by name"
            className="max-w-xs"
          />
          {isAdmin && selected.size > 0 && (
            <div className="flex items-center gap-2 text-xs">
              <span style={{ color: "var(--text-secondary)" }}>
                {selected.size} selected
              </span>
              <Button size="sm" onClick={() => setBulkOpen(true)}>
                Bulk edit
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
                Clear
              </Button>
            </div>
          )}
        </div>

        {limits.initialLoading ? (
          <div className="px-5 pb-5">
            <Spinner />
          </div>
        ) : limits.error ? (
          <div className="px-5 pb-5">
            <ErrorNote>{limits.error}</ErrorNote>
          </div>
        ) : visible.length === 0 ? (
          <EmptyState
            title="No limits here yet"
            description={
              isAdmin
                ? "Create one to start monitoring credit consumption. Monitoring has no side effects."
                : "An Admin has not configured any limits at this level."
            }
            action={
              isAdmin && (
                <Button variant="primary" onClick={() => setCreating(true)}>
                  New limit
                </Button>
              )
            }
          />
        ) : (
          <Table>
            <thead>
              <tr>
                {isAdmin && <Th className="w-8" />}
                <Th>Entity</Th>
                <Th>Level</Th>
                <Th>Period</Th>
                <Th>Usage this period</Th>
                <Th>Status</Th>
                <Th>Mode</Th>
                <Th align="right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {visible.map((limit) => (
                <tr
                  key={limit.id}
                  style={
                    highlightId && limit.entity_id === highlightId
                      ? { background: "var(--hover)" }
                      : undefined
                  }
                >
                  {isAdmin && (
                    <Td>
                      <input
                        type="checkbox"
                        checked={selected.has(limit.id)}
                        onChange={() => toggleSelected(limit.id)}
                        aria-label={`Select ${limit.entity_label ?? limit.entity_id}`}
                      />
                    </Td>
                  )}
                  <Td>
                    <div className="min-w-0">
                      <p className="truncate font-medium">{limit.entity_label ?? limit.entity_id}</p>
                      <p className="truncate text-xs font-mono" style={{ color: "var(--text-muted)" }}>
                        {limit.entity_id}
                      </p>
                      {limit.notes && (
                        <p className="mt-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
                          {limit.notes}
                        </p>
                      )}
                    </div>
                  </Td>
                  <Td>{entityLabel(limit.entity_type)}</Td>
                  <Td>
                    <span className="text-xs">{periodLabel(limit.period_type)}</span>
                    {limit.current_period && (
                      <span className="block text-xs" style={{ color: "var(--text-muted)" }}>
                        {limit.current_period.period_key}
                      </span>
                    )}
                  </Td>
                  <Td>
                    <UsageBar limit={limit} />
                  </Td>
                  <Td>
                    <div className="flex flex-col items-start gap-1">
                      {statusBadge(limit)}
                      {limit.active_restrictions > 0 && (
                        <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                          {limit.active_restrictions} active
                        </span>
                      )}
                    </div>
                  </Td>
                  <Td>
                    {isAdmin ? (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => toggleEnforce(limit, !limit.enforce)}
                        className="text-xs underline"
                        style={{
                          color: limit.enforce ? "var(--status-critical)" : "var(--text-secondary)",
                        }}
                      >
                        {limit.enforce ? "Enforcing" : "Monitor only"}
                      </button>
                    ) : (
                      <span className="text-xs">{limit.enforce ? "Enforcing" : "Monitor only"}</span>
                    )}
                  </Td>
                  <Td align="right">
                    {isAdmin && (
                      <div className="flex justify-end gap-2 text-xs">
                        <button
                          type="button"
                          className="underline"
                          onClick={() => setEditing(limit)}
                          style={{ color: "var(--text-secondary)" }}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="underline"
                          onClick={() => toggleExempt(limit)}
                          style={{ color: "var(--text-secondary)" }}
                        >
                          {limit.exempt ? "Unexempt" : "Exempt"}
                        </button>
                        <button
                          type="button"
                          className="underline"
                          onClick={() => setDeleting(limit)}
                          style={{ color: "var(--status-critical)" }}
                        >
                          Delete
                        </button>
                      </div>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      {(exemptions.data ?? []).length > 0 && (
        <div className="mt-6">
          <Card
            title="Exemptions"
            description="These entities are never restricted, whatever their usage. Limits on them still report."
          >
            <ul className="flex flex-wrap gap-2">
              {(exemptions.data ?? []).map((row) => (
                <li
                  key={row.id}
                  className="flex items-center gap-2 rounded-md border border-hairline px-2.5 py-1.5 text-xs"
                >
                  <span className="font-medium">{row.entity_label ?? row.entity_id}</span>
                  <span style={{ color: "var(--text-muted)" }}>{entityLabel(row.entity_type)}</span>
                  {row.reason && <span style={{ color: "var(--text-secondary)" }}>{row.reason}</span>}
                  {isAdmin && (
                    <button
                      type="button"
                      className="underline"
                      style={{ color: "var(--text-secondary)" }}
                      onClick={async () => {
                        await api.delete(`/api/exemptions/${row.id}`);
                        await reloadAll();
                      }}
                    >
                      Remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}

      {creating && (
        <LimitDialog
          onClose={() => setCreating(false)}
          onSaved={async () => {
            setCreating(false);
            await reloadAll();
          }}
        />
      )}

      {editing && (
        <LimitDialog
          limit={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await reloadAll();
          }}
        />
      )}

      {bulkOpen && (
        <BulkDialog
          ids={[...selected]}
          onClose={() => setBulkOpen(false)}
          onSaved={async () => {
            setBulkOpen(false);
            await reloadAll();
          }}
        />
      )}

      {importOpen && (
        <ImportDialog
          onClose={() => setImportOpen(false)}
          onImported={async () => {
            setImportOpen(false);
            await reloadAll();
          }}
        />
      )}

      <ConfirmDialog
        open={deleting !== null}
        title="Delete this limit?"
        destructive
        confirmLabel="Delete limit"
        busy={busy}
        message={
          deleting
            ? `The limit on ${deleting.entity_label ?? deleting.entity_id} will be removed.` +
              (deleting.active_restrictions > 0
                ? `\n\n${deleting.active_restrictions} active restriction(s) caused by it will be lifted first, so nobody is left locked out by a limit that no longer exists.`
                : "")
            : ""
        }
        onConfirm={remove}
        onCancel={() => setDeleting(null)}
      />
    </>
  );
}

/* --------------------------------------------------------------- create/edit */

function LimitDialog({
  limit,
  onClose,
  onSaved,
}: {
  limit?: Limit;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const toast = useToast();
  const editing = limit !== undefined;
  const [entityType, setEntityType] = useState<EntityType>(limit?.entity_type ?? "user");
  const [entity, setEntity] = useState<OrgEntity | null>(
    limit
      ? {
          entity_type: limit.entity_type,
          entity_id: limit.entity_id,
          label: limit.entity_label ?? limit.entity_id,
          secondary: null,
          has_limit: true,
          is_exempt: limit.exempt,
          is_deleted: false,
        }
      : null,
  );
  const [form, setForm] = useState<LimitForm>(
    limit
      ? {
          credit_limit: String(limit.credit_limit),
          period_type: limit.period_type,
          warning_threshold_pct: String(limit.warning_threshold_pct),
          enforce: limit.enforce,
          is_active: limit.is_active,
          include_member_usage: limit.include_member_usage,
          hold_until_released: limit.hold_until_released,
          count_existing_usage: limit.count_existing_usage,
          custom_period_start: limit.custom_period_start?.slice(0, 10) ?? "",
          custom_period_end: limit.custom_period_end?.slice(0, 10) ?? "",
          notes: limit.notes ?? "",
        }
      : EMPTY_FORM,
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function update<K extends keyof LimitForm>(key: K, value: LimitForm[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const payload: Record<string, unknown> = {
        credit_limit: Number(form.credit_limit),
        period_type: form.period_type,
        warning_threshold_pct: Number(form.warning_threshold_pct),
        enforce: form.enforce,
        include_member_usage: form.include_member_usage,
        hold_until_released: form.hold_until_released,
        count_existing_usage: form.count_existing_usage,
        notes: form.notes.trim() || null,
      };
      if (form.period_type === "custom") {
        payload.custom_period_start = form.custom_period_start
          ? new Date(`${form.custom_period_start}T00:00:00Z`).toISOString()
          : null;
        payload.custom_period_end = form.custom_period_end
          ? new Date(`${form.custom_period_end}T00:00:00Z`).toISOString()
          : null;
      }

      if (editing && limit) {
        payload.is_active = form.is_active;
        await api.patch(`/api/limits/${limit.id}`, payload);
        toast.success("Limit updated.");
      } else {
        if (!entity) {
          setError("Choose an entity first.");
          setBusy(false);
          return;
        }
        await api.post("/api/limits", {
          ...payload,
          entity_type: entity.entity_type,
          entity_id: entity.entity_id,
        });
        toast.success(
          form.enforce
            ? "Limit created in enforce mode."
            : "Limit created in monitor only mode. Nothing will be restricted.",
        );
      }
      await onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not save the limit.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title={editing ? "Edit limit" : "New limit"}
      description={
        editing
          ? `${limit?.entity_label ?? limit?.entity_id}`
          : "Pick an entity, set a budget, and decide whether to enforce it."
      }
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={save}
            loading={busy}
            disabled={!form.credit_limit || (!editing && !entity)}
          >
            {editing ? "Save changes" : "Create limit"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-5">
        {error && <ErrorNote>{error}</ErrorNote>}

        {!editing && (
          <EntityPicker
            entityType={entityType}
            onEntityTypeChange={setEntityType}
            selected={entity}
            onSelect={setEntity}
          />
        )}

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Credit limit" required hint="Credits allowed per period.">
            <Input
              type="number"
              min={0}
              value={form.credit_limit}
              onChange={(event) => update("credit_limit", event.target.value)}
            />
          </Field>

          <Field label="Budget period">
            <Select
              value={form.period_type}
              onChange={(event) => update("period_type", event.target.value as PeriodType)}
            >
              <option value="monthly">Monthly</option>
              <option value="quarterly">Quarterly</option>
              <option value="custom">Custom range</option>
              <option value="lifetime">Lifetime</option>
            </Select>
          </Field>
        </div>

        {form.period_type === "custom" && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Start date" required>
              <Input
                type="date"
                value={form.custom_period_start}
                onChange={(event) => update("custom_period_start", event.target.value)}
              />
            </Field>
            <Field label="End date" hint="Leave empty for an open ended range.">
              <Input
                type="date"
                value={form.custom_period_end}
                onChange={(event) => update("custom_period_end", event.target.value)}
              />
            </Field>
          </div>
        )}

        <Field
          label="Warning threshold (percent)"
          hint="A notification is raised once per period when usage passes this share of the limit."
        >
          <Input
            type="number"
            min={1}
            max={100}
            value={form.warning_threshold_pct}
            onChange={(event) => update("warning_threshold_pct", event.target.value)}
          />
        </Field>

        <div className="flex flex-col gap-3 border-t border-hairline pt-4">
          <Toggle
            checked={form.enforce}
            onChange={(value) => update("enforce", value)}
            label="Enforce this limit"
            description={
              form.enforce
                ? "When the limit is reached, access will be restricted. Every restriction is reversible from the Notification Center."
                : "Monitor only. Warnings and breaches are recorded, and nothing is restricted."
            }
          />

          {(entity?.entity_type ?? limit?.entity_type) === "group" && (
            <Toggle
              checked={form.include_member_usage}
              onChange={(value) => update("include_member_usage", value)}
              label="Count usage by group members as well as by group projects"
              description="Off by default, because a group whose members also work on its projects would otherwise count the same credits twice."
            />
          )}

          {form.period_type === "monthly" || form.period_type === "quarterly" ? (
            <Toggle
              checked={form.count_existing_usage}
              onChange={(value) => update("count_existing_usage", value)}
              label="Count consumption that predates this period"
              description="Off by default. Checkmarx reports a lookback window wider than one period and does not say when inside it the credits were spent, so counting all of it could exhaust a fresh budget on day one. Turn it on if you want the figure Checkmarx shows to count in full."
            />
          ) : (
            <InfoNote>
              {periodLabel(form.period_type)} budgets count every credit Checkmarx
              reports, including consumption from before the limit was created.
            </InfoNote>
          )}

          <Toggle
            checked={form.hold_until_released}
            onChange={(value) => update("hold_until_released", value)}
            label="Hold restrictions until manually released"
            description="By default a new budget period lifts restrictions automatically. Turn this on to keep them until you release them yourself."
          />

          {editing && (
            <Toggle
              checked={form.is_active}
              onChange={(value) => update("is_active", value)}
              label="Limit is active"
              description="Disabling stops evaluation and lifts any restriction this limit caused."
            />
          )}
        </div>

        <Field label="Notes" hint="Optional. Shown in the limits table.">
          <Textarea
            rows={2}
            value={form.notes}
            onChange={(event) => update("notes", event.target.value)}
            maxLength={1024}
          />
        </Field>

        {form.enforce && (
          <InfoNote tone="warning">
            Enforcement changes real access in Checkmarx One. For a user it removes the AI Triage and
            Remediation roles; for a project, group or application it disables Auto Triage and PR
            remediation on the affected projects.
          </InfoNote>
        )}
      </div>
    </Modal>
  );
}

/* -------------------------------------------------------------------- bulk */

function BulkDialog({
  ids,
  onClose,
  onSaved,
}: {
  ids: number[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const toast = useToast();
  const [creditLimit, setCreditLimit] = useState("");
  const [threshold, setThreshold] = useState("");
  const [enforce, setEnforce] = useState<"unchanged" | "on" | "off">("unchanged");
  const [active, setActive] = useState<"unchanged" | "on" | "off">("unchanged");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      const payload: Record<string, unknown> = { limit_ids: ids };
      if (creditLimit) payload.credit_limit = Number(creditLimit);
      if (threshold) payload.warning_threshold_pct = Number(threshold);
      if (enforce !== "unchanged") payload.enforce = enforce === "on";
      if (active !== "unchanged") payload.is_active = active === "on";

      const result = await api.post<BulkResult>("/api/limits/bulk", payload);
      if (result.errors.length > 0) {
        toast.error(result.errors.join("; "));
      }
      toast.success(
        `${result.updated} limit(s) updated.` +
          (result.restrictions_lifted > 0
            ? ` ${result.restrictions_lifted} restriction(s) lifted.`
            : ""),
      );
      await onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The bulk edit failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title={`Bulk edit ${ids.length} limit(s)`}
      description="Only the fields you set are changed. The rest are left alone."
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={apply} loading={busy}>
            Apply to {ids.length}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {error && <ErrorNote>{error}</ErrorNote>}
        <Field label="Credit limit" hint="Leave empty to keep each limit as it is.">
          <Input
            type="number"
            min={0}
            value={creditLimit}
            onChange={(event) => setCreditLimit(event.target.value)}
          />
        </Field>
        <Field label="Warning threshold (percent)" hint="Leave empty to keep the current value.">
          <Input
            type="number"
            min={1}
            max={100}
            value={threshold}
            onChange={(event) => setThreshold(event.target.value)}
          />
        </Field>
        <Field label="Enforcement">
          <Select value={enforce} onChange={(event) => setEnforce(event.target.value as typeof enforce)}>
            <option value="unchanged">Leave unchanged</option>
            <option value="off">Switch to monitor only (lifts restrictions)</option>
            <option value="on">Switch to enforcing</option>
          </Select>
        </Field>
        <Field label="Active">
          <Select value={active} onChange={(event) => setActive(event.target.value as typeof active)}>
            <option value="unchanged">Leave unchanged</option>
            <option value="on">Active</option>
            <option value="off">Disabled (lifts restrictions)</option>
          </Select>
        </Field>
        {enforce === "on" && (
          <InfoNote tone="warning">
            Switching limits to enforcing means the next cycle can restrict access for any of them
            that is already over budget.
          </InfoNote>
        )}
      </div>
    </Modal>
  );
}

/* ------------------------------------------------------------------ import */

function ImportDialog({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: () => Promise<void>;
}) {
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<CsvImportResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(dryRun: boolean) {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const result = await api.upload<CsvImportResult>("/api/limits/import", formData, {
        dry_run: dryRun,
      });
      setPreview(result);
      if (!dryRun && result.errors.length === 0) {
        toast.success(`${result.created} created, ${result.updated} updated.`);
        await onImported();
      }
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "The file could not be read.");
    } finally {
      setBusy(false);
    }
  }

  const validated = preview !== null && preview.errors.length === 0;

  return (
    <Modal
      open
      title="Import limits from CSV"
      description="The file is validated first. A file with any bad row applies none of it."
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => send(true)} disabled={!file} loading={busy}>
            Validate
          </Button>
          <Button variant="primary" onClick={() => send(false)} disabled={!validated} loading={busy}>
            Apply import
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        {error && <ErrorNote>{error}</ErrorNote>}

        <Field
          label="CSV file"
          hint="Required columns: entity_type, entity_id, credit_limit. Export the current limits first to get the full header."
        >
          <input
            ref={fileRef}
            type="file"
            accept=".csv,text/csv"
            onChange={(event) => {
              setFile(event.target.files?.[0] ?? null);
              setPreview(null);
            }}
            className="w-full text-sm"
          />
        </Field>

        <InfoNote>
          Rows without an enforce column are imported as monitor only. An import can never switch on
          enforcement by omission.
        </InfoNote>

        {preview && (
          <div className="rounded-md border border-hairline p-3 text-sm">
            <p className="font-medium">
              {preview.dry_run ? "Validation result" : "Import applied"}
            </p>
            <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
              {preview.created} to create, {preview.updated} to update
              {preview.skipped > 0 ? `, ${preview.skipped} skipped` : ""}.
            </p>
            {preview.errors.length > 0 && (
              <ul className="mt-2 flex flex-col gap-1 text-xs" style={{ color: "var(--status-critical)" }}>
                {preview.errors.slice(0, 12).map((message) => (
                  <li key={message}>{message}</li>
                ))}
                {preview.errors.length > 12 && <li>and {preview.errors.length - 12} more</li>}
              </ul>
            )}
            {validated && preview.dry_run && (
              <p className="mt-2 text-xs" style={{ color: "var(--status-good-text)" }}>
                No problems found. Apply the import to write these limits.
              </p>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
}
