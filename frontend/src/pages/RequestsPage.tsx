import { useState } from "react";
import { api, ApiError } from "../api/client";
import type { CreditRequest, EntityType, OrgEntity, RequestStatus } from "../api/types";
import { EntityPicker } from "../components/EntityPicker";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Input,
  Modal,
  PageHeader,
  Spinner,
  Table,
  Tabs,
  Td,
  Textarea,
  Th,
  type BadgeTone,
} from "../components/ui";
import { useResource } from "../hooks/useResource";
import { entityLabel, formatCredits, formatDateTime } from "../lib/format";
import { useToast } from "../lib/ui-context";

type StatusTab = "pending" | "approved" | "denied" | "all";

const STATUS_TONE: Record<RequestStatus, BadgeTone> = {
  pending: "warning",
  approved: "good",
  denied: "neutral",
};

const STATUS_LABEL: Record<RequestStatus, string> = {
  pending: "Pending",
  approved: "Approved",
  denied: "Denied",
};

export function RequestsPage({ isAdmin }: { isAdmin: boolean }) {
  const [tab, setTab] = useState<StatusTab>(isAdmin ? "pending" : "all");
  const [creating, setCreating] = useState(false);
  const [deciding, setDeciding] = useState<{ request: CreditRequest; approve: boolean } | null>(
    null,
  );

  const requests = useResource<CreditRequest[]>(
    (signal) =>
      api.get<CreditRequest[]>(
        "/api/requests",
        tab === "all" ? undefined : { status: tab },
        signal,
      ),
    [tab],
  );

  const rows = requests.data ?? [];

  return (
    <div>
      <PageHeader
        title="Credit requests"
        description={
          isAdmin
            ? "Review requests to raise an entity's budget. Approving applies the budget as a monitor only limit; a temporary grant is rolled back automatically when it expires."
            : "Ask for a higher budget for a user, group, project or application. An admin approves or declines each request."
        }
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            New request
          </Button>
        }
      />

      <Tabs<StatusTab>
        tabs={[
          { id: "pending", label: "Pending" },
          { id: "approved", label: "Approved" },
          { id: "denied", label: "Denied" },
          { id: "all", label: "All" },
        ]}
        active={tab}
        onChange={setTab}
      />

      <div className="mt-4">
        <Card padded={false}>
          {requests.initialLoading ? (
            <div
              className="flex items-center gap-2 px-5 py-10 text-sm"
              style={{ color: "var(--text-secondary)" }}
            >
              <Spinner /> Loading requests
            </div>
          ) : requests.error ? (
            <div className="p-5">
              <ErrorNote>{requests.error}</ErrorNote>
            </div>
          ) : rows.length === 0 ? (
            <EmptyState
              title="No requests here"
              description={
                tab === "pending"
                  ? "Nothing is waiting on a decision."
                  : "No requests match this filter yet."
              }
            />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Entity</Th>
                  <Th align="right">Requested</Th>
                  <Th>Status</Th>
                  <Th>Requested by</Th>
                  <Th>When</Th>
                  <Th>Outcome</Th>
                  {isAdmin && <Th align="right">Actions</Th>}
                </tr>
              </thead>
              <tbody>
                {rows.map((request) => (
                  <RequestRow
                    key={request.id}
                    request={request}
                    isAdmin={isAdmin}
                    onDecide={(approve) => setDeciding({ request, approve })}
                  />
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </div>

      {creating && (
        <RequestDialog
          onClose={() => setCreating(false)}
          onSaved={async () => {
            setCreating(false);
            await requests.reload();
          }}
        />
      )}

      {deciding && (
        <DecisionDialog
          request={deciding.request}
          approve={deciding.approve}
          onClose={() => setDeciding(null)}
          onSaved={async () => {
            setDeciding(null);
            await requests.reload();
          }}
        />
      )}
    </div>
  );
}

function RequestRow({
  request,
  isAdmin,
  onDecide,
}: {
  request: CreditRequest;
  isAdmin: boolean;
  onDecide: (approve: boolean) => void;
}) {
  return (
    <tr>
      <Td>
        <span className="font-medium">{request.entity_label ?? request.entity_id}</span>
        <span className="ml-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
          {entityLabel(request.entity_type)}
        </span>
        {request.reason && (
          <p className="mt-0.5 max-w-xs text-xs" style={{ color: "var(--text-secondary)" }}>
            {request.reason}
          </p>
        )}
      </Td>
      <Td align="right" className="tabular">
        {formatCredits(request.requested_limit)}
      </Td>
      <Td>
        <Badge tone={STATUS_TONE[request.status]}>{STATUS_LABEL[request.status]}</Badge>
      </Td>
      <Td>{request.requested_by_name ?? "Unknown"}</Td>
      <Td className="whitespace-nowrap text-xs" >
        {formatDateTime(request.requested_at)}
      </Td>
      <Td>
        <RequestOutcome request={request} />
      </Td>
      {isAdmin && (
        <Td align="right">
          {request.status === "pending" ? (
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="primary" onClick={() => onDecide(true)}>
                Approve
              </Button>
              <Button size="sm" variant="secondary" onClick={() => onDecide(false)}>
                Deny
              </Button>
            </div>
          ) : (
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Decided
            </span>
          )}
        </Td>
      )}
    </tr>
  );
}

function RequestOutcome({ request }: { request: CreditRequest }) {
  if (request.status === "pending") {
    return (
      <span className="text-xs" style={{ color: "var(--text-muted)" }}>
        Awaiting a decision
      </span>
    );
  }
  return (
    <div className="text-xs" style={{ color: "var(--text-secondary)" }}>
      {request.status === "approved" && request.approved_limit !== null && (
        <p>
          Granted {formatCredits(request.approved_limit)}
          {request.previous_limit !== null && ` (was ${formatCredits(request.previous_limit)})`}
        </p>
      )}
      {request.expires_at && (
        <p>
          {request.reverted ? "Expired " : "Expires "}
          {formatDateTime(request.expires_at)}
        </p>
      )}
      {request.decided_by_name && <p>by {request.decided_by_name}</p>}
      {request.decision_note && (
        <p className="mt-0.5 italic" style={{ color: "var(--text-muted)" }}>
          “{request.decision_note}”
        </p>
      )}
    </div>
  );
}

function RequestDialog({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const toast = useToast();
  const [entityType, setEntityType] = useState<EntityType>("user");
  const [entity, setEntity] = useState<OrgEntity | null>(null);
  const [requestedLimit, setRequestedLimit] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!entity) {
      setError("Choose an entity first.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/requests", {
        entity_type: entity.entity_type,
        entity_id: entity.entity_id,
        requested_limit: Number(requestedLimit),
        reason: reason.trim() || null,
      });
      toast.success("Request submitted for review.");
      await onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not submit the request.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title="Request a higher budget"
      description="Pick an entity and the budget you need. An admin decides whether to grant it."
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={submit}
            loading={busy}
            disabled={!entity || !requestedLimit}
          >
            Submit request
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-5">
        {error && <ErrorNote>{error}</ErrorNote>}
        <EntityPicker
          entityType={entityType}
          onEntityTypeChange={setEntityType}
          selected={entity}
          onSelect={setEntity}
          disabled={busy}
        />
        <Field label="Requested budget (credits)" required>
          <Input
            type="number"
            min={0}
            value={requestedLimit}
            onChange={(event) => setRequestedLimit(event.target.value)}
            placeholder="e.g. 1000"
          />
        </Field>
        <Field label="Reason" hint="Optional, but it helps the admin decide.">
          <Textarea
            rows={3}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Why is more budget needed?"
          />
        </Field>
      </div>
    </Modal>
  );
}

function DecisionDialog({
  request,
  approve,
  onClose,
  onSaved,
}: {
  request: CreditRequest;
  approve: boolean;
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const toast = useToast();
  const [approvedLimit, setApprovedLimit] = useState(String(request.requested_limit));
  const [temporary, setTemporary] = useState(false);
  const [expiresAt, setExpiresAt] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      if (approve) {
        let expiresIso: string | null = null;
        if (temporary) {
          if (!expiresAt) {
            setError("Set an expiry date, or turn off the temporary grant.");
            setBusy(false);
            return;
          }
          const parsed = new Date(expiresAt);
          if (Number.isNaN(parsed.getTime()) || parsed.getTime() <= Date.now()) {
            setError("The expiry must be a date in the future.");
            setBusy(false);
            return;
          }
          expiresIso = parsed.toISOString();
        }
        await api.post(`/api/requests/${request.id}/approve`, {
          approved_limit: Number(approvedLimit),
          expires_at: expiresIso,
          note: note.trim() || null,
        });
        toast.success("Request approved and budget applied.");
      } else {
        await api.post(`/api/requests/${request.id}/deny`, {
          note: note.trim() || null,
        });
        toast.success("Request denied.");
      }
      await onSaved();
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not record the decision.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open
      title={approve ? "Approve request" : "Deny request"}
      description={`${request.entity_label ?? request.entity_id} — requested ${formatCredits(
        request.requested_limit,
      )} credits`}
      onClose={onClose}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={approve ? "primary" : "danger"}
            onClick={submit}
            loading={busy}
            disabled={approve && !approvedLimit}
          >
            {approve ? "Approve and apply" : "Deny request"}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-5">
        {error && <ErrorNote>{error}</ErrorNote>}
        {approve ? (
          <>
            <Field
              label="Budget to grant (credits)"
              required
              hint="Grant less than requested if you prefer; this becomes a monitor only limit."
            >
              <Input
                type="number"
                min={0}
                value={approvedLimit}
                onChange={(event) => setApprovedLimit(event.target.value)}
              />
            </Field>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={temporary}
                onChange={(event) => setTemporary(event.target.checked)}
              />
              Temporary grant (roll back automatically when it expires)
            </label>
            {temporary && (
              <Field label="Expires at" required>
                <Input
                  type="datetime-local"
                  value={expiresAt}
                  onChange={(event) => setExpiresAt(event.target.value)}
                />
              </Field>
            )}
          </>
        ) : null}
        <Field label={approve ? "Note" : "Reason"} hint="Recorded on the request and in the audit log.">
          <Textarea
            rows={3}
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder={approve ? "Optional note for the requester." : "Why is this being declined?"}
          />
        </Field>
      </div>
    </Modal>
  );
}
