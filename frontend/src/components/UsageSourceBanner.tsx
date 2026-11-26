import { api } from "../api/client";
import { useResource } from "../hooks/useResource";
import { formatDateTime } from "../lib/format";
import { InfoNote } from "./ui";

interface UsageSourceInfo {
  setting: string | null;
  status: string | null;
  restrictions_held: {
    reason: string | null;
    since: string | null;
    summary_only: boolean;
  } | null;
}

/**
 * Shown while new restrictions of monthly and quarterly budgets are paused:
 * their usage comes from the consumption summary, which warns but does not
 * restrict (only usage counted from the credit activity log does).
 */
export function UsageSourceBanner() {
  const info = useResource<UsageSourceInfo>(
    (signal) => api.get("/api/usage/source", undefined, signal),
    [],
  );
  const held = info.data?.restrictions_held;
  if (!held) return null;
  const why = held.summary_only
    ? "the usage source is the consumption summary only"
    : `activity log unavailable${held.since ? ` since ${formatDateTime(held.since)}` : ""}`;
  return (
    <div className="mb-4">
      <InfoNote tone="warning">
        Restrictions paused for period budgets: {why}. Monthly and quarterly budgets over their
        limit on summary totals are warned, not restricted; restrictions already in force stay, and
        lifetime, custom and count-existing budgets restrict as usual.
      </InfoNote>
    </div>
  );
}
