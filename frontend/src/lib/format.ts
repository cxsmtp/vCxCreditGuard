/** Formatting helpers. No em dashes in any user visible string. */

export function formatCredits(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "0";
  const numeric = typeof value === "number" ? value : Number(value);
  if (Number.isNaN(numeric)) return String(value);
  const fractional = Math.abs(numeric % 1) > 0.0001;
  return numeric.toLocaleString(undefined, {
    minimumFractionDigits: fractional ? 2 : 0,
    maximumFractionDigits: fractional ? 2 : 0,
  });
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "0";
  return value.toLocaleString();
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined) return "";
  return `${value.toFixed(digits)}%`;
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return value;
  const seconds = Math.round((then - Date.now()) / 1000);
  const absolute = Math.abs(seconds);
  const units: [number, Intl.RelativeTimeFormatUnit][] = [
    [60, "second"],
    [3600, "minute"],
    [86400, "hour"],
    [2592000, "day"],
  ];
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (absolute < 60) return formatter.format(seconds, "second");
  if (absolute < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (absolute < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  if (absolute < 2592000) return formatter.format(Math.round(seconds / 86400), "day");
  void units;
  return formatDate(value);
}

/** Turns "ai_triage" into "AI triage" and "dast_correlation" into "DAST correlation". */
const ACTION_LABELS: Record<string, string> = {
  triage: "AI Triage",
  auto_triage: "Auto Triage",
  remediation: "AI Remediation",
  dast_correlation: "DAST correlation",
  fusion: "Fusion scan",
  unknown: "Unattributed",
};

export function actionLabel(actionType: string): string {
  return ACTION_LABELS[actionType] ?? humanise(actionType);
}

export function humanise(value: string): string {
  const spaced = value.replace(/[_.-]+/g, " ").trim();
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

const ENTITY_LABELS: Record<string, string> = {
  user: "User",
  group: "Group",
  project: "Project",
  application: "Application",
};

export function entityLabel(entityType: string): string {
  return ENTITY_LABELS[entityType] ?? humanise(entityType);
}

const PERIOD_LABELS: Record<string, string> = {
  monthly: "Monthly",
  quarterly: "Quarterly",
  custom: "Custom range",
  lifetime: "Lifetime",
};

export function periodLabel(periodType: string): string {
  return PERIOD_LABELS[periodType] ?? humanise(periodType);
}

const ENFORCEMENT_LABELS: Record<string, string> = {
  remove_user_roles: "AI roles removed",
  disable_auto_triage: "Auto Triage disabled",
  disable_pr_remediation: "PR triage and remediation disabled",
};

export function enforcementLabel(kind: string): string {
  return ENFORCEMENT_LABELS[kind] ?? humanise(kind);
}

export function pluralise(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}
