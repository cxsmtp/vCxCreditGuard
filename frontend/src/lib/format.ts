/** Formatting helpers. No em dashes in any user visible string. */

const ONE_DECIMAL: Intl.NumberFormatOptions = { minimumFractionDigits: 1, maximumFractionDigits: 1 };

/** Credits always read with exactly one decimal and thousands separators: "12.0", "1,365.5", "0.5". */
export function formatCredits(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return (0).toLocaleString(undefined, ONE_DECIMAL);
  const numeric = typeof value === "number" ? value : Number(value);
  if (Number.isNaN(numeric)) return String(value);
  return numeric.toLocaleString(undefined, ONE_DECIMAL);
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "0";
  return value.toLocaleString();
}

/**
 * Percentages always read with exactly one decimal, as credits do: "4.9%", "64.2%",
 * "100.0%". One rule everywhere, and the same as the server's sentences, so the
 * same figure never reads 4.9% in one place and 5% in another.
 */
export function formatPercent(value: number | string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "";
  const numeric = typeof value === "number" ? value : Number(value);
  if (Number.isNaN(numeric)) return "";
  return `${numeric.toLocaleString(undefined, ONE_DECIMAL)}%`;
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
  disable_fusion: "Fusion turned off",
  disable_repo_fusion: "Repository Fusion setting turned off",
};

/** What a project, group or application limit can turn off, in order. */
export const PROJECT_ACTIONS: { id: "auto_triage" | "pr_remediation" | "fusion"; label: string; help: string }[] = [
  {
    id: "auto_triage",
    label: "Auto Triage",
    help: "Turned off in the project's AI agent configuration.",
  },
  {
    id: "pr_remediation",
    label: "PR triage and remediation",
    help: "Severities cleared in the repository settings (projects with a repository only).",
  },
  {
    id: "fusion",
    label: "Fusion",
    help: "Turned off in the project's scan settings, and in its repository's where Checkmarx reports it. A scan started with its own settings may still turn it on; CreditGuard records any such scan under Policy violations.",
  },
];

export function projectActionsLabel(actions: string[]): string {
  const names = PROJECT_ACTIONS.filter((action) => actions.includes(action.id)).map((a) => a.label);
  if (names.length <= 1) return names.join("") || "Nothing";
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

export function enforcementLabel(kind: string): string {
  return ENFORCEMENT_LABELS[kind] ?? humanise(kind);
}

export function pluralise(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}

/** A count with its noun and thousands separators: "1 entity", "3 entities", "1,250 users". */
export function countNoun(count: number, singular: string, plural?: string): string {
  return `${formatNumber(count)} ${pluralise(count, singular, plural)}`;
}

/** "a project", "an application": the article that fits the word. */
export function withArticle(word: string): string {
  return `${/^[aeiou]/i.test(word) ? "an" : "a"} ${word}`;
}

const RUN_STATUS_LABELS: Record<string, string> = {
  running: "Running",
  success: "Succeeded",
  partial: "Partly succeeded",
  failed: "Failed",
  skipped: "Skipped",
};

/** A cycle's status in words: "Partly succeeded", not "partial". */
export function runStatusLabel(status: string): string {
  return RUN_STATUS_LABELS[status] ?? humanise(status);
}

/**
 * Checkmarx One's own warning and cut-off thresholds as one phrase. Equal
 * thresholds read once: "it warns and cuts off at 100%".
 */
export function thresholdsPhrase(warnAt?: number | null, cutOffAt?: number | null): string {
  const hasWarn = warnAt !== undefined && warnAt !== null;
  const hasCut = cutOffAt !== undefined && cutOffAt !== null;
  if (hasWarn && hasCut && warnAt === cutOffAt) return `it warns and cuts off at ${warnAt}%`;
  if (hasWarn && hasCut) return `it warns at ${warnAt}% and cuts off at ${cutOffAt}%`;
  if (hasWarn) return `it warns at ${warnAt}%`;
  if (hasCut) return `it cuts off at ${cutOffAt}%`;
  return "";
}
