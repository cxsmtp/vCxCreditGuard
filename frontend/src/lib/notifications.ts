/**
 * Notification category names as the Notification Center shows them.
 *
 * The categories "warning" (a budget nearing or over its limit) and the
 * severities share words, so a plain rendering of the code read "Warning /
 * Warning". Each category is named for what it is about instead.
 */
const CATEGORY_LABELS: Record<string, string> = {
  warning: "Budget",
  enforcement: "Enforcement",
  restoration: "Restoration",
  attribution: "Attribution",
  sync_error: "Sync",
  auth_failure: "Sign-in",
  permissions: "API key",
  policy: "Policy violation",
  updates: "Updates",
};

export function notificationCategoryLabel(category: string): string {
  const known = CATEGORY_LABELS[category];
  if (known) return known;
  const words = category.replace(/_/g, " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "Other";
}
