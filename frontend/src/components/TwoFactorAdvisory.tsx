import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { InfoNote } from "./ui";

const DISMISSED_KEY = "cxcg-2fa-advisory-dismissed";

function wasDismissed(key: string): boolean {
  try {
    return localStorage.getItem(key) === "1";
  } catch {
    // Private browsing can throw on localStorage access.
    return false;
  }
}

function rememberDismissed(key: string): void {
  try {
    localStorage.setItem(key, "1");
  } catch {
    // Not fatal: the advisory shows again after a reload.
  }
}

/**
 * Advice, never a requirement: an admin account can restrict tenant users, so
 * it should have two factor authentication. Dismissed once on this device, it
 * stays dismissed on every page that shows the same advice (``scope``: "self" for
 * the signed-in admin's own account, "accounts" for the list of admins).
 */
export function TwoFactorAdvisory({
  children,
  scope = "self",
}: {
  children?: ReactNode;
  scope?: "self" | "accounts";
}) {
  const key = `${DISMISSED_KEY}-${scope}`;
  const [dismissed, setDismissed] = useState(() => wasDismissed(key));
  if (dismissed) return null;
  return (
    <InfoNote tone="warning">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <span className="min-w-0 flex-1">
          {children ?? (
            <>
              Your admin account has no two factor authentication. An admin can restrict tenant
              users, so a stolen password is enough to do that. Set it up under{" "}
              <Link to="/account" className="underline">
                Your account
              </Link>
              .
            </>
          )}
        </span>
        <button
          type="button"
          className="text-xs underline"
          style={{ color: "var(--text-secondary)" }}
          onClick={() => {
            rememberDismissed(key);
            setDismissed(true);
          }}
        >
          Dismiss
        </button>
      </div>
    </InfoNote>
  );
}
