import { useState, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import type { Me } from "../api/types";
import { useTheme, useToast } from "../lib/ui-context";
import { Button } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", exact: true },
  { to: "/limits", label: "Limits" },
  { to: "/notifications", label: "Notifications" },
  { to: "/audit", label: "Audit log" },
  { to: "/settings", label: "Settings" },
] as const;

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      className="rounded-md border border-hairline px-2.5 py-1.5 text-xs font-medium"
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
    >
      {theme === "dark" ? "Light mode" : "Dark mode"}
    </button>
  );
}

function Toasts() {
  const { toasts, dismiss } = useToast();
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-full max-w-sm flex-col gap-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          role="status"
          className="pointer-events-auto flex items-start gap-3 rounded-md border px-3 py-2.5 text-sm shadow-lg"
          style={{
            background: "var(--surface-raised)",
            borderColor:
              toast.kind === "error"
                ? "var(--status-critical)"
                : toast.kind === "success"
                  ? "var(--status-good)"
                  : "var(--border)",
          }}
        >
          <span className="min-w-0 flex-1 whitespace-pre-wrap">{toast.message}</span>
          <button
            type="button"
            onClick={() => dismiss(toast.id)}
            className="shrink-0 text-xs underline"
            style={{ color: "var(--text-secondary)" }}
          >
            Dismiss
          </button>
        </div>
      ))}
    </div>
  );
}

export function AppShell({
  me,
  unreadCount,
  onSignOut,
  children,
}: {
  me: Me;
  unreadCount: number;
  onSignOut: () => void;
  children: ReactNode;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();

  return (
    <div className="flex min-h-screen flex-col">
      <header
        className="sticky top-0 z-30 border-b border-hairline"
        style={{ background: "var(--surface)" }}
      >
        <div className="mx-auto flex max-w-[1400px] items-center gap-4 px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <span
              aria-hidden="true"
              className="inline-block size-2.5 rounded-sm"
              style={{ background: "var(--series-1)" }}
            />
            CxCreditGuard
          </Link>

          <nav className="ml-4 hidden items-center gap-1 md:flex">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={"exact" in item ? item.exact : false}
                className="rounded-md px-3 py-1.5 text-sm font-medium"
                style={({ isActive }) => ({
                  background: isActive ? "var(--hover)" : "transparent",
                  color: isActive ? "var(--text-primary)" : "var(--text-secondary)",
                })}
              >
                {item.label}
                {item.to === "/notifications" && unreadCount > 0 && (
                  <span
                    className="ml-1.5 rounded-full px-1.5 py-0.5 text-[10px] font-semibold text-white tabular"
                    style={{ background: "var(--status-critical)" }}
                  >
                    {unreadCount > 99 ? "99+" : unreadCount}
                  </span>
                )}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-2">
            {me.tenant_name && (
              <span
                className="hidden text-xs sm:inline"
                style={{ color: "var(--text-secondary)" }}
                title="Connected Checkmarx One tenant"
              >
                {me.tenant_name}
              </span>
            )}
            <ThemeToggle />
            <div className="hidden items-center gap-2 sm:flex">
              <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
                {me.username}
                {me.role === "viewer" && " (viewer)"}
              </span>
              <Button size="sm" variant="secondary" onClick={onSignOut}>
                Sign out
              </Button>
            </div>
            <button
              type="button"
              className="rounded-md border border-hairline px-2.5 py-1.5 text-xs md:hidden"
              onClick={() => setMenuOpen((open) => !open)}
              aria-expanded={menuOpen}
            >
              Menu
            </button>
          </div>
        </div>

        {menuOpen && (
          <nav className="border-t border-hairline px-4 py-2 md:hidden">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={"exact" in item ? item.exact : false}
                onClick={() => setMenuOpen(false)}
                className="block rounded-md px-3 py-2 text-sm"
                style={({ isActive }) => ({
                  background: isActive ? "var(--hover)" : "transparent",
                })}
              >
                {item.label}
              </NavLink>
            ))}
            <button
              type="button"
              onClick={onSignOut}
              className="block w-full px-3 py-2 text-left text-sm"
            >
              Sign out
            </button>
          </nav>
        )}
      </header>

      {me.role === "viewer" && (
        <div
          className="border-b border-hairline px-4 py-2 text-center text-xs sm:px-6"
          style={{ background: "var(--hover)", color: "var(--text-secondary)" }}
        >
          You are signed in as a viewer. Dashboards, notifications and the audit log are read only.
        </div>
      )}

      <main key={location.pathname} className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-6 sm:px-6">
        {children}
      </main>

      <footer
        className="border-t border-hairline px-4 py-3 text-xs sm:px-6"
        style={{ color: "var(--text-muted)" }}
      >
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-2">
          <span>CxCreditGuard {me.version}</span>
          <span>
            {me.connection_configured
              ? `Connected to ${me.tenant_name ?? "a tenant"} (${me.connection_status})`
              : "No Checkmarx connection configured yet"}
          </span>
        </div>
      </footer>

      <Toasts />
    </div>
  );
}
