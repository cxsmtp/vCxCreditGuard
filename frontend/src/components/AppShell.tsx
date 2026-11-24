import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import type { Me } from "../api/types";
import { LOOKS, PHOSPHORS, useTheme, useToast } from "../lib/ui-context";
import { settingsDraft, useSettingsDraft } from "../lib/settingsDraft";
import { BrandMark, Icon, type IconName } from "./Icon";
import { PermissionBanner, PermissionPopup, permissionProblem } from "./KeyPermissions";
import { Modal } from "./ui";

/* --------------------------------------------------------------- the map */

type NavItem = { to: string; label: string; icon: IconName; exact?: boolean };
type SettingsLink = { to: string; label: string };

/** The main menu: what people do every day. Everything else is under Settings. */
function mainNav(me: Me): NavItem[] {
  const items: NavItem[] = [
    { to: "/", label: "Overview", icon: "overview", exact: true },
    { to: "/limits", label: "Budgets", icon: "budgets" },
    { to: "/preview", label: "Simulation", icon: "simulation" },
  ];
  if (me.can_request_credits) items.push({ to: "/requests", label: "Requests", icon: "requests" });
  items.push(
    { to: "/reports", label: "Reports", icon: "reports" },
    { to: "/notifications", label: "Notifications", icon: "bell" },
  );
  // Admins only: a violation names people, and following it up is an admin's call.
  if (me.role === "admin") items.push({ to: "/violations", label: "Violations", icon: "shield" });
  items.push({ to: "/settings", label: "Settings", icon: "settings" });
  return items;
}

/** Settings, in groups. Pages listed here show the settings menu beside them. */
export function settingsNav(me: Me): [string, SettingsLink[]][] {
  const admin = me.role === "admin";
  return [
    [
      "Tenant",
      [
        { to: "/setup", label: "Connection" },
        { to: "/settings/attribution", label: "Attribution" },
      ],
    ],
    [
      "Governance",
      [
        { to: "/settings/enforcement", label: "Enforcement" },
        { to: "/settings/requests", label: "Credit requests" },
        { to: "/settings/general", label: "Schedule & data" },
      ],
    ],
    ["Delivery", [{ to: "/settings/notifications", label: "Notifications & reports" }]],
    [
      "People",
      [
        ...(admin ? [{ to: "/settings/accounts", label: "Accounts" }] : []),
        { to: "/account", label: "Your account" },
      ],
    ],
    ["Records", [{ to: "/audit", label: "Audit log" }]],
    [
      "System",
      [
        { to: "/settings/appearance", label: "Appearance" },
        ...(admin ? [{ to: "/settings/operations", label: "Backups & health" }] : []),
        { to: "/settings/about", label: "About" },
      ],
    ],
  ];
}

function inSettings(pathname: string): boolean {
  return (
    pathname.startsWith("/settings") ||
    pathname === "/setup" ||
    pathname === "/account" ||
    pathname === "/audit"
  );
}

/* ---------------------------------------------------------------- pieces */

function initials(name: string): string {
  const parts = name.split(/[\s._@-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "?") + (parts[1]?.[0] ?? "")).toUpperCase();
}

function useUtcClock(enabled: boolean): string {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    if (!enabled) return;
    const id = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(id);
  }, [enabled]);
  return now.toISOString().slice(11, 19);
}

/** Command Center's status strip: the state of the whole system on one line. */
function OpsStrip({ me }: { me: Me }) {
  const { look } = useTheme();
  const clock = useUtcClock(look === "command");
  let level = "DEFCON 5";
  let state = "All systems nominal";
  let tone = "";
  if (!me.connection_configured) {
    level = "DEFCON 4";
    state = "No tenant connected";
    tone = "warn";
  } else if (me.connection_status !== "healthy") {
    level = "DEFCON 3";
    state = `Tenant link ${me.connection_status}`;
    tone = "bad";
  } else if (permissionProblem(me)) {
    const insufficient = me.key_permissions?.verdict === "insufficient";
    level = insufficient ? "DEFCON 3" : "DEFCON 4";
    state = "API key missing permissions";
    tone = insufficient ? "bad" : "warn";
  } else if (me.enforcement_paused) {
    level = "DEFCON 4";
    state = "Enforcement paused";
    tone = "warn";
  } else if (me.demo_mode) {
    level = "DEFCON 5";
    state = "Demo data · enforcement suppressed";
  }
  return (
    <div className="cg-ops" aria-hidden="true">
      <span className="cg-ops-dot" />
      <b className={tone}>{level}</b>
      <span>{state}</span>
      <span className="sep">│</span>
      <span>{me.tenant_name ? `Tenant: ${me.tenant_name}` : "Tenant: none"}</span>
      <span className="sep">│</span>
      <span>{window.location.protocol === "https:" ? "Secure link · TLS" : "Link open"}</span>
      <span className="sep">│</span>
      <span>
        Operator: {me.username} · {me.role}
      </span>
      <span className="grow" />
      <span className="clock">{clock} UTC</span>
      <span className="sep">│</span>
      <span>{me.version}</span>
    </div>
  );
}

/** The small status lights in the top bar: only what needs attention. */
function Lights({ me }: { me: Me }) {
  const lights: { key: string; tone: string; label: string; to: string; title: string }[] = [];
  const location = useLocation();
  useSettingsDraft();
  if (settingsDraft.dirty() && !location.pathname.startsWith("/settings/")) {
    lights.push({
      key: "unsaved",
      tone: "warn",
      label: "Unsaved settings",
      to: "/settings/general",
      title: "Settings were changed and not saved yet",
    });
  }
  if (!me.connection_configured) {
    lights.push({
      key: "conn",
      tone: "warn",
      label: "Not connected",
      to: "/setup",
      title: "No Checkmarx One tenant is connected yet",
    });
  } else if (me.connection_status !== "healthy") {
    lights.push({
      key: "conn",
      tone: "bad",
      label: "Tenant link",
      to: "/setup",
      title: `The tenant connection is ${me.connection_status}`,
    });
  }
  if (permissionProblem(me) && me.key_permissions) {
    lights.push({
      key: "perm",
      tone: me.key_permissions.verdict === "insufficient" ? "bad" : "warn",
      label: "Key permissions",
      to: "/setup#key-permissions",
      title: me.key_permissions.summary,
    });
  }
  if ((me.open_violations ?? 0) > 0) {
    lights.push({
      key: "violations",
      tone: "warn",
      label: `${me.open_violations} policy violation${me.open_violations === 1 ? "" : "s"}`,
      to: "/violations",
      title: "Someone acted against a restriction in force. Open Policy violations to follow up.",
    });
  }
  if (me.enforcement_paused) {
    lights.push({
      key: "paused",
      tone: "warn",
      label: "Enforcement paused",
      to: "/settings/enforcement",
      title: me.enforcement_paused,
    });
  }
  if (me.demo_mode) {
    lights.push({
      key: "demo",
      tone: "off",
      label: "Demo data",
      to: "/settings/general",
      title: "Showing synthetic data; nothing is changed in Checkmarx One",
    });
  }
  if (lights.length === 0) return null;
  return (
    <span className="cg-lights flex items-center gap-2">
      {lights.map((light) => (
        <Link key={light.key} to={light.to} className={`cg-light ${light.tone}`} title={light.title}>
          <i />
          {light.label}
        </Link>
      ))}
    </span>
  );
}

function Toasts() {
  const { toasts, dismiss } = useToast();
  if (toasts.length === 0) return null;
  return (
    <div className="cg-toasts">
      {toasts.map((toast) => (
        <div key={toast.id} role="status" className={`cg-toast ${toast.kind}`}>
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

/* ---------------------------------------------------------- the look picker */

export function LookPicker() {
  const { look, setLook, mode, setMode, phosphor, setPhosphor } = useTheme();
  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-3 sm:grid-cols-2">
        {LOOKS.map((option) => (
          <button
            key={option.id}
            type="button"
            className={`cg-look-card ${look === option.id ? "on" : ""}`}
            aria-pressed={look === option.id}
            onClick={() => setLook(option.id)}
          >
            <span className={`cg-look-sample ${option.id}`} />
            <span className="text-sm font-semibold">{option.name}</span>
            <span className="text-xs" style={{ color: "var(--text-secondary)" }}>
              {option.blurb}
            </span>
          </button>
        ))}
      </div>
      <div>
        <div className="cg-field-label">Light or dark</div>
        <div className="cg-seg" role="group" aria-label="Light or dark">
          {(["light", "dark", "system"] as const).map((option) => (
            <button
              key={option}
              type="button"
              className={mode === option ? "on" : ""}
              aria-pressed={mode === option}
              onClick={() => setMode(option)}
            >
              {option === "system" ? "As the system" : option === "light" ? "Light" : "Dark"}
            </button>
          ))}
        </div>
      </div>
      {look === "command" && (
        <div>
          <div className="cg-field-label">Phosphor colour</div>
          <div className="flex flex-wrap items-center gap-2">
            {PHOSPHORS.map((option) => (
              <button
                key={option.id}
                type="button"
                className={`cg-swatch ${phosphor === option.id ? "on" : ""}`}
                style={{ ["--c" as string]: option.colour }}
                aria-label={option.id}
                aria-pressed={phosphor === option.id}
                title={option.id}
                onClick={() => setPhosphor(option.id)}
              />
            ))}
          </div>
        </div>
      )}
      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
        Remembered on this device. The organisation's accent colour (Settings → Appearance)
        colours the Standard look.
      </p>
    </div>
  );
}

/* --------------------------------------------------------------- Jump to */

type JumpTarget = { label: string; where: string; to: string; icon: IconName };

function JumpPalette({ me, open, onClose }: { me: Me; open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const targets = useMemo<JumpTarget[]>(() => {
    const pages: JumpTarget[] = mainNav(me).map((item) => ({
      label: item.to === "/violations" ? "Policy violations" : item.label,
      where: "Page",
      to: item.to,
      icon: item.icon,
    }));
    for (const [group, links] of settingsNav(me)) {
      for (const link of links) {
        pages.push({ label: link.label, where: `Settings · ${group}`, to: link.to, icon: "settings" });
      }
    }
    return pages;
  }, [me]);

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter((t) => `${t.label} ${t.where}`.toLowerCase().includes(q));
  }, [query, targets]);

  useEffect(() => {
    if (!open) return;
    const before = document.activeElement as HTMLElement | null;
    setQuery("");
    setIndex(0);
    window.setTimeout(() => inputRef.current?.focus(), 0);
    return () => before?.focus?.();
  }, [open]);

  useEffect(() => setIndex(0), [query]);

  if (!open) return null;

  function go(target: JumpTarget | undefined) {
    if (!target) return;
    onClose();
    navigate(target.to);
  }

  return (
    <div className="cg-overlay top" role="presentation" onClick={onClose}>
      <div
        className="cg-dialog max-w-xl"
        role="dialog"
        aria-modal="true"
        aria-label="Jump to a page"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b px-4 py-3" style={{ borderColor: "var(--border)" }}>
          <Icon name="search" />
          <input
            ref={inputRef}
            className="cg-input"
            placeholder="Jump to a page or a setting…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "ArrowDown") {
                event.preventDefault();
                setIndex((i) => Math.min(i + 1, matches.length - 1));
              } else if (event.key === "ArrowUp") {
                event.preventDefault();
                setIndex((i) => Math.max(i - 1, 0));
              } else if (event.key === "Enter") {
                event.preventDefault();
                go(matches[index]);
              } else if (event.key === "Escape") {
                event.stopPropagation();
                onClose();
              }
            }}
            aria-label="Search pages"
          />
          <span className="cg-kbd">Esc</span>
        </div>
        <div className="cg-jump-list" role="listbox">
          {matches.length === 0 && (
            <p className="px-3 py-6 text-center text-sm" style={{ color: "var(--text-secondary)" }}>
              Nothing matches “{query}”.
            </p>
          )}
          {matches.map((target, i) => (
            <button
              key={`${target.to}-${target.label}`}
              type="button"
              role="option"
              aria-selected={i === index}
              className={`cg-jump-item ${i === index ? "on" : ""}`}
              onMouseEnter={() => setIndex(i)}
              onClick={() => go(target)}
            >
              <Icon name={target.icon} />
              <span>
                {target.label}
                <small>{target.where}</small>
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- shell */

export function AppShell({
  me,
  unreadCount,
  onSignOut,
  onMeChanged,
  children,
}: {
  me: Me;
  unreadCount: number;
  onSignOut: () => void;
  /** Re-reads /api/me, after something on it may have changed. */
  onMeChanged: () => Promise<unknown>;
  children: ReactNode;
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const { theme, toggle } = useTheme();
  const [sideOpen, setSideOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [jumpOpen, setJumpOpen] = useState(false);
  const [lookOpen, setLookOpen] = useState(false);
  const [permOpen, setPermOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const nav = mainNav(me);
  const settings = inSettings(location.pathname);

  // Ctrl K (or Cmd K) opens Jump to, except over a dialog that is already open.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (
        (event.ctrlKey || event.metaKey) &&
        !event.shiftKey &&
        !event.altKey &&
        !event.repeat &&
        event.key.toLowerCase() === "k" &&
        !document.querySelector('[aria-modal="true"]')
      ) {
        event.preventDefault();
        setJumpOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // Close the person menu on a click elsewhere, and the phone menu on navigation.
  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMenuOpen(false);
        menuRef.current?.querySelector<HTMLElement>(".cg-who")?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    // Focus the first item, so the menu can be used from the keyboard.
    window.setTimeout(() => menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus(), 0);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);
  useEffect(() => {
    setSideOpen(false);
    setMenuOpen(false);
  }, [location.pathname]);

  const main = (
    <main key={location.pathname} className="cg-main">
      {children}
    </main>
  );

  return (
    <>
      <div className="cg-bg" aria-hidden="true">
        <div className="cg-grid" />
      </div>
      <OpsStrip me={me} />
      <div className="cg-app">
        <aside className={`cg-side ${sideOpen ? "open" : ""}`} aria-label="Main menu">
          <Link to="/" className="cg-brand">
            <BrandMark />
            <span>
              <b>CxCreditGuard</b>
              <small>Credit governance</small>
            </span>
          </Link>
          <nav className="cg-nav">
            {nav.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.exact ?? false}
                className={({ isActive }) =>
                  isActive || (item.to === "/settings" && settings) ? "active" : ""
                }
              >
                <Icon name={item.icon} />
                <span>{item.label}</span>
                {item.to === "/notifications" && unreadCount > 0 && (
                  <span className="cg-count tabular" aria-label={`${unreadCount} unread`}>
                    {unreadCount > 99 ? "99+" : unreadCount}
                  </span>
                )}
                {item.to === "/violations" && (me.open_violations ?? 0) > 0 && (
                  <span
                    className="cg-count tabular"
                    aria-label={`${me.open_violations} open violations`}
                  >
                    {(me.open_violations ?? 0) > 99 ? "99+" : me.open_violations}
                  </span>
                )}
              </NavLink>
            ))}
          </nav>
          <div className="cg-side-foot">
            <Link to="/settings/about" className="cg-ver" title="About this installation">
              {me.version}
            </Link>
            <span>
              {me.connection_configured
                ? `Tenant: ${me.tenant_name ?? "connected"}`
                : "No tenant connected"}
            </span>
          </div>
        </aside>
        {sideOpen && (
          <div
            className="fixed inset-0 z-50"
            style={{ background: "rgba(0,0,0,0.35)" }}
            onClick={() => setSideOpen(false)}
            role="presentation"
          />
        )}

        <div className="cg-col">
          <header className="cg-topbar">
            <button
              type="button"
              className="cg-icon-btn cg-burger"
              aria-label="Open the menu"
              onClick={() => setSideOpen(true)}
            >
              <Icon name="menu" />
            </button>
            <button type="button" className="cg-jump" onClick={() => setJumpOpen(true)}>
              <Icon name="search" size={16} />
              <span>Jump to…</span>
              <kbd className="cg-kbd">Ctrl K</kbd>
            </button>
            <span className="flex-1" />
            <Lights me={me} />
            <button
              type="button"
              className="cg-icon-btn"
              onClick={toggle}
              aria-label={theme === "dark" ? "Switch to light" : "Switch to dark"}
              title={theme === "dark" ? "Switch to light" : "Switch to dark"}
            >
              <Icon name="theme" />
            </button>
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                className="cg-who"
                aria-haspopup="true"
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen((open) => !open)}
              >
                <span className="cg-avatar">{initials(me.username)}</span>
                <span>
                  <b>{me.username}</b>
                  <small>{me.role === "admin" ? "Admin" : "Viewer"}</small>
                </span>
              </button>
              {menuOpen && (
                <div className="cg-menu" role="menu">
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      navigate("/account");
                    }}
                  >
                    <Icon name="user" size={16} />
                    Your account
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      setLookOpen(true);
                    }}
                  >
                    <Icon name="theme" size={16} />
                    Look…
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      navigate("/settings/about");
                    }}
                  >
                    <Icon name="info" size={16} />
                    About
                  </button>
                  <hr />
                  <button type="button" role="menuitem" className="danger" onClick={onSignOut}>
                    <Icon name="out" size={16} />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </header>

          <PermissionBanner me={me} onOpen={() => setPermOpen(true)} />
          {me.demo_mode && (
            <div className="cg-banner" role="status">
              Demo mode: showing synthetic data. Enforcement is suppressed, so nothing is changed in
              Checkmarx One.
            </div>
          )}
          {me.enforcement_paused && !me.demo_mode && (
            <div className="cg-banner" role="status">
              <span>
                <b>Enforcement is paused.</b> Limits are still monitored, but no new restriction is
                applied. {me.enforcement_paused}
              </span>
              <Link to="/settings/enforcement">Review</Link>
            </div>
          )}
          {me.role === "viewer" && (
            <div className="cg-banner info">
              {me.can_request_credits
                ? "You are signed in as a viewer. You can submit credit requests; budgets and settings stay read only."
                : "You are signed in as a viewer. Everything here is read only."}
            </div>
          )}

          {settings ? (
            <div className="cg-set-wrap">
              <nav className="cg-set-nav" aria-label="Settings">
                {settingsNav(me).map(([group, links]) => (
                  <div key={group} className="cg-set-group">
                    <span className="cg-set-label">{group}</span>
                    {links.map((link) => (
                      <NavLink
                        key={link.to}
                        to={link.to}
                        className={({ isActive }) => (isActive ? "active" : "")}
                      >
                        {link.label}
                      </NavLink>
                    ))}
                  </div>
                ))}
              </nav>
              {main}
            </div>
          ) : (
            main
          )}
        </div>
      </div>

      <JumpPalette me={me} open={jumpOpen} onClose={() => setJumpOpen(false)} />
      <PermissionPopup me={me} open={permOpen} onOpenChange={setPermOpen} onChanged={onMeChanged} />
      <Modal open={lookOpen} title="Look" onClose={() => setLookOpen(false)} width="max-w-xl">
        <LookPicker />
      </Modal>
      <Toasts />
    </>
  );
}
