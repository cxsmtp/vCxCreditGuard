import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

/* ----------------------------------------------------------------- theme */

/*
  Three independent choices, each remembered on this device:

  * mode: light, dark, or follow the system;
  * look: Standard (calm, one accent) or Command Center (the operations room);
  * phosphor: Command Center's colour.

  The organisation's accent (an admin's choice, from /api/me) colours Standard
  and is applied separately by applyAccent.
*/

export type Theme = "light" | "dark";
export type ThemeMode = Theme | "system";
export type Look = "standard" | "command";
export type Phosphor = "green" | "cyan" | "blue" | "amber" | "red" | "violet";

export const LOOKS: { id: Look; name: string; blurb: string }[] = [
  { id: "standard", name: "Standard", blurb: "Calm and plain: one accent colour, plain surfaces." },
  {
    id: "command",
    name: "Command Center",
    blurb: "The operations room: phosphor on a dark grid, radar and a status strip.",
  },
];

export const PHOSPHORS: { id: Phosphor; colour: string }[] = [
  { id: "green", colour: "#39ff88" },
  { id: "cyan", colour: "#00e5ff" },
  { id: "blue", colour: "#4d9fff" },
  { id: "amber", colour: "#ffb000" },
  { id: "red", colour: "#ff4d4d" },
  { id: "violet", colour: "#be82ff" },
];

const THEME_KEY = "cxcg-theme";
const LOOK_KEY = "cxcg-look";
const OPS_KEY = "cxcg-ops";

function stored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    // Private browsing can throw on localStorage access.
    return null;
  }
}

function remember(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Not fatal: the choice simply will not survive a reload.
  }
}

const media = typeof window !== "undefined" ? window.matchMedia?.("(prefers-color-scheme: dark)") : undefined;

function resolve(mode: ThemeMode): Theme {
  if (mode === "system") return media?.matches ? "dark" : "light";
  return mode;
}

export function readInitialMode(): ThemeMode {
  const value = stored(THEME_KEY);
  return value === "light" || value === "dark" || value === "system" ? value : "system";
}

export function readInitialLook(): Look {
  return stored(LOOK_KEY) === "command" ? "command" : "standard";
}

export function readInitialPhosphor(): Phosphor {
  const value = stored(OPS_KEY);
  return PHOSPHORS.some((option) => option.id === value) ? (value as Phosphor) : "green";
}

/** Applied before React renders so a reload does not flash the wrong look. */
export function applyTheme(mode: ThemeMode, look: Look, phosphor: Phosphor): void {
  const root = document.documentElement;
  root.dataset.theme = resolve(mode);
  root.dataset.look = look;
  root.dataset.ops = phosphor;
}

/**
 * The organisation accent theme (admin-set). It only colours the Standard look.
 * The last applied accent is cached so a reload can pre-apply it before /api/me
 * resolves.
 */
const ACCENT_KEY = "cxcg-accent";

export function readInitialAccent(): string {
  return stored(ACCENT_KEY) || "default";
}

export function applyAccent(accent: string | null | undefined): void {
  const value = accent || "default";
  document.documentElement.dataset.accent = value;
  remember(ACCENT_KEY, value);
}

interface ThemeContextValue {
  /** What is on screen now: light or dark. */
  theme: Theme;
  mode: ThemeMode;
  look: Look;
  phosphor: Phosphor;
  setMode: (mode: ThemeMode) => void;
  setLook: (look: Look) => void;
  setPhosphor: (phosphor: Phosphor) => void;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(readInitialMode);
  const [look, setLookState] = useState<Look>(readInitialLook);
  const [phosphor, setPhosphorState] = useState<Phosphor>(readInitialPhosphor);
  const [systemDark, setSystemDark] = useState<boolean>(Boolean(media?.matches));

  useEffect(() => {
    if (!media) return;
    const onChange = () => setSystemDark(media.matches);
    media.addEventListener?.("change", onChange);
    return () => media.removeEventListener?.("change", onChange);
  }, []);

  useEffect(() => {
    applyTheme(mode, look, phosphor);
    remember(THEME_KEY, mode);
    remember(LOOK_KEY, look);
    remember(OPS_KEY, phosphor);
  }, [mode, look, phosphor, systemDark]);

  const theme: Theme = mode === "system" ? (systemDark ? "dark" : "light") : mode;

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      mode,
      look,
      phosphor,
      setMode: setModeState,
      setLook: setLookState,
      setPhosphor: setPhosphorState,
      toggle: () => setModeState(theme === "dark" ? "light" : "dark"),
    }),
    [theme, mode, look, phosphor],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used inside ThemeProvider");
  return context;
}

/* ----------------------------------------------------------------- toasts */

export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

interface ToastContextValue {
  toasts: Toast[];
  push: (kind: ToastKind, message: string) => void;
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const TOAST_TTL_MS = 6000;
let nextToastId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback(
    (kind: ToastKind, message: string) => {
      const id = nextToastId++;
      setToasts((current) => [...current, { id, kind, message }]);
      // Errors stay until dismissed: they usually contain something to act on.
      if (kind !== "error") {
        window.setTimeout(() => dismiss(id), TOAST_TTL_MS);
      }
    },
    [dismiss],
  );

  const value = useMemo<ToastContextValue>(
    () => ({
      toasts,
      push,
      dismiss,
      success: (message: string) => push("success", message),
      error: (message: string) => push("error", message),
      info: (message: string) => push("info", message),
    }),
    [toasts, push, dismiss],
  );

  return <ToastContext.Provider value={value}>{children}</ToastContext.Provider>;
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
