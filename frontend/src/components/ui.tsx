import {
  useEffect,
  useId,
  useRef,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";

/* ------------------------------------------------------------------- layout */

export function Card({
  title,
  description,
  actions,
  children,
  className = "",
  padded = true,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  padded?: boolean;
}) {
  return (
    <section
      className={`rounded-lg border border-hairline bg-surface ${className}`}
      style={{ background: "var(--surface)" }}
    >
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-hairline px-5 py-4">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold tracking-tight">{title}</h2>}
            {description && (
              <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
                {description}
              </p>
            )}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && (
          <p className="mt-1 max-w-3xl text-sm" style={{ color: "var(--text-secondary)" }}>
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ controls */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

const BUTTON_STYLES: Record<ButtonVariant, string> = {
  primary: "text-white",
  secondary: "border border-hairline-strong",
  ghost: "border border-transparent",
  danger: "text-white",
};

export function Button({
  variant = "secondary",
  size = "md",
  loading = false,
  children,
  className = "",
  style,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  loading?: boolean;
}) {
  const background =
    variant === "primary"
      ? "var(--series-1)"
      : variant === "danger"
        ? "var(--status-critical)"
        : "transparent";
  return (
    <button
      {...rest}
      disabled={rest.disabled || loading}
      className={`inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
        size === "sm" ? "px-2.5 py-1.5 text-xs" : "px-3.5 py-2 text-sm"
      } ${BUTTON_STYLES[variant]} ${className}`}
      style={{ background, ...style }}
    >
      {loading && <Spinner size={14} />}
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  required,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1.5 flex items-center gap-1 text-xs font-medium">
        {label}
        {required && <span style={{ color: "var(--status-critical)" }}>*</span>}
      </span>
      {children}
      {hint && !error && (
        <span className="mt-1.5 block text-xs" style={{ color: "var(--text-muted)" }}>
          {hint}
        </span>
      )}
      {error && (
        <span className="mt-1.5 block text-xs" style={{ color: "var(--status-critical)" }}>
          {error}
        </span>
      )}
    </label>
  );
}

const CONTROL_CLASS =
  "w-full rounded-md border border-hairline-strong px-3 py-2 text-sm outline-none disabled:opacity-60";

export function Input({ className = "", ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...rest}
      className={`${CONTROL_CLASS} ${className}`}
      style={{ background: "var(--surface-raised)", color: "var(--text-primary)" }}
    />
  );
}

export function Textarea({ className = "", ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...rest}
      className={`${CONTROL_CLASS} ${className}`}
      style={{ background: "var(--surface-raised)", color: "var(--text-primary)" }}
    />
  );
}

export function Select({
  className = "",
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...rest}
      className={`${CONTROL_CLASS} ${className}`}
      style={{ background: "var(--surface-raised)", color: "var(--text-primary)" }}
    >
      {children}
    </select>
  );
}

export function Toggle({
  checked,
  onChange,
  label,
  description,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  description?: ReactNode;
  disabled?: boolean;
}) {
  const id = useId();
  return (
    <div className="flex items-start gap-3">
      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className="mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full border border-hairline-strong transition-colors disabled:opacity-50"
        style={{ background: checked ? "var(--series-1)" : "var(--hover)" }}
      >
        <span
          className="ml-0.5 inline-block size-4 rounded-full bg-white transition-transform"
          style={{ transform: checked ? "translateX(15px)" : "translateX(0)" }}
        />
      </button>
      <div className="min-w-0">
        <label htmlFor={id} className="block text-sm font-medium">
          {label}
        </label>
        {description && (
          <p className="mt-0.5 text-xs" style={{ color: "var(--text-secondary)" }}>
            {description}
          </p>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------- status */

export type BadgeTone = "neutral" | "good" | "warning" | "serious" | "critical" | "info";

const BADGE_COLORS: Record<BadgeTone, { fg: string; dot: string }> = {
  neutral: { fg: "var(--text-secondary)", dot: "var(--text-muted)" },
  good: { fg: "var(--status-good-text)", dot: "var(--status-good)" },
  warning: { fg: "var(--text-primary)", dot: "var(--status-warning)" },
  serious: { fg: "var(--text-primary)", dot: "var(--status-serious)" },
  critical: { fg: "var(--status-critical)", dot: "var(--status-critical)" },
  info: { fg: "var(--text-secondary)", dot: "var(--series-1)" },
};

/**
 * A status pill. The coloured dot never carries the meaning on its own: the label
 * beside it always says the same thing in words.
 */
export function Badge({
  tone = "neutral",
  children,
  icon,
}: {
  tone?: BadgeTone;
  children: ReactNode;
  icon?: ReactNode;
}) {
  const colors = BADGE_COLORS[tone];
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border border-hairline px-2 py-0.5 text-xs font-medium whitespace-nowrap"
      style={{ color: colors.fg }}
    >
      {icon ?? (
        <span
          aria-hidden="true"
          className="inline-block size-1.5 rounded-full"
          style={{ background: colors.dot }}
        />
      )}
      {children}
    </span>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      aria-hidden="true"
      className="animate-spin"
      style={{ display: "block" }}
    >
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeOpacity="0.25" strokeWidth="2.5" />
      <path
        d="M21 12a9 9 0 0 0-9-9"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <p className="text-sm font-medium">{title}</p>
      {description && (
        <p className="max-w-md text-xs" style={{ color: "var(--text-secondary)" }}>
          {description}
        </p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div
      className="flex items-start gap-2 rounded-md border px-3 py-2 text-sm"
      style={{ borderColor: "var(--status-critical)", color: "var(--text-primary)" }}
      role="alert"
    >
      <span aria-hidden="true" style={{ color: "var(--status-critical)" }}>
        !
      </span>
      <div className="min-w-0 whitespace-pre-wrap">{children}</div>
    </div>
  );
}

export function InfoNote({ children, tone = "info" }: { children: ReactNode; tone?: BadgeTone }) {
  const colors = BADGE_COLORS[tone];
  return (
    <div
      className="rounded-md border-l-2 px-3 py-2 text-xs"
      style={{ borderColor: colors.dot, background: "var(--hover)", color: "var(--text-secondary)" }}
    >
      {children}
    </div>
  );
}

/* --------------------------------------------------------------------- table */

export function Table({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className={`w-full border-collapse text-sm ${className}`}>{children}</table>
    </div>
  );
}

export function Th({
  children,
  align = "left",
  className = "",
}: {
  children?: ReactNode;
  align?: "left" | "right" | "center";
  className?: string;
}) {
  return (
    <th
      scope="col"
      className={`border-b border-hairline px-3 py-2 text-xs font-medium whitespace-nowrap ${className}`}
      style={{ color: "var(--text-secondary)", textAlign: align }}
    >
      {children}
    </th>
  );
}

export function Td({
  children,
  align = "left",
  className = "",
  colSpan,
}: {
  children?: ReactNode;
  align?: "left" | "right" | "center";
  className?: string;
  colSpan?: number;
}) {
  return (
    <td
      colSpan={colSpan}
      className={`border-b border-hairline px-3 py-2 align-top ${className}`}
      style={{ textAlign: align }}
    >
      {children}
    </td>
  );
}

/* --------------------------------------------------------------------- modal */

export function Modal({
  open,
  title,
  description,
  onClose,
  children,
  footer,
  width = "max-w-lg",
}: {
  open: boolean;
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  width?: string;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    dialogRef.current?.focus();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      style={{ background: "rgba(0,0,0,0.55)" }}
      onClick={onClose}
      role="presentation"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={`w-full ${width} rounded-lg border border-hairline shadow-xl outline-none`}
        style={{ background: "var(--surface)" }}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="border-b border-hairline px-5 py-4">
          <h2 className="text-sm font-semibold">{title}</h2>
          {description && (
            <p className="mt-1 text-xs" style={{ color: "var(--text-secondary)" }}>
              {description}
            </p>
          )}
        </header>
        <div className="max-h-[65vh] overflow-y-auto p-5">{children}</div>
        {footer && (
          <footer className="flex flex-wrap justify-end gap-2 border-t border-hairline px-5 py-4">
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = "Confirm",
  destructive = false,
  busy = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  message: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal
      open={open}
      title={title}
      onClose={onCancel}
      width="max-w-md"
      footer={
        <>
          <Button variant="secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={destructive ? "danger" : "primary"}
            onClick={onConfirm}
            loading={busy}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="text-sm whitespace-pre-wrap">{message}</div>
    </Modal>
  );
}

/* -------------------------------------------------------------------- misc */

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: T; label: string; count?: number }[];
  active: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1 border-b border-hairline" role="tablist">
      {tabs.map((tab) => {
        const selected = tab.id === active;
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={selected}
            onClick={() => onChange(tab.id)}
            className="-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors"
            style={{
              borderColor: selected ? "var(--series-1)" : "transparent",
              color: selected ? "var(--text-primary)" : "var(--text-secondary)",
            }}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className="ml-1.5 text-xs tabular" style={{ color: "var(--text-muted)" }}>
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

export function KeyValue({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs" style={{ color: "var(--text-muted)" }}>
        {label}
      </dt>
      <dd className="mt-0.5 truncate text-sm">{children}</dd>
    </div>
  );
}
