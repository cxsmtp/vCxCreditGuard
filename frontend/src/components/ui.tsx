import {
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";

/* ------------------------------------------------------------------- layout */

export function Card({
  title,
  description,
  actions,
  children,
  className = "",
  padded = true,
  help,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  padded?: boolean;
  /** A longer explanation, folded behind a "?" beside the title. */
  help?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <section className={`cg-panel ${className}`}>
      {(title || actions) && (
        <header className="cg-panel-head">
          <div className="min-w-0">
            {title && (
              <h2 className="cg-panel-title flex items-center gap-2">
                {title}
                {help && <HelpToggle open={open} onToggle={() => setOpen((v) => !v)} />}
              </h2>
            )}
            {description && <p className="cg-panel-desc">{description}</p>}
            {help && open && <div className="cg-help-text">{help}</div>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={padded ? "cg-panel-body" : title || actions ? "pt-3" : ""}>{children}</div>
    </section>
  );
}

/** The "?" that unfolds an explanation. */
export function HelpToggle({ open, onToggle }: { open: boolean; onToggle: () => void }) {
  return (
    <button
      type="button"
      className="cg-help"
      aria-expanded={open}
      aria-label={open ? "Hide the explanation" : "Explain this"}
      title={open ? "Hide the explanation" : "Explain this"}
      onClick={onToggle}
    >
      ?
    </button>
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
    <div className="cg-head">
      <div className="min-w-0">
        <h1 className="cg-title">{title}</h1>
        {description && <p className="cg-subtitle">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ controls */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

/**
 * A button. Each page has at most one primary button: its main next step.
 */
export function Button({
  variant = "secondary",
  size = "md",
  loading = false,
  children,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  loading?: boolean;
}) {
  const variantClass =
    variant === "primary"
      ? "primary"
      : variant === "danger"
        ? "danger solid"
        : variant === "ghost"
          ? "ghost"
          : "";
  return (
    <button
      type="button"
      {...rest}
      disabled={rest.disabled || loading}
      className={`cg-btn ${variantClass} ${size === "sm" ? "sm" : ""} ${className}`}
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
  help,
  fold = true,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  required?: boolean;
  /** A longer explanation, folded behind a "?" beside the label. */
  help?: ReactNode;
  /**
   * A long hint is an explanation and folds behind the "?" so the form stays
   * light. Pass false for a hint that must always be read (a safety caveat).
   */
  fold?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const generatedId = useId();
  if (fold && !help && typeof hint === "string" && hint.length > 110) {
    help = hint;
    hint = undefined;
  }
  // The label names its control by id, so the "?" can sit beside it without
  // being inside the <label> (where it would become the labelled control).
  let control = children;
  let controlId: string | undefined;
  if (isValidElement<{ id?: string }>(children)) {
    controlId = children.props.id ?? generatedId;
    if (!children.props.id) control = cloneElement(children, { id: controlId });
  }
  return (
    <div className="block">
      <span className="cg-field-label">
        <label htmlFor={controlId}>{label}</label>
        {required && <span style={{ color: "var(--status-critical)" }}>*</span>}
        {help && <HelpToggle open={open} onToggle={() => setOpen((v) => !v)} />}
      </span>
      {help && open && <span className="cg-help-text mb-2 block">{help}</span>}
      {control}
      {hint && !error && <span className="cg-hint">{hint}</span>}
      {error && (
        <span className="cg-hint" style={{ color: "var(--status-critical)" }}>
          {error}
        </span>
      )}
    </div>
  );
}

export function Input({ className = "", ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...rest} className={`cg-input ${className}`} />;
}

export function Textarea({ className = "", ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...rest} className={`cg-input ${className}`} />;
}

export function Select({
  className = "",
  children,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...rest} className={`cg-input ${className}`}>
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
        style={{ background: checked ? "var(--accent)" : "var(--hover)" }}
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
          <p className="mt-0.5 text-[13px]" style={{ color: "var(--text-secondary)" }}>
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
    <span className="cg-chip" style={{ color: colors.fg }}>
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
      className="flex items-start gap-2 border px-3 py-2 text-sm"
      style={{
        borderColor: "var(--status-critical)",
        borderRadius: "var(--radius-sm)",
        background: "color-mix(in srgb, var(--status-critical) 8%, var(--surface))",
        color: "var(--text-primary)",
      }}
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
      className="border-l-2 px-3 py-2 text-[13px]"
      style={{
        borderColor: colors.dot,
        borderRadius: "0 var(--radius-sm) var(--radius-sm) 0",
        background: "var(--surface-2)",
        color: "var(--text-secondary)",
      }}
    >
      {children}
    </div>
  );
}

/* --------------------------------------------------------------------- table */

export function Table({
  children,
  className = "",
  before,
}: {
  children: ReactNode;
  className?: string;
  /** Shown above the table, such as how many rows a filter left. */
  before?: ReactNode;
}) {
  return (
    <div className="overflow-x-auto">
      {before}
      <table className={`cg-table ${className}`}>{children}</table>
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
      className={className}
      style={{ textAlign: align }}
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
      className={className}
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

  // Focus the dialog and lock body scroll once, when it opens. This must not
  // depend on onClose: callers pass an inline arrow that changes identity on
  // every render, and re-running focus() on each keystroke would yank focus out
  // of any input inside the modal (one letter typed, then focus jumps away).
  useEffect(() => {
    if (!open) return;
    dialogRef.current?.focus();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

  // Escape to close, kept separate so an unstable onClose can't disturb focus.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      // Only the dialog on top closes: one Escape, one dialog.
      const dialogs = document.querySelectorAll('[aria-modal="true"]');
      if (dialogs[dialogs.length - 1] !== dialogRef.current) return;
      onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  // Rendered at page level: a dialog opened from inside a card must not be
  // positioned or clipped by that card.
  return createPortal(
    <div
      className="cg-overlay"
      onClick={onClose}
      role="presentation"
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        className={`cg-dialog ${width}`}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="border-b border-hairline px-5 py-4">
          <h2 className="cg-panel-title">{title}</h2>
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
    </div>,
    document.body,
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
              borderColor: selected ? "var(--accent)" : "transparent",
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
