import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { Me, MessageResponse, TotpConfirmResult, TotpEnrollResult } from "../api/types";
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  InfoNote,
  Input,
  Modal,
  PageHeader,
} from "../components/ui";
import { AuthFrame } from "../components/AppShell";
import { downloadText } from "../lib/export";
import { useToast } from "../lib/ui-context";

function describe(caught: unknown, fallback: string): string {
  if (caught instanceof ApiError) {
    return caught.problems.length > 0
      ? `${caught.message} ${caught.problems.join(", ")}`
      : caught.message;
  }
  return fallback;
}

/**
 * Choose a new password. Used on the account page, and on its own as the only
 * thing an account can do while it still has a temporary password.
 *
 * Changing the password ends every session for the account, this one included,
 * so on success the caller returns to the sign-in screen.
 */
export function ChangePasswordForm({
  onChanged,
  submitLabel = "Change password",
}: {
  onChanged: () => void;
  submitLabel?: string;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const mismatch = confirm.length > 0 && next !== confirm;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (next !== confirm) {
      setError("The two new passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.post<MessageResponse>("/api/auth/password", {
        current_password: current,
        new_password: next,
      });
      onChanged();
    } catch (caught) {
      setError(describe(caught, "Could not change the password."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="flex max-w-md flex-col gap-4" onSubmit={submit}>
      {error && <ErrorNote>{error}</ErrorNote>}
      <Field label="Current password" required>
        <Input
          type="password"
          value={current}
          onChange={(event) => setCurrent(event.target.value)}
          autoComplete="current-password"
          required
        />
      </Field>
      <Field
        label="New password"
        required
        hint="At least 12 characters with mixed case, a digit and a symbol."
      >
        <Input
          type="password"
          value={next}
          onChange={(event) => setNext(event.target.value)}
          autoComplete="new-password"
          minLength={12}
          required
        />
      </Field>
      <Field
        label="New password again"
        required
        error={mismatch ? "This does not match the new password." : undefined}
      >
        <Input
          type="password"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          autoComplete="new-password"
          required
        />
      </Field>
      <div>
        <Button
          type="submit"
          variant="primary"
          loading={busy}
          disabled={!current || !next || !confirm || mismatch}
        >
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

/** Shown instead of the app while the account still has a temporary password. */
export function PasswordChangeRequired({
  username,
  onChanged,
  onSignOut,
}: {
  username: string;
  onChanged: () => void;
  onSignOut: () => void;
}) {
  return (
    <AuthFrame title="Choose a new password" description="One step before you carry on">
      <div className="w-full max-w-[560px]">
        <Card
          title="Choose a new password"
          description={`${username}, the password you signed in with was set by someone else. Choose your own before continuing. You will be asked to sign in again with it.`}
        >
          <ChangePasswordForm onChanged={onChanged} submitLabel="Set password and sign in again" />
          <button
            type="button"
            className="mt-4 text-xs underline"
            style={{ color: "var(--text-secondary)" }}
            onClick={onSignOut}
          >
            Sign out instead
          </button>
        </Card>
      </div>
    </AuthFrame>
  );
}

type TwoFactorStep =
  | { name: "idle" }
  | { name: "password"; purpose: "enable" | "disable" | "codes" }
  | { name: "scan"; enrollment: TotpEnrollResult }
  | { name: "codes"; codes: string[] };

function TwoFactorCard({ me, onChanged }: { me: Me; onChanged: () => Promise<unknown> }) {
  const toast = useToast();
  const [step, setStep] = useState<TwoFactorStep>({ name: "idle" });
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function close() {
    setStep({ name: "idle" });
    setPassword("");
    setCode("");
    setError(null);
  }

  async function confirmPassword() {
    if (step.name !== "password") return;
    setBusy(true);
    setError(null);
    try {
      if (step.purpose === "enable") {
        const enrollment = await api.post<TotpEnrollResult>("/api/auth/totp/enroll", {
          current_password: password,
        });
        setPassword("");
        setStep({ name: "scan", enrollment });
      } else if (step.purpose === "codes") {
        const result = await api.post<TotpConfirmResult>("/api/auth/totp/recovery-codes", {
          current_password: password,
        });
        setPassword("");
        setStep({ name: "codes", codes: result.recovery_codes });
      } else {
        await api.post<MessageResponse>("/api/auth/totp/disable", { current_password: password });
        toast.success("Two factor authentication turned off.");
        close();
        await onChanged();
      }
    } catch (caught) {
      setError(describe(caught, "That did not work. Try again."));
    } finally {
      setBusy(false);
    }
  }

  async function confirmCode() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.post<TotpConfirmResult>("/api/auth/totp/confirm", {
        code: code.trim(),
      });
      setCode("");
      setStep({ name: "codes", codes: result.recovery_codes });
      await onChanged();
    } catch (caught) {
      setError(describe(caught, "That code did not match. Try again."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="Two factor authentication"
      description="A code from an authenticator app, asked for after your password each time you sign in."
      actions={
        me.totp_enabled ? <Badge tone="good">Enabled</Badge> : <Badge tone="neutral">Not set up</Badge>
      }
    >
      {me.totp_enabled ? (
        <div className="flex flex-col items-start gap-3">
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Signing in needs your password and a code from your authenticator app. If you lose the
            device, sign in with one of your recovery codes, or ask another administrator to reset
            two factor for your account.
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              onClick={() => setStep({ name: "password", purpose: "codes" })}
            >
              New recovery codes
            </Button>
            <Button
              variant="secondary"
              onClick={() => setStep({ name: "password", purpose: "disable" })}
            >
              Turn off two factor
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-col items-start gap-3">
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Recommended for every administrator: this account can restrict access for people in
            your Checkmarx One tenant.
          </p>
          <Button variant="primary" onClick={() => setStep({ name: "password", purpose: "enable" })}>
            Set up two factor
          </Button>
        </div>
      )}

      <Modal
        open={step.name === "password"}
        title="Confirm it is you"
        description="Changing how your account is protected needs your password again."
        onClose={close}
        footer={
          <>
            <Button variant="secondary" onClick={close} disabled={busy}>
              Cancel
            </Button>
            <Button variant="primary" onClick={confirmPassword} loading={busy} disabled={!password}>
              Continue
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          {error && <ErrorNote>{error}</ErrorNote>}
          <Field label="Current password" required>
            <Input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              autoFocus
            />
          </Field>
        </div>
      </Modal>

      <Modal
        open={step.name === "scan"}
        title="Add this account to your authenticator app"
        description="Enter the setup key in an authenticator app (or open the link on a device that has one), then type the six digit code it shows."
        onClose={close}
        footer={
          <>
            <Button variant="secondary" onClick={close} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={confirmCode}
              loading={busy}
              disabled={code.trim().length < 6}
            >
              Turn on two factor
            </Button>
          </>
        }
      >
        {step.name === "scan" && (
          <div className="flex flex-col gap-4">
            {error && <ErrorNote>{error}</ErrorNote>}
            <Field label="Setup key">
              <code
                className="block rounded-md px-3 py-2 text-sm break-all"
                style={{ background: "var(--hover)" }}
              >
                {step.enrollment.secret.replace(/(.{4})/g, "$1 ").trim()}
              </code>
            </Field>
            <a
              className="text-xs underline"
              style={{ color: "var(--text-secondary)" }}
              href={step.enrollment.otpauth_uri}
            >
              Open in an authenticator app on this device
            </a>
            <Field label="Code from the app" required>
              <Input
                value={code}
                onChange={(event) => setCode(event.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={8}
                autoFocus
              />
            </Field>
            <InfoNote>
              Two factor is not on until you confirm a code, so closing this window leaves your
              account as it was.
            </InfoNote>
          </div>
        )}
      </Modal>

      <Modal
        open={step.name === "codes"}
        title="Save your recovery codes"
        description="Each code signs you in once, in place of the authenticator code, if you lose your device. They are shown only now, and any earlier codes no longer work."
        // Not dismissable by Escape or a stray click: the codes cannot be shown
        // again, so leaving has to be a deliberate press of the button below.
        onClose={() => undefined}
        footer={
          <>
            {step.name === "codes" && (
              <Button
                variant="secondary"
                onClick={() =>
                  downloadText(
                    `CxCreditGuard recovery codes for ${me.username}\nEach code works once.\n\n${step.codes.join("\n")}\n`,
                    "cxcreditguard-recovery-codes.txt",
                    "text/plain",
                  )
                }
              >
                Download
              </Button>
            )}
            <Button variant="primary" onClick={close}>
              I have saved them
            </Button>
          </>
        }
      >
        {step.name === "codes" && (
          <div className="flex flex-col gap-3">
            <div
              className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-md px-3 py-3 font-mono text-sm"
              style={{ background: "var(--hover)" }}
            >
              {step.codes.map((recoveryCode) => (
                <span key={recoveryCode}>{recoveryCode}</span>
              ))}
            </div>
            <InfoNote tone="warning">
              Keep them somewhere other than the device with your authenticator app. Without them,
              only another administrator can get you back in.
            </InfoNote>
          </div>
        )}
      </Modal>
    </Card>
  );
}

export function AccountPage({
  me,
  onChanged,
  onPasswordChanged,
}: {
  me: Me;
  onChanged: () => Promise<unknown>;
  onPasswordChanged: () => void;
}) {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Your account"
        description={`Signed in as ${me.username} (${me.role === "admin" ? "Admin" : "Viewer"}).`}
      />
      <Card
        title="Password"
        description="Changing it signs you out everywhere, including here, so you sign in again with the new one."
      >
        <ChangePasswordForm onChanged={onPasswordChanged} />
      </Card>
      <TwoFactorCard me={me} onChanged={onChanged} />
    </div>
  );
}
