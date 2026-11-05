import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { MessageResponse, SessionInfo } from "../api/types";
import { Button, ErrorNote, Field, Input, InfoNote } from "../components/ui";

type Mode = "login" | "forgot" | "reset";

/**
 * Sign in. Two step only when the account has TOTP enabled: the backend answers
 * 401 with code totp_required once the password has been accepted, so the code
 * prompt never appears for someone who has not already got the password right.
 *
 * The same screen also hosts self-service password reset: request a code, then
 * redeem it. The request response is deliberately the same whether or not the
 * account exists, so this UI never reveals which usernames are registered.
 */
export function LoginPage({ onSignedIn }: { onSignedIn: () => void }) {
  const [mode, setMode] = useState<Mode>("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needsTotp, setNeedsTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [retryAfter, setRetryAfter] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Reset-flow fields.
  const [resetIdentifier, setResetIdentifier] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [resetPassword, setResetPassword] = useState("");

  function switchMode(next: Mode) {
    setMode(next);
    setError(null);
    setNotice(null);
    setRetryAfter(null);
  }

  async function submitLogin(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setRetryAfter(null);
    try {
      await api.post<SessionInfo>("/api/auth/login", {
        username: username.trim(),
        password,
        ...(needsTotp && totpCode ? { totp_code: totpCode.trim() } : {}),
      });
      onSignedIn();
    } catch (caught) {
      if (caught instanceof ApiError) {
        if (caught.code === "totp_required") {
          setNeedsTotp(true);
          setError(null);
        } else if (caught.code === "account_locked" || caught.code === "rate_limited") {
          setError(caught.message);
          setRetryAfter(caught.message);
        } else {
          setError(caught.message);
        }
      } else {
        setError("Could not reach the server.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function submitForgot(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await api.post<MessageResponse>("/api/auth/forgot-password", {
        identifier: resetIdentifier.trim(),
      });
      // Jump straight to redeeming a code; the message explains delivery.
      setNotice(response.message);
      setMode("reset");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  async function submitReset(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post<MessageResponse>("/api/auth/reset-password", {
        token: resetToken.trim(),
        new_password: resetPassword,
      });
      setResetToken("");
      setResetPassword("");
      switchMode("login");
      setNotice("Password set. Sign in with your new password.");
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : "Could not reach the server.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center gap-2">
          <span
            aria-hidden="true"
            className="inline-block size-3 rounded-sm"
            style={{ background: "var(--series-1)" }}
          />
          <h1 className="text-lg font-semibold tracking-tight">CxCreditGuard</h1>
        </div>

        {mode === "login" && (
          <form
            onSubmit={submitLogin}
            className="flex flex-col gap-4 rounded-lg border border-hairline p-5"
            style={{ background: "var(--surface)" }}
          >
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Sign in to manage Checkmarx One AI credit budgets.
            </p>

            {notice && <InfoNote>{notice}</InfoNote>}
            {error && <ErrorNote>{error}</ErrorNote>}

            <Field label="Username" required>
              <Input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                autoFocus
                required
                disabled={needsTotp}
              />
            </Field>

            <Field label="Password" required>
              <Input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
                disabled={needsTotp}
              />
            </Field>

            {needsTotp && (
              <>
                <InfoNote>
                  Enter the six digit code from your authenticator app to finish signing in.
                </InfoNote>
                <Field label="Authentication code" required>
                  <Input
                    value={totpCode}
                    onChange={(event) => setTotpCode(event.target.value)}
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={8}
                    autoFocus
                    required
                  />
                </Field>
              </>
            )}

            <Button type="submit" variant="primary" loading={busy}>
              {needsTotp ? "Verify and sign in" : "Sign in"}
            </Button>

            {retryAfter && (
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                Repeated failures lock the account for a while, and the wait grows each time.
              </p>
            )}

            {!needsTotp && (
              <div className="flex justify-between text-xs">
                <button
                  type="button"
                  className="underline"
                  style={{ color: "var(--text-secondary)" }}
                  onClick={() => switchMode("forgot")}
                >
                  Forgot password?
                </button>
                <button
                  type="button"
                  className="underline"
                  style={{ color: "var(--text-secondary)" }}
                  onClick={() => switchMode("reset")}
                >
                  I have a reset code
                </button>
              </div>
            )}
          </form>
        )}

        {mode === "forgot" && (
          <form
            onSubmit={submitForgot}
            className="flex flex-col gap-4 rounded-lg border border-hairline p-5"
            style={{ background: "var(--surface)" }}
          >
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Enter your username or email. If the account exists and has an email on file, a
              single-use reset code is sent. No email set up? Ask an admin to issue one.
            </p>

            {error && <ErrorNote>{error}</ErrorNote>}

            <Field label="Username or email" required>
              <Input
                value={resetIdentifier}
                onChange={(event) => setResetIdentifier(event.target.value)}
                autoComplete="username"
                autoFocus
                required
              />
            </Field>

            <Button type="submit" variant="primary" loading={busy}>
              Send reset code
            </Button>
            <button
              type="button"
              className="text-xs underline"
              style={{ color: "var(--text-secondary)" }}
              onClick={() => switchMode("login")}
            >
              Back to sign in
            </button>
          </form>
        )}

        {mode === "reset" && (
          <form
            onSubmit={submitReset}
            className="flex flex-col gap-4 rounded-lg border border-hairline p-5"
            style={{ background: "var(--surface)" }}
          >
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Enter the one-time code and choose a new password (at least 12 characters).
            </p>

            {notice && <InfoNote>{notice}</InfoNote>}
            {error && <ErrorNote>{error}</ErrorNote>}

            <Field label="Reset code" required>
              <Input
                value={resetToken}
                onChange={(event) => setResetToken(event.target.value)}
                autoComplete="one-time-code"
                autoFocus
                required
              />
            </Field>

            <Field label="New password" required>
              <Input
                type="password"
                value={resetPassword}
                onChange={(event) => setResetPassword(event.target.value)}
                autoComplete="new-password"
                required
              />
            </Field>

            <Button type="submit" variant="primary" loading={busy}>
              Set new password
            </Button>
            <button
              type="button"
              className="text-xs underline"
              style={{ color: "var(--text-secondary)" }}
              onClick={() => switchMode("login")}
            >
              Back to sign in
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
