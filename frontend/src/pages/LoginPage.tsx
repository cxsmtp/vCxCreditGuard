import { useState } from "react";
import { ApiError, api } from "../api/client";
import type { SessionInfo } from "../api/types";
import { Button, ErrorNote, Field, Input, InfoNote } from "../components/ui";

/**
 * Sign in. Two step only when the account has TOTP enabled: the backend answers
 * 401 with code totp_required once the password has been accepted, so the code
 * prompt never appears for someone who has not already got the password right.
 */
export function LoginPage({ onSignedIn }: { onSignedIn: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needsTotp, setNeedsTotp] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryAfter, setRetryAfter] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
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

        <form
          onSubmit={submit}
          className="flex flex-col gap-4 rounded-lg border border-hairline p-5"
          style={{ background: "var(--surface)" }}
        >
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Sign in to manage Checkmarx One AI credit budgets.
          </p>

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
        </form>
      </div>
    </div>
  );
}
