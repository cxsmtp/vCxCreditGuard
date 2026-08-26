import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, onUnauthorized } from "./api/client";
import type { Me, NotificationList } from "./api/types";
import { AppShell } from "./components/AppShell";
import { Spinner } from "./components/ui";
import { useInterval } from "./hooks/useResource";
import { AuditPage } from "./pages/AuditPage";
import { DashboardPage } from "./pages/DashboardPage";
import { LimitsPage } from "./pages/LimitsPage";
import { LoginPage } from "./pages/LoginPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SetupPage } from "./pages/SetupPage";

type AuthState = "checking" | "signedOut" | "signedIn";

export function App() {
  const [authState, setAuthState] = useState<AuthState>("checking");
  const [me, setMe] = useState<Me | null>(null);
  const [unread, setUnread] = useState(0);
  const navigate = useNavigate();
  const location = useLocation();

  const loadMe = useCallback(async () => {
    try {
      const profile = await api.get<Me>("/api/me");
      setMe(profile);
      setAuthState("signedIn");
      return profile;
    } catch {
      setMe(null);
      setAuthState("signedOut");
      return null;
    }
  }, []);

  useEffect(() => {
    void loadMe();
  }, [loadMe]);

  // The server is the only authority on session validity. When it says the session
  // is gone, drop straight back to the login screen rather than rendering pages
  // that will fail one request at a time.
  useEffect(
    () =>
      onUnauthorized(() => {
        setAuthState("signedOut");
        setMe(null);
      }),
    [],
  );

  const refreshUnread = useCallback(async () => {
    if (authState !== "signedIn") return;
    try {
      const feed = await api.get<NotificationList>("/api/notifications", { limit: 1 });
      setUnread(feed.unread);
    } catch {
      // A failed badge refresh is not worth interrupting the user for.
    }
  }, [authState]);

  useEffect(() => {
    void refreshUnread();
  }, [refreshUnread, location.pathname]);

  useInterval(() => {
    void refreshUnread();
  }, authState === "signedIn" ? 60_000 : null);

  async function signOut() {
    try {
      await api.post("/api/auth/logout");
    } catch {
      // Even if the call fails, drop the local session view.
    }
    setAuthState("signedOut");
    setMe(null);
    navigate("/");
  }

  if (authState === "checking") {
    return (
      <div className="flex min-h-screen items-center justify-center gap-2" style={{ color: "var(--text-secondary)" }}>
        <Spinner /> Loading
      </div>
    );
  }

  if (authState === "signedOut" || !me) {
    return (
      <LoginPage
        onSignedIn={async () => {
          const profile = await loadMe();
          navigate(profile?.setup_required ? "/setup" : "/");
        }}
      />
    );
  }

  const isAdmin = me.role === "admin";

  return (
    <AppShell me={me} unreadCount={unread} onSignOut={signOut}>
      {me.setup_required && location.pathname !== "/setup" && (
        <Navigate to="/setup" replace />
      )}
      <Routes>
        <Route path="/" element={<DashboardPage isAdmin={isAdmin} />} />
        <Route path="/setup" element={<SetupPage isAdmin={isAdmin} onConnected={loadMe} />} />
        <Route path="/limits" element={<LimitsPage isAdmin={isAdmin} />} />
        <Route
          path="/notifications"
          element={<NotificationsPage isAdmin={isAdmin} onUnreadChange={setUnread} />}
        />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/settings" element={<SettingsPage isAdmin={isAdmin} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
