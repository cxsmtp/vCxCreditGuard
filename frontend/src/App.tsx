import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { api, onUnauthorized } from "./api/client";
import type { Me, NotificationList } from "./api/types";
import { AppShell } from "./components/AppShell";
import { Spinner } from "./components/ui";
import { applyAccent } from "./lib/ui-context";
import { useInterval } from "./hooks/useResource";
import { AccountPage, PasswordChangeRequired } from "./pages/AccountPage";
import { AuditPage } from "./pages/AuditPage";
import { DashboardPage } from "./pages/DashboardPage";
import { LimitsPage } from "./pages/LimitsPage";
import { LoginPage } from "./pages/LoginPage";
import { NotificationsPage } from "./pages/NotificationsPage";
import { PreviewPage } from "./pages/PreviewPage";
import { ReportsPage } from "./pages/ReportsPage";
import { RequestsPage } from "./pages/RequestsPage";
import { SettingsPage, type SettingsSection } from "./pages/SettingsPage";
import { AboutPage } from "./pages/AboutPage";
import { SetupPage } from "./pages/SetupPage";

type AuthState = "checking" | "signedOut" | "signedIn";

const SECTIONS: SettingsSection[] = [
  "general",
  "enforcement",
  "requests",
  "notifications",
  "attribution",
  "accounts",
  "appearance",
  "operations",
];

/** /settings itself, and the old single-page anchors, open the right page. */
function SettingsIndex() {
  const location = useLocation();
  const target =
    location.hash === "#attribution"
      ? "/settings/attribution#unmatched"
      : location.hash === "#enforcement-safety"
        ? "/settings/enforcement"
        : "/settings/general";
  return <Navigate to={target} replace />;
}

function SettingsRoute({
  isAdmin,
  onSettingsSaved,
}: {
  isAdmin: boolean;
  onSettingsSaved: () => Promise<unknown>;
}) {
  const { section } = useParams();
  if (!SECTIONS.includes(section as SettingsSection)) return <Navigate to="/settings/general" replace />;
  return (
    <SettingsPage
      key={section}
      section={section as SettingsSection}
      isAdmin={isAdmin}
      onSettingsSaved={onSettingsSaved}
    />
  );
}

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
      applyAccent(profile.ui_accent);
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
    // Drop the cached org accent so a shared browser does not pre-apply one
    // organisation's accent for the next person who signs in.
    applyAccent("default");
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

  // Changing the password ends every session for the account, this one
  // included, so the only honest next screen is the sign-in page.
  function passwordChanged() {
    setAuthState("signedOut");
    setMe(null);
    applyAccent("default");
    navigate("/");
  }

  // An account still on a temporary password can do nothing else: the server
  // refuses every other request, so the app shows only the way out of that.
  if (me.must_change_password) {
    return (
      <PasswordChangeRequired
        username={me.username}
        onChanged={passwordChanged}
        onSignOut={signOut}
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
        <Route path="/preview" element={<PreviewPage />} />
        <Route path="/reports" element={<ReportsPage isAdmin={isAdmin} />} />
        {me.can_request_credits && (
          <Route path="/requests" element={<RequestsPage isAdmin={isAdmin} />} />
        )}
        <Route
          path="/notifications"
          element={<NotificationsPage isAdmin={isAdmin} onUnreadChange={setUnread} />}
        />
        <Route path="/audit" element={<AuditPage isAdmin={isAdmin} />} />
        <Route path="/settings" element={<SettingsIndex />} />
        <Route path="/settings/about" element={<AboutPage me={me} />} />
        <Route
          path="/settings/:section"
          element={<SettingsRoute isAdmin={isAdmin} onSettingsSaved={loadMe} />}
        />
        <Route
          path="/account"
          element={<AccountPage me={me} onChanged={loadMe} onPasswordChanged={passwordChanged} />}
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
