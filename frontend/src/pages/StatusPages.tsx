import { Link, useLocation } from "react-router-dom";
import { DiagnosticsPanel } from "../components/DiagnosticsPanel";
import { EmptyState, PageHeader } from "../components/ui";

/** /diagnose: the System health checks (also a panel on the Overview), open. */
export function DiagnosePage({ needsTwoFactor = false }: { needsTwoFactor?: boolean }) {
  return (
    <>
      <PageHeader
        title="System health"
        description="Read-only checks of the connection, the scheduler, the usage data and enforcement. The same panel is on the Overview."
      />
      <DiagnosticsPanel defaultOpen needsTwoFactor={needsTwoFactor} />
    </>
  );
}

/** Any address the app has no page for. */
export function NotFoundPage() {
  const location = useLocation();
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState
        title="There is no page at this address"
        description={
          <>
            <code>{location.pathname}</code> is not a CreditGuard page, or your account cannot open
            it. Press Ctrl K to jump to a page.
          </>
        }
        action={
          <Link to="/" className="text-sm underline">
            Go to the Overview
          </Link>
        }
      />
    </>
  );
}
