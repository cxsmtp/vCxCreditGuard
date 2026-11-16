import type { Me } from "../api/types";
import { Card, InfoNote, KeyValue, PageHeader } from "../components/ui";

export function AboutPage({ me }: { me: Me }) {
  return (
    <>
      <PageHeader
        title="About"
        description="What this installation is, and what it connects to."
      />
      <div className="flex max-w-[1000px] flex-col gap-6">
        <Card title="About CxCreditGuard">
          <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
            Budgets for Checkmarx One AI credits: it reads what each person, group, project and
            application has used, warns as they near their budget, and, only for budgets set to
            enforce, takes a person's AI roles or a project's Auto Triage and PR remediation away
            at the limit and puts them back afterwards. Every change is recorded and reversible.
          </p>
          <dl className="mt-4 grid gap-4 sm:grid-cols-3">
            <KeyValue label="Version">{me.version}</KeyValue>
            <KeyValue label="Tenant">{me.tenant_name ?? "Not connected"}</KeyValue>
            <KeyValue label="Connection">{me.connection_status}</KeyValue>
          </dl>
          <div className="mt-4">
            <InfoNote tone="good">
              <b>On premise, your data stays yours.</b> CxCreditGuard runs on your own server and
              connects only to what you connect it to: your Checkmarx One tenant, your mail server
              and your webhook. No telemetry, no analytics, nothing calls home.
            </InfoNote>
          </div>
        </Card>
        <Card title="Where to look next">
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm" style={{ color: "var(--text-secondary)" }}>
            <li>The operating guide (backups, upgrades, losing the master key) is in the README shipped with the release.</li>
            <li>Press Ctrl K anywhere to jump to a page or a setting.</li>
            <li>A "?" beside a heading or a field explains it.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}
