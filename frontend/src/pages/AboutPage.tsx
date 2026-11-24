import { useEffect, useRef, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import type { Me } from "../api/types";
import { Card, InfoNote, KeyValue, PageHeader, Tabs } from "../components/ui";

/*
  The same content as README.md "Features and limitations" and the user guide's
  "Features and limitations" section. Keep the three in step: every line here
  should be something the code does today, and every limitation something it
  really cannot do (or has not been verified to do) yet.
*/

type FeatureGroup = { title: string; items: ReactNode[] };

const FEATURES: FeatureGroup[] = [
  {
    title: "Measure and attribute",
    items: [
      "Reads AI credit use from Checkmarx One on a schedule (every 15 minutes by default) for every user, group, project and application.",
      "Matches each usage row to a Checkmarx user: exactly where it can, by name similarity where not. Unsure matches wait for an admin to confirm.",
      "Shows the usage that counts towards no budget, and why: automation (Auto Triage, bots, integrations without an email), people it could not match, and project or application names that match no project (an admin can map them).",
      "Can also charge a project's Auto Triage credits to the person whose scan set it off (off by default).",
      "Overview of spend over time, by action type and by top consumers, with each budget marked.",
      "Explains a figure: each budget shows what Checkmarx reported and what the period's starting point discounted.",
    ],
  },
  {
    title: "Budgets and requests",
    items: [
      "Budgets per user, group, project or application: monthly, quarterly, a custom range or lifetime.",
      "A warning when usage reaches a set share of the budget (80% by default).",
      "Every new budget only monitors until you switch it to enforce.",
      "Exemptions, permanent or until a date, for people and projects that must never be restricted.",
      "Bulk edit, and import and export as CSV.",
      "Credit requests: when an admin allows it, viewers ask for more budget; an admin approves in full or in part, optionally until a date, or refuses with a reason.",
      "Optional automatic approval of small increases, up to a cap you set (off by default).",
      "Reports: where each budget is heading this period, chargeback by business unit (with a cost per credit if you set one), and a weekly summary by email (off by default).",
    ],
  },
  {
    title: "Enforcement and safety",
    items: [
      "At the limit, an enforcing budget removes a person's AI roles, or turns off Auto Triage, PR triage and remediation and Fusion (your choice) on the projects it covers.",
      "Records what was there before every change; Restore access puts it back in one click.",
      "Gives access back by itself when usage drops under budget, the budget is raised or a new period starts (unless the budget is set to hold until released).",
      "Simulation: a dry run of the next cycle showing who would be warned and restricted, before anything happens.",
      "Enforcement coverage: how many of the people holding an AI role a user restriction could actually take it from, and why not the rest (composite roles, groups, protected roles), with a warning when user budgets will not bite. It never changes the role list.",
      "Safety ceilings: a cycle about to restrict more than 25 budgets or 100 users and projects restricts nobody and pauses itself.",
      "A pause switch stops new restrictions at once; warnings and giving access back carry on.",
      "Protected roles (ast-admin and iam-admin by default) are never restricted.",
      "A sudden fall in reported usage is held, not believed, until later readings confirm it.",
    ],
  },
  {
    title: "Watch and alert",
    items: [
      "Reads each restriction back and puts it back if someone undid it in Checkmarx One.",
      "Policy violations (admins only): settings switched back on, Fusion scans during a restriction, usage still rising after one.",
      "A Notification Center, with copies by email and webhook (optionally signed), filtered by severity.",
      "Checks the API key's permissions and says what is missing before it matters.",
      "An audit log of every action and change, chained so that an edited or deleted entry can be detected.",
    ],
  },
  {
    title: "Operate",
    items: [
      "Runs on your own server: one container with SQLite, or Compose with PostgreSQL behind an HTTPS proxy.",
      "Admin and viewer accounts, two-factor sign-in with recovery codes, password reset by email.",
      "In-app updates for the single container: signed releases, installed in a quiet hour, rolled back if the new version does not start.",
      "Configuration backup (settings, budgets, exemptions) to download, email or restore. Compose also dumps the database daily.",
      "Demo mode with made-up data that never touches a tenant.",
      "Two looks, Standard and Command Center, each in light and dark.",
    ],
  },
];

type Limitation = { title: string; meaning: ReactNode; group: LimitGroup };
type LimitGroup = "enforcement" | "data" | "running";

const LIMITATIONS: Limitation[] = [
  {
    title: "It acts once a cycle, not the moment credits are spent.",
    group: "enforcement",
    meaning: (
      <>
        Usage is read and budgets judged once a cycle (every 15 minutes by
        default), and Checkmarx can report credits a little after they are
        spent. Usage in between can take a budget past its limit before the
        restriction lands, so leave some headroom. A large group or application
        is restricted over several cycles (at most 1,000 changes a cycle by
        default).
      </>
    ),
  },
  {
    title: "It restricts access, it does not meter credits.",
    group: "enforcement",
    meaning: (
      <>
        It removes roles and turns settings off; it cannot stop an action
        already running or cap a budget to the exact credit.
      </>
    ),
  },
  {
    title: "Only roles held directly are removed.",
    group: "enforcement",
    meaning: (
      <>
        An AI role a person holds through a group or a composite role stays in
        effect. CreditGuard says so once and never changes the group or role,
        because that would affect everyone in it. Remove it there in Checkmarx
        One, or exempt the person.
      </>
    ),
  },
  {
    title: "User budgets may not bite at all.",
    group: "enforcement",
    meaning: (
      <>
        On a live tenant ast-admin, held by 274 of 296 users, is a composite
        role containing all three default AI roles, and it is protected: a user
        restriction would have reached almost nobody. Check Enforcement coverage
        (Simulation or Settings → Enforcement) before relying on user budgets;
        project, group and application budgets still turn AI features off on
        projects.
      </>
    ),
  },
  {
    title:
      "A project budget does not stop people's own AI Triage and AI Remediation.",
    group: "enforcement",
    meaning: (
      <>
        Turning project features off leaves what people start themselves
        working; only a user budget stops that.
      </>
    ),
  },
  {
    title: "Account-wide Auto Triage may override a project.",
    group: "enforcement",
    meaning: (
      <>
        If Auto Triage is switched on for the whole account and projects cannot
        override it, turning it off on one project does not hold. CreditGuard
        notices on the second read-back and says so once: turn it off in the
        account's Auto Triage settings, or exempt the project.
      </>
    ),
  },
  {
    title: "Turning Fusion off is not airtight.",
    group: "enforcement",
    meaning: (
      <>
        A scan started with its own settings may still run Fusion; the lock
        against that is not verified. The AI engine can still run without
        Fusion, and whether that costs credits is not known. Such scans are
        recorded as policy violations.
      </>
    ),
  },
  {
    title: "The general Risk Management roles are used for now.",
    group: "enforcement",
    meaning: (
      <>
        AI Triage and AI Remediation are reached through them today, so a
        restricted person also loses the Risk Management pages and dashboard.
        When Checkmarx One's dedicated AI permissions reach your tenant, swap
        them in under Settings → Enforcement,{" "}
        <i>Roles a user restriction removes</i>.
      </>
    ),
  },
  {
    title: "Figures only cover Checkmarx's lookback window.",
    group: "data",
    meaning: (
      <>
        Checkmarx reports totals over a window (at most the last year), not
        individual events. "Lifetime" means everything in that window. Monthly
        and quarterly budgets do not count credits spent before the period
        opened, unless the budget is set to.
      </>
    ),
  },
  {
    title: "Unmatched usage counts against nobody.",
    group: "data",
    meaning: (
      <>
        Credits reported under a name that matches no Checkmarx user, or an
        unconfirmed match, count towards no person's budget until an admin maps
        them (Settings → Attribution). Automation (bots, integrations without an
        email) never does. Project usage reported under a repository name that
        is no project counts towards no project, group or application budget
        until mapped. All of it is shown on the Overview.
      </>
    ),
  },
  {
    title: "Credits per action are measured, not quoted.",
    group: "data",
    meaning: (
      <>
        Checkmarx's listed rate is not what a Fusion or DAST correlation action
        costs (on a live tenant about 109 credits per Opus 5.5 Fusion scan
        against a rate of 2). Where they disagree, messages price an action at
        the feed's average over the lookback window and say so; it is an
        average, not the cost of one scan.
      </>
    ),
  },
  {
    title: "It cannot say who undid a restriction.",
    group: "enforcement",
    meaning: (
      <>
        Checkmarx One does not report who switched a setting back on. By default
        each restriction is read back once an hour, so a setting switched back
        on can stay on for up to about that long, and one undone and redone
        between two read-backs is not seen.
      </>
    ),
  },
  {
    title: "Some Checkmarx behaviour is not yet verified on a real tenant.",
    group: "data",
    meaning: (
      <>
        Each of these degrades safely and says so rather than guessing:
        <ul className="mt-1 flex list-disc flex-col gap-0.5 pl-5">
          <li>where a person's roles come from (groups, composite roles);</li>
          <li>the Fusion lock and the repository's Fusion setting;</li>
          <li>
            usage rows per group (only ever seen empty; the sum of its projects
            is used instead);
          </li>
          <li>
            writes of PR triage and remediation and Auto Triage in the shape a
            live tenant reads them (sent back as read, not yet tested by a
            write on one);
          </li>
          <li>
            finding a project's repository (without it, PR triage and
            remediation is skipped there);
          </li>
          <li>
            whether a Fusion setting the project inherited can inherit again
            after Restore (for now it is restored on the project itself).
          </li>
        </ul>
      </>
    ),
  },
  {
    title: "Tested to 2,000 projects on a synthetic tenant.",
    group: "running",
    meaning: (
      <>
        Load tested with 2,000 projects and 1,000 users made up for the test,
        not on a real tenant of that size. Use PostgreSQL above about 500
        projects or 300 users.
      </>
    ),
  },
  {
    title: "One instance only.",
    group: "running",
    meaning: (
      <>
        A second copy against the same database refuses to start. Availability
        comes from restarting the one copy, not from running several.
      </>
    ),
  },
  {
    title: "The database is the only record of how to undo a restriction.",
    group: "running",
    meaning: (
      <>
        The in-app backup holds configuration only. Back the database up; after
        restoring an older one, restrictions made since it was taken have to be
        given back by hand in Checkmarx One.
      </>
    ),
  },
  {
    title: "Updates are only as trustworthy as the release signing key.",
    group: "running",
    meaning: (
      <>
        Until the image carries the release signing key, auto-update installs
        nothing and a manual install cannot be verified. Updates need a registry
        token, and only the single container updates itself: Compose shows the
        steps instead. Operating system, Python and OpenSSL fixes need a new
        image.
      </>
    ),
  },
  {
    title: "The audit log is tamper-evident, not tamper-proof.",
    group: "running",
    meaning: (
      <>
        An edited or deleted entry is detected, but someone with full write
        access to the database could rewrite the whole chain.
      </>
    ),
  },
];

type TabId =
  | "overview"
  | "measure"
  | "budgets"
  | "enforcement"
  | "watch"
  | "operate"
  | LimitTab;
type LimitTab = "limits-enforcement" | "limits-data" | "limits-running";

const FEATURE_TABS: { id: TabId; label: string; group: string }[] = [
  {
    id: "measure",
    label: "Measure & attribute",
    group: "Measure and attribute",
  },
  { id: "budgets", label: "Budgets & requests", group: "Budgets and requests" },
  {
    id: "enforcement",
    label: "Enforcement & safety",
    group: "Enforcement and safety",
  },
  { id: "watch", label: "Watch & alert", group: "Watch and alert" },
  { id: "operate", label: "Operate", group: "Operate" },
];

const LIMIT_TABS: {
  id: LimitTab;
  label: string;
  group: LimitGroup;
  title: string;
  description: string;
}[] = [
  {
    id: "limits-enforcement",
    label: "Limits: enforcement",
    group: "enforcement",
    title: "Limits of enforcement",
    description: "What a restriction can and cannot stop, and when it lands.",
  },
  {
    id: "limits-data",
    label: "Limits: figures",
    group: "data",
    title: "Limits of the figures",
    description:
      "What the numbers cover, and what is not yet verified on a real tenant.",
  },
  {
    id: "limits-running",
    label: "Limits: running it",
    group: "running",
    title: "Limits of running it",
    description: "Scale, availability, backups, updates and the audit log.",
  },
];

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  ...FEATURE_TABS.map(({ id, label }) => ({ id, label })),
  ...LIMIT_TABS.map(({ id, label }) => ({ id, label })),
];

function isTabId(value: string | null): value is TabId {
  return TABS.some((tab) => tab.id === value);
}

export function AboutPage({ me }: { me: Me }) {
  // The open tab is in the address (?tab=...), so a link can point at one heading.
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const active: TabId = isTabId(requested) ? requested : "overview";
  const open = (id: TabId) => {
    const next = new URLSearchParams(params);
    if (id === "overview") next.delete("tab");
    else next.set("tab", id);
    setParams(next, { replace: true });
  };
  const feature = FEATURE_TABS.find((tab) => tab.id === active);
  const limit = LIMIT_TABS.find((tab) => tab.id === active);

  // On a phone the tab bar is one row that scrolls sideways: keep the open
  // tab in view, also when the page is opened on a later tab by its link.
  const tabBar = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const selected = tabBar.current?.querySelector<HTMLElement>(
      '[role="tab"][aria-selected="true"]',
    );
    selected?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [active]);

  return (
    <>
      <PageHeader
        title="About"
        description="What this installation is, what it does, what it cannot do, and what it connects to."
      />
      <div className="flex max-w-[1000px] flex-col gap-3">
        {/* Compact tabs. Below sm one row scrolling sideways (as the Settings
            menu does), so the content starts near the top; from sm up they
            wrap, two rows at 1440 px. */}
        <div
          ref={tabBar}
          className="min-w-0 [&_[role=tab]]:shrink-0 [&_[role=tab]]:px-2.5 [&_[role=tab]]:py-1.5 [&_[role=tab]]:whitespace-nowrap [&>[role=tablist]]:flex-nowrap [&>[role=tablist]]:overflow-x-auto sm:[&>[role=tablist]]:flex-wrap sm:[&>[role=tablist]]:overflow-visible"
        >
          <Tabs<TabId> tabs={TABS} active={active} onChange={open} />
        </div>

        {active === "overview" && (
          <>
            <Card title="About CxCreditGuard">
              <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
                Budgets for Checkmarx One AI credits: it reads what each person,
                group, project and application has used, warns as they near
                their budget, and, only for budgets set to enforce, takes a
                person's AI roles or a project's Auto Triage, PR triage and
                remediation or Fusion away at the limit and puts them back
                afterwards. Every change is recorded and reversible.
              </p>
              <dl className="mt-4 grid gap-4 sm:grid-cols-3">
                <KeyValue label="Version">{me.version}</KeyValue>
                <KeyValue label="Tenant">
                  {me.tenant_name ?? "Not connected"}
                </KeyValue>
                <KeyValue label="Connection">{me.connection_status}</KeyValue>
              </dl>
              <div className="mt-4">
                <InfoNote tone="good">
                  <b>On premise, your data stays yours.</b> CxCreditGuard runs
                  on your own server. It connects to your Checkmarx One tenant
                  and, only if you set them up, your mail server and your
                  webhook. With a registry token entered under Settings →
                  Updates, it also contacts GitHub's container registry (ghcr.io
                  and pkg-containers.githubusercontent.com) to check for and
                  download releases. No telemetry, no analytics, and nothing
                  else is contacted.
                </InfoNote>
              </div>
            </Card>
            <Card title="Where to look next">
              <ul
                className="flex list-disc flex-col gap-1 pl-5 text-sm"
                style={{ color: "var(--text-secondary)" }}
              >
                <li>
                  The tabs above list what it does, one heading each, and its
                  limitations.
                </li>
                <li>
                  The operating guide (backups, upgrades, losing the master key)
                  is in the README shipped with the release; the user guide
                  walks through setup and daily use.
                </li>
                <li>Press Ctrl K anywhere to jump to a page or a setting.</li>
                <li>A "?" beside a heading or a field explains it.</li>
              </ul>
            </Card>
          </>
        )}

        {feature && (
          <Card
            title={feature.group}
            description="What it does. The README and the user guide explain each one in detail."
          >
            <ul
              className="flex list-disc flex-col gap-1.5 pl-5 text-sm"
              style={{ color: "var(--text-secondary)" }}
            >
              {(
                FEATURES.find((group) => group.title === feature.group)
                  ?.items ?? []
              ).map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </Card>
        )}

        {limit && (
          <Card title={limit.title} description={limit.description}>
            {/* Two balanced columns on a wide screen, so the longest tab
                fits a 900 px high window at 1440 px. */}
            <ul className="gap-x-8 lg:columns-2">
              {LIMITATIONS.filter((item) => item.group === limit.group).map(
                (item) => (
                  <li
                    key={item.title}
                    className="mb-3 break-inside-avoid border-l-2 pl-3 text-sm last:mb-0"
                    style={{ borderColor: "var(--border-strong)" }}
                  >
                    <p
                      className="font-medium"
                      style={{ color: "var(--text-primary)" }}
                    >
                      {item.title}
                    </p>
                    <div
                      className="mt-0.5"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      {item.meaning}
                    </div>
                  </li>
                ),
              )}
            </ul>
          </Card>
        )}
      </div>
    </>
  );
}
