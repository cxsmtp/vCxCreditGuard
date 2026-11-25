"""Runtime settings that an admin changes from the GUI without a restart.

Environment variables cover deployment concerns (database, master key, TLS).
These cover operational ones: how often to poll, how wide a usage window to ask
for, where to send notifications. They live in ``app_setting`` as JSON text, with
secret values encrypted under their own purpose and never returned unmasked.
"""

from __future__ import annotations

import fnmatch
import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES, never_removed
from app.checkmarx.usage import DEFAULT_PERIOD
from app.core.crypto import (
    PURPOSE_SMTP_PASSWORD,
    PURPOSE_UPDATE_TOKEN,
    PURPOSE_WEBHOOK_SECRET,
    PURPOSE_WEBHOOK_URL,
    get_secret_box,
)
from app.models.connection import AppSetting

logger = logging.getLogger(__name__)

# Scheduler
KEY_SCHEDULE_MODE = "scheduler.mode"  # "interval" or "cron"
KEY_SCHEDULE_INTERVAL_MINUTES = "scheduler.interval_minutes"
KEY_SCHEDULE_CRON = "scheduler.cron"
KEY_ORG_REFRESH_MINUTES = "scheduler.org_refresh_minutes"
KEY_SCHEDULER_ENABLED = "scheduler.enabled"

# Ingestion
KEY_USAGE_PERIOD = "usage.period_param"
KEY_USAGE_PAGE_SIZE = "usage.page_size"
# Where period budgets of projects, users and applications get their usage:
# "activity" (the default) reads the per-action credit log (GET
# /api/credits/activity) and falls back to the consumption summary while the
# log cannot be read; "summary" reads the summary only, as before the log was
# used. See app/services/activity_source.py.
KEY_USAGE_SOURCE = "usage.source"
USAGE_SOURCE_ACTIVITY = "activity"
USAGE_SOURCE_SUMMARY = "summary"
USAGE_SOURCES: tuple[str, ...] = (USAGE_SOURCE_ACTIVITY, USAGE_SOURCE_SUMMARY)
# At most this many pages of the activity log are read in one cycle (a
# normal cycle reads the last couple of hours; more is read after downtime,
# and the daily reconciliation reads the whole window). 0: no cap.
KEY_ACTIVITY_MAX_PAGES = "usage.activity_max_pages_per_cycle"
# With the usage source at "summary": whether usage the summary ledger counted
# may start a restriction of a period budget (the behaviour before the
# activity log). Off by default: from running totals the summary cannot always
# tell a glitch from a real fall, so a period budget then warns and is not
# restricted. Usage the activity log counted always may. Budgets that count
# current totals (lifetime, custom, count existing usage) are not affected.
KEY_SUMMARY_RESTRICTS = "usage.summary_restricts"

# Retention
KEY_RETENTION_DAYS = "retention.days"
# Thin old usage snapshots (app/services/retention.py): every one of the last
# 3 days, one an hour per dimension up to 40 days, one a day after that, never
# one anything refers to. Off: every snapshot is kept for the whole window.
KEY_RETENTION_THIN_SNAPSHOTS = "retention.thin_snapshots"

# Notifications
KEY_SMTP_HOST = "notify.smtp.host"
KEY_SMTP_PORT = "notify.smtp.port"
KEY_SMTP_USERNAME = "notify.smtp.username"
KEY_SMTP_PASSWORD = "notify.smtp.password"  # secret
KEY_SMTP_USE_TLS = "notify.smtp.use_tls"
KEY_SMTP_FROM = "notify.smtp.from"
KEY_SMTP_RECIPIENTS = "notify.smtp.recipients"
KEY_WEBHOOK_URL = "notify.webhook.url"
KEY_WEBHOOK_SECRET = "notify.webhook.secret"  # secret
KEY_NOTIFY_MIN_SEVERITY = "notify.min_severity"

# Appearance: the organisation-wide accent theme an admin picks. Applied to
# every signed-in browser; the chart series palette is never affected.
KEY_UI_ACCENT = "ui.accent"
# The Standard look's earth accents: default (Ink), teal (Lagoon), sage, violet
# (Plum) and amber (Ochre). Rose and slate are kept so a saved choice stays valid;
# the web UI shows them as Plum and Ink.
ALLOWED_ACCENTS: tuple[str, ...] = ("default", "teal", "sage", "violet", "amber", "rose", "slate")

# Credit requests: when on, a non-admin (viewer) may submit a request to raise an
# entity's budget for an admin to approve. Off by default, so self-service is a
# deliberate choice an admin makes rather than something viewers get silently.
KEY_SELF_SERVICE_REQUESTS = "requests.self_service"

# Scheduled report email: when on, a weekly summary report is emailed to the
# configured notification recipients. Off by default; needs SMTP configured.
KEY_REPORT_EMAIL_ENABLED = "reports.weekly_email"

# Chargeback: the monetary cost of one credit, used only to put a figure next to
# per-business-unit consumption. 0 means "cost unknown"; the report then shows
# credits without a currency amount.
KEY_CREDIT_UNIT_COST = "reports.credit_unit_cost"

# Demo mode: when on, the UI is clearly marked as demo and real enforcement is
# suppressed (no writes to Checkmarx), so the product can be trialled with the
# seeded synthetic dataset without touching a live tenant.
KEY_DEMO_MODE = "demo.enabled"

# Hands-off automation: when enabled, the cycle auto-approves pending credit
# requests whose increase over the current budget is within
# ``auto_approve_max_increase`` credits. A cap of 0 auto-approves nothing even
# when enabled (an explicit, safe default: the admin must set a cap). A non-zero
# ``auto_approve_expiry_days`` makes each auto-grant temporary, so it self-reverts
# via the existing grant-expiry step and the mode stays safe to leave on.
KEY_AUTOMATION_ENABLED = "automation.enabled"
KEY_AUTO_APPROVE_MAX_INCREASE = "automation.auto_approve_max_increase"
KEY_AUTO_APPROVE_EXPIRY_DAYS = "automation.auto_approve_expiry_days"

# Enforcement safety. ``paused`` stops new restrictions (restores still happen);
# the cycle sets it itself, with a reason, when more limits than
# ``max_new_enforcements_per_cycle`` would start restricting in one cycle - a
# sign of bad data or a mistake far more often than of that many people
# overspending in the same few minutes. ``protected_roles`` are tenant roles
# whose holders are never restricted.
KEY_ENFORCEMENT_PAUSED = "enforcement.paused"
KEY_ENFORCEMENT_PAUSE_REASON = "enforcement.pause_reason"
KEY_MAX_NEW_ENFORCEMENTS = "enforcement.max_new_enforcements_per_cycle"
# The same ceiling counted in users and projects rather than limits: one group
# or application limit can restrict hundreds of projects on its own.
KEY_MAX_NEW_TARGETS = "enforcement.max_new_targets_per_cycle"
# Set when an admin resumes enforcement: the batch they have just looked at is
# let through once, and the ceilings apply again from the following cycle.
KEY_CEILING_WAIVED_ONCE = "enforcement.ceiling_waived_once"
KEY_PROTECTED_ROLES = "enforcement.protected_roles"
# Turning Fusion off for a project also tries to lock the project's setting
# (allowOverride false), so that a single scan cannot switch it back on. Whether
# Checkmarx One honours that lock for ad hoc scans is not verified, and a
# tenant that rejects the lock still gets Fusion turned off without it.
KEY_FUSION_LOCK = "enforcement.fusion_lock_override"
# The client roles (on the platform client, ast-app) a user restriction removes.
# The default is the Fusion and LLM roles that gate spending AI credits
# (iam.DEFAULT_AI_ROLE_NAMES). A change applies to restrictions made from then
# on: each restriction records the list it used, and its Restore and drift check
# go by that record. ``ai-triage-assist`` is never one of them
# (iam.NEVER_AI_ROLE_NAMES).
KEY_AI_ROLES = "enforcement.ai_roles"
AI_ROLES_MAX = 50

# Attribution: when on, the Auto Triage credits a project reports are also
# charged to the person (a synced Checkmarx user) whose scan triggered the auto
# triage, so their user limit - and group limits that include member usage -
# reflect it. Off by default: it changes who is counted for what, and turning it
# on can push many people over budget at once (the enforcement safety ceilings
# still apply). Project, application and tenant totals are unaffected either way.
KEY_AUTO_TRIAGE_TO_INITIATOR = "attribution.auto_triage_to_scan_initiator"
# When the setting above last became effective (switched on, or demo mode
# switched off while it was on), as an ISO timestamp. Written by ``set_value``
# itself, so every way of turning it on stamps it. Auto-triage attribution
# restarts observation of every project whose cursor belongs to an earlier
# stamp: credits that arrived while it was off are history (estimated), never
# a single "observed" rise. Not part of the configuration backup.
KEY_AUTO_TRIAGE_OBSERVATION_EPOCH = "attribution.auto_triage_observation_epoch"
# Names (case-insensitive) of integration accounts the activity log reports
# usage under, besides the ones recognised by themselves ("[bot]" accounts,
# Auto-triage, Auto-remediation): an SCM or CI integration's account, for
# example. Usage of an integration account counts towards no user budget when
# its project had an active project budget (app/services/activity_source.py).
KEY_INTEGRATION_ACCOUNTS = "attribution.integration_accounts"
INTEGRATION_ACCOUNTS_MAX = 200

# Pacing for large tenants (app/services/pacing.py). Each is a per-cycle budget;
# 0 means no budget: everything, every cycle (see pacing.py for how that
# compares with before pacing).
# How often each restriction in force is read back from Checkmarx One, at most
# (minutes). 0: every restriction, every cycle.
KEY_VERIFY_INTERVAL_MINUTES = "enforcement.verify_interval_minutes"
# At most this many restrictions read back in one cycle.
KEY_MAX_VERIFICATIONS = "enforcement.max_verifications_per_cycle"
# At most this many restrictions applied or lifted in one cycle; a larger
# first enforcement (or restore) carries on over the next cycles.
KEY_MAX_WRITES = "enforcement.max_writes_per_cycle"
# Restricted projects whose scans the policy violation check lists per cycle.
KEY_VIOLATION_PROJECTS = "violations.max_projects_per_cycle"
# Projects and scan requests auto-triage attribution works through per cycle.
KEY_ATTRIBUTION_PROJECTS = "attribution.max_projects_per_cycle"
KEY_ATTRIBUTION_REQUESTS = "attribution.max_requests_per_cycle"
# Independent read-only Checkmarx calls made at the same time (1: one by one).
KEY_READ_CONCURRENCY = "cycle.read_concurrency"
# Share of the interval a cycle may spend before it stops starting new
# per-target work and leaves the rest to the next cycle (0: no time budget).
KEY_CYCLE_TIME_BUDGET_PCT = "cycle.time_budget_pct"
PACING_KEYS: tuple[str, ...] = (
    KEY_VERIFY_INTERVAL_MINUTES,
    KEY_MAX_VERIFICATIONS,
    KEY_MAX_WRITES,
    KEY_VIOLATION_PROJECTS,
    KEY_ATTRIBUTION_PROJECTS,
    KEY_ATTRIBUTION_REQUESTS,
    KEY_READ_CONCURRENCY,
    KEY_CYCLE_TIME_BUDGET_PCT,
)

# Updates (app/updates). Auto-update is on by default: a newer release is
# installed in the quiet hour (UTC). The registry token is a read-only GitHub
# token (read:packages) for the private release images; a secret like the
# Checkmarx API key, encrypted under its own purpose and never shown back.
KEY_UPDATE_AUTO = "updates.auto_enabled"
KEY_UPDATE_QUIET_HOUR = "updates.quiet_hour"
KEY_UPDATE_TOKEN = "updates.registry_token"  # secret

# The latest API key permission report (app/services/key_permissions.py), as
# JSON. Bookkeeping, not configuration: it is never shown on the Settings page,
# never part of a configuration backup and never part of the attestation digest.
KEY_KEY_PERMISSIONS = "connection.key_permissions"
# The latest price per action from GET /api/v1/credits/action-rates, read once
# per cycle, best effort. Bookkeeping like the report above: never a setting.
KEY_ACTION_RATES = "credits.action_rates"
# The last enforcement coverage report (app/services/coverage.py), cached.
KEY_ENFORCEMENT_COVERAGE = "enforcement.coverage"
# The group names last found not to be unique, kept for Diagnostics.
KEY_DUPLICATE_GROUP_NAMES = "org_sync.duplicate_group_names"
# Newest scan the policy violation check has looked at, per restricted project.
KEY_VIOLATION_SCAN_CURSORS = "violations.scan_cursors"
# The launcher events (updates) already written to the audit log. Kept in the
# database, not beside the events, so a database restored by a rollback reports
# again what its restored copy does not hold.
KEY_UPDATE_REPORTED_EVENTS = "updates.reported_events"
# How far the retention job has cleared old raw consumption rows (an ISO
# timestamp: snapshots collected before it are done). Bookkeeping.
KEY_RETENTION_RAW_CLEARED_UNTIL = "retention.raw_cleared_until"
# The recounts before a new restriction that refused it (app/services/recount.py):
# a disagreement with the activity log, or no recount possible. Bookkeeping.
KEY_RECOUNT_RECORDS = "recount.records"
# Onboarding (app/services/readiness.py). ``gate`` is set by the data migration
# on a new install only: leaving watch-only then needs a green readiness
# checklist or an admin's typed override. Cleared once enforcement is on.
KEY_READINESS_GATE = "readiness.gate"
# When an admin last marked the dry run / Simulation reviewed, and who.
KEY_READINESS_REVIEWED = "readiness.dry_run_reviewed"
# Each checklist item's last state, to warn when one turns red later.
KEY_READINESS_LAST = "readiness.last_states"
# Rows kept in app_setting that are state rather than settings.
INTERNAL_KEYS: frozenset[str] = frozenset(
    {
        KEY_KEY_PERMISSIONS,
        KEY_ACTION_RATES,
        KEY_VIOLATION_SCAN_CURSORS,
        KEY_UPDATE_REPORTED_EVENTS,
        KEY_RETENTION_RAW_CLEARED_UNTIL,
        KEY_RECOUNT_RECORDS,
        KEY_READINESS_GATE,
        KEY_READINESS_REVIEWED,
        KEY_READINESS_LAST,
    }
)

# Marker stamped on a demo usage snapshot's period_param. Distinctive on purpose
# so it can never collide with a real Checkmarx lookback window, and so the read
# path can hide demo snapshots whenever demo mode is off.
DEMO_PERIOD_PARAM = "__demo__"

SECRET_KEYS: dict[str, str] = {
    KEY_SMTP_PASSWORD: PURPOSE_SMTP_PASSWORD,
    KEY_WEBHOOK_SECRET: PURPOSE_WEBHOOK_SECRET,
    # A chat or automation webhook URL is a credential in its own right: anyone
    # who has it can post to the channel. It is stored encrypted, never shown
    # back, and kept out of audit entries and backups like any other secret.
    KEY_WEBHOOK_URL: PURPOSE_WEBHOOK_URL,
    KEY_UPDATE_TOKEN: PURPOSE_UPDATE_TOKEN,
}

ALLOWED_INTERVAL_MINUTES: tuple[int, ...] = (2, 5, 15, 60)

DEFAULTS: dict[str, Any] = {
    KEY_SCHEDULER_ENABLED: True,
    KEY_SCHEDULE_MODE: "interval",
    KEY_SCHEDULE_INTERVAL_MINUTES: 15,
    KEY_SCHEDULE_CRON: None,
    KEY_ORG_REFRESH_MINUTES: 30,
    KEY_USAGE_PERIOD: DEFAULT_PERIOD,
    KEY_USAGE_PAGE_SIZE: 100,
    KEY_USAGE_SOURCE: USAGE_SOURCE_ACTIVITY,
    KEY_ACTIVITY_MAX_PAGES: 40,
    KEY_SUMMARY_RESTRICTS: False,
    KEY_INTEGRATION_ACCOUNTS: [],
    KEY_RETENTION_DAYS: 365,
    KEY_RETENTION_THIN_SNAPSHOTS: True,
    KEY_SMTP_PORT: 587,
    KEY_SMTP_USE_TLS: True,
    KEY_NOTIFY_MIN_SEVERITY: "warning",
    KEY_UI_ACCENT: "default",
    KEY_SELF_SERVICE_REQUESTS: False,
    KEY_REPORT_EMAIL_ENABLED: False,
    KEY_CREDIT_UNIT_COST: 0.0,
    KEY_DEMO_MODE: False,
    KEY_AUTOMATION_ENABLED: False,
    KEY_AUTO_APPROVE_MAX_INCREASE: 0,
    KEY_AUTO_APPROVE_EXPIRY_DAYS: 0,
    KEY_ENFORCEMENT_PAUSED: False,
    KEY_ENFORCEMENT_PAUSE_REASON: None,
    KEY_MAX_NEW_ENFORCEMENTS: 25,
    KEY_MAX_NEW_TARGETS: 100,
    KEY_CEILING_WAIVED_ONCE: False,
    KEY_PROTECTED_ROLES: "ast-admin, iam-admin",
    KEY_FUSION_LOCK: True,
    KEY_AI_ROLES: list(DEFAULT_AI_ROLE_NAMES),
    KEY_AUTO_TRIAGE_TO_INITIATOR: False,
    KEY_VERIFY_INTERVAL_MINUTES: 60,
    KEY_MAX_VERIFICATIONS: 2000,
    KEY_MAX_WRITES: 1000,
    KEY_VIOLATION_PROJECTS: 150,
    KEY_ATTRIBUTION_PROJECTS: 150,
    KEY_ATTRIBUTION_REQUESTS: 600,
    KEY_READ_CONCURRENCY: 4,
    KEY_CYCLE_TIME_BUDGET_PCT: 80,
    KEY_UPDATE_AUTO: True,
    KEY_UPDATE_QUIET_HOUR: 3,
}


@dataclass(frozen=True, slots=True)
class ScheduleConfig:
    enabled: bool
    mode: str
    interval_minutes: int
    cron: str | None
    org_refresh_minutes: int


def ui_accent(session: Session) -> str:
    """The organisation accent theme, falling back to the default if unset or
    somehow invalid (so a stray stored value can never break the UI)."""
    value = get_value(session, KEY_UI_ACCENT, DEFAULTS[KEY_UI_ACCENT])
    return value if value in ALLOWED_ACCENTS else DEFAULTS[KEY_UI_ACCENT]


def self_service_requests_enabled(session: Session) -> bool:
    """Whether a viewer may submit a credit request for an admin to decide."""
    return bool(get_value(session, KEY_SELF_SERVICE_REQUESTS, DEFAULTS[KEY_SELF_SERVICE_REQUESTS]))


def report_email_enabled(session: Session) -> bool:
    """Whether the weekly summary report is emailed to the notification recipients."""
    return bool(get_value(session, KEY_REPORT_EMAIL_ENABLED, DEFAULTS[KEY_REPORT_EMAIL_ENABLED]))


def auto_triage_to_initiator(session: Session) -> bool:
    """Whether auto-triage credits are also charged to the scan's initiator.

    Never in demo mode: the charges are collected from the live tenant and must
    not be laid over the seeded demo figures.
    """
    if demo_mode(session):
        return False
    return (
        get_value(session, KEY_AUTO_TRIAGE_TO_INITIATOR, DEFAULTS[KEY_AUTO_TRIAGE_TO_INITIATOR])
        is True
    )


def auto_triage_observation_epoch(session: Session) -> str | None:
    """The stamp of the current auto-triage observation epoch, if one was taken."""
    value = get_value(session, KEY_AUTO_TRIAGE_OBSERVATION_EPOCH, None)
    return value if isinstance(value, str) and value else None


def start_auto_triage_observation_epoch(session: Session) -> str:
    """Stamp a new observation epoch: every project's observation restarts."""
    from app.db.base import utcnow

    stamp = utcnow().isoformat()
    _write_value(session, KEY_AUTO_TRIAGE_OBSERVATION_EPOCH, stamp)
    return stamp


def demo_mode(session: Session) -> bool:
    """Whether demo mode is on (synthetic data, enforcement suppressed)."""
    return bool(get_value(session, KEY_DEMO_MODE, DEFAULTS[KEY_DEMO_MODE]))


@dataclass(frozen=True, slots=True)
class AutomationPolicy:
    """Hands-off automation settings, normalised to safe values."""

    enabled: bool
    auto_approve_max_increase: int
    auto_approve_expiry_days: int

    @property
    def auto_approves(self) -> bool:
        """Whether anything is actually auto-approved (enabled and a non-zero cap)."""
        return self.enabled and self.auto_approve_max_increase > 0


def _non_negative_int(value: Any, fallback: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    return number if number >= 0 else fallback


def automation_policy(session: Session) -> AutomationPolicy:
    return AutomationPolicy(
        enabled=bool(get_value(session, KEY_AUTOMATION_ENABLED, DEFAULTS[KEY_AUTOMATION_ENABLED])),
        auto_approve_max_increase=_non_negative_int(
            get_value(session, KEY_AUTO_APPROVE_MAX_INCREASE), 0
        ),
        auto_approve_expiry_days=_non_negative_int(
            get_value(session, KEY_AUTO_APPROVE_EXPIRY_DAYS), 0
        ),
    )


@dataclass(frozen=True, slots=True)
class EnforcementGuard:
    """The safety settings around applying restrictions, normalised."""

    paused: bool
    pause_reason: str | None
    # 0 means no ceiling.
    max_new_per_cycle: int
    max_new_targets_per_cycle: int
    # True for the one cycle after an admin resumes enforcement.
    ceiling_waived_once: bool
    protected_roles: frozenset[str]


def enforcement_guard(session: Session) -> EnforcementGuard:
    roles = get_value(session, KEY_PROTECTED_ROLES, DEFAULTS[KEY_PROTECTED_ROLES])
    reason = get_value(session, KEY_ENFORCEMENT_PAUSE_REASON)
    return EnforcementGuard(
        paused=bool(get_value(session, KEY_ENFORCEMENT_PAUSED, False)),
        pause_reason=reason if isinstance(reason, str) and reason else None,
        max_new_per_cycle=_non_negative_int(
            get_value(session, KEY_MAX_NEW_ENFORCEMENTS), DEFAULTS[KEY_MAX_NEW_ENFORCEMENTS]
        ),
        max_new_targets_per_cycle=_non_negative_int(
            get_value(session, KEY_MAX_NEW_TARGETS), DEFAULTS[KEY_MAX_NEW_TARGETS]
        ),
        ceiling_waived_once=bool(get_value(session, KEY_CEILING_WAIVED_ONCE, False)),
        protected_roles=parse_protected_roles(roles),
    )


def thin_snapshots(session: Session) -> bool:
    """Whether the retention job thins old usage snapshots (on unless switched off)."""
    return (
        get_value(session, KEY_RETENTION_THIN_SNAPSHOTS, DEFAULTS[KEY_RETENTION_THIN_SNAPSHOTS])
        is not False
    )


def fusion_lock_enabled(session: Session) -> bool:
    """Whether turning Fusion off also tries to lock it against per-scan override."""
    return get_value(session, KEY_FUSION_LOCK, DEFAULTS[KEY_FUSION_LOCK]) is not False


# Role names that look like administration roles. Taking one away from a person
# over a budget would take away far more than AI features, so choosing one as an
# AI role needs an explicit confirmation.
ADMIN_ROLE_PATTERNS: tuple[str, ...] = ("*admin*", "manage-*", "realm-*", "iam-*")


def admin_like_role(name: str) -> bool:
    """Whether a role name matches one of ADMIN_ROLE_PATTERNS (case ignored).

    The default AI roles never do: ``manage-fusion`` and
    ``manage-llm-configuration`` match ``manage-*`` but are known to govern
    only Fusion and LLM settings.
    """
    lowered = name.strip().lower()
    if lowered in DEFAULT_AI_ROLE_NAMES:
        return False
    return any(fnmatch.fnmatchcase(lowered, pattern) for pattern in ADMIN_ROLE_PATTERNS)


def parse_protected_roles(value: Any) -> frozenset[str]:
    """The protected role names (lowercase) from the stored comma separated text."""
    return frozenset(
        name.strip().lower()
        for name in str(value or "").replace(";", ",").split(",")
        if name.strip()
    )


def normalise_role_names(value: Any) -> list[str]:
    """A list of role names, trimmed, without blanks or repeats, in order."""
    if isinstance(value, str):
        value = value.replace(";", ",").split(",")
    if not isinstance(value, list | tuple):
        return []
    seen: dict[str, None] = {}
    for entry in value:
        if isinstance(entry, str) and entry.strip():
            seen.setdefault(entry.strip(), None)
    return list(seen)


def ai_role_names(session: Session) -> tuple[str, ...]:
    """The client roles a user restriction removes from now on.

    Falls back to the default list when unset or unusable, so a stray stored
    value can never make a restriction remove nothing. A role a restriction
    must never remove (``iam.NEVER_AI_ROLE_NAMES``) is left out, however it got
    stored (the Settings page refuses it).
    """
    names = [
        name
        for name in normalise_role_names(get_value(session, KEY_AI_ROLES, DEFAULTS[KEY_AI_ROLES]))
        if not never_removed(name)
    ]
    return tuple(names[:AI_ROLES_MAX]) or DEFAULT_AI_ROLE_NAMES


def action_rates(session: Session) -> dict[str, Any] | None:
    """The stored action rates ({"read_at", "rates": [...]}) or None if never read."""
    value = get_value(session, KEY_ACTION_RATES)
    if not isinstance(value, dict) or not isinstance(value.get("rates"), list):
        return None
    return value


def duplicate_group_names(session: Session) -> list[str]:
    value = get_value(session, KEY_DUPLICATE_GROUP_NAMES)
    return [name for name in value if isinstance(name, str)] if isinstance(value, list) else []


def credit_unit_cost(session: Session) -> float:
    """Monetary cost of one credit for chargeback, or 0.0 when unset/invalid."""
    value = get_value(session, KEY_CREDIT_UNIT_COST, DEFAULTS[KEY_CREDIT_UNIT_COST])
    try:
        cost = float(value)
    except (TypeError, ValueError):
        return 0.0
    return cost if cost >= 0 else 0.0


@dataclass(frozen=True, slots=True)
class UpdatePolicy:
    auto_enabled: bool
    quiet_hour: int  # 0-23, UTC


def update_policy(session: Session) -> UpdatePolicy:
    hour = get_value(session, KEY_UPDATE_QUIET_HOUR, DEFAULTS[KEY_UPDATE_QUIET_HOUR])
    if not isinstance(hour, int) or isinstance(hour, bool) or not 0 <= hour <= 23:
        hour = DEFAULTS[KEY_UPDATE_QUIET_HOUR]
    return UpdatePolicy(
        auto_enabled=get_value(session, KEY_UPDATE_AUTO, DEFAULTS[KEY_UPDATE_AUTO]) is not False,
        quiet_hour=hour,
    )


def get_raw(session: Session, key: str) -> AppSetting | None:
    return session.get(AppSetting, key)


def get_value(session: Session, key: str, default: Any = None) -> Any:
    """Decoded value, falling back to DEFAULTS then the supplied default."""
    row = get_raw(session, key)
    if row is None or row.value is None:
        return DEFAULTS.get(key, default)
    if row.is_secret:
        # Callers that genuinely need the plaintext use get_secret().
        return "********"
    try:
        return json.loads(row.value)
    except json.JSONDecodeError:
        logger.warning("Setting %s holds invalid JSON, using the default", key)
        return DEFAULTS.get(key, default)


def get_secret(session: Session, key: str) -> str | None:
    purpose = SECRET_KEYS.get(key)
    if purpose is None:
        raise ValueError(f"{key} is not a secret setting")
    row = get_raw(session, key)
    if row is None or not row.value:
        return None
    if not row.is_secret:
        # Written before this setting was treated as a secret: still plain JSON.
        # encrypt_legacy_secrets() converts these at start-up.
        return _legacy_plaintext(row.value)
    return get_secret_box().decrypt(row.value, purpose=purpose)


def _legacy_plaintext(value: str) -> str | None:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, str) and decoded else None


def encrypt_legacy_secrets(session: Session) -> int:
    """Encrypt any secret setting that an older version stored in the clear."""
    converted = 0
    for key in SECRET_KEYS:
        row = get_raw(session, key)
        if row is None or row.is_secret:
            continue
        set_secret(session, key, _legacy_plaintext(row.value) if row.value else None)
        converted += 1
    if converted:
        logger.info("Encrypted %d setting(s) that were previously stored in the clear", converted)
    return converted


def set_value(session: Session, key: str, value: Any, *, description: str | None = None) -> None:
    """Store a non secret setting as JSON.

    Turning auto-triage attribution on (directly, or by leaving demo mode while
    it is on) also stamps a new observation epoch, whichever path made the
    change: the route, a restore, a script.
    """
    if key in SECRET_KEYS:
        raise ValueError(f"{key} is a secret; use set_secret()")
    watched = key in (KEY_AUTO_TRIAGE_TO_INITIATOR, KEY_DEMO_MODE)
    was_on = auto_triage_to_initiator(session) if watched else False
    _write_value(session, key, value, description=description)
    if watched and not was_on and auto_triage_to_initiator(session):
        start_auto_triage_observation_epoch(session)


def _write_value(session: Session, key: str, value: Any, *, description: str | None = None) -> None:
    row = get_raw(session, key)
    encoded = json.dumps(value)
    if row is None:
        session.add(AppSetting(key=key, value=encoded, is_secret=False, description=description))
    else:
        row.value = encoded
        if description:
            row.description = description
    session.flush()


def set_secret(session: Session, key: str, value: str | None) -> None:
    """Store or clear a secret setting, encrypted under its own purpose."""
    purpose = SECRET_KEYS.get(key)
    if purpose is None:
        raise ValueError(f"{key} is not a secret setting")
    row = get_raw(session, key)
    ciphertext = get_secret_box().encrypt(value, purpose=purpose) if value else None
    if row is None:
        session.add(AppSetting(key=key, value=ciphertext, is_secret=True))
    else:
        row.value = ciphertext
        row.is_secret = True
    session.flush()


def all_public_settings(session: Session) -> dict[str, Any]:
    """Every setting with secrets masked, for the Settings page."""
    stored = {row.key: row for row in session.scalars(select(AppSetting))}
    result: dict[str, Any] = dict(DEFAULTS)
    for key, row in stored.items():
        if key in INTERNAL_KEYS:
            continue
        if key in SECRET_KEYS:
            result[key] = "********" if row.value else None
        elif row.value is not None:
            try:
                result[key] = json.loads(row.value)
            except json.JSONDecodeError:
                result[key] = None
    # Report whether each secret is configured without revealing it.
    for key in SECRET_KEYS:
        row = stored.get(key)
        result[f"{key}.configured"] = bool(row and row.value)
    return result


def schedule_config(session: Session) -> ScheduleConfig:
    interval = get_value(session, KEY_SCHEDULE_INTERVAL_MINUTES)
    if not isinstance(interval, int) or interval < 1:
        interval = DEFAULTS[KEY_SCHEDULE_INTERVAL_MINUTES]
    org_refresh = get_value(session, KEY_ORG_REFRESH_MINUTES)
    if not isinstance(org_refresh, int) or org_refresh < 1:
        org_refresh = DEFAULTS[KEY_ORG_REFRESH_MINUTES]
    mode = get_value(session, KEY_SCHEDULE_MODE)
    cron = get_value(session, KEY_SCHEDULE_CRON)
    return ScheduleConfig(
        enabled=bool(get_value(session, KEY_SCHEDULER_ENABLED)),
        mode="cron" if mode == "cron" and isinstance(cron, str) and cron.strip() else "interval",
        interval_minutes=interval,
        cron=cron.strip() if isinstance(cron, str) and cron.strip() else None,
        org_refresh_minutes=org_refresh,
    )


def usage_period(session: Session) -> str:
    value = get_value(session, KEY_USAGE_PERIOD)
    return value if isinstance(value, str) and value.strip() else DEFAULT_PERIOD


def usage_source(session: Session) -> str:
    """ "activity" (the default) or "summary"; anything else reads as the default."""
    value = get_value(session, KEY_USAGE_SOURCE, DEFAULTS[KEY_USAGE_SOURCE])
    return value if value in USAGE_SOURCES else USAGE_SOURCE_ACTIVITY


def summary_restricts(session: Session) -> bool:
    """Whether summary-counted usage may start a restriction of a period
    budget: only with the usage source at "summary" and the opt-in on."""
    if usage_source(session) != USAGE_SOURCE_SUMMARY:
        return False
    return get_value(session, KEY_SUMMARY_RESTRICTS, DEFAULTS[KEY_SUMMARY_RESTRICTS]) is True


def activity_max_pages(session: Session) -> int:
    """Pages of the activity log one cycle may read; 0 means no cap."""
    value = get_value(session, KEY_ACTIVITY_MAX_PAGES, DEFAULTS[KEY_ACTIVITY_MAX_PAGES])
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return int(DEFAULTS[KEY_ACTIVITY_MAX_PAGES])
    return min(value, 100_000)


def normalise_account_names(value: Any) -> list[str]:
    """A list of account names, stripped, without duplicates (case-insensitive),
    from a list or a comma or newline separated string."""
    if isinstance(value, str):
        entries: list[Any] = value.replace("\n", ",").split(",")
    elif isinstance(value, list):
        entries = value
    else:
        return []
    names: dict[str, str] = {}
    for entry in entries:
        name = entry.strip() if isinstance(entry, str) else ""
        if name and len(name) <= 320:
            names.setdefault(name.lower(), name)
    return list(names.values())[:INTEGRATION_ACCOUNTS_MAX]


def integration_accounts(session: Session) -> list[str]:
    """The extra integration account names an admin listed."""
    return normalise_account_names(get_value(session, KEY_INTEGRATION_ACCOUNTS, []))


def usage_page_size(session: Session) -> int:
    value = get_value(session, KEY_USAGE_PAGE_SIZE)
    return value if isinstance(value, int) and 1 <= value <= 1000 else 100
