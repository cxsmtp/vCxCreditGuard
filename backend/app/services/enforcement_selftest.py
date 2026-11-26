"""Enforcement self-test: prove, on the live tenant, that a restriction bites and comes back.

An admin picks a user, a project, or both (Settings → Enforcement → Run
self-test). For each, the self-test:

1. reads the target's current state (a user's direct and effective roles; a
   project's Auto Triage, PR triage and remediation and Fusion settings);
2. applies the restriction exactly as a budget breach would:
   ``enforcement.apply_enforcement``, the cycle's own entry point, with a
   stand-in limit that exists for this run only (``_TestLimit``);
3. reads the target back and checks the restriction took effect, and for a
   user whether an AI role stays effective through a group or a composite
   role (a restriction that cannot bite);
4. restores it from the undo snapshot through ``enforcement.restore_action``,
   the same path as the Restore button;
5. reads it back again and compares with step 1, setting by setting.

Safety, which is the point:

* **Refusals.** A target is refused when it is restricted now (or may be), is
  covered by an active budget that has reached its warning threshold, is
  exempt, is protected (a protected role, or the API key's own account), or
  for a project when a scan is running on it. In demo mode only demo targets
  can be tested, and outside it no demo target.
* **Restore always.** Steps 4 and 5 run in a ``finally``: whatever step 2 or 3
  did, raised or found. A restriction this run made is an ordinary
  ``enforcement_action`` row (no limit, period ``selftest-<run id>``), so if
  its restore fails it is marked in doubt (``OUTCOME_UNKNOWN``) and stays a
  tracked restriction: the next cycle's sweep lifts it like any restriction
  whose limit is gone, and the Notification Center offers Restore. Read back
  incomplete after a restore that answered OK, it is put back the same way.
  A prominent notification, the audit log and the result all carry the
  exact snapshot. Nothing is left restricted silently.
* **Never pins, never releases.** Fusion the project inherits is not tested:
  Restore can only write it back at the project level, which would stop the
  project following the tenant (README, Remaining unknowns #6). Lifting a
  self-test restriction later uses ``SELFTEST_CLEANUP_REASON``, never the
  admin's, so a real budget's restriction on the same target stays in force.
  A demo self-test's restriction is only ever restored in the demo tenant.
* **No transaction across a Checkmarx call.** Everything written before a
  tenant call is committed first (the restriction code does the same).
* **One at a time.** A process lock admits one self-test, and a partial
  unique index on ``status = 'running'`` makes the database refuse a second
  one from another process; the target's own
  lock (``enforcement._target_lock``, the one a cycle takes for each target)
  is held from the checks to the last read, so a cycle working on the same
  target waits for the self-test, and the self-test waits (briefly) for it.
* **Audited.** Start, every step, the restore and the outcome are written to
  the hash-chained audit log, next to the restriction's own entries.

Notifications the restriction code raises ("User X restricted", "restored")
are suppressed for this thread while it runs: the result says it instead. A
restore that fails raises its own alert.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, cast

from sqlalchemy import delete, func, select, true
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.checkmarx import iam, platform, scans
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError
from app.db.base import utcnow
from app.models.enums import (
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    LimitStatus,
    ProjectAction,
    Severity,
)
from app.models.limits import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.org import (
    CxApplicationProject,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.selftest import (
    STATUS_FAILED,
    STATUS_INTERRUPTED,
    STATUS_PASSED,
    STATUS_RESTORE_FAILED,
    STATUS_RUNNING,
    STATUS_WARNING,
    EnforcementSelfTest,
)
from app.services import enforcement, notifications, role_sources, settings_store
from app.services.audit import AuditActor, record_audit
from app.services.periods import PeriodError, current_window

logger = logging.getLogger(__name__)

# Reversal reason on a self-test's restrictions.
SELFTEST_REASON = "selftest"
# Reversal reason when a self-test restriction left behind (its restore failed)
# is lifted later: by the cycle's sweep, the demo retry or Restore on its alert.
# Not the admin reason, so a real budget's restriction on the same target is
# never released with it (see enforcement._restore_action_locked).
SELFTEST_CLEANUP_REASON = "selftest_cleanup"
# Period key of a self-test's restrictions: one per run, so each run's rows are its own.
PERIOD_PREFIX = enforcement.SELFTEST_PERIOD_PREFIX
# How many results are kept.
KEEP_RESULTS = 20
# How long the self-test waits for a cycle that is working on the same target.
TARGET_LOCK_WAIT_SECONDS = 30.0
# A run still "running" after this long was interrupted (the process stopped).
STALE_AFTER = timedelta(minutes=15)
AUDIT_TARGET = "enforcement_selftest"

ALL_PROJECT_ACTIONS: tuple[str, ...] = (
    ProjectAction.AUTO_TRIAGE.value,
    ProjectAction.PR_REMEDIATION.value,
    ProjectAction.FUSION.value,
)

# Shown in a reading for a value that could not be read, or is not there.
UNREADABLE = "(could not be read)"
ABSENT = "(not present)"
UNKNOWN_SHAPE = "(in a shape CreditGuard does not know)"

_STATUS_RANK = {
    STATUS_PASSED: 0,
    STATUS_WARNING: 1,
    STATUS_FAILED: 2,
    STATUS_RESTORE_FAILED: 3,
}

# One self-test at a time, in this process (the utility runs as one process).
_run_lock = threading.Lock()


# ------------------------------------------------------------------- errors


class SelfTestError(Exception):
    code = "selftest"


class SelfTestBusy(SelfTestError):
    code = "busy"


class SelfTestInvalid(SelfTestError):
    code = "invalid"


class ConfirmationMismatch(SelfTestError):
    code = "confirmation"


class SelfTestRefused(SelfTestError):
    code = "refused"

    def __init__(self, refusals: list[Refusal]) -> None:
        super().__init__(
            "The self-test was refused: " + " ".join(refusal.sentence() for refusal in refusals)
        )
        self.refusals = refusals


# ------------------------------------------------------------------- inputs


@dataclass(frozen=True, slots=True)
class SelfTestRequest:
    user_id: str | None = None
    project_id: str | None = None
    project_actions: tuple[str, ...] = ALL_PROJECT_ACTIONS


@dataclass(frozen=True, slots=True)
class TestTarget:
    target_type: str  # enforcement.TARGET_USER or TARGET_PROJECT
    target_id: str
    # The name the admin types to confirm, and how the target is shown.
    label: str

    @property
    def is_user(self) -> bool:
        return self.target_type == enforcement.TARGET_USER

    @property
    def noun(self) -> str:
        return "user" if self.is_user else "project"

    def as_dict(self) -> dict[str, str]:
        return {"target_type": self.noun, "target_id": self.target_id, "label": self.label}


@dataclass(frozen=True, slots=True)
class Refusal:
    target: TestTarget | None
    code: str
    reason: str

    def sentence(self) -> str:
        if self.target is None:
            return self.reason
        return f"{self.target.label}: {self.reason}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_type": self.target.noun if self.target else None,
            "target_id": self.target.target_id if self.target else None,
            "label": self.target.label if self.target else None,
            "code": self.code,
            "reason": self.reason,
        }


@dataclass
class _TestLimit:
    """Stands in for a breached limit, for this run only. Never stored.

    ``apply_enforcement`` and the restriction code read only these attributes.
    With no id the restriction rows it creates have no limit: one left in
    force is lifted by the cycle's sweep, like a restriction whose limit was
    deleted.
    """

    entity_type: str
    entity_id: str
    entity_label: str
    project_actions: list[str] | None
    id: int | None = None
    credit_limit: int = 0
    enforce: bool = True
    is_active: bool = True


def period_key_for(run_id: int) -> str:
    return f"{PERIOD_PREFIX}{run_id}"


def is_selftest_action(action: EnforcementAction) -> bool:
    return enforcement.is_selftest(action)


def is_demo_action(action: EnforcementAction) -> bool:
    """A self-test restriction on a demo entity: it lives in the demo tenant."""
    from app.services import demo_service

    return is_selftest_action(action) and str(action.target_id).startswith(demo_service.DEMO_PREFIX)


def client_for(
    action: EnforcementAction, live: Callable[[], CheckmarxClient | None]
) -> CheckmarxClient | None:
    """The client a restore of this action must use: the built-in demo tenant
    for a demo self-test's restriction (never the live tenant), else ``live()``."""
    if is_demo_action(action):
        from app.services import demo_tenant

        return demo_tenant.client()
    return live()


def restore_reason_for(action: EnforcementAction, requested: str) -> str:
    """The reason to restore with: a self-test's restriction is always cleaned
    up as such, so an admin's Restore on it releases no real budget's hold."""
    return SELFTEST_CLEANUP_REASON if is_selftest_action(action) else requested


def budgets_still_restricting(
    session: Session, action: EnforcementAction
) -> list[EnforcementAction]:
    """Real budgets' restrictions of the same kind still in force on this
    action's target: lifting a self-test restriction hands over to them and
    gives nothing back while one holds."""
    rows = session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.target_type == action.target_type,
            EnforcementAction.target_id == action.target_id,
            EnforcementAction.kind == action.kind,
            EnforcementAction.id != action.id,
            EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
        )
        .execution_options(populate_existing=True)
    )
    return [
        row for row in rows if not enforcement.is_selftest(row) and enforcement.may_be_in_force(row)
    ]


# Said wherever Fusion is skipped because the project inherits it.
FUSION_INHERITED = (
    "Fusion is inherited from the tenant; the self-test does not change it, because "
    "restoring would pin it on the project (Restore can only write a value at the project "
    "level). The repository's Fusion setting goes with it and is not tested either."
)


def _fusion_inherited(reading: Reading | None) -> bool:
    return reading is not None and reading.settings.get("Fusion: set on the project") is False


def _auto_triage_inherited_words(reading: Reading | None) -> str | None:
    """Why Auto Triage is skipped, when the project's AI agent configuration
    was not read at the project scope (it is inherited): writing it would pin
    the whole configuration on the project. None when it may be tested."""
    if reading is None or "AI agent configuration: scope" not in reading.settings:
        return None
    scope = reading.settings["AI agent configuration: scope"]
    if isinstance(scope, str) and scope.strip().lower() == "project":
        return None
    shown = "not given" if scope == ABSENT else f"“{scope}”"
    return (
        f"Auto Triage is not set on the project (the AI agent configuration's scope is "
        f"{shown}, not “project”): it is inherited. The self-test does not change it, "
        "because writing it back would pin the configuration on the project."
    )


def _skipped_kinds(kinds: list[str], reading: Reading | None) -> dict[str, str]:
    """Kinds the self-test leaves alone on this project, with the reason: what
    the project inherits, which a restore could only pin on the project."""
    skipped: dict[str, str] = {}
    if _fusion_inherited(reading):
        for kind in kinds:
            if kind in (EnforcementKind.DISABLE_FUSION, EnforcementKind.DISABLE_REPO_FUSION):
                skipped[kind] = FUSION_INHERITED
    triage = _auto_triage_inherited_words(reading)
    if triage is not None and EnforcementKind.DISABLE_AUTO_TRIAGE in kinds:
        skipped[EnforcementKind.DISABLE_AUTO_TRIAGE.value] = triage
    return skipped


# The project action each project kind belongs to (what a limit is told to turn off).
_ACTION_OF_KIND = {
    EnforcementKind.DISABLE_AUTO_TRIAGE.value: ProjectAction.AUTO_TRIAGE.value,
    EnforcementKind.DISABLE_PR_REMEDIATION.value: ProjectAction.PR_REMEDIATION.value,
    EnforcementKind.DISABLE_FUSION.value: ProjectAction.FUSION.value,
    EnforcementKind.DISABLE_REPO_FUSION.value: ProjectAction.FUSION.value,
}


# ---------------------------------------------------------------- refusals


def resolve_targets(
    session: Session, request: SelfTestRequest
) -> tuple[list[TestTarget], list[Refusal]]:
    """The targets the request names, and refusals for any that are not usable."""
    if not request.user_id and not request.project_id:
        raise SelfTestInvalid("Choose a user, a project, or both.")
    if request.project_id and not request.project_actions:
        raise SelfTestInvalid("Choose at least one project setting to test.")
    unknown = [a for a in request.project_actions if a not in ALL_PROJECT_ACTIONS]
    if unknown:
        raise SelfTestInvalid(f"Unknown project setting: {', '.join(unknown)}.")
    targets: list[TestTarget] = []
    refusals: list[Refusal] = []
    if request.user_id:
        user = session.get(CxUser, request.user_id)
        if user is None:
            refusals.append(
                Refusal(
                    None,
                    "unknown",
                    f"No synced user has the id {request.user_id}. Run an organisation sync.",
                )
            )
        else:
            targets.append(TestTarget(enforcement.TARGET_USER, user.id, user.display_name))
    if request.project_id:
        project = session.get(CxProject, request.project_id)
        if project is None:
            refusals.append(
                Refusal(
                    None,
                    "unknown",
                    f"No synced project has the id {request.project_id}. Run an organisation sync.",
                )
            )
        else:
            targets.append(TestTarget(enforcement.TARGET_PROJECT, project.id, project.name))
    return targets, refusals


def _db_refusals(session: Session, target: TestTarget, *, demo: bool) -> list[Refusal]:
    """Why this target must not be tested, from what CreditGuard knows. Database only."""
    from app.services import demo_service

    found: list[Refusal] = []
    is_demo = target.target_id.startswith(demo_service.DEMO_PREFIX)
    if demo and not is_demo:
        found.append(
            Refusal(
                target,
                "demo",
                "demo mode is on, so only the demo users and projects can be tested (against "
                "the built-in demo tenant). Turn demo mode off to test a real one.",
            )
        )
    elif not demo and is_demo:
        found.append(
            Refusal(target, "demo", "this is a demo entity; turn demo mode on to test it.")
        )
    if target.is_user:
        user = session.get(CxUser, target.target_id)
        if user is not None and user.is_deleted:
            found.append(Refusal(target, "deleted", "the user was deleted in Checkmarx One."))
        if target.target_id in enforcement.protected_user_ids(session):
            found.append(
                Refusal(
                    target,
                    "api_key_user",
                    "this is the account the Checkmarx One API key belongs to. Taking its roles "
                    "away could cut CreditGuard off from the tenant, including from giving them "
                    "back.",
                )
            )
        else:
            why = enforcement.protection_reason(session, target.target_id)
            if why is not None:
                found.append(Refusal(target, "protected", f"never restricted: {why}."))
        if enforcement.is_exempt(session, entity_type=EntityType.USER, entity_id=target.target_id):
            found.append(Refusal(target, "exempt", "exempt: never restricted."))
    else:
        project = session.get(CxProject, target.target_id)
        if project is not None and project.is_deleted:
            found.append(Refusal(target, "deleted", "the project was deleted in Checkmarx One."))
        if enforcement.is_exempt(
            session, entity_type=EntityType.PROJECT, entity_id=target.target_id
        ):
            found.append(Refusal(target, "exempt", "exempt: never restricted."))
    in_force = _restrictions_in_force(session, target)
    if in_force:
        kinds = ", ".join(sorted({action.kind for action in in_force}))
        found.append(
            Refusal(
                target,
                "restricted",
                f"it is restricted now ({kinds}). Testing it would hand back and take away a "
                "real restriction; restore it first, or pick another target.",
            )
        )
    found.extend(
        Refusal(target, "near_limit", reason) for reason in _budgets_near_limit(session, target)
    )
    return found


def _restrictions_in_force(session: Session, target: TestTarget) -> list[EnforcementAction]:
    rows = session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.target_type == target.target_type,
            EnforcementAction.target_id == target.target_id,
            EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
        )
        .execution_options(populate_existing=True)
    )
    return [row for row in rows if enforcement.may_be_in_force(row)]


def _covering_limits(session: Session, target: TestTarget) -> list[CreditLimit]:
    """Active budgets whose breach would restrict this target (or count its usage)."""
    clauses: list[tuple[str, list[str]]] = []
    if target.is_user:
        clauses.append((EntityType.USER, [target.target_id]))
        groups = list(
            session.scalars(
                select(CxGroupMembership.group_id).where(
                    CxGroupMembership.user_id == target.target_id
                )
            )
        )
        group_limits = list(
            session.scalars(
                select(CreditLimit).where(
                    CreditLimit.entity_type == EntityType.GROUP,
                    CreditLimit.entity_id.in_(groups or [""]),
                    CreditLimit.include_member_usage.is_(True),
                )
            )
        )
    else:
        clauses.append((EntityType.PROJECT, [target.target_id]))
        clauses.append(
            (
                EntityType.GROUP,
                list(
                    session.scalars(
                        select(CxProjectGroup.group_id).where(
                            CxProjectGroup.project_id == target.target_id
                        )
                    )
                ),
            )
        )
        clauses.append(
            (
                EntityType.APPLICATION,
                list(
                    session.scalars(
                        select(CxApplicationProject.application_id).where(
                            CxApplicationProject.project_id == target.target_id
                        )
                    )
                ),
            )
        )
        group_limits = []
    limits: list[CreditLimit] = list(group_limits)
    for entity_type, ids in clauses:
        if not ids:
            continue
        limits.extend(
            session.scalars(
                select(CreditLimit).where(
                    CreditLimit.entity_type == entity_type, CreditLimit.entity_id.in_(ids)
                )
            )
        )
    return [limit for limit in limits if limit.is_active]


def _budgets_near_limit(
    session: Session, target: TestTarget, *, now: datetime | None = None
) -> list[str]:
    """One sentence per active budget covering the target that is close to (or
    over) its limit: its warning threshold reached, or warned, breached or
    restricted this period."""
    moment = now or utcnow()
    reasons: list[str] = []
    for limit in _covering_limits(session, target):
        label = f"the {limit.entity_type} budget on {limit.entity_label or limit.entity_id}"
        try:
            window = current_window(limit, moment)
        except PeriodError:
            reasons.append(f"{label} has no current period that can be worked out.")
            continue
        state = session.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == window.key
            )
        )
        if state is None:
            continue
        used = state.credits_used or 0
        threshold = limit.warning_threshold_pct or 100
        close = state.status in (
            LimitStatus.WARNED,
            LimitStatus.BREACHED,
            LimitStatus.RESTRICTED,
        ) or (
            state.usage_available
            and (limit.credit_limit <= 0 or used * 100 >= threshold * limit.credit_limit)
        )
        if close:
            share = (
                f"{used * 100 / limit.credit_limit:.0f}% of its {limit.credit_limit} credits"
                if limit.credit_limit > 0
                else f"{used} credits of a budget of 0"
            )
            reasons.append(
                f"{label} is close to its limit ({share}, {state.status}). A real restriction "
                "may be due, and a self-test must not hand it back or race it."
            )
    return reasons


def _running_scans(client: CheckmarxClient, project_id: str) -> list[str] | None:
    """Scans running or queued on the project (one page, newest first); None
    when the listing could not be read."""
    try:
        payload = client.get_json(
            scans.SCANS_PATH, params={"project-id": project_id, "limit": 20, "offset": 0}
        )
    except CheckmarxError as exc:
        logger.info("Could not list the scans of %s for the self-test: %s", project_id, exc)
        return None
    page = scans.parse_scan_page(payload)
    return [
        scan.id
        for scan in page.scans
        if scan.status.strip().lower() in {"running", "queued", "scanning", "pending"}
    ]


def enforcement_notes(session: Session) -> list[str]:
    """What the admin should know before reading a self-test as "budgets work"."""
    notes: list[str] = []
    if settings_store.demo_mode(session):
        notes.append(
            "Demo mode is on: the self-test runs against CreditGuard's built-in demo tenant, "
            "with made-up data. Nothing in Checkmarx One is read or changed."
        )
    guard = settings_store.enforcement_guard(session)
    if guard.paused:
        notes.append(
            "Enforcement is paused"
            + (f" ({guard.pause_reason})" if guard.pause_reason else "")
            + ". The self-test still runs because you asked for it, but budgets will not "
            "restrict anyone until enforcement is resumed."
        )
    enforcing = session.scalar(
        select(func.count())
        .select_from(CreditLimit)
        .where(CreditLimit.is_active.is_(True), CreditLimit.enforce.is_(True))
    )
    if not enforcing:
        notes.append(
            "No budget is set to enforce (every budget is monitor only). The self-test still "
            "runs, but budgets will not restrict anyone until one is switched to enforce."
        )
    if not settings_store.get_value(session, settings_store.KEY_SCHEDULER_ENABLED, True):
        notes.append(
            "The scheduler is switched off, so no cycle runs: budgets will not restrict "
            "anyone, and a restriction a failed restore leaves behind is not retried, until "
            "it is switched on."
        )
    return notes


# ---------------------------------------------------------------- reading


@dataclass
class Reading:
    """One read of a target's state. ``settings`` is what is compared."""

    settings: dict[str, Any]
    # The direct roles in the order the tenant listed them (users), for display.
    listed: list[str] = field(default_factory=list)
    # AI role -> where it comes from, for every AI role held other than directly.
    kept: dict[str, list[str]] = field(default_factory=dict)
    unread: list[str] = field(default_factory=list)


# Settings each kind owns: what its restriction changes and its restore puts back.
_OWNED: dict[str, tuple[str, ...]] = {
    EnforcementKind.REMOVE_USER_ROLES.value: ("Direct AI roles",),
    EnforcementKind.DISABLE_AUTO_TRIAGE.value: ("Auto Triage: on", "Auto Triage: configuration"),
    EnforcementKind.DISABLE_PR_REMEDIATION.value: ("PR triage and remediation: severities",),
    EnforcementKind.DISABLE_FUSION.value: ("Fusion: value", "Fusion: allowOverride"),
    EnforcementKind.DISABLE_REPO_FUSION.value: ("Repository Fusion (fusionScanConfig)",),
}


def _owner_of(setting: str) -> str | None:
    for kind, names in _OWNED.items():
        if setting in names:
            return kind
    return None


def _read_user(
    client: CheckmarxClient,
    resolver: enforcement.RoleResolver,
    *,
    user_id: str,
    ai_roles: tuple[str, ...],
) -> Reading:
    """A user's direct roles (must be readable) and effective roles (best effort)."""
    uuid = resolver.client_uuid
    direct = iam.fetch_user_client_roles(client, user_id=user_id, client_uuid=uuid)
    # A reader of its own: the effective roles are never cached, and nothing
    # it caches (groups, composites) is shared with the restriction itself.
    reader = role_sources.RoleSourceReader(
        client, client_uuid=lambda: uuid, client_roles=resolver.all_roles
    )
    analysis = reader.read_user(user_id, ai_roles=ai_roles, direct=direct)
    wanted = set(ai_roles)
    names = [role.name for role in direct]
    effective = analysis.effective
    kept: dict[str, list[str]] = {
        name: [source.describe() for source in sources]
        for name, sources in analysis.indirect.items()
    }
    if effective is not None:
        for name in sorted((effective & wanted) - set(names) - set(kept)):
            if name not in analysis.removed_contains:
                kept[name] = [role_sources.RoleSource(role_sources.SOURCE_UNKNOWN).describe()]
    return Reading(
        settings={
            "Direct client roles": sorted(names),
            "Direct AI roles": sorted(name for name in names if name in wanted),
            "Effective AI roles": (
                sorted(effective & wanted) if effective is not None else UNREADABLE
            ),
            "Effective client roles": sorted(effective) if effective is not None else UNREADABLE,
        },
        listed=names,
        kept=kept,
        unread=list(analysis.unread),
    )


def _read_project(
    session: Session, client: CheckmarxClient, *, project_id: str, kinds: list[str]
) -> Reading:
    """The project settings the kinds under test change. A read that fails
    raises: what cannot be read cannot be compared."""
    project = session.get(CxProject, project_id)
    repo_id = project.repo_id if project is not None else None
    settings: dict[str, Any] = {}
    unread: list[str] = []
    if EnforcementKind.DISABLE_AUTO_TRIAGE in kinds:
        state = platform.get_auto_triage(client, project_id=project_id)
        settings["Auto Triage: on"] = state.enabled
        settings["Auto Triage: configuration"] = state.config
        settings["Auto Triage: allowOverride"] = state.allow_override
        # Where the configuration comes from, and the inherited AI switch: a
        # write that pinned either on the project shows as a difference.
        settings["AI agent configuration: scope"] = state.scope if state.scope else ABSENT
        raw = state.raw or {}
        settings["AI agent configuration: allowAiUsage"] = raw.get("allowAiUsage", ABSENT)
        entries = raw.get("configurations")
        settings["AI agent configuration: other features"] = {
            str(entry.get("feature")): entry
            for entry in (entries if isinstance(entries, list) else [])
            if isinstance(entry, dict) and entry.get("feature") != platform.AUTO_TRIAGE_FEATURE
        }
    if EnforcementKind.DISABLE_PR_REMEDIATION in kinds:
        try:
            read = (
                platform.read_pr_remediation(client, repo_id=repo_id, project_id=project_id)
                if repo_id
                else None
            )
        except platform.PrSeveritiesShapeError:
            # Enforcement leaves such a setting alone; there is nothing to compare.
            read = None
            settings["PR triage and remediation: severities"] = UNKNOWN_SHAPE
        else:
            if read is None:
                unread.append("the repository's PR triage and remediation setting")
            settings["PR triage and remediation: severities"] = (
                sorted(read.severities) if read is not None else UNREADABLE
            )
            settings["PR triage and remediation: editable"] = (
                read.editable if read is not None else UNREADABLE
            )
    if EnforcementKind.DISABLE_FUSION in kinds:
        setting = platform.get_fusion_setting(client, project_id=project_id)
        if setting is None:
            settings["Fusion: value"] = ABSENT
            settings["Fusion: allowOverride"] = ABSENT
        else:
            settings["Fusion: value"] = setting.value
            settings["Fusion: allowOverride"] = setting.allow_override
            settings["Fusion: origin level"] = setting.origin_level
            settings["Fusion: set on the project"] = not setting.inherited
    if EnforcementKind.DISABLE_REPO_FUSION in kinds:
        repo = (
            platform.get_repo_fusion(client, repo_id=repo_id, project_id=project_id)
            if repo_id
            else platform.RepoFusionRead(readable=False)
        )
        if not repo.readable:
            unread.append("the repository's settings")
        settings["Repository Fusion (fusionScanConfig)"] = (
            UNREADABLE
            if not repo.readable
            else (repo.config if repo.config is not None else ABSENT)
        )
    return Reading(settings=settings, unread=unread)


def _planned_kinds(session: Session, target: TestTarget, request: SelfTestRequest) -> list[str]:
    """The restrictions a breach would make on this target, in order."""
    if target.is_user:
        return [EnforcementKind.REMOVE_USER_ROLES.value]
    planned = enforcement.plan_targets(
        session,
        entity_type=EntityType.PROJECT,
        entity_id=target.target_id,
        project_actions=list(request.project_actions),
    )
    return [str(item.kind) for item in planned]


def _read(
    session: Session,
    client: CheckmarxClient,
    resolver: enforcement.RoleResolver,
    target: TestTarget,
    *,
    kinds: list[str],
    ai_roles: tuple[str, ...],
) -> Reading:
    # Nothing is left open in the database while Checkmarx is called.
    session.commit()
    if target.is_user:
        return _read_user(client, resolver, user_id=target.target_id, ai_roles=ai_roles)
    return _read_project(session, client, project_id=target.target_id, kinds=kinds)


# ------------------------------------------------------------------ preflight


_KIND_WORDS = {
    EnforcementKind.DISABLE_AUTO_TRIAGE.value: "Auto Triage",
    EnforcementKind.DISABLE_PR_REMEDIATION.value: "PR triage and remediation",
    EnforcementKind.DISABLE_FUSION.value: f"Fusion ({platform.FUSION_SETTING_KEY})",
    EnforcementKind.DISABLE_REPO_FUSION.value: "Repository Fusion (fusionScanConfig)",
    EnforcementKind.REMOVE_USER_ROLES.value: "AI roles",
}


def _show(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "none"
    if isinstance(value, bool):
        return "on" if value else "off"
    return str(value)


def _plan_lines(
    session: Session, target: TestTarget, kinds: list[str], reading: Reading | None
) -> list[str]:
    """What the self-test will change, in words, from a fresh read when there is one."""
    lines: list[str] = []
    if target.is_user:
        ai_roles = settings_store.ai_role_names(session)
        if reading is None:
            lines.append(
                "Remove the direct mappings of the configured AI roles the user holds "
                f"({', '.join(ai_roles)}), then map them back."
            )
        else:
            direct_ai = reading.settings["Direct AI roles"]
            lines.append(
                f"Remove the direct mappings of {', '.join(direct_ai)}, then map them back."
                if direct_ai
                else "The user holds none of the configured AI roles directly: nothing is "
                "removed, and the test shows whether they still hold one some other way."
            )
            for name, sources in reading.kept.items():
                lines.append(
                    f"{name} stays effective through {', '.join(sources)}: the restriction "
                    "cannot take it (groups and composite roles are never changed)."
                )
        lines.append("No other role, group or composite role is changed.")
        return lines
    settings = reading.settings if reading is not None else {}
    for kind in kinds:
        words = _KIND_WORDS.get(kind, kind)
        if kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
            triage = _auto_triage_inherited_words(reading)
            if triage is not None:
                lines.append(f"{words}: not tested. {triage}")
                continue
            now = settings.get("Auto Triage: on")
            lines.append(
                f"{words}: on → off, then turned back on with the configuration read "
                "before; the test checks it then reads exactly as before."
                if now is True
                else f"{words}: already off, so nothing is written (checked only)."
                if now is not None
                else f"{words}: turned off if it is on, then turned back on as read before; "
                "the test checks it then reads exactly as before."
            )
        elif kind == EnforcementKind.DISABLE_PR_REMEDIATION:
            now = settings.get("PR triage and remediation: severities")
            lines.append(
                f"{words}: severities {_show(now)} → none, then written back as "
                f"{_show(now)}; the test checks they then read exactly as before."
                if isinstance(now, list)
                else f"{words}: severities cleared, then written back as read before; the "
                "test checks they then read exactly as before."
            )
        elif kind == EnforcementKind.DISABLE_FUSION:
            if _fusion_inherited(reading):
                lines.append(f"{words}: not tested. {FUSION_INHERITED}")
                continue
            now = settings.get("Fusion: value")
            lock = settings_store.fusion_lock_enabled(session)
            lines.append(
                f"{words}: {_show(now) if now is not None else 'its value'} → false"
                + (" and locked against per-scan override" if lock else "")
                + ", then written back with the value and lock read before; the test checks "
                "it then reads exactly as before, the level it is set at included."
                + (
                    ""
                    if reading is not None
                    else " If it turns out to be inherited from the tenant, it is not tested."
                )
            )
        elif kind == EnforcementKind.DISABLE_REPO_FUSION:
            if _fusion_inherited(reading):
                continue
            now = settings.get("Repository Fusion (fusionScanConfig)")
            if now == ABSENT:
                lines.append(f"{words}: not present on this repository; nothing to change.")
            else:
                lines.append(
                    f"{words}: enabled → false, then written back as read before; the test "
                    "checks it then reads exactly as before."
                )
    if not kinds:
        lines.append("Nothing: none of the chosen settings applies to this project.")
    return lines


@dataclass
class Preflight:
    targets: list[dict[str, Any]]
    refusals: list[Refusal]
    warnings: list[str]
    notes: list[str]
    demo: bool
    busy: bool

    @property
    def allowed(self) -> bool:
        return not self.refusals and not self.busy and bool(self.targets)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "busy": self.busy,
            "demo": self.demo,
            "targets": self.targets,
            "refusals": [refusal.as_dict() for refusal in self.refusals],
            "warnings": self.warnings,
            "notes": self.notes,
            "duration": (
                "For as long as the test takes, usually a few seconds: the restore starts as "
                "soon as the restriction has been read back. If the restore fails, the target "
                "stays restricted until the next cycle restores it (or you press Restore in "
                "the Notification Center), and you are told at once."
            ),
        }


def check(
    session: Session,
    client: CheckmarxClient | None,
    request: SelfTestRequest,
    *,
    demo: bool,
) -> Preflight:
    """What a self-test of these targets would change, or why it is refused.

    Reads the tenant (never writes) so the confirmation can say exactly what
    will be changed.
    """
    targets, refusals = resolve_targets(session, request)
    warnings: list[str] = []
    plans: list[dict[str, Any]] = []
    for target in targets:
        refusals.extend(_db_refusals(session, target, demo=demo))
    for target in targets:
        kinds = _planned_kinds(session, target, request)
        reading: Reading | None = None
        if client is not None:
            resolver = enforcement.RoleResolver(client)
            try:
                reading = _read(
                    session,
                    client,
                    resolver,
                    target,
                    kinds=kinds,
                    ai_roles=settings_store.ai_role_names(session),
                )
            except CheckmarxError as exc:
                warnings.append(f"{target.label} could not be read from the tenant now: {exc}")
            if reading is not None and target.is_user:
                live = _live_protection(session, target, reading)
                if live is not None:
                    refusals.append(live)
            if not target.is_user:
                for reason in dict.fromkeys(_skipped_kinds(kinds, reading).values()):
                    warnings.append(f"{target.label}: {reason}")
            if not target.is_user:
                session.commit()  # nothing open while the scans are listed
                refusal, warning = _scan_check(client, target)
                if refusal is not None:
                    refusals.append(refusal)
                if warning is not None:
                    warnings.append(warning)
        plans.append(
            {
                **target.as_dict(),
                "kinds": kinds,
                "changes": _plan_lines(session, target, kinds, reading),
            }
        )
    return Preflight(
        targets=plans,
        refusals=refusals,
        warnings=warnings,
        notes=enforcement_notes(session),
        demo=demo,
        busy=_run_lock.locked() or _running_row(session) is not None,
    )


def _live_protection(session: Session, target: TestTarget, reading: Reading) -> Refusal | None:
    why = enforcement.protection_reason(session, target.target_id, live_roles=set(reading.listed))
    if why is None:
        return None
    return Refusal(target, "protected", f"never restricted: {why}.")


def _scan_check(client: CheckmarxClient, target: TestTarget) -> tuple[Refusal | None, str | None]:
    running = _running_scans(client, target.target_id)
    if running is None:
        return None, (
            f"Whether a scan is running on {target.label} could not be checked. A scan that "
            "starts during the test runs with the settings of that moment."
        )
    if running:
        return (
            Refusal(
                target,
                "scan_running",
                f"a scan is running or queued on it ({', '.join(running[:3])}). Turning its "
                "AI settings off now could change that scan; try again when it has finished.",
            ),
            None,
        )
    return None, None


# ------------------------------------------------------------------- running


def _running_row(session: Session) -> EnforcementSelfTest | None:
    """A run another process (or a stopped one, until it goes stale) holds."""
    return session.scalar(
        select(EnforcementSelfTest)
        .where(
            EnforcementSelfTest.status == STATUS_RUNNING,
            EnforcementSelfTest.started_at > utcnow() - STALE_AFTER,
        )
        .limit(1)
    )


def _mark_interrupted(session: Session) -> None:
    """A run still "running" long after it started belongs to a process that
    stopped: it is recorded as interrupted (and frees the one-run slot). What
    it left restricted is an ordinary restriction the cycle lifts."""
    stale = list(
        session.scalars(
            select(EnforcementSelfTest).where(
                EnforcementSelfTest.status == STATUS_RUNNING,
                EnforcementSelfTest.started_at <= utcnow() - STALE_AFTER,
            )
        )
    )
    for row in stale:
        row.status = STATUS_INTERRUPTED
        row.finished_at = row.finished_at or utcnow()
        row.summary = row.summary or (
            "Interrupted: the process stopped while the self-test ran. Anything it left "
            "restricted is lifted by the next cycle."
        )
    if stale:
        session.commit()


def _audit_label(labels: Iterable[str]) -> str | None:
    """Labels for an audit entry, cut to the column's width here: the entry's
    hash is taken over the value as given, so it must not be trimmed later."""
    joined = ", ".join(labels)
    return joined[:512] or None


def _settle(session: Session) -> None:
    """End the open transaction: commit it, or roll it back if it cannot be."""
    try:
        session.commit()
    except Exception:  # noqa: BLE001 - a broken transaction is rolled back, never kept
        session.rollback()


def _check_confirmation(targets: list[TestTarget], confirm: dict[str, str | None]) -> None:
    for target in targets:
        typed = (confirm.get(target.noun) or "").strip()
        if typed != target.label.strip():
            raise ConfirmationMismatch(
                f"Type the {target.noun}'s name exactly as shown ({target.label}) to confirm."
            )


def run(
    session: Session,
    client: CheckmarxClient,
    request: SelfTestRequest,
    *,
    actor: AuditActor,
    confirm: dict[str, str | None],
    demo: bool,
) -> EnforcementSelfTest:
    """Run a self-test. Raises ``SelfTestBusy``, ``SelfTestRefused``,
    ``SelfTestInvalid`` or ``ConfirmationMismatch`` before anything is changed."""
    if not _run_lock.acquire(blocking=False):
        raise SelfTestBusy("Another self-test is running. Wait for it to finish.")
    try:
        return _run_locked(session, client, request, actor=actor, confirm=confirm, demo=demo)
    finally:
        _run_lock.release()


def _run_locked(
    session: Session,
    client: CheckmarxClient,
    request: SelfTestRequest,
    *,
    actor: AuditActor,
    confirm: dict[str, str | None],
    demo: bool,
) -> EnforcementSelfTest:
    _mark_interrupted(session)
    if _running_row(session) is not None:
        raise SelfTestBusy("Another self-test is running. Wait for it to finish.")
    targets, refusals = resolve_targets(session, request)
    if not refusals:
        for target in targets:
            refusals.extend(_db_refusals(session, target, demo=demo))
    if not refusals:
        _check_confirmation(targets, confirm)
    warnings: list[str] = []
    if not refusals:
        session.commit()  # nothing open while the scans are listed
        for target in targets:
            if not target.is_user:
                refusal, warning = _scan_check(client, target)
                if refusal is not None:
                    refusals.append(refusal)
                if warning is not None:
                    warnings.append(warning)
    if refusals:
        record_audit(
            session,
            action="selftest.refused",
            actor=actor,
            target_type=AUDIT_TARGET,
            target_label=_audit_label(target.label for target in targets),
            after={"refusals": [refusal.as_dict() for refusal in refusals]},
            detail=" ".join(refusal.sentence() for refusal in refusals),
        )
        session.commit()
        raise SelfTestRefused(refusals)

    user = next((target for target in targets if target.is_user), None)
    project = next((target for target in targets if not target.is_user), None)
    notes = enforcement_notes(session)
    row = EnforcementSelfTest(
        started_at=utcnow(),
        status=STATUS_RUNNING,
        actor_name=actor.actor_name,
        demo=demo,
        user_id=user.target_id if user else None,
        user_label=user.label if user else None,
        project_id=project.target_id if project else None,
        project_label=project.label if project else None,
        result={"notes": notes, "warnings": warnings, "targets": []},
    )
    session.add(row)
    try:
        session.flush()
    except IntegrityError as exc:
        # The partial unique index: another process started a run meanwhile.
        session.rollback()
        raise SelfTestBusy("Another self-test is running. Wait for it to finish.") from exc
    record_audit(
        session,
        action="selftest.started",
        actor=actor,
        target_type=AUDIT_TARGET,
        target_id=str(row.id),
        target_label=_audit_label(target.label for target in targets),
        after={
            "targets": [target.as_dict() for target in targets],
            "project_actions": list(request.project_actions) if project else [],
            "demo": demo,
            "notes": notes,
        },
        detail=(
            "Enforcement self-test started"
            + (" against the built-in demo tenant" if demo else "")
            + f": {', '.join(target.label for target in targets)} will be restricted, read "
            "back and restored."
        ),
    )
    session.commit()

    reports: list[dict[str, Any]] = []
    completed = False
    try:
        for target in targets:
            reports.append(
                _test_target(session, client, run=row, target=target, request=request, actor=actor)
            )
            _store(session, row, notes=notes, warnings=warnings, reports=reports)
        completed = True
    finally:
        if not completed:
            # Something escaped a target's own handling: whatever this run
            # still holds is restored now (each target's restore already ran
            # in its own finally; this is the net under it).
            session.rollback()
            _safety_net(session, client, row=row, actor=actor)
        _finish(session, row, notes=notes, warnings=warnings, reports=reports, actor=actor)
    return row


def _store(
    session: Session,
    row: EnforcementSelfTest,
    *,
    notes: list[str],
    warnings: list[str],
    reports: list[dict[str, Any]],
) -> None:
    row.result = {"notes": notes, "warnings": warnings, "targets": list(reports)}
    session.commit()


def _finish(
    session: Session,
    row: EnforcementSelfTest,
    *,
    notes: list[str],
    warnings: list[str],
    reports: list[dict[str, Any]],
    actor: AuditActor,
) -> None:
    _settle(session)
    try:
        statuses = [report["status"] for report in reports] or [STATUS_FAILED]
        status = max(statuses, key=lambda value: _STATUS_RANK.get(value, 2))
        if len(reports) < (1 if row.user_id is None or row.project_id is None else 2):
            status = max(status, STATUS_FAILED, key=lambda value: _STATUS_RANK.get(value, 2))
        row.status = status
        row.finished_at = utcnow()
        row.summary = "; ".join(report["summary"] for report in reports) or (
            "The self-test stopped before it finished."
        )
        row.result = {"notes": notes, "warnings": warnings, "targets": list(reports)}
        record_audit(
            session,
            action="selftest.finished",
            actor=actor,
            target_type=AUDIT_TARGET,
            target_id=str(row.id),
            target_label=_audit_label(report["label"] for report in reports),
            after={"status": status, "summary": row.summary},
            detail=f"Enforcement self-test {status.replace('_', ' ')}: {row.summary}",
        )
        _prune(session)
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Could not record the end of self-test %s", row.id)
        raise


def _prune(session: Session) -> None:
    """Keep the newest KEEP_RESULTS results."""
    floor = session.scalar(
        select(EnforcementSelfTest.id)
        .order_by(EnforcementSelfTest.id.desc())
        .offset(KEEP_RESULTS - 1)
        .limit(1)
    )
    if floor is not None:
        session.execute(delete(EnforcementSelfTest).where(EnforcementSelfTest.id < floor))


# ------------------------------------------------------------- one target


class _Steps:
    """Runs and records the steps of one target: timing, outcome, audit."""

    def __init__(
        self,
        session: Session,
        *,
        run: EnforcementSelfTest,
        target: TestTarget,
        actor: AuditActor,
        report: dict[str, Any],
    ) -> None:
        self.session = session
        self.run_row = run
        self.target = target
        self.actor = actor
        self.report = report

    def run(self, name: str, label: str, work: Callable[[], tuple[Any, bool, str]]) -> Any:
        """``work`` returns (value, ok, detail). An exception is a failed step:
        recorded, never raised further, and the value is None."""
        started = time.monotonic()
        try:
            value, ok, detail = work()
        except CheckmarxError as exc:
            value, ok, detail = None, False, f"Checkmarx One: {exc}"
        except Exception as exc:  # noqa: BLE001 - a failed step must never skip the restore
            logger.exception("Self-test step %s failed on %s", name, self.target.label)
            _settle(self.session)
            value, ok, detail = None, False, f"Unexpected error: {type(exc).__name__}: {exc}"
        elapsed = int((time.monotonic() - started) * 1000)
        entry = {"step": name, "label": label, "ok": ok, "ms": elapsed, "detail": detail}
        self.report["steps"].append(entry)
        if not ok:
            self.report["failures"].append(f"{label}: {detail}")
        self._audit(entry)
        return value

    def _audit(self, entry: dict[str, Any]) -> None:
        _settle(self.session)
        try:
            record_audit(
                self.session,
                action="selftest.step",
                actor=self.actor,
                target_type=AUDIT_TARGET,
                target_id=str(self.run_row.id),
                target_label=self.target.label,
                after={
                    "target_type": self.target.noun,
                    "target_id": self.target.target_id,
                    "step": entry["step"],
                    "ok": entry["ok"],
                    "ms": entry["ms"],
                },
                detail=(
                    f"{self.target.label}: {entry['label']} "
                    f"{'passed' if entry['ok'] else 'failed'} in {entry['ms']} ms. "
                    f"{entry['detail']}"
                )[:4000],
            )
            # Committed at once: the audit chain's lock is never held across
            # the next Checkmarx call.
            self.session.commit()
        except Exception:  # noqa: BLE001 - recording a step must not stop the restore
            self.session.rollback()
            logger.exception("Could not audit self-test step %s", entry["step"])


def _test_target(
    session: Session,
    client: CheckmarxClient,
    *,
    run: EnforcementSelfTest,
    target: TestTarget,
    request: SelfTestRequest,
    actor: AuditActor,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        **target.as_dict(),
        "status": STATUS_PASSED,
        "summary": "",
        "kinds": [],
        "steps": [],
        "settings": [],
        "cannot_bite": [],
        "warnings": [],
        "failures": [],
        "restore": {"ok": None, "actions": [], "held": []},
        "ms": 0,
    }
    started = time.monotonic()
    lock = enforcement._target_lock(target.target_type, target.target_id)
    # Never wait on a target lock with anything open in the database.
    session.commit()
    if not lock.acquire(timeout=TARGET_LOCK_WAIT_SECONDS):
        report["failures"].append(
            "CreditGuard's cycle has been working on this target for more than "
            f"{int(TARGET_LOCK_WAIT_SECONDS)} seconds, so it was not tested. Nothing was "
            "changed; try again shortly."
        )
        report["status"] = STATUS_FAILED
        report["summary"] = f"{target.label}: not tested (busy)"
        return report
    try:
        _test_target_locked(
            session, client, run=run, target=target, request=request, actor=actor, report=report
        )
    finally:
        lock.release()
    report["ms"] = int((time.monotonic() - started) * 1000)
    report["status"] = _target_status(report)
    report["summary"] = _target_summary(report)
    return report


def _test_target_locked(
    session: Session,
    client: CheckmarxClient,
    *,
    run: EnforcementSelfTest,
    target: TestTarget,
    request: SelfTestRequest,
    actor: AuditActor,
    report: dict[str, Any],
) -> None:
    steps = _Steps(session, run=run, target=target, actor=actor, report=report)
    period_key = period_key_for(run.id)
    demo = bool(run.demo)

    def recheck() -> tuple[None, bool, str]:
        # The cycle may have restricted it while this run waited for the lock,
        # and a scan may have started since the first check.
        again = _db_refusals(session, target, demo=demo)
        if again:
            return None, False, " ".join(refusal.reason for refusal in again)
        if not target.is_user:
            session.commit()  # nothing open while the scans are listed
            refusal, _warning = _scan_check(client, target)
            if refusal is not None:
                return None, False, refusal.reason
        return None, True, "Not restricted, not near a budget, not protected or exempt."

    steps.run("checks", "Safety checks (under the target's lock)", recheck)
    if report["failures"]:
        return

    resolver = enforcement.RoleResolver(client)
    # The usage breakdown in a breach message: there is no budget behind this one.
    resolver.mixes[(None, period_key)] = None
    ai_roles = settings_store.ai_role_names(session)
    kinds = _planned_kinds(session, target, request)
    report["kinds"] = [{"kind": kind, "outcome": "planned", "detail": ""} for kind in kinds]
    if not kinds:
        report["failures"].append("Nothing to test: none of the chosen settings applies.")
        return

    def read_before() -> tuple[Reading, bool, str]:
        reading = _read(session, client, resolver, target, kinds=kinds, ai_roles=ai_roles)
        if target.is_user:
            live = _live_protection(session, target, reading)
            if live is not None:
                return reading, False, f"Refused: {live.reason}"
        return reading, True, _describe_reading(reading)

    before: Reading | None = steps.run("read_before", "Read the current state", read_before)
    if before is None or report["failures"]:
        # Nothing was changed: no restriction was attempted.
        return

    # What is applied: every kind read, except what the project inherits
    # (Fusion, or an AI agent configuration not set at the project scope):
    # restoring it would pin it on the project. It is still read before and
    # after, which shows it was left alone.
    apply_actions = [] if target.is_user else list(request.project_actions)
    apply_kinds = list(kinds)
    skipped: list[dict[str, Any]] = []
    left_alone = {} if target.is_user else _skipped_kinds(kinds, before)
    if left_alone:
        dropped = {_ACTION_OF_KIND[kind] for kind in left_alone}
        apply_actions = [action for action in apply_actions if action not in dropped]
        apply_kinds = [kind for kind in kinds if _ACTION_OF_KIND.get(kind) not in dropped]
        skipped = [
            {"kind": kind, "action_id": None, "outcome": "not_applicable", "detail": reason}
            for kind, reason in left_alone.items()
        ]
        report["warnings"].extend(dict.fromkeys(left_alone.values()))
    report["kinds"] = [
        {"kind": kind, "outcome": "planned", "detail": ""} for kind in apply_kinds
    ] + skipped
    if not apply_kinds:
        # Nothing left to change (an empty action list would mean the legacy
        # pair to the restriction code, so it is never passed on).
        return

    restricted: Reading | None = None
    try:
        limit = _TestLimit(
            entity_type=EntityType.USER if target.is_user else EntityType.PROJECT,
            entity_id=target.target_id,
            entity_label=f"{target.label} (self-test #{run.id})",
            project_actions=None if target.is_user else apply_actions,
        )

        def apply() -> tuple[enforcement.EnforcementOutcome, bool, str]:
            session.commit()
            with notifications.suppressed():
                outcome = enforcement.apply_enforcement(
                    session,
                    client,
                    limit=cast(CreditLimit, limit),
                    period_key=period_key,
                    actor=actor,
                    resolver=resolver,
                )
            session.commit()
            ok, detail = _classify(
                session, target, period_key, apply_kinds, outcome, before, report
            )
            report["kinds"] = report["kinds"] + skipped
            return outcome, ok, detail

        steps.run("apply", "Apply the restriction (the budget-breach code path)", apply)

        def verify() -> tuple[Reading, bool, str]:
            reading = _read(session, client, resolver, target, kinds=kinds, ai_roles=ai_roles)
            problems = _verify_restricted(session, target, period_key, before, reading, report)
            if problems:
                return reading, False, " ".join(problems)
            return reading, True, "The restriction is in force in the tenant."

        restricted = steps.run("verify_restricted", "Read back: restriction in force", verify)
    finally:
        # Whatever happened above (a failed check, an error, a bug), what this
        # run took is given back now, and read back.
        def restore() -> tuple[dict[str, Any], bool, str]:
            outcome = _restore_target(
                session, client, run=run, target=target, actor=actor, resolver=resolver
            )
            return outcome, outcome["ok"], outcome["detail"]

        restored_outcome = steps.run("restore", "Restore from the undo snapshot", restore)
        if restored_outcome is not None:
            report["restore"].update(restored_outcome)
        else:
            report["restore"]["ok"] = False

        def verify_restored() -> tuple[Reading, bool, str]:
            reading = _read(session, client, resolver, target, kinds=kinds, ai_roles=ai_roles)
            return reading, *_compare_restored(before, reading, report)

        after = steps.run(
            "verify_restored", "Read back: state equals the state before", verify_restored
        )
        report["settings"] = _diff_rows(before, restricted, after)
        _hold_what_did_not_come_back(
            session,
            client,
            run=run,
            target=target,
            before=before,
            after=after,
            report=report,
            actor=actor,
        )


def _describe_reading(reading: Reading) -> str:
    parts = [
        f"{name}: {_show(value)}"
        for name, value in reading.settings.items()
        if not isinstance(value, dict)
    ]
    if reading.unread:
        parts.append(f"not read: {', '.join(reading.unread)}")
    return "; ".join(parts)[:1500]


def _run_actions(session: Session, target: TestTarget, period_key: str) -> list[EnforcementAction]:
    return list(
        session.scalars(
            select(EnforcementAction)
            .where(
                EnforcementAction.period_key == period_key,
                EnforcementAction.limit_id.is_(None),
                EnforcementAction.target_type == target.target_type,
                EnforcementAction.target_id == target.target_id,
            )
            .order_by(EnforcementAction.id)
            .execution_options(populate_existing=True)
        )
    )


def _classify(
    session: Session,
    target: TestTarget,
    period_key: str,
    kinds: list[str],
    outcome: enforcement.EnforcementOutcome,
    before: Reading,
    report: dict[str, Any],
) -> tuple[bool, str]:
    """What the restriction code did for each kind: applied, declined (and why),
    failed, or left in doubt."""
    actions = {action.kind: action for action in _run_actions(session, target, period_key)}
    rows: list[dict[str, Any]] = []
    ok = True
    for kind in kinds:
        action = actions.get(kind)
        prefix = f"{kind} on "
        skipped = next((line for line in outcome.skipped if line.startswith(prefix)), None)
        failed = next((line for line in outcome.failed if line.startswith(prefix)), None)
        row = {"kind": kind, "action_id": action.id if action else None, "detail": ""}
        if action is not None and action.status == EnforcementStatus.APPLIED:
            row["outcome"] = "applied"
            row["detail"] = "Applied and read back by the restriction code."
        elif action is not None and enforcement.may_be_in_force(action):
            row["outcome"] = "in_doubt"
            row["detail"] = action.error or skipped or failed or "The outcome is not known."
            ok = False
        elif failed is not None:
            row["outcome"] = "failed"
            row["detail"] = failed
            ok = False
        elif skipped is not None:
            not_there = (
                kind == EnforcementKind.DISABLE_REPO_FUSION
                and before.settings.get("Repository Fusion (fusionScanConfig)") == ABSENT
            )
            row["outcome"] = "not_applicable" if not_there else "not_restricted"
            row["detail"] = skipped
            if not not_there:
                report["warnings"].append(
                    f"{_KIND_WORDS.get(kind, kind)} was left unchanged by the restriction "
                    f"code, so a budget cannot turn it off here: {skipped}"
                )
        else:
            row["outcome"] = "not_run"
            row["detail"] = "; ".join(outcome.skipped + outcome.failed) or "Nothing was done."
            ok = False
        rows.append(row)
    report["kinds"] = rows
    detail = "; ".join(f"{_KIND_WORDS.get(r['kind'], r['kind'])}: {r['outcome']}" for r in rows)
    return ok, detail


def _verify_restricted(
    session: Session,
    target: TestTarget,
    period_key: str,
    before: Reading,
    restricted: Reading,
    report: dict[str, Any],
) -> list[str]:
    """Problems with the restricted state (empty: it is in force). Also records
    the AI roles a user keeps (cannot bite)."""
    problems: list[str] = []
    outcomes = {row["kind"]: row["outcome"] for row in report["kinds"]}
    actions = {action.kind: action for action in _run_actions(session, target, period_key)}
    now = restricted.settings
    was = before.settings
    if target.is_user:
        kind = EnforcementKind.REMOVE_USER_ROLES.value
        if outcomes.get(kind) == "applied":
            still = now.get("Direct AI roles") or []
            if still:
                problems.append(f"Still mapped directly: {', '.join(still)}.")
            snapshot = actions[kind].undo_snapshot or {}
            removed = {
                entry.get("name")
                for entry in snapshot.get("removed_roles") or []
                if isinstance(entry, dict)
            }
            listed = set(restricted.listed)
            back = sorted(name for name in removed if name in listed)
            if back:
                problems.append(f"Removed but read back as mapped: {', '.join(back)}.")
        effective = now.get("Effective AI roles")
        if effective == UNREADABLE:
            report["warnings"].append(
                "The user's effective roles could not be read, so whether they still hold an "
                "AI role through a group or a composite role is not known."
            )
        elif effective:
            for name in effective:
                via = restricted.kept.get(name) or [
                    role_sources.RoleSource(role_sources.SOURCE_UNKNOWN).describe()
                ]
                report["cannot_bite"].append({"role": name, "via": via})
            report["warnings"].append(
                "The restriction cannot bite: the user still holds "
                + ", ".join(
                    f"{item['role']} (through {', '.join(item['via'])})"
                    for item in report["cannot_bite"]
                )
                + ". CreditGuard removes direct mappings only; change the group or composite "
                "role in Checkmarx One, or rely on project limits."
            )
        elif not was.get("Direct AI roles") and was.get("Effective AI roles") in ([], UNREADABLE):
            report["warnings"].append(
                "The user held none of the configured AI roles, so the test could only show "
                "that nothing is taken. Pick a user who holds one to see a removal."
            )
        return problems

    for kind, outcome in outcomes.items():
        snapshot = (actions[kind].undo_snapshot or {}) if kind in actions else {}
        if outcome in ("not_restricted", "not_applicable"):
            for name in _OWNED.get(kind, ()):
                if name in was and now.get(name) != was.get(name):
                    problems.append(
                        f"{name} changed although the restriction left it alone "
                        f"({_show(was.get(name))} → {_show(now.get(name))})."
                    )
            continue
        if outcome != "applied":
            continue
        if kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
            if was.get("Auto Triage: on") is True and now.get("Auto Triage: on") is not False:
                problems.append(f"Auto Triage still reads as {_show(now.get('Auto Triage: on'))}.")
        elif kind == EnforcementKind.DISABLE_PR_REMEDIATION:
            severities = now.get("PR triage and remediation: severities")
            if severities == UNREADABLE:
                problems.append("PR triage and remediation could not be read back.")
            elif severities:
                problems.append(
                    f"PR triage and remediation severities still read {_show(severities)}."
                )
        elif kind == EnforcementKind.DISABLE_FUSION:
            if platform.setting_is_true(now.get("Fusion: value")):
                problems.append("Fusion still reads as on.")
            if (
                snapshot.get("lock_applied") is True
                and now.get("Fusion: allowOverride") is not False
            ):
                if snapshot.get("lock_unconfirmed"):
                    report["warnings"].append(
                        "The Fusion lock against per-scan override did not read back; the "
                        "restriction code noted it as unconfirmed (Fusion itself is off)."
                    )
                else:
                    problems.append("The Fusion lock against per-scan override did not read back.")
            elif snapshot.get("lock_applied") is False:
                report["warnings"].append(
                    "Checkmarx One refused the Fusion lock against per-scan override, so a scan "
                    "started with its own settings could still turn Fusion on."
                )
        elif kind == EnforcementKind.DISABLE_REPO_FUSION:
            config = now.get("Repository Fusion (fusionScanConfig)")
            if isinstance(config, dict) and platform.setting_is_true(config.get("enabled")):
                problems.append("The repository's Fusion setting still reads as on.")
            elif not isinstance(config, dict):
                problems.append(f"The repository's Fusion setting read back as {_show(config)}.")
    return problems


def _restore_target(
    session: Session,
    client: CheckmarxClient,
    *,
    run: EnforcementSelfTest,
    target: TestTarget,
    actor: AuditActor,
    resolver: enforcement.RoleResolver | None,
) -> dict[str, Any]:
    """Restore every restriction this run made on the target, through the
    Restore path. A restore that fails is held for the cycle to retry."""
    _settle(session)
    period_key = period_key_for(run.id)
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for action in _run_actions(session, target, period_key):
        entry: dict[str, Any] = {"action_id": action.id, "kind": action.kind}
        if not enforcement.may_be_in_force(action):
            entry["restored"] = False
            entry["needed"] = False
            entry["detail"] = f"Nothing to give back ({action.status})."
            results.append(entry)
            continue
        snapshot = {
            key: value
            for key, value in (action.undo_snapshot or {}).items()
            if key != enforcement.OUTCOME_UNKNOWN
        }
        entry["needed"] = True
        entry["snapshot"] = snapshot
        try:
            with notifications.suppressed():
                done = enforcement.restore_action(
                    session,
                    client,
                    action=action,
                    actor=actor,
                    reason=SELFTEST_REASON,
                    resolver=resolver,
                )
            session.commit()
            entry["restored"] = bool(done)
            entry["detail"] = "Restored from the snapshot." if done else "Nothing to restore."
        except Exception as exc:  # noqa: BLE001 - every action is tried; each failure is held
            _settle(session)
            message = (
                f"{type(exc).__name__}: {exc}" if not isinstance(exc, CheckmarxError) else str(exc)
            )
            entry["restored"] = False
            entry["detail"] = message
            errors.append(f"{_KIND_WORDS.get(action.kind, action.kind)}: {message}")
            _hold_for_retry(
                session,
                run=run,
                target=target,
                action_id=action.id,
                why=f"The self-test's restore failed: {message}",
                snapshot=snapshot,
                actor=actor,
            )
            entry["held"] = True
        results.append(entry)
    ok = not errors
    detail = (
        "; ".join(errors)
        if errors
        else (
            f"{sum(1 for item in results if item.get('restored'))} restriction(s) restored."
            if results
            else "Nothing had been changed."
        )
    )
    return {
        "ok": ok,
        "actions": results,
        "held": [item["action_id"] for item in results if item.get("held")],
        "detail": detail,
    }


def _hold_for_retry(
    session: Session,
    *,
    run: EnforcementSelfTest,
    target: TestTarget,
    action_id: int,
    why: str,
    snapshot: dict[str, Any],
    actor: AuditActor,
) -> None:
    """Keep a restriction this run could not (verifiably) give back tracked as
    in force, in doubt, for the next cycle (and the Restore button) to finish.

    Marked the existing way: ``OUTCOME_UNKNOWN`` on its snapshot, status
    applied (or failed, which ``may_be_in_force`` reads together with the
    marker). Having no limit, the cycle's sweep lifts it on its next run.
    """
    action = session.get(EnforcementAction, action_id, populate_existing=True)
    if action is None:
        return
    held = dict(action.undo_snapshot or {})
    held[enforcement.OUTCOME_UNKNOWN] = True
    action.undo_snapshot = held
    if action.status == EnforcementStatus.REVERSED:
        action.status = EnforcementStatus.FAILED
        action.reversed_at = None
    action.reversal_reason = SELFTEST_REASON
    action.error = why[:2000]
    session.flush()
    label = target.label
    notifications.notify(
        session,
        category=notifications.CATEGORY_RESTORATION,
        severity=Severity.CRITICAL,
        title=f"Self-test could not restore {label}",
        body=(
            f"The enforcement self-test #{run.id} restricted {label} "
            f"({_KIND_WORDS.get(action.kind, action.kind)}) and could not give it back: "
            f"{why}\n\n"
            "It stays a tracked restriction: the next cycle tries the restore again, and "
            "Restore here does it now. If it keeps failing, put it back in Checkmarx One by "
            f"hand. What was there before:\n{_snapshot_words(snapshot)}"
        ),
        entity_type=action.entity_type,
        entity_id=action.entity_id,
        entity_label=action.entity_label,
        dedupe_key=f"selftest-restore:{action.id}",
        enforcement_action_id=action.id,
    )
    record_audit(
        session,
        action="selftest.restore_failed",
        actor=actor,
        target_type=target.target_type,
        target_id=target.target_id,
        target_label=label,
        before=snapshot,
        after={"enforcement_action_id": action.id, "held_for_retry": True},
        detail=(
            f"Self-test #{run.id}: {why} The restriction stays tracked (in doubt) and the next "
            "cycle retries the restore."
        )[:4000],
    )
    session.commit()


def _snapshot_words(snapshot: dict[str, Any]) -> str:
    import json

    try:
        return json.dumps(snapshot, sort_keys=True, default=str)[:3000]
    except (TypeError, ValueError):
        return repr(snapshot)[:3000]


def _compare_restored(before: Reading, after: Reading, report: dict[str, Any]) -> tuple[bool, str]:
    """Whether the state read after the restore is the state read before, exactly.

    Lists are compared as sorted values (the tenant may list roles in another
    order), and every value must be equal: a role granted meanwhile is a
    difference like any other.
    """
    differences: list[str] = []
    for name, was in before.settings.items():
        now = after.settings.get(name, ABSENT)
        if now == was:
            continue
        if was == UNREADABLE or now == UNREADABLE:
            report["warnings"].append(f"{name} could not be compared (not readable).")
            continue
        differences.append(f"{name}: {_describe_change(was, now)}")
    if differences:
        return False, "Not as before: " + "; ".join(differences)
    return True, "Every setting reads exactly as before."


def _describe_change(was: Any, now: Any) -> str:
    if isinstance(was, list) and isinstance(now, list):
        added = [item for item in now if item not in was]
        removed = [item for item in was if item not in now]
        parts = []
        if added:
            parts.append("+" + ", +".join(str(item) for item in added))
        if removed:
            parts.append("-" + ", -".join(str(item) for item in removed))
        return " ".join(parts) or f"{_show(was)} → {_show(now)}"
    return f"{_show(was)} → {_show(now)}"


def _diff_rows(
    before: Reading, restricted: Reading | None, after: Reading | None
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name, was in before.settings.items():
        mid = restricted.settings.get(name, UNREADABLE) if restricted is not None else UNREADABLE
        end = after.settings.get(name, UNREADABLE) if after is not None else UNREADABLE
        rows.append(
            {
                "setting": name,
                "before": was,
                "restricted": mid,
                "restored": end,
                "changed": mid != was and mid != UNREADABLE,
                "restored_equal": end == was,
                "owned_by": _owner_of(name),
            }
        )
    return rows


def _hold_what_did_not_come_back(
    session: Session,
    client: CheckmarxClient,
    *,
    run: EnforcementSelfTest,
    target: TestTarget,
    before: Reading,
    after: Reading | None,
    report: dict[str, Any],
    actor: AuditActor,
) -> None:
    """A restore that answered OK but whose read-back shows something this run
    took still missing (or that could not be read back at all) is held for the
    cycle to finish, as a failed restore is. Something else that changed
    meanwhile (a role granted by someone) is reported, never "restored"."""
    _settle(session)
    held = set(report["restore"].get("held") or [])
    restored_ids = {
        item["action_id"] for item in report["restore"].get("actions") or [] if item.get("restored")
    }
    for action in _run_actions(session, target, period_key_for(run.id)):
        if action.id in held or action.id not in restored_ids:
            continue
        snapshot = {
            key: value
            for key, value in (action.undo_snapshot or {}).items()
            if key != enforcement.OUTCOME_UNKNOWN
        }
        missing = _still_taken(action.kind, snapshot, before, after)
        if not missing:
            continue
        _hold_for_retry(
            session,
            run=run,
            target=target,
            action_id=action.id,
            why=f"The restore was accepted, but {missing}",
            snapshot=snapshot,
            actor=actor,
        )
        report["restore"].setdefault("held", []).append(action.id)
        report["restore"]["ok"] = False
        report["failures"].append(f"Restore incomplete: {missing}")


def _still_taken(
    kind: str, snapshot: dict[str, Any], before: Reading, after: Reading | None
) -> str | None:
    """What this restriction took that the read after the restore does not
    show back, in words; None when all of it is back."""
    if not enforcement._took_something(snapshot):
        return None
    if after is None:
        return "the state after it could not be read back, so it is not known to be back."
    if kind == EnforcementKind.REMOVE_USER_ROLES:
        removed = sorted(
            str(entry.get("name"))
            for entry in snapshot.get("removed_roles") or []
            if isinstance(entry, dict) and entry.get("name")
        )
        missing = [name for name in removed if name not in set(after.listed)]
        if missing:
            return f"{', '.join(missing)} did not read back as mapped to the user."
        return None
    for name in _OWNED.get(kind, ()):
        if name in before.settings and after.settings.get(name) != before.settings[name]:
            return (
                f"{name} reads {_show(after.settings.get(name))}, not "
                f"{_show(before.settings[name])} as before."
            )
    return None


def _safety_net(
    session: Session, client: CheckmarxClient, *, row: EnforcementSelfTest, actor: AuditActor
) -> None:
    """Restore anything this run still holds (used only when a target's own
    handling was cut short)."""
    period_key = period_key_for(row.id)
    try:
        leftovers = list(
            session.scalars(
                select(EnforcementAction).where(
                    EnforcementAction.period_key == period_key,
                    EnforcementAction.limit_id.is_(None),
                )
            )
        )
    except Exception:  # noqa: BLE001
        logger.exception("Could not look for what self-test %s still holds", row.id)
        return
    for action in leftovers:
        if not enforcement.may_be_in_force(action) or action.reversal_reason == SELFTEST_REASON:
            continue
        target = TestTarget(action.target_type, action.target_id, action.target_label or "")
        try:
            _restore_target(session, client, run=row, target=target, actor=actor, resolver=None)
        except Exception:  # noqa: BLE001 - the cycle's sweep is the last net
            session.rollback()
            logger.exception("Self-test %s could not restore %s", row.id, action.target_id)


def _target_status(report: dict[str, Any]) -> str:
    if report["restore"].get("held") or report["restore"].get("ok") is False:
        return STATUS_RESTORE_FAILED
    if report["failures"]:
        return STATUS_FAILED
    if report["warnings"] or report["cannot_bite"]:
        return STATUS_WARNING
    return STATUS_PASSED


def _target_summary(report: dict[str, Any]) -> str:
    seconds = report["ms"] / 1000
    status = report["status"]
    words = {
        STATUS_PASSED: "passed",
        STATUS_WARNING: "passed with warnings",
        STATUS_FAILED: "failed",
        STATUS_RESTORE_FAILED: "RESTORE FAILED, still restricted until the next cycle",
    }.get(status, status)
    extra = ""
    if report["cannot_bite"]:
        extra = " (cannot bite: " + ", ".join(item["role"] for item in report["cannot_bite"]) + ")"
    elif report["failures"]:
        extra = f" ({report['failures'][0][:200]})"
    return f"{report['label']}: {words} in {seconds:.1f} s{extra}"


# ---------------------------------------------------------------- demo holds


def retry_demo_holds(session: Session, *, actor: AuditActor) -> int:
    """Restore every demo self-test restriction still in force, in the demo
    tenant (the cycle's sweep, which talks to the live tenant, leaves them
    alone). Returns how many were restored."""
    from app.services import demo_service, demo_tenant

    held = [
        action
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id.is_(None),
                EnforcementAction.period_key.like(f"{PERIOD_PREFIX}%"),
                EnforcementAction.target_id.like(f"{demo_service.DEMO_PREFIX}%"),
                EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
            )
        )
        if enforcement.may_be_in_force(action)
    ]
    if not held:
        return 0
    client = demo_tenant.client()
    restored = 0
    for action in held:
        try:
            if enforcement.restore_action(
                session, client, action=action, actor=actor, reason=SELFTEST_CLEANUP_REASON
            ):
                restored += 1
            session.commit()
        except CheckmarxError:
            # Recorded on the action by restore_action; tried again next cycle.
            session.commit()
            logger.warning("Could not restore demo self-test restriction %s", action.id)
    return restored


def unsettled_in_force(session: Session) -> list[EnforcementAction]:
    """Restrictions that are not "applied" but may be in force: a write (or a
    self-test's restore) whose outcome is in doubt. Counted with the applied
    ones wherever restrictions in force are counted."""
    # Narrowed in the database to rows whose snapshot is marked in doubt (few,
    # and usually none): the rest of the check needs the snapshot itself.
    return [
        action
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.status.in_((EnforcementStatus.PENDING, EnforcementStatus.FAILED)),
                EnforcementAction.undo_snapshot[enforcement.OUTCOME_UNKNOWN].as_boolean() == true(),
            )
        )
        if enforcement.may_be_in_force(action)
    ]


# -------------------------------------------------------------------- reading


def as_dict(row: EnforcementSelfTest, *, now: datetime | None = None) -> dict[str, Any]:
    status = row.status
    if status == STATUS_RUNNING and row.started_at < (now or utcnow()) - STALE_AFTER:
        status = STATUS_INTERRUPTED
    return {
        "id": row.id,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "status": status,
        "actor_name": row.actor_name,
        "demo": bool(row.demo),
        "user_id": row.user_id,
        "user_label": row.user_label,
        "project_id": row.project_id,
        "project_label": row.project_label,
        "summary": row.summary,
        "result": row.result or {},
    }


def recent(session: Session, *, limit: int = KEEP_RESULTS) -> list[EnforcementSelfTest]:
    return list(
        session.scalars(
            select(EnforcementSelfTest).order_by(EnforcementSelfTest.id.desc()).limit(limit)
        )
    )


def latest(session: Session) -> EnforcementSelfTest | None:
    return session.scalar(
        select(EnforcementSelfTest)
        .where(EnforcementSelfTest.status != STATUS_RUNNING)
        .order_by(EnforcementSelfTest.id.desc())
        .limit(1)
    )


def is_running(session: Session) -> bool:
    return _run_lock.locked() or _running_row(session) is not None
