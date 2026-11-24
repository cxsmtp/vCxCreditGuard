"""Applying and reversing restrictions in Checkmarx One.

Three properties matter more than anything else in this file, because this is the
code that takes privileges away from real engineers.

**Reversibility.** Nothing is changed before the current state has been read and
stored on the enforcement row. Restore replays that snapshot, so a feature that
was already off before we touched it stays off afterwards.

**Idempotency.** Every action carries a key derived from the limit, the budget
period, the kind of change and the target. A cycle that restarts mid flight finds
the existing row and skips work already done, and re-running enforcement never
produces a second row or a second undo snapshot.

**Blast radius is explicit.** A group or application breach fans out to every
project underneath it. Each project gets its own row with its own restore, and
exempt entities are filtered out at the target level, not just at the limit level,
so an exempt project inside a breached application is left alone.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import iam, platform
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import (
    CheckmarxAuthError,
    CheckmarxError,
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxRateLimitError,
    CheckmarxResponseError,
)
from app.db.base import utcnow
from app.models.audit import AuditLogEntry
from app.models.enums import (
    LEGACY_PROJECT_ACTIONS,
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    ProjectAction,
    Severity,
)
from app.models.limits import (
    CreditLimit,
    EnforcementAction,
    Exemption,
    effective_project_actions,
)
from app.models.org import CxApplicationProject, CxProject, CxProjectGroup, CxUser
from app.services import key_permissions, notifications, settings_store, usage_mix
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

TARGET_USER = "cx_user"
TARGET_PROJECT = "cx_project"

# Written when PR remediation is disabled. Restore uses the captured value.
DISABLED_SEVERITIES: list[str] = []

# Reversal_reason recorded when a restriction is lifted because an exemption was
# added. Unlike a manual admin restore (reason "admin"), this is conditional on
# the exemption: once the exemption is removed the next cycle can restrict again.
EXEMPTED_REASON = "exempted"
# An administrator pressed Restore. The one reversal that is not conditional: the
# cycle does not re-apply the restriction for the rest of the period.
ADMIN_REASON = "admin"
# The limit no longer turns this off (an admin changed what it turns off).
DESELECTED_REASON = "action_deselected"

# Which project action each project kind belongs to.
PROJECT_ACTION_OF_KIND: dict[str, str] = {
    EnforcementKind.DISABLE_AUTO_TRIAGE.value: ProjectAction.AUTO_TRIAGE.value,
    EnforcementKind.DISABLE_PR_REMEDIATION.value: ProjectAction.PR_REMEDIATION.value,
    EnforcementKind.DISABLE_FUSION.value: ProjectAction.FUSION.value,
    EnforcementKind.DISABLE_REPO_FUSION.value: ProjectAction.FUSION.value,
}

# Audited once per target when a restriction has nothing to act on there.
AUDIT_NOT_APPLICABLE = "enforcement.not_applicable"

# Snapshot key: True from the moment a tenant write is about to be attempted
# until its result is recorded. See may_be_in_force.
OUTCOME_UNKNOWN = "outcome_unknown"
# Answers that mean Checkmarx did not make the change. Anything else (a timeout,
# a dropped connection, a 5xx) leaves the outcome in doubt.
_DEFINITE_REJECTIONS = (
    CheckmarxAuthError,
    CheckmarxPermissionError,
    CheckmarxNotFoundError,
    CheckmarxRateLimitError,
    CheckmarxResponseError,
)


# One lock per restricted target, held across "read tenant state, commit intent,
# change the tenant, commit outcome". Without it a manual Restore and the cycle's
# drift check can interleave: the admin gives the roles back, the cycle (still
# seeing the action as applied) removes them again as "drift", the admin's commit
# then records the action as reversed - restored on paper, restricted in fact.
# In-process is sufficient because the utility runs as a single process (one
# uvicorn worker, with the scheduler as a thread inside it); see docs/operations.
_target_locks: dict[str, threading.RLock] = {}
_target_locks_guard = threading.Lock()


def _target_lock(target_type: str, target_id: str) -> threading.RLock:
    key = f"{target_type}:{target_id}"
    with _target_locks_guard:
        lock = _target_locks.get(key)
        if lock is None:
            lock = _target_locks[key] = threading.RLock()
        return lock


@dataclass(frozen=True, slots=True)
class Target:
    kind: EnforcementKind
    target_type: str
    target_id: str
    target_label: str | None


@dataclass
class EnforcementOutcome:
    applied: list[EnforcementAction]
    skipped: list[str]
    failed: list[str]
    # Restrictions that had already been applied and were verified this run and
    # re-asserted after they had drifted back on in Checkmarx One.
    reconciled: list[EnforcementAction] = field(default_factory=list)
    # Restrictions whose current state could not be read back, so whether they
    # still hold is unknown. They were re-applied (harmless if they still hold),
    # but this is not drift and nobody is told it was.
    unverified: list[EnforcementAction] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed

    def as_stats(self) -> dict[str, Any]:
        return {
            "applied": len(self.applied),
            "reconciled": len(self.reconciled),
            "unverified": len(self.unverified),
            "skipped": self.skipped,
            "failed": self.failed,
        }


def _permission_hint(exc: Exception) -> str:
    if isinstance(exc, CheckmarxPermissionError):
        return (
            "The API key is missing this permission. Settings → Connection → Key permissions "
            "shows what is missing and why.\n\n"
        )
    return ""


def _record_refusals(session: Session, actor: AuditActor) -> None:
    """Put any 403 met so far on the API key permission report (no commit)."""
    if key_permissions.pending_denials():
        key_permissions.flush_runtime_denials(session, actor=actor)


def idempotency_key(*, limit_id: int, period_key: str, kind: str, target_id: str) -> str:
    return f"{limit_id}|{period_key}|{kind}|{target_id}"


# ------------------------------------------------------------------ exemptions


def is_exempt(session: Session, *, entity_type: str, entity_id: str) -> bool:
    return (
        session.scalar(
            select(Exemption.id).where(
                Exemption.entity_type == entity_type, Exemption.entity_id == entity_id
            )
        )
        is not None
    )


# ----------------------------------------------------------------- protection


class NotRestricted(Exception):  # noqa: N818 - a decision, not an error
    """This target is deliberately left alone. Nothing was changed.

    ``title`` is what the admin is told, once; the message says why. A
    ``quiet`` one is recorded on the action and audited, but raises no
    notification: there was simply nothing there to change.
    """

    def __init__(self, message: str, *, title: str, quiet: bool = False) -> None:
        super().__init__(message)
        self.title = title
        self.quiet = quiet


class _NotKept(NotRestricted):
    """The tenant accepted the write and did not keep it: nothing was taken."""


class _NotApplicable(NotRestricted):
    """There is nothing there to turn off. Audited once per target, not per period."""

    def __init__(self, message: str, *, title: str) -> None:
        super().__init__(message, title=title, quiet=True)


class ProtectedTarget(NotRestricted):
    """This target must not be restricted, whatever its usage."""

    def __init__(self, message: str, *, label: str | None = None) -> None:
        super().__init__(message, title=f"{label or 'A user'} is over budget but protected")


# Recorded on an action lifted because its target turned out to be protected.
PROTECTED_REASON = "protected"


def protected_user_ids(session: Session) -> frozenset[str]:
    """Tenant users the utility never restricts.

    The account the stored API key belongs to: the utility acts as that user,
    so taking its roles away could cut off the utility's own access to the
    tenant - including its ability to give anyone's access back.
    """
    from app.services import connection as connection_service

    subject = connection_service.api_key_subject(session)
    return frozenset({subject}) if subject else frozenset()


def protection_reason(
    session: Session,
    user_id: str,
    *,
    protected_roles: frozenset[str] | None = None,
    live_roles: set[str] | None = None,
) -> str | None:
    """Why this tenant user is never restricted, or None if they may be.

    Judged on what the last sync recorded about the user and, where the caller
    has just read them from the tenant, on their roles as they are now.
    """
    if user_id in protected_user_ids(session):
        return "it is the account the Checkmarx One API key belongs to"
    if protected_roles is None:
        protected_roles = settings_store.enforcement_guard(session).protected_roles
    if not protected_roles:
        return None
    user = session.get(CxUser, user_id)
    held = {str(name).lower() for name in ((user.role_names if user else None) or [])}
    held |= {name.lower() for name in (live_roles or set())}
    shielding = sorted(held & protected_roles)
    if shielding:
        return f"they hold a protected role ({', '.join(shielding)})"
    return None


def target_released(session: Session, action: EnforcementAction) -> str | None:
    """A reason this action's *target* should not be restricted by anyone.

    Distinct from the limit no longer applying: when the target itself is exempt
    or protected, every limit restricting it has to let go, not just this one.
    """
    if action.target_type == TARGET_USER:
        if is_exempt(session, entity_type=EntityType.USER, entity_id=action.target_id):
            return EXEMPTED_REASON
        if protection_reason(session, action.target_id) is not None:
            return PROTECTED_REASON
        return None
    if is_exempt(session, entity_type=EntityType.PROJECT, entity_id=action.target_id):
        return EXEMPTED_REASON
    return None


# --------------------------------------------------------------------- planning


def project_ids_for(session: Session, *, entity_type: str, entity_id: str) -> list[str]:
    """Projects affected by a breach of this entity's limit."""
    if entity_type == EntityType.PROJECT:
        return [entity_id]
    if entity_type == EntityType.GROUP:
        return list(
            session.scalars(
                select(CxProjectGroup.project_id).where(CxProjectGroup.group_id == entity_id)
            )
        )
    if entity_type == EntityType.APPLICATION:
        return list(
            session.scalars(
                select(CxApplicationProject.project_id).where(
                    CxApplicationProject.application_id == entity_id
                )
            )
        )
    return []


def plan_targets(
    session: Session,
    *,
    entity_type: str,
    entity_id: str,
    project_actions: Iterable[str] | None = None,
) -> list[Target]:
    """Every concrete change a breach of this limit implies, exemptions removed.

    ``project_actions`` is what a project, group or application limit turns off
    (``effective_project_actions``); None means the legacy pair, Auto Triage and
    PR triage and remediation.
    """
    chosen = set(LEGACY_PROJECT_ACTIONS if project_actions is None else project_actions)
    if entity_type == EntityType.USER:
        if is_exempt(session, entity_type=EntityType.USER, entity_id=entity_id):
            return []
        if protection_reason(session, entity_id) is not None:
            return []
        user = session.get(CxUser, entity_id)
        return [
            Target(
                kind=EnforcementKind.REMOVE_USER_ROLES,
                target_type=TARGET_USER,
                target_id=entity_id,
                target_label=user.display_name if user else entity_id,
            )
        ]

    targets: list[Target] = []
    for project_id in dict.fromkeys(
        project_ids_for(session, entity_type=entity_type, entity_id=entity_id)
    ):
        if is_exempt(session, entity_type=EntityType.PROJECT, entity_id=project_id):
            continue
        project = session.get(CxProject, project_id)
        if project is not None and project.is_deleted:
            continue
        label = project.name if project else project_id
        has_repo = project is not None and bool(project.repo_id)
        kinds: list[EnforcementKind] = []
        if ProjectAction.AUTO_TRIAGE in chosen:
            kinds.append(EnforcementKind.DISABLE_AUTO_TRIAGE)
        # The repository settings are only meaningful for projects with a
        # supported SCM integration.
        if ProjectAction.PR_REMEDIATION in chosen and has_repo:
            kinds.append(EnforcementKind.DISABLE_PR_REMEDIATION)
        if ProjectAction.FUSION in chosen:
            kinds.append(EnforcementKind.DISABLE_FUSION)
            if has_repo:
                kinds.append(EnforcementKind.DISABLE_REPO_FUSION)
        targets.extend(
            Target(
                kind=kind,
                target_type=TARGET_PROJECT,
                target_id=project_id,
                target_label=label,
            )
            for kind in kinds
        )
    return targets


# --------------------------------------------------------------- role resolution


class RoleResolver:
    """Caches the client UUID and role ids for one enforcement run."""

    def __init__(self, client: CheckmarxClient) -> None:
        self._client = client
        self._client_uuid: str | None = None
        self._roles: dict[str, iam.RoleRef] | None = None

    @property
    def client_uuid(self) -> str:
        if self._client_uuid is None:
            self._client_uuid = iam.resolve_platform_client_uuid(self._client)
        return self._client_uuid

    def all_roles(self) -> dict[str, iam.RoleRef]:
        if self._roles is None:
            self._roles = iam.fetch_client_roles(self._client, client_uuid=self.client_uuid)
        return self._roles

    def ai_roles(self) -> dict[str, iam.RoleRef]:
        if self._roles is None:
            self._roles = iam.fetch_client_roles(self._client, client_uuid=self.client_uuid)
        missing = [name for name in iam.AI_ROLE_NAMES if name not in self._roles]
        if missing:
            logger.warning("Roles not present on the client: %s", ", ".join(missing))
        return {name: self._roles[name] for name in iam.AI_ROLE_NAMES if name in self._roles}


# ------------------------------------------------------------------- enforcing


def apply_enforcement(
    session: Session,
    client: CheckmarxClient,
    *,
    limit: CreditLimit,
    period_key: str,
    actor: AuditActor,
    resolver: RoleResolver | None = None,
) -> EnforcementOutcome:
    """Enforce one breached limit. Safe to call repeatedly for the same period."""
    outcome = EnforcementOutcome(applied=[], skipped=[], failed=[])
    if is_exempt(session, entity_type=limit.entity_type, entity_id=limit.entity_id):
        outcome.skipped.append(f"{limit.entity_type} {limit.entity_id} is exempt")
        return outcome

    resolver = resolver or RoleResolver(client)
    protected_roles = settings_store.enforcement_guard(session).protected_roles
    if limit.entity_type == EntityType.USER:
        why = protection_reason(session, limit.entity_id, protected_roles=protected_roles)
        if why is not None:
            label = limit.entity_label or limit.entity_id
            outcome.skipped.append(f"{label} is protected: {why}")
            raised = notifications.notify(
                session,
                category=notifications.CATEGORY_ENFORCEMENT,
                severity=Severity.WARNING,
                title=f"{label} is over budget but protected",
                body=(
                    f"{label} has gone over their credit limit, but their AI access is "
                    f"not removed automatically because {why}. Raise it with them, or "
                    "change the protected roles under Settings → Enforcement."
                ),
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                entity_label=limit.entity_label,
                dedupe_key=notifications.protected_key(limit.id, period_key),
            )
            if raised is not None:
                record_audit(
                    session,
                    action="enforcement.protected",
                    actor=actor,
                    target_type=TARGET_USER,
                    target_id=limit.entity_id,
                    target_label=label,
                    detail=f"Over budget in {period_key}, not restricted: {why}.",
                )
            return outcome
    targets = plan_targets(
        session,
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        project_actions=effective_project_actions(limit),
    )
    if not targets:
        outcome.skipped.append("no targets to restrict (exempt, or no projects linked)")
        return outcome

    for target in targets:
        # Lock order: never wait on a target lock while holding anything in the
        # database. Whoever holds the target lock needs the database to record
        # its outcome, so waiting on it with a write open would stall both.
        session.commit()
        with _target_lock(target.target_type, target.target_id):
            _enforce_target(
                session,
                client,
                limit=limit,
                period_key=period_key,
                target=target,
                actor=actor,
                resolver=resolver,
                outcome=outcome,
                protected_roles=protected_roles,
            )
    return outcome


def _enforce_target(
    session: Session,
    client: CheckmarxClient,
    *,
    limit: CreditLimit,
    period_key: str,
    target: Target,
    actor: AuditActor,
    resolver: RoleResolver,
    outcome: EnforcementOutcome,
    protected_roles: frozenset[str] = frozenset(),
) -> None:
    """Restrict one target, or verify an existing restriction. Caller holds its lock.

    Every tenant write is bracketed by commits: the intent and the undo snapshot
    are durable *before* Checkmarx is changed, and the outcome is committed right
    after. A crash in between leaves a PENDING row that still carries the snapshot,
    so the next cycle completes the action and Restore can still give back exactly
    what was taken. Committing after each audit row also means the audit chain's
    lock is never held across a network call.
    """
    key = idempotency_key(
        limit_id=limit.id,
        period_key=period_key,
        kind=str(target.kind),
        target_id=target.target_id,
    )
    action = session.scalar(
        select(EnforcementAction).where(EnforcementAction.idempotency_key == key)
    )
    if action is not None:
        # A manual Restore may have committed a change to this row while we
        # waited for the target lock; never act on the stale copy.
        session.refresh(action)

    if action is not None and action.status == EnforcementStatus.APPLIED:
        _verify_applied(
            session,
            client,
            limit=limit,
            period_key=period_key,
            target=target,
            action=action,
            actor=actor,
            resolver=resolver,
            outcome=outcome,
        )
        return

    if action is not None and action.status == EnforcementStatus.REVERSED:
        if action.reversal_reason != ADMIN_REASON:
            # Lifted automatically: because an exemption was granted, the budget
            # was raised, or the limit stopped enforcing. The limit is breached
            # and enforcing again now (and the target is not exempt, or it would
            # not be in the plan), so whatever lifted it no longer holds and the
            # breach restricts it again rather than leaving it unlocked for the
            # rest of the period. Only an admin's own Restore is left alone.
            action.error = None
            action.reversed_at = None
            action.reversed_by_id = None
            action.reversal_reason = None
            # Its old snapshot was already replayed by that restore, so it says
            # nothing about what is about to be taken away now.
            action.undo_snapshot = None
            action.status = EnforcementStatus.PENDING
        else:
            # An admin restored access during this period. Respect that decision
            # instead of fighting them every cycle.
            outcome.skipped.append(
                f"{target.kind} on {target.target_label} was restored by an admin this period"
            )
            return

    if action is None:
        action = EnforcementAction(
            idempotency_key=key,
            kind=str(target.kind),
            status=EnforcementStatus.PENDING,
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            target_type=target.target_type,
            target_id=target.target_id,
            target_label=target.target_label,
            limit_id=limit.id,
            period_key=period_key,
            created_at=utcnow(),
            attempts=0,
        )
        session.add(action)
    # Column defaults are applied at INSERT, so a freshly constructed row still
    # has None here until it is flushed.
    action.attempts = (action.attempts or 0) + 1
    # Committed, not just flushed: nothing may be left open while we wait on
    # Checkmarx, or every other writer (a sign-in included) queues behind it.
    session.commit()

    earlier = action.undo_snapshot if _outcome_unknown(action.undo_snapshot) else None
    # What the last attempt failed with, if it failed: a retry that fails the
    # same way is not news.
    previous_error = action.error if action.status == EnforcementStatus.FAILED else None
    write_attempted = False
    try:
        # Phase 1: read the tenant's current state. Nothing is changed yet.
        captured = _capture(
            session, client, target=target, resolver=resolver, protected_roles=protected_roles
        )
        # Phase 2: make the intent and the undo snapshot durable. If an earlier
        # attempt's write may have landed without being recorded, its snapshot
        # holds the true "before" state and is merged in rather than overwritten
        # by what is, by now, possibly an already-restricted state. The same
        # goes for another limit that already restricts this target: what we
        # just read is the state *it* left, and what must eventually be given
        # back is what was there before either. The snapshot is marked "outcome
        # unknown" until the write's result is recorded, so a process that stops
        # in between leaves a row that can still be undone.
        # What the siblings and the earlier attempt know is kept aside: the
        # outcome of the write below is merged with it again (Phase 4), so a
        # later attempt that takes nothing itself can never erase the evidence
        # that an earlier one (or another limit) took something.
        known = [_settled(sibling.undo_snapshot) for sibling in _siblings_in_force(session, action)]
        known.append(earlier)
        snapshot = _combine(known, captured.snapshot)
        snapshot[OUTCOME_UNKNOWN] = True
        action.undo_snapshot = snapshot
        action.status = EnforcementStatus.PENDING
        session.commit()
        # Phase 3: change the tenant. No transaction is open during this call.
        write_attempted = True
        captured.apply()
    except NotRestricted as exc:
        # A decision, not a failure: nothing is changed, the admin is told once,
        # and the cycle is not marked as degraded for honouring its own rule.
        message = str(exc)[:2000]
        first_report = previous_error != message
        if isinstance(exc, _NotKept) and action.undo_snapshot is not None:
            # Read back after the write: the setting is as it was, so nothing is
            # in doubt and nothing is held.
            settled = dict(action.undo_snapshot)
            settled[OUTCOME_UNKNOWN] = False
            action.undo_snapshot = settled
        action.status = EnforcementStatus.FAILED
        action.error = message
        session.flush()
        outcome.skipped.append(f"{target.kind} on {target.target_label}: {exc}")
        if not exc.quiet:
            notifications.notify(
                session,
                category=notifications.CATEGORY_ENFORCEMENT,
                severity=Severity.WARNING,
                title=exc.title,
                body=str(exc),
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                entity_label=limit.entity_label,
                dedupe_key=notifications.not_restricted_key(action.id),
                enforcement_action_id=action.id,
            )
        audit_action = "enforcement.not_restricted"
        if isinstance(exc, _NotApplicable):
            # Nothing to do there, and likely the same every period: said once
            # per target, ever (it is still looked at again every cycle).
            audit_action = AUDIT_NOT_APPLICABLE
            first_report = (
                session.scalar(
                    select(AuditLogEntry.id)
                    .where(
                        AuditLogEntry.action == AUDIT_NOT_APPLICABLE,
                        AuditLogEntry.target_type == target.target_type,
                        AuditLogEntry.target_id == target.target_id,
                    )
                    .limit(1)
                )
                is None
            )
        if first_report:
            record_audit(
                session,
                action=audit_action,
                actor=actor,
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
                detail=str(exc),
            )
        _record_refusals(session, actor)
        session.commit()
        return
    except CheckmarxError as exc:
        if action.undo_snapshot is not None and (
            not write_attempted or isinstance(exc, _DEFINITE_REJECTIONS)
        ):
            # Checkmarx refused the change outright (or it was never sent), so
            # nothing was taken by this attempt. Only an earlier attempt can
            # still be in doubt.
            settled = dict(action.undo_snapshot)
            settled[OUTCOME_UNKNOWN] = earlier is not None
            action.undo_snapshot = settled
        message = str(exc)[:2000]
        first_report = previous_error != message
        action.status = EnforcementStatus.FAILED
        action.error = message
        session.flush()
        outcome.failed.append(f"{target.kind} on {target.target_label}: {exc}")
        # The attempt is repeated every cycle for as long as the limit is
        # breached. The admin is told once a day, and the audit log records the
        # failure when it is new or changes, not on every retry.
        notifications.notify(
            session,
            category=notifications.CATEGORY_ENFORCEMENT,
            severity=Severity.ERROR,
            title=f"Could not restrict {target.target_label}",
            body=f"{exc}\n\n{_permission_hint(exc)}It will be tried again on the next cycle.",
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            dedupe_key=notifications.enforcement_failed_key(
                action.id, utcnow().strftime("%Y-%m-%d")
            ),
            enforcement_action_id=action.id,
        )
        if first_report:
            record_audit(
                session,
                action="enforcement.failed",
                actor=actor,
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
                detail=f"{target.kind} failed: {exc}",
            )
        _record_refusals(session, actor)
        session.commit()
        return

    # Phase 4: record the outcome, and commit before anything else happens.
    # What the write itself found out (Fusion: whether the lock was accepted and
    # kept) belongs to this attempt's read; it is merged with what was known
    # before exactly as the read was, never laid over the merged result.
    snapshot = _combine(known, {**captured.snapshot, **captured.outcome})
    action.undo_snapshot = snapshot
    captured.mirror()
    action.status = EnforcementStatus.APPLIED
    action.applied_at = utcnow()
    action.error = None
    session.flush()
    outcome.applied.append(action)

    record_audit(
        session,
        action="enforcement.applied",
        actor=actor,
        target_type=target.target_type,
        target_id=target.target_id,
        target_label=target.target_label,
        before=snapshot,
        after={"kind": str(target.kind), "restricted": True},
        detail=(
            f"Limit on {limit.entity_type} {limit.entity_label or limit.entity_id} "
            f"was breached in {period_key}."
        ),
    )
    notifications.notify(
        session,
        category=notifications.CATEGORY_ENFORCEMENT,
        severity=Severity.CRITICAL,
        title=_enforcement_title(target),
        body=_enforcement_body(
            limit,
            target,
            period_key,
            snapshot,
            mix=usage_mix.mix_for(session, limit, period_key=period_key),
        ),
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        dedupe_key=notifications.enforcement_key(action.id),
        enforcement_action_id=action.id,
    )
    session.commit()


def _verify_applied(
    session: Session,
    client: CheckmarxClient,
    *,
    limit: CreditLimit,
    period_key: str,
    target: Target,
    action: EnforcementAction,
    actor: AuditActor,
    resolver: RoleResolver,
    outcome: EnforcementOutcome,
) -> None:
    """Already restricted: re-verify, and re-assert if it drifted back on.

    A manual (or automated) change in Checkmarx One could have re-enabled the
    feature or re-granted a role, so the restriction is checked rather than
    assumed to hold.
    """
    if action.reversal_reason == ADMIN_REASON:
        # An admin's Restore was started and did not finish. Re-asserting the
        # restriction now would silently undo what they asked for; the cycle
        # completes the restore instead (see evaluation's unjustified sweep).
        outcome.skipped.append(f"{target.kind} on {target.target_label} has a restore in progress")
        return
    if action.reversal_reason:
        # An automatic lift was started and did not finish, and the limit is
        # breached and enforcing again, so its reason no longer holds.
        action.reversal_reason = None
        action.reversed_by_id = None
    if target.target_type == TARGET_USER and protection_reason(session, target.target_id):
        # Protected since the restriction was applied (given an admin role, or
        # this is now the API key's own account): give the access back rather
        # than keep taking it away.
        _restore_action_locked(
            session,
            client,
            action=action,
            actor=actor,
            reason=PROTECTED_REASON,
            resolver=resolver,
        )
        outcome.skipped.append(f"{target.target_label} is now protected; restriction lifted")
        return
    session.commit()  # nothing held open while we wait on Checkmarx
    found: dict[str, Any] = {}
    try:
        verdict = _reconcile(
            session, client, action=action, target=target, resolver=resolver, found=found
        )
    except CheckmarxError as exc:
        logger.warning(
            "Could not verify %s on %s this cycle: %s", target.kind, target.target_label, exc
        )
        outcome.skipped.append(
            f"{target.kind} on {target.target_label} could not be verified this cycle: {exc}"
        )
        _record_refusals(session, actor)
        session.commit()
        return
    if verdict == RECONCILE_UNVERIFIED:
        # The setting could not be read back. The restriction was written again
        # (it is idempotent, so a restriction that still holds is unchanged),
        # but nothing says it had drifted: no alert. The tenant was written to,
        # so the first such re-apply of this restriction is audited; later ones
        # (every cycle while the read keeps failing) are not.
        outcome.unverified.append(action)
        outcome.skipped.append(
            f"{target.kind} on {target.target_label} could not be verified (its setting could "
            "not be read back); the restriction was re-applied to keep it in force"
        )
        _record_refusals(session, actor)
        if not _unverified_reapply_audited(session, action):
            record_audit(
                session,
                action=AUDIT_UNVERIFIED_REAPPLY,
                actor=actor,
                target_type=AUDIT_TARGET_ACTION,
                target_id=str(action.id),
                target_label=target.target_label,
                after={"kind": str(target.kind), "restricted": True, "verified": False},
                detail=(
                    f"The restriction on {target.target_label} could not be read back from "
                    "Checkmarx One, so it was written again to keep it in force. Recorded once "
                    "per restriction; later re-applies are not audited."
                ),
            )
        session.commit()
        return
    if verdict == RECONCILE_HELD:
        outcome.skipped.append(
            f"{target.kind} on {target.target_label} already applied and verified in Checkmarx"
        )
        return

    outcome.reconciled.append(action)
    record_audit(
        session,
        action="enforcement.reconciled",
        actor=actor,
        target_type=target.target_type,
        target_id=target.target_id,
        target_label=target.target_label,
        after={"kind": str(target.kind), "restricted": True},
        detail=(
            f"A previously applied restriction on {target.target_label} "
            "drifted back on in Checkmarx One and was re-asserted."
        ),
    )
    # Someone undid a restriction in force: a policy violation to follow up.
    # Its own notification (category "policy") is the one alert for it; the
    # enforcement "re-asserted" notification is raised only if the violation
    # could not be recorded, so the admin always hears of it exactly once.
    from app.services import violations

    recorded = False
    try:
        with session.begin_nested():
            violations.record_reenabled(
                session,
                action=action,
                limit=limit,
                found=found,
                title=_reconciled_title(action),
                body=_reconciled_body(action),
            )
        recorded = True
    except Exception:  # noqa: BLE001 - recording it must never undo the re-assert
        logger.warning("Could not record the policy violation for %s", action.id, exc_info=True)
    if not recorded:
        notifications.notify(
            session,
            category=notifications.CATEGORY_ENFORCEMENT,
            severity=Severity.WARNING,
            title=_reconciled_title(action),
            body=_reconciled_body(action),
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            dedupe_key=notifications.reconcile_key(action.id, period_key),
            enforcement_action_id=action.id,
        )
    session.commit()


@dataclass(frozen=True, slots=True)
class _Captured:
    """The tenant's state before a restriction, and how to apply the restriction.

    ``snapshot`` is what Restore needs. ``apply`` performs the tenant write and
    touches no database state; ``mirror`` updates the local copy of the project's
    AI settings once the write has succeeded. ``outcome`` is filled by ``apply``
    with what only the write can tell (whether Checkmarx accepted the Fusion
    lock) and is added to the snapshot once the write has succeeded.
    """

    snapshot: dict[str, Any]
    apply: Callable[[], None]
    mirror: Callable[[], None]
    outcome: dict[str, Any] = field(default_factory=dict)


def _capture(
    session: Session,
    client: CheckmarxClient,
    *,
    target: Target,
    resolver: RoleResolver,
    protected_roles: frozenset[str] = frozenset(),
) -> _Captured:
    """Read the state a restriction is about to change. Makes no change itself."""
    if target.kind == EnforcementKind.REMOVE_USER_ROLES:
        client_uuid = resolver.client_uuid
        current = iam.fetch_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid
        )
        current_names = {role.name for role in current}
        # The plan already left out anyone the last sync showed as protected;
        # this catches a role granted since then.
        why = protection_reason(
            session, target.target_id, protected_roles=protected_roles, live_roles=current_names
        )
        if why is not None:
            raise ProtectedTarget(
                f"{target.target_label}'s AI access is not removed automatically because "
                f"{why}. Raise it with them, or change the protected roles under "
                "Settings → Enforcement.",
                label=target.target_label,
            )
        to_remove = [role for role in current if role.name in iam.AI_ROLE_NAMES]

        def remove_roles() -> None:
            if to_remove:
                iam.remove_user_client_roles(
                    client, user_id=target.target_id, client_uuid=client_uuid, roles=to_remove
                )

        return _Captured(
            snapshot={
                "kind": str(target.kind),
                "client_uuid": client_uuid,
                "removed_roles": [role.as_payload() for role in to_remove],
                "roles_before": sorted(current_names),
            },
            apply=remove_roles,
            mirror=lambda: None,
        )

    project = session.get(CxProject, target.target_id)

    if target.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        state = platform.get_auto_triage(client, project_id=target.target_id)

        def disable_auto_triage() -> None:
            if state.enabled:
                platform.set_auto_triage(
                    client, project_id=target.target_id, enabled=False, config=state.config
                )

        def mirror_auto_triage() -> None:
            if project is not None:
                project.auto_triage_enabled = False
                project.auto_triage_config = state.config or None
                project.ai_state_checked_at = utcnow()

        return _Captured(
            snapshot={
                "kind": str(target.kind),
                # False here means it was already off, so restore leaves it off.
                "enabled_before": bool(state.enabled),
                "config_before": state.config or {},
            },
            apply=disable_auto_triage,
            mirror=mirror_auto_triage,
        )

    if target.kind == EnforcementKind.DISABLE_PR_REMEDIATION:
        if project is None or not project.repo_id:
            raise CheckmarxError(
                "No repository id is known for this project, so PR triage and "
                "remediation cannot be changed."
            )
        repo_id = project.repo_id
        read = platform.get_pr_remediation_severities(
            client, repo_id=repo_id, project_id=target.target_id
        )
        if read is not None:
            # The real, current severities (captured before disabling) - this is
            # what a Restore must reproduce, including MEDIUM/LOW if configured.
            severities_before = read
        elif project.pr_remediation_severities is not None:
            # The tenant cannot be read, but the last sync recorded the setting.
            # Used as it is, empty included: "already off" must restore to off.
            severities_before = list(project.pr_remediation_severities)
        else:
            # Nothing says what the setting is now, so nothing could put it back
            # afterwards. A restriction that cannot be undone faithfully is not
            # applied; Auto Triage on the same project is unaffected.
            raise NotRestricted(
                f"The PR triage and remediation setting for {target.target_label}'s "
                "repository cannot be read from Checkmarx One, so it was left unchanged: "
                "it could not have been restored to what it was. Auto Triage on the "
                "project is restricted as normal.",
                title=f"{target.target_label}: PR triage and remediation left unchanged",
            )

        def disable_pr_remediation() -> None:
            platform.set_pr_remediation_severities(
                client,
                repo_id=repo_id,
                project_id=target.target_id,
                severities=DISABLED_SEVERITIES,
            )

        def mirror_pr_remediation() -> None:
            project.pr_remediation_severities = []
            project.ai_state_checked_at = utcnow()

        return _Captured(
            snapshot={
                "kind": str(target.kind),
                "repo_id": repo_id,
                "severities_before": severities_before,
            },
            apply=disable_pr_remediation,
            mirror=mirror_pr_remediation,
        )

    if target.kind == EnforcementKind.DISABLE_FUSION:
        return _capture_fusion(session, client, target=target)

    if target.kind == EnforcementKind.DISABLE_REPO_FUSION:
        return _capture_repo_fusion(client, target=target, project=project)

    raise CheckmarxError(f"Unknown enforcement kind {target.kind!r}")


# Checkmarx answers a body it will not accept with one of these.
_LOCK_REJECTED_STATUSES = (400, 422)


def _off_value(value: Any) -> Any:
    """The "off" value in the type the setting was reported in ("false" for a string)."""
    return False if isinstance(value, bool) else "false"


def _fusion_entry(
    base: dict[str, Any], *, value: Any, allow_override: bool | None
) -> dict[str, Any]:
    entry = dict(base)
    entry["key"] = platform.FUSION_SETTING_KEY
    entry["value"] = value
    if allow_override is not None:
        entry["allowOverride"] = allow_override
    return entry


def _write_fusion_off(
    client: CheckmarxClient,
    *,
    project_id: str,
    base: dict[str, Any],
    value_type: Any,
    lock: bool,
    allow_override: bool | None,
    outcome: dict[str, Any],
    fallback: bool = True,
) -> None:
    """Turn the project's Fusion setting off, locked against per-scan override
    when ``lock`` is set and Checkmarx accepts it.

    Whether a lock (``allowOverride: false``) stops a scan started with its own
    settings from turning Fusion back on is not verified. A tenant that refuses
    the locked entry (400 or 422) gets the value written without the lock, and
    ``outcome["lock_applied"]`` records which happened. With ``fallback`` off a
    refused lock is an error instead: used where writing the entry without the
    lock could unlock a setting that is meant to stay locked.
    """
    off = _off_value(value_type)
    if lock:
        try:
            platform.set_project_setting(
                client,
                project_id=project_id,
                entry=_fusion_entry(base, value=off, allow_override=False),
            )
        except CheckmarxResponseError as exc:
            if exc.status_code not in _LOCK_REJECTED_STATUSES or not fallback:
                raise
            logger.info(
                "Checkmarx did not accept locking Fusion on project %s (%s); "
                "turning it off without the lock",
                project_id,
                exc.status_code,
            )
            outcome["lock_applied"] = False
            outcome["lock_rejected"] = f"Checkmarx One answered {exc.status_code}."
        else:
            outcome["lock_applied"] = True
            return
    platform.set_project_setting(
        client,
        project_id=project_id,
        entry=_fusion_entry(base, value=off, allow_override=allow_override),
    )


def _confirm_fusion_off(
    client: CheckmarxClient, *, project_id: str, label: str, outcome: dict[str, Any]
) -> None:
    """Read the Fusion setting back once after turning it off.

    A tenant can answer 2xx and not keep what it was sent. The value must read
    back as off, or the write is not counted (it is retried next cycle). A lock
    that does not read back is recorded, once, as not kept by this tenant, and
    from then on is not checked as drift: only a lock that was seen to hold can
    be "removed". When the read itself fails, the lock is kept as sent but
    marked unconfirmed (its removal is then re-applied without an alarm).
    """
    try:
        after = platform.get_fusion_setting(client, project_id=project_id)
    except CheckmarxAuthError:
        raise
    except CheckmarxError as exc:
        logger.info("Could not read Fusion back on project %s: %s", project_id, exc)
        if outcome.get("lock_applied"):
            outcome["lock_unconfirmed"] = True
        return
    if after is None:
        if outcome.get("lock_applied"):
            outcome["lock_unconfirmed"] = True
        return
    if after.enabled:
        # Not a definite rejection: part of it (the lock) may have landed, so the
        # outcome stays in doubt and Restore still considers it.
        raise CheckmarxError(
            f"Checkmarx One accepted turning Fusion off for {label}, but the setting still "
            "reads as on, so it is not counted as turned off."
        )
    if outcome.get("lock_applied") and after.allow_override is not False:
        outcome["lock_applied"] = False
        outcome["lock_not_kept"] = True
        outcome["lock_rejected"] = (
            "Checkmarx One accepted the lock but did not keep it; this tenant does not appear "
            "to support it."
        )


def _capture_fusion(session: Session, client: CheckmarxClient, *, target: Target) -> _Captured:
    label = target.target_label or target.target_id
    setting = platform.get_fusion_setting(client, project_id=target.target_id)
    if setting is None:
        raise NotRestricted(
            f"{label}'s scan settings in Checkmarx One have no Fusion setting "
            f"({platform.FUSION_SETTING_KEY}), so Fusion was left unchanged for this project. "
            "The project's other restrictions are applied as normal.",
            title=f"{label}: Fusion left unchanged",
        )
    if not isinstance(setting.value, str | bool):
        raise NotRestricted(
            f"{label}'s Fusion setting in Checkmarx One has no readable value, so it was left "
            "unchanged: it could not have been restored to what it was.",
            title=f"{label}: Fusion left unchanged",
        )
    lock = settings_store.fusion_lock_enabled(session)
    enabled_before = setting.enabled
    # The lock is only worth writing when the setting is not locked already.
    wants_lock = lock and setting.allow_override is not False
    write = enabled_before or wants_lock
    outcome: dict[str, Any] = {}

    def disable_fusion() -> None:
        if not write:
            return
        _write_fusion_off(
            client,
            project_id=target.target_id,
            base=setting.entry,
            value_type=setting.value,
            lock=wants_lock,
            allow_override=setting.allow_override,
            outcome=outcome,
        )
        _confirm_fusion_off(client, project_id=target.target_id, label=label, outcome=outcome)
        if outcome.get("lock_applied") is False and not enabled_before:
            # Only the lock was to be written, and it was refused (or not kept):
            # what is there now is what was there. This attempt took nothing;
            # what an earlier attempt or another limit took is merged back in
            # by the caller.
            outcome["fusion_write"] = False

    return _Captured(
        snapshot={
            "kind": str(target.kind),
            "setting_key": platform.FUSION_SETTING_KEY,
            # False here means it was already off, so restore leaves it off.
            "fusion_enabled_before": enabled_before,
            "value_before": setting.value,
            "allow_override_before": setting.allow_override,
            # "Project" when the project set it itself; "Tenant" (or another
            # level) when it was inherited. Writing it back sets it on the project.
            "origin_level_before": setting.origin_level,
            "entry_before": setting.entry,
            "lock_requested": wants_lock,
            # Whether anything is written at all (and so put back on restore).
            "fusion_write": write,
        },
        apply=disable_fusion,
        mirror=lambda: None,
        outcome=outcome,
    )


def _capture_repo_fusion(
    client: CheckmarxClient, *, target: Target, project: CxProject | None
) -> _Captured:
    label = target.target_label or target.target_id
    if project is None or not project.repo_id:
        raise CheckmarxError(
            "No repository id is known for this project, so its repository Fusion setting "
            "cannot be changed."
        )
    repo_id = project.repo_id
    read = platform.get_repo_fusion(client, repo_id=repo_id, project_id=target.target_id)
    if not read.readable:
        raise NotRestricted(
            f"The settings of {label}'s repository cannot be read from Checkmarx One, so its "
            "repository Fusion setting was left unchanged: it could not have been restored "
            "to what it was. Fusion in the project's scan settings is handled separately.",
            title=f"{label}: repository Fusion setting left unchanged",
        )
    if read.config is None:
        # Not verified that the repos-manager read carries it at all. Nothing
        # is invented: this half is skipped and the record says why.
        raise _NotApplicable(
            f"Checkmarx One's settings for {label}'s repository do not include a Fusion "
            f"setting ({platform.REPO_FUSION_FIELD}), so there was nothing to turn off there "
            "(not applicable). Fusion in the project's scan settings is handled separately.",
            title=f"{label}: no repository Fusion setting",
        )
    before = dict(read.config)
    enabled_before = read.enabled

    def disable_repo_fusion() -> None:
        if not enabled_before:
            return
        platform.set_repo_fusion(
            client,
            repo_id=repo_id,
            project_id=target.target_id,
            config={**before, "enabled": False},
        )
        # Read back once: that this write takes effect is not verified. A tenant
        # that answers 2xx and still reports it on does not support it; that is
        # recorded once (not as a failure, and never later as drift).
        after = platform.get_repo_fusion(client, repo_id=repo_id, project_id=target.target_id)
        if after.readable and after.config is not None and after.enabled:
            raise _NotKept(
                f"Checkmarx One accepted turning Fusion off in {label}'s repository settings "
                f"({platform.REPO_FUSION_FIELD}) but did not keep it, so this tenant does not "
                "appear to support changing it. Nothing was taken there. Fusion in the "
                "project's scan settings is handled separately.",
                title=f"{label}: repository Fusion setting not supported",
            )

    return _Captured(
        snapshot={
            "kind": str(target.kind),
            "repo_id": repo_id,
            "repo_fusion_enabled_before": enabled_before,
            "repo_fusion_before": before,
        },
        apply=disable_repo_fusion,
        mirror=lambda: None,
    )


def _combine(known: list[dict[str, Any] | None], fresh: dict[str, Any]) -> dict[str, Any]:
    """``fresh`` merged with each of ``known`` in turn (see ``_merge_snapshots``).

    Always a new dict without the bookkeeping marker: ``fresh`` is never changed.
    """
    snapshot = _settled(fresh) or {}
    for previous in known:
        snapshot = _merge_snapshots(previous, snapshot)
    return dict(snapshot)


# Bookkeeping about the Fusion lock that a later snapshot without its own word
# on it inherits (a sibling limit that found the lock already in place).
_FUSION_LOCK_KEYS = ("lock_applied", "lock_rejected", "lock_not_kept")


def _merge_snapshots(previous: dict[str, Any] | None, fresh: dict[str, Any]) -> dict[str, Any]:
    """Combine the snapshot of an unfinished earlier attempt with a fresh read.

    An earlier attempt may have changed the tenant and then died before saying
    so. The fresh read then shows the *restricted* state, and taking it at face
    value would record "nothing was removed" - Restore would succeed and give
    nothing back. So whatever the earlier snapshot says was there is kept, and the
    fresh read can only add to it. The bias is deliberate: when the two disagree,
    prefer the answer that returns more access on restore.
    """
    if not previous or previous.get("kind") != fresh.get("kind"):
        return fresh
    kind = fresh.get("kind")

    if kind == EnforcementKind.REMOVE_USER_ROLES:
        roles: dict[str, dict[str, Any]] = {}
        for source in (previous, fresh):
            for entry in source.get("removed_roles") or []:
                if isinstance(entry, dict) and entry.get("id") and entry.get("name"):
                    roles[entry["name"]] = entry
        merged = dict(fresh)
        merged["removed_roles"] = [roles[name] for name in sorted(roles)]
        merged["roles_before"] = sorted(
            set(previous.get("roles_before") or []) | set(fresh.get("roles_before") or [])
        )
        return merged

    if kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        if previous.get("enabled_before") and not fresh.get("enabled_before"):
            merged = dict(fresh)
            merged["enabled_before"] = True
            merged["config_before"] = previous.get("config_before") or {}
            return merged
        return fresh

    if kind == EnforcementKind.DISABLE_PR_REMEDIATION:
        if previous.get("severities_before") and not fresh.get("severities_before"):
            merged = dict(fresh)
            merged["severities_before"] = previous["severities_before"]
            return merged
        return fresh

    if kind == EnforcementKind.DISABLE_FUSION:
        merged = dict(fresh)
        if "lock_applied" not in fresh:
            # This read wrote no lock (it found one in place, or wrote nothing):
            # whatever the earlier one learned about the lock still holds, so
            # the lock is still verified after the earlier limit lets go.
            for key in _FUSION_LOCK_KEYS:
                if key in previous:
                    merged[key] = previous[key]
        if previous.get("fusion_write"):
            # The earlier read came before any write of this chain: it is the
            # true "before" (value, lock and the level it was set at).
            for key in (
                "fusion_enabled_before",
                "value_before",
                "allow_override_before",
                "origin_level_before",
                "entry_before",
            ):
                if key in previous:
                    merged[key] = previous[key]
            merged["fusion_write"] = True
            merged["fusion_enabled_before"] = bool(
                previous.get("fusion_enabled_before") or fresh.get("fusion_enabled_before")
            )
            if merged["fusion_enabled_before"] and not platform.setting_is_true(
                merged.get("value_before")
            ):
                merged["value_before"] = fresh.get("value_before")
        return merged

    if kind == EnforcementKind.DISABLE_REPO_FUSION:
        if previous.get("repo_fusion_enabled_before") and not fresh.get(
            "repo_fusion_enabled_before"
        ):
            merged = dict(fresh)
            merged["repo_fusion_enabled_before"] = True
            merged["repo_fusion_before"] = previous.get("repo_fusion_before") or {}
            return merged
        return fresh

    return fresh


# ---------------------------------------------------------------- reconciliation


AUDIT_UNVERIFIED_REAPPLY = "enforcement.reapplied_unverified"
AUDIT_TARGET_ACTION = "enforcement_action"


def _unverified_reapply_audited(session: Session, action: EnforcementAction) -> bool:
    return (
        session.scalar(
            select(AuditLogEntry.id)
            .where(
                AuditLogEntry.action == AUDIT_UNVERIFIED_REAPPLY,
                AuditLogEntry.target_type == AUDIT_TARGET_ACTION,
                AuditLogEntry.target_id == str(action.id),
            )
            .limit(1)
        )
        is not None
    )


# What _reconcile found.
RECONCILE_HELD = "held"  # read back, still in force
RECONCILE_REASSERTED = "reasserted"  # read back, had drifted, re-applied
RECONCILE_UNVERIFIED = "unverified"  # could not be read back, re-applied anyway


def _reconcile(
    session: Session,
    client: CheckmarxClient,
    *,
    action: EnforcementAction,
    target: Target,
    resolver: RoleResolver,
    found: dict[str, Any] | None = None,
) -> str:
    """Verify an already-applied restriction is still in force, re-asserting it if
    it drifted back on in Checkmarx One.

    ``found`` is filled with what was read back when it had drifted, for the
    policy violation record.

    Only a state actually read back and found switched on again is drift
    (``RECONCILE_REASSERTED``). A state that cannot be read is not evidence of
    anything (``RECONCILE_UNVERIFIED``): the restriction is written again,
    which changes nothing if it still holds, and the caller raises no alarm.
    The ``undo_snapshot`` is left untouched here so a future restore still puts
    back the exact pre-restriction state.
    """
    snapshot = action.undo_snapshot or {}
    kind = action.kind
    if found is None:
        found = {}

    if kind == EnforcementKind.REMOVE_USER_ROLES:
        client_uuid = snapshot.get("client_uuid") or resolver.client_uuid
        current = iam.fetch_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid
        )
        to_remove = [role for role in current if role.name in iam.AI_ROLE_NAMES]
        if not to_remove:
            return RECONCILE_HELD
        found.update({"found": {"roles": sorted(role.name for role in to_remove)}})
        iam.remove_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid, roles=to_remove
        )
        return RECONCILE_REASSERTED

    project = session.get(CxProject, target.target_id)

    if kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        # A read that fails raises (the caller reports "could not be verified");
        # a read that succeeds but has no Auto Triage entry, or one that is off,
        # is not drift. Only an entry read back as enabled is.
        state = platform.get_auto_triage(client, project_id=target.target_id)
        if not state.enabled:
            return RECONCILE_HELD
        found.update({"found": {"enabled": True}})
        config = snapshot.get("config_before")
        platform.set_auto_triage(
            client,
            project_id=target.target_id,
            enabled=False,
            config=config if isinstance(config, dict) and config else None,
        )
        if project is not None:
            project.auto_triage_enabled = False
            project.auto_triage_config = config or None
            project.ai_state_checked_at = utcnow()
        return RECONCILE_REASSERTED

    if kind == EnforcementKind.DISABLE_PR_REMEDIATION:
        repo_id = snapshot.get("repo_id") or (project.repo_id if project else None)
        if not repo_id:
            return RECONCILE_HELD
        current = platform.get_pr_remediation_severities(
            client, repo_id=repo_id, project_id=target.target_id
        )
        if current is not None and not current:
            return RECONCILE_HELD  # read back as disabled
        if current is not None:
            found.update({"found": {"remediationSeverities": current}})
        # Either severities were read back re-enabled (drift), or the setting
        # could not be read at all. Both re-apply the restriction; only the
        # first is drift.
        platform.set_pr_remediation_severities(
            client,
            repo_id=repo_id,
            project_id=target.target_id,
            severities=DISABLED_SEVERITIES,
        )
        if project is not None:
            project.pr_remediation_severities = []
            project.ai_state_checked_at = utcnow()
        return RECONCILE_UNVERIFIED if current is None else RECONCILE_REASSERTED

    if kind == EnforcementKind.DISABLE_FUSION:
        lock = bool(snapshot.get("lock_applied"))
        try:
            setting = platform.get_fusion_setting(client, project_id=target.target_id)
        except CheckmarxError as exc:
            if isinstance(exc, CheckmarxAuthError):
                raise
            # Unreadable is not evidence of drift: written again from the entry
            # read before the restriction, which changes nothing if it holds.
            base = snapshot.get("entry_before")
            if not isinstance(base, dict) or not base:
                raise
            # A setting that is locked (by this restriction, or already before
            # it) is written locked, with no unlocked fallback: falling back to
            # the value as it was before could unlock it.
            locked = lock or snapshot.get("allow_override_before") is False
            _write_fusion_off(
                client,
                project_id=target.target_id,
                base=base,
                value_type=snapshot.get("value_before"),
                lock=locked,
                allow_override=snapshot.get("allow_override_before"),
                outcome={},
                fallback=not locked,
            )
            return RECONCILE_UNVERIFIED
        if setting is None:
            return RECONCILE_HELD
        unlocked = lock and setting.allow_override is True
        if not setting.enabled and not unlocked:
            return RECONCILE_HELD
        if not setting.enabled and snapshot.get("lock_unconfirmed"):
            # The lock was never seen to hold, so its absence is not evidence
            # that anyone removed it: it is written again, without an alarm.
            _write_fusion_off(
                client,
                project_id=target.target_id,
                base=setting.entry,
                value_type=setting.value,
                lock=True,
                allow_override=setting.allow_override,
                outcome={},
            )
            return RECONCILE_UNVERIFIED
        found.update(
            {
                "found": {"value": setting.value, "allowOverride": setting.allow_override},
                "origin_level": setting.origin_level,
            }
        )
        _write_fusion_off(
            client,
            project_id=target.target_id,
            base=setting.entry,
            value_type=setting.value,
            lock=lock,
            allow_override=setting.allow_override,
            outcome={},
        )
        return RECONCILE_REASSERTED

    if kind == EnforcementKind.DISABLE_REPO_FUSION:
        repo_id = snapshot.get("repo_id") or (project.repo_id if project else None)
        if not repo_id:
            return RECONCILE_HELD
        read = platform.get_repo_fusion(client, repo_id=repo_id, project_id=target.target_id)
        if read.readable and (read.config is None or not read.enabled):
            return RECONCILE_HELD
        base = read.config if read.config is not None else snapshot.get("repo_fusion_before")
        if not isinstance(base, dict):
            return RECONCILE_HELD
        if read.readable:
            found.update({"found": dict(base)})
        platform.set_repo_fusion(
            client,
            repo_id=repo_id,
            project_id=target.target_id,
            config={**base, "enabled": False},
        )
        return RECONCILE_REASSERTED if read.readable else RECONCILE_UNVERIFIED

    return RECONCILE_HELD


def _reconciled_title(action: EnforcementAction) -> str:
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        return f"User {action.target_label}: AI roles re-removed"
    if action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        return f"Project {action.target_label}: Auto Triage re-disabled"
    if action.kind == EnforcementKind.DISABLE_FUSION:
        return f"Project {action.target_label}: Fusion turned off again"
    if action.kind == EnforcementKind.DISABLE_REPO_FUSION:
        return f"Project {action.target_label}: repository Fusion setting turned off again"
    return f"Project {action.target_label}: PR triage and remediation re-disabled"


def _reconciled_body(action: EnforcementAction) -> str:
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        return (
            "The AI roles were found back on this user after they had been removed, "
            "so they were removed again."
        )
    if action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        return (
            "Auto Triage was found enabled again after it had been disabled, so it "
            "was turned back off with its previous configuration preserved."
        )
    if action.kind == EnforcementKind.DISABLE_FUSION:
        return (
            "Fusion was found switched on again in the project's scan settings (or its lock "
            "against per-scan override was removed) after it had been turned off, so it was "
            "turned off again."
        )
    if action.kind == EnforcementKind.DISABLE_REPO_FUSION:
        return (
            "Fusion was found enabled again in the repository's settings after it had been "
            "turned off, so it was turned off again."
        )
    return (
        "PR triage and remediation severities were re-asserted to none, keeping "
        "the repository setting disabled."
    )


# ------------------------------------------------------------------- restoring

# An action that never reached APPLIED may still have changed the tenant: the
# process can stop, or a request can time out, after Checkmarx made the change
# and before the outcome was recorded. Its undo snapshot was committed before the
# write and is marked OUTCOME_UNKNOWN until the result is known, so such a row
# can still be undone, and every path that gives access back considers it. A
# write Checkmarx refused outright is *not* in doubt and is never treated as a
# restriction.
_UNSETTLED = (EnforcementStatus.PENDING, EnforcementStatus.FAILED)
RESTORABLE_STATUSES = (EnforcementStatus.APPLIED, *_UNSETTLED)


def _outcome_unknown(snapshot: dict[str, Any] | None) -> bool:
    return bool(snapshot and snapshot.get(OUTCOME_UNKNOWN))


def _took_something(snapshot: dict[str, Any] | None) -> bool:
    """Does this snapshot record anything a restore would give back?"""
    if not snapshot:
        return False
    return bool(
        snapshot.get("removed_roles")
        or snapshot.get("enabled_before")
        or snapshot.get("severities_before")
        or snapshot.get("fusion_write")
        or snapshot.get("repo_fusion_enabled_before")
    )


def _settled(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    """A snapshot without its bookkeeping marker."""
    if not snapshot:
        return None
    return {key: value for key, value in snapshot.items() if key != OUTCOME_UNKNOWN}


def _siblings_in_force(session: Session, action: EnforcementAction) -> list[EnforcementAction]:
    """Other actions, from other limits, restricting the same thing on the same target.

    A user can be over a personal limit and a group limit at once; a project can
    sit under a project limit and an application limit. Each limit has its own
    action row, but the tenant holds a single state, and there is one true
    "before" to give back when the last of them lets go.
    """
    rows = session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.target_type == action.target_type,
            EnforcementAction.target_id == action.target_id,
            EnforcementAction.kind == action.kind,
            EnforcementAction.id != action.id,
            EnforcementAction.status.in_(RESTORABLE_STATUSES),
        )
        # Another session may have changed them since this one last looked.
        .execution_options(populate_existing=True)
    )
    return [row for row in rows if may_be_in_force(row)]


def _roles_outside_the_restriction(action: EnforcementAction) -> list[dict[str, str]]:
    """Roles this action's snapshot says were removed that a restriction no longer covers."""
    removed = (action.undo_snapshot or {}).get("removed_roles") or []
    return [
        role
        for role in removed
        if isinstance(role, dict)
        and isinstance(role.get("name"), str)
        and role["name"] not in iam.AI_ROLE_NAMES
    ]


def return_roles_outside_the_restriction(
    session: Session,
    client: CheckmarxClient,
    *,
    actor: AuditActor,
    resolver: RoleResolver | None = None,
) -> int:
    """Give back roles an earlier version removed that a restriction no longer covers.

    A restriction used to take the scan-viewing role as well as the AI roles.
    Someone restricted back then is still without it, and would stay so until
    every restriction on them is lifted. This returns it, once per user, and
    takes it out of every undo snapshot that holds it, so it is not this tool's
    business again: an admin who later removes the role in Checkmarx One on
    purpose is not undone, by a later cycle or by a later Restore.

    It runs as its own pass over every restriction that is or may be in force,
    whatever the state of the limit behind it - paused, held from an earlier
    period, not currently breached - because none of those is a reason to keep
    withholding a role the restriction should never have taken. The AI roles
    stay removed. Returns how many users were given something back.
    """
    by_user: dict[str, list[int]] = {}
    for action in session.scalars(
        select(EnforcementAction)
        .where(
            EnforcementAction.kind == EnforcementKind.REMOVE_USER_ROLES,
            EnforcementAction.status.in_(RESTORABLE_STATUSES),
        )
        .order_by(EnforcementAction.id)
    ):
        if may_be_in_force(action) and _roles_outside_the_restriction(action):
            by_user.setdefault(action.target_id, []).append(action.id)
    if not by_user:
        return 0

    resolver = resolver or RoleResolver(client)
    returned = 0
    for user_id, action_ids in by_user.items():
        session.commit()  # never wait on a target lock with anything open in the database
        with _target_lock(TARGET_USER, user_id):
            actions = [
                action
                for action_id in action_ids
                if (action := session.get(EnforcementAction, action_id, populate_existing=True))
                is not None
                and may_be_in_force(action)
                and _roles_outside_the_restriction(action)
            ]
            if not actions:
                continue
            label = actions[0].target_label or user_id
            wanted: dict[str, dict[str, str]] = {}
            for action in actions:
                for role in _roles_outside_the_restriction(action):
                    wanted.setdefault(role["name"], role)
            client_uuid = (actions[0].undo_snapshot or {}).get("client_uuid")
            session.commit()  # nothing held open while we wait on Checkmarx
            try:
                # The id in an old snapshot may be stale; the role's name is what
                # identifies it. A role that no longer exists cannot be returned.
                known = resolver.all_roles()
                roles = [known[name] for name in sorted(wanted) if name in known]
                iam.add_user_client_roles(
                    client,
                    user_id=user_id,
                    client_uuid=client_uuid or resolver.client_uuid,
                    roles=roles,
                )
            except CheckmarxError as exc:
                logger.warning(
                    "Could not give %s back to %s this cycle: %s",
                    ", ".join(sorted(wanted)),
                    label,
                    exc,
                )
                _record_refusals(session, actor)
                session.commit()
                continue
            for action in actions:
                snapshot = dict(action.undo_snapshot or {})
                snapshot["removed_roles"] = [
                    role
                    for role in snapshot.get("removed_roles") or []
                    if not (isinstance(role, dict) and role.get("name") in wanted)
                ]
                action.undo_snapshot = snapshot
            names = [role.name for role in roles]
            gone = sorted(set(wanted) - set(names))
            record_audit(
                session,
                action="enforcement.narrowed",
                actor=actor,
                target_type=TARGET_USER,
                target_id=user_id,
                target_label=label,
                after={"roles_returned": names, "roles_no_longer_in_tenant": gone},
                detail=(
                    f"A restriction now removes only the AI roles, so {label} was given back "
                    f"{', '.join(names) or 'nothing (the role no longer exists)'}. "
                    "The AI roles stay removed."
                ),
            )
            session.commit()
            if names:
                returned += 1
    return returned


def may_be_in_force(action: EnforcementAction) -> bool:
    """True if the tenant is, or may be, restricted because of this action."""
    if action.status == EnforcementStatus.APPLIED:
        return True
    return (
        action.status in _UNSETTLED
        and _outcome_unknown(action.undo_snapshot)
        and _took_something(action.undo_snapshot)
    )


def restore_action(
    session: Session,
    client: CheckmarxClient,
    *,
    action: EnforcementAction,
    actor: AuditActor,
    reason: str = ADMIN_REASON,
    resolver: RoleResolver | None = None,
) -> bool:
    """Undo one enforcement action from its snapshot. Returns False if not needed.

    Runs under the target's lock and commits its outcome before releasing it, so
    the cycle can never observe "still applied" for an action whose roles have
    already been given back (and re-remove them as drift).
    """
    # Whatever the caller has written so far (its own audit row included) is made
    # durable before waiting on the lock: see the lock order note in
    # apply_enforcement. Callers therefore finish their own unit of work first.
    session.commit()
    with _target_lock(action.target_type, action.target_id):
        return _restore_action_locked(
            session, client, action=action, actor=actor, reason=reason, resolver=resolver
        )


def _restore_action_locked(
    session: Session,
    client: CheckmarxClient,
    *,
    action: EnforcementAction,
    actor: AuditActor,
    reason: str,
    resolver: RoleResolver | None,
) -> bool:
    # The cycle may have committed a change to this row while we waited.
    session.refresh(action)
    if not may_be_in_force(action):
        return False

    was_applied = action.status == EnforcementStatus.APPLIED
    snapshot = _settled(action.undo_snapshot) or {}
    resolver = resolver or RoleResolver(client)

    siblings = _siblings_in_force(session, action)
    # An admin's Restore, or the target itself becoming exempt or protected,
    # means nobody may restrict it: every limit holding it lets go together.
    # Anything else is about this one limit, and the others keep their hold.
    release_target = reason == ADMIN_REASON or target_released(session, action) is not None
    if siblings and not release_target:
        # Another limit still restricts this target, so nothing is given back in
        # Checkmarx yet. What this action knows about the original state is
        # handed to the ones that remain, so the last to be lifted returns all
        # of it - not just whatever it happened to see when it was applied.
        for sibling in siblings:
            merged = _merge_snapshots(snapshot, _settled(sibling.undo_snapshot) or snapshot)
            if _outcome_unknown(sibling.undo_snapshot):
                merged[OUTCOME_UNKNOWN] = True
            sibling.undo_snapshot = merged
        action.status = EnforcementStatus.REVERSED
        action.reversed_at = utcnow()
        action.reversed_by_id = actor.actor_id
        action.reversal_reason = reason
        action.undo_snapshot = snapshot
        action.error = None
        session.flush()
        record_audit(
            session,
            action="enforcement.reversed",
            actor=actor,
            target_type=action.target_type,
            target_id=action.target_id,
            target_label=action.target_label,
            before={"kind": action.kind, "restricted": True},
            after={"kind": action.kind, "restricted": True, "still_restricted_by": len(siblings)},
            detail=(
                f"This limit no longer restricts {action.target_label} ({reason}), but "
                f"{len(siblings)} other limit(s) still do, so nothing was changed in "
                "Checkmarx One."
            ),
        )
        session.commit()
        return True
    if siblings:
        # Given back now, whichever limits took it: all of them are lifted
        # together, from their combined snapshot.
        for sibling in siblings:
            snapshot = _merge_snapshots(_settled(sibling.undo_snapshot), snapshot)

    # Record the intent before touching the tenant. If the access is given back
    # and the process stops before saying so, the row still reads "restricted";
    # this mark is what stops the next cycle from taking the access away again
    # as drift, and tells it to finish the restore instead.
    action.reversal_reason = reason
    action.reversed_by_id = actor.actor_id
    session.commit()
    try:
        _undo(session, client, action=action, snapshot=snapshot, resolver=resolver)
    except CheckmarxError as exc:
        message = str(exc)[:2000]
        first_report = action.error != message
        action.error = message
        session.flush()
        notifications.notify(
            session,
            category=notifications.CATEGORY_RESTORATION,
            severity=Severity.ERROR,
            title=f"Could not restore {action.target_label}",
            body=(
                f"{exc}\n\n{_permission_hint(exc)}It will be tried again on the next cycle. "
                "If it keeps failing, "
                "restore it directly in Checkmarx One; the snapshot of the previous state "
                "is on the audit entry."
            ),
            entity_type=action.entity_type,
            entity_id=action.entity_id,
            entity_label=action.entity_label,
            # One notification a day per action, however many cycles retry it.
            dedupe_key=notifications.restore_failed_key(action.id, utcnow().strftime("%Y-%m-%d")),
            enforcement_action_id=action.id,
        )
        if first_report:
            # Audited when the failure is new or changes, not on every retry.
            record_audit(
                session,
                action="enforcement.restore_failed",
                actor=actor,
                target_type=action.target_type,
                target_id=action.target_id,
                target_label=action.target_label,
                before=snapshot,
                detail=str(exc),
            )
        _record_refusals(session, actor)
        session.commit()
        raise

    for lifted in (action, *siblings):
        lifted.status = EnforcementStatus.REVERSED
        lifted.reversed_at = utcnow()
        lifted.reversed_by_id = actor.actor_id
        lifted.reversal_reason = reason
        lifted.undo_snapshot = snapshot
        lifted.error = None
    session.flush()

    record_audit(
        session,
        action="enforcement.reversed",
        actor=actor,
        target_type=action.target_type,
        target_id=action.target_id,
        target_label=action.target_label,
        before={"kind": action.kind, "restricted": True},
        after=snapshot,
        detail=_reversal_detail(reason, was_applied=was_applied, also_lifted=len(siblings)),
    )
    notifications.notify(
        session,
        category=notifications.CATEGORY_RESTORATION,
        severity=Severity.INFO,
        title=_restoration_title(action),
        body=_restoration_body(action, snapshot, reason),
        entity_type=action.entity_type,
        entity_id=action.entity_id,
        entity_label=action.entity_label,
        dedupe_key=notifications.restoration_key(action.id),
        enforcement_action_id=action.id,
    )
    # Committed here, inside the lock, and before any further network call so the
    # audit chain's lock is never held while talking to Checkmarx.
    session.commit()
    return True


def _reversal_detail(reason: str, *, was_applied: bool, also_lifted: int) -> str:
    if not was_applied:
        return (
            "A restriction whose outcome was never confirmed was undone to be safe "
            f"({reason}): its previous state was put back."
        )
    detail = f"Access restored ({reason})."
    if also_lifted:
        detail += f" {also_lifted} other limit(s) restricting it were lifted too."
    return detail


def _undo(
    session: Session,
    client: CheckmarxClient,
    *,
    action: EnforcementAction,
    snapshot: dict[str, Any],
    resolver: RoleResolver,
) -> None:
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        removed = snapshot.get("removed_roles") or []
        roles = [
            iam.RoleRef(id=entry["id"], name=entry["name"])
            for entry in removed
            if isinstance(entry, dict) and entry.get("id") and entry.get("name")
        ]
        if not roles:
            # Nothing was removed, so nothing to give back.
            return
        client_uuid = snapshot.get("client_uuid") or resolver.client_uuid
        iam.add_user_client_roles(
            client, user_id=action.target_id, client_uuid=client_uuid, roles=roles
        )
        return

    if action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        if not snapshot.get("enabled_before"):
            return
        config = snapshot.get("config_before")
        platform.set_auto_triage(
            client,
            project_id=action.target_id,
            enabled=True,
            config=config if isinstance(config, dict) and config else None,
        )
        project = session.get(CxProject, action.target_id)
        if project is not None:
            project.auto_triage_enabled = True
            project.ai_state_checked_at = utcnow()
        return

    if action.kind == EnforcementKind.DISABLE_PR_REMEDIATION:
        severities = snapshot.get("severities_before")
        if not isinstance(severities, list):
            severities = list(platform.DEFAULT_PR_SEVERITIES)
        repo_id = snapshot.get("repo_id")
        project = session.get(CxProject, action.target_id)
        if not repo_id and project is not None:
            repo_id = project.repo_id
        if not repo_id:
            raise CheckmarxError(
                "The repository id recorded for this action is missing, so PR triage and "
                "remediation cannot be restored automatically."
            )
        platform.set_pr_remediation_severities(
            client, repo_id=repo_id, project_id=action.target_id, severities=severities
        )
        if project is not None:
            project.pr_remediation_severities = severities
            project.ai_state_checked_at = utcnow()
        return

    if action.kind == EnforcementKind.DISABLE_FUSION:
        if not snapshot.get("fusion_write"):
            return
        value = snapshot.get("value_before")
        if not isinstance(value, str | bool):
            raise CheckmarxError(
                "The Fusion setting recorded for this action is missing, so Fusion cannot be "
                "restored automatically."
            )
        base = snapshot.get("entry_before")
        platform.set_project_setting(
            client,
            project_id=action.target_id,
            entry=_fusion_entry(
                base if isinstance(base, dict) else {},
                value=value,
                allow_override=snapshot.get("allow_override_before"),
            ),
        )
        return

    if action.kind == EnforcementKind.DISABLE_REPO_FUSION:
        if not snapshot.get("repo_fusion_enabled_before"):
            return
        before = snapshot.get("repo_fusion_before")
        repo_id = snapshot.get("repo_id")
        if not repo_id:
            project = session.get(CxProject, action.target_id)
            repo_id = project.repo_id if project is not None else None
        if not isinstance(before, dict) or not repo_id:
            raise CheckmarxError(
                "The repository Fusion setting recorded for this action is missing, so it "
                "cannot be restored automatically."
            )
        platform.set_repo_fusion(
            client, repo_id=repo_id, project_id=action.target_id, config=before
        )
        return

    raise CheckmarxError(f"Unknown enforcement kind {action.kind!r}")


def restore_for_limit(
    session: Session,
    client: CheckmarxClient,
    *,
    limit_id: int,
    period_key: str | None = None,
    actor: AuditActor,
    reason: str,
) -> int:
    """Restore every applied action for a limit, optionally for one period only."""
    query = select(EnforcementAction).where(
        EnforcementAction.limit_id == limit_id,
        EnforcementAction.status.in_(RESTORABLE_STATUSES),
    )
    if period_key is not None:
        query = query.where(EnforcementAction.period_key == period_key)

    resolver = RoleResolver(client)
    restored = 0
    first_error: CheckmarxError | None = None
    for action in [row for row in session.scalars(query) if may_be_in_force(row)]:
        # Attempt every action before reporting a failure: one target Checkmarx
        # rejects (a deleted user, say) must not leave the others restricted.
        try:
            if restore_action(
                session, client, action=action, actor=actor, reason=reason, resolver=resolver
            ):
                restored += 1
        except CheckmarxError as exc:
            first_error = first_error or exc
    if first_error is not None:
        raise first_error
    return restored


def deselected(action: EnforcementAction, limit: CreditLimit | None) -> bool:
    """True when this project action's limit no longer turns its kind off."""
    if limit is None or action.target_type != TARGET_PROJECT:
        return False
    wanted = PROJECT_ACTION_OF_KIND.get(str(action.kind))
    return wanted is not None and wanted not in effective_project_actions(limit)


def restore_deselected(
    session: Session,
    client: CheckmarxClient,
    *,
    limit: CreditLimit,
    actor: AuditActor,
) -> int:
    """Put back what this limit turned off and no longer turns off.

    An admin who takes Fusion (say) off a limit's list expects Fusion to come
    back now, not at the end of the period. Other limits restricting the same
    project keep their hold, exactly as with any other automatic lift.
    """
    rows = [
        action
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id == limit.id,
                EnforcementAction.status.in_(RESTORABLE_STATUSES),
            )
        )
        if may_be_in_force(action) and deselected(action, limit)
    ]
    restored = 0
    first_error: CheckmarxError | None = None
    resolver = RoleResolver(client)
    for action in rows:
        try:
            if restore_action(
                session,
                client,
                action=action,
                actor=actor,
                reason=DESELECTED_REASON,
                resolver=resolver,
            ):
                restored += 1
        except CheckmarxError as exc:
            first_error = first_error or exc
    if first_error is not None:
        raise first_error
    return restored


def active_actions_for(
    session: Session, *, entity_type: str, entity_id: str
) -> list[EnforcementAction]:
    """Actions restricting this entity, including any whose outcome is in doubt."""
    return [
        action
        for action in session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.entity_type == entity_type,
                EnforcementAction.entity_id == entity_id,
                EnforcementAction.status.in_(RESTORABLE_STATUSES),
            )
        )
        if may_be_in_force(action)
    ]


# --------------------------------------------------------------- message copy


def _enforcement_title(target: Target) -> str:
    if target.kind == EnforcementKind.REMOVE_USER_ROLES:
        return f"User {target.target_label} restricted"
    if target.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        return f"Project {target.target_label}: Auto Triage disabled"
    if target.kind == EnforcementKind.DISABLE_FUSION:
        return f"Project {target.target_label}: Fusion turned off"
    if target.kind == EnforcementKind.DISABLE_REPO_FUSION:
        return f"Project {target.target_label}: repository Fusion setting turned off"
    return f"Project {target.target_label}: PR triage and remediation disabled"


def _fusion_lines(snapshot: dict[str, Any]) -> list[str]:
    """What turning Fusion off did to the project's scan setting, plainly."""
    lines: list[str] = []
    if snapshot.get("fusion_enabled_before"):
        lines.append(f"Fusion was turned off for this project ({platform.FUSION_SETTING_KEY}).")
        origin = snapshot.get("origin_level_before")
        if origin and str(origin).lower() != "project":
            lines.append(
                f"It was inherited from the {str(origin).lower()} level; it is now set on the "
                "project itself."
            )
    else:
        lines.append("Fusion was already off for this project.")
    if snapshot.get("lock_applied") is True:
        lines.append(
            "Its setting was also locked against per-scan override (allowOverride off). "
            "Whether Checkmarx One honours that lock for a scan started with its own settings "
            "is not verified; CreditGuard checks the setting every cycle and records any scan "
            "that ran Fusion anyway as a policy violation."
        )
    elif snapshot.get("lock_not_kept"):
        lines.append(
            "Checkmarx One accepted locking the setting against per-scan override but did not "
            "keep it (read back straight after), so this tenant does not appear to support the "
            "lock and a scan started with its own settings can still turn Fusion on for that "
            "one scan. The lock is not checked again; Fusion being off still is. Any scan that "
            "runs Fusion is recorded as a policy violation."
        )
    elif snapshot.get("lock_applied") is False:
        lines.append(
            "Checkmarx One did not accept locking the setting against per-scan override "
            f"({snapshot.get('lock_rejected') or 'refused'}), so a scan started with its own "
            "settings can still turn Fusion on for that one scan. Any scan that does is "
            "recorded as a policy violation."
        )
    elif snapshot.get("allow_override_before") is False:
        lines.append("Its setting was already locked against per-scan override.")
    else:
        lines.append(
            "Its setting was not locked against per-scan override (switched off in Settings → "
            "Enforcement), so a scan started with its own settings can still turn Fusion on "
            "for that one scan. Any scan that does is recorded as a policy violation."
        )
    return lines


def _enforcement_body(
    limit: CreditLimit,
    target: Target,
    period_key: str,
    snapshot: dict[str, Any],
    *,
    mix: usage_mix.UsageMix | None = None,
) -> str:
    entity = limit.entity_label or limit.entity_id
    lines = [
        f"The {limit.entity_type} limit on {entity} was reached in {period_key} "
        f"({limit.credit_limit} credits).",
    ]
    if mix is not None:
        lines.append(
            usage_mix.describe(mix, period_key=period_key, entity_type=str(limit.entity_type))
        )
    if target.kind == EnforcementKind.REMOVE_USER_ROLES:
        removed = [entry.get("name") for entry in snapshot.get("removed_roles") or []]
        lines.append(
            f"The AI roles were removed: {', '.join(name for name in removed if name)}."
            if removed
            else "The user did not hold the AI roles, so nothing was removed."
        )
    elif target.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        lines.append(
            "Auto Triage was already off for this project."
            if not snapshot.get("enabled_before")
            else "Auto Triage was turned off for this project."
        )
    elif target.kind == EnforcementKind.DISABLE_FUSION:
        lines.extend(_fusion_lines(snapshot))
    elif target.kind == EnforcementKind.DISABLE_REPO_FUSION:
        before = snapshot.get("repo_fusion_before") or {}
        model = before.get("llmModel") if isinstance(before, dict) else None
        lines.append(
            "Fusion was turned off in the repository's settings"
            + (f" (it was on, model {model})." if model else ".")
            if snapshot.get("repo_fusion_enabled_before")
            else "Fusion was already off in the repository's settings."
        )
    else:
        before = snapshot.get("severities_before") or []
        lines.append(f"PR remediation severities cleared (were: {', '.join(before) or 'none'}).")
    lines.append(
        usage_mix.does_not_stop(target.kind, mix, actions=effective_project_actions(limit))
    )
    lines.append("Use Restore access to reverse this.")
    return "\n".join(lines)


def _restoration_title(action: EnforcementAction) -> str:
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        return f"User {action.target_label} restored"
    if action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        return f"Project {action.target_label}: Auto Triage re-enabled"
    if action.kind == EnforcementKind.DISABLE_FUSION:
        return f"Project {action.target_label}: Fusion setting restored"
    if action.kind == EnforcementKind.DISABLE_REPO_FUSION:
        return f"Project {action.target_label}: repository Fusion setting restored"
    return f"Project {action.target_label}: PR triage and remediation re-enabled"


def _restoration_body(action: EnforcementAction, snapshot: dict[str, Any], reason: str) -> str:
    explanation = {
        "admin": "An administrator restored access from the Notification Center.",
        "period_rollover": "A new budget period started, so the restriction was lifted.",
        "limit_removed": "The limit that caused this restriction was removed or disabled.",
        "credit_increased": (
            "The credit limit was increased or consumption is within budget, "
            "so the restriction was lifted."
        ),
        EXEMPTED_REASON: "An exemption was granted for this entity, so the restriction was lifted.",
        DESELECTED_REASON: (
            "The limit no longer turns this off (its choice of what to turn off was changed), "
            "so it was put back."
        ),
    }.get(reason, reason)
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        restored = [entry.get("name") for entry in snapshot.get("removed_roles") or []]
        detail = (
            f"Re-added roles: {', '.join(name for name in restored if name)}"
            if restored
            else "No roles needed re-adding."
        )
    elif action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        detail = (
            "Auto Triage was restored to enabled with its previous configuration."
            if snapshot.get("enabled_before")
            else "Auto Triage was off before the restriction, so it was left off."
        )
    elif action.kind == EnforcementKind.DISABLE_FUSION:
        detail = _fusion_restore_detail(snapshot)
    elif action.kind == EnforcementKind.DISABLE_REPO_FUSION:
        detail = (
            "The repository's Fusion setting was put back to what it was."
            if snapshot.get("repo_fusion_enabled_before")
            else "Fusion was off in the repository's settings before the restriction, so it "
            "was left off."
        )
    else:
        severities = snapshot.get("severities_before") or []
        detail = f"PR remediation severities restored to: {', '.join(severities) or 'none'}."
    return f"{explanation}\n{detail}"


def _fusion_restore_detail(snapshot: dict[str, Any]) -> str:
    if not snapshot.get("fusion_write"):
        return "Fusion was off (and locked) before the restriction, so nothing was changed."
    value = snapshot.get("value_before")
    state = "on" if platform.setting_is_true(value) else "off"
    lock = snapshot.get("allow_override_before")
    detail = f"Fusion was put back {state}"
    if lock is not None:
        detail += (
            ", with per-scan override allowed" if lock else ", locked against per-scan override"
        )
    detail += ", as it was before the restriction."
    origin = snapshot.get("origin_level_before")
    if origin and str(origin).lower() != "project":
        detail += (
            f" Before the restriction it was inherited from the {str(origin).lower()} level. "
            "Checkmarx One offers no known way to remove a project's own value, so it is now "
            "set on the project with the same value, and a later change at the "
            f"{str(origin).lower()} level no longer reaches this project."
        )
    return detail
