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
from collections.abc import Callable
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
from app.models.enums import (
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    Severity,
)
from app.models.limits import CreditLimit, EnforcementAction, Exemption
from app.models.org import CxApplicationProject, CxProject, CxProjectGroup, CxUser
from app.services import notifications, settings_store
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

    @property
    def ok(self) -> bool:
        return not self.failed

    def as_stats(self) -> dict[str, Any]:
        return {
            "applied": len(self.applied),
            "reconciled": len(self.reconciled),
            "skipped": self.skipped,
            "failed": self.failed,
        }


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


class ProtectedTarget(Exception):  # noqa: N818 - a decision, not an error
    """This target must not be restricted, whatever its usage."""


def protected_user_ids(session: Session) -> frozenset[str]:
    """Tenant users the utility never restricts.

    The account the stored API key belongs to: the utility acts as that user,
    so taking its roles away could cut off the utility's own access to the
    tenant - including its ability to give anyone's access back.
    """
    from app.services import connection as connection_service

    subject = connection_service.api_key_subject(session)
    return frozenset({subject}) if subject else frozenset()


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


def plan_targets(session: Session, *, entity_type: str, entity_id: str) -> list[Target]:
    """Every concrete change a breach of this limit implies, exemptions removed."""
    if entity_type == EntityType.USER:
        if is_exempt(session, entity_type=EntityType.USER, entity_id=entity_id):
            return []
        if entity_id in protected_user_ids(session):
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
        targets.append(
            Target(
                kind=EnforcementKind.DISABLE_AUTO_TRIAGE,
                target_type=TARGET_PROJECT,
                target_id=project_id,
                target_label=label,
            )
        )
        # Only meaningful for projects with a supported SCM integration.
        if project is not None and project.repo_id:
            targets.append(
                Target(
                    kind=EnforcementKind.DISABLE_PR_REMEDIATION,
                    target_type=TARGET_PROJECT,
                    target_id=project_id,
                    target_label=label,
                )
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
    targets = plan_targets(session, entity_type=limit.entity_type, entity_id=limit.entity_id)
    if not targets:
        outcome.skipped.append("no targets to restrict (exempt, protected, or no projects linked)")
        return outcome
    protected_roles = settings_store.enforcement_guard(session).protected_roles

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
        snapshot = captured.snapshot
        for sibling in _siblings_in_force(session, action):
            snapshot = _merge_snapshots(_settled(sibling.undo_snapshot), snapshot)
        snapshot = _merge_snapshots(earlier, snapshot)
        snapshot[OUTCOME_UNKNOWN] = True
        action.undo_snapshot = snapshot
        action.status = EnforcementStatus.PENDING
        session.commit()
        # Phase 3: change the tenant. No transaction is open during this call.
        write_attempted = True
        captured.apply()
    except ProtectedTarget as exc:
        # A decision, not a failure: nothing is changed, the admin is told once,
        # and the cycle is not marked as degraded for honouring its own rule.
        message = str(exc)[:2000]
        first_report = previous_error != message
        action.status = EnforcementStatus.FAILED
        action.error = message
        session.flush()
        outcome.skipped.append(f"{target.kind} on {target.target_label}: {exc}")
        notifications.notify(
            session,
            category=notifications.CATEGORY_ENFORCEMENT,
            severity=Severity.WARNING,
            title=f"{target.target_label} is over budget but protected",
            body=str(exc),
            entity_type=limit.entity_type,
            entity_id=limit.entity_id,
            entity_label=limit.entity_label,
            dedupe_key=notifications.protected_key(action.id),
            enforcement_action_id=action.id,
        )
        if first_report:
            record_audit(
                session,
                action="enforcement.protected",
                actor=actor,
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
                detail=str(exc),
            )
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
            body=f"{exc}\n\nIt will be tried again on the next cycle.",
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
        session.commit()
        return

    # Phase 4: record the outcome, and commit before anything else happens.
    snapshot = {k: v for k, v in (action.undo_snapshot or {}).items() if k != OUTCOME_UNKNOWN}
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
        body=_enforcement_body(limit, target, period_key, snapshot),
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
    session.commit()  # nothing held open while we wait on Checkmarx
    try:
        reasserted = _reconcile(session, client, action=action, target=target, resolver=resolver)
    except CheckmarxError as exc:
        logger.warning(
            "Could not verify %s on %s this cycle: %s", target.kind, target.target_label, exc
        )
        outcome.skipped.append(
            f"{target.kind} on {target.target_label} could not be verified this cycle: {exc}"
        )
        return
    if not reasserted:
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
    AI settings once the write has succeeded.
    """

    snapshot: dict[str, Any]
    apply: Callable[[], None]
    mirror: Callable[[], None]


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
        # Judged on the roles just read from the tenant, plus what the last sync
        # recorded (which also covers roles held outside the platform client).
        user = session.get(CxUser, target.target_id)
        held = {name.lower() for name in current_names} | {
            str(name).lower() for name in ((user.role_names if user else None) or [])
        }
        shielding = sorted(held & protected_roles)
        if shielding:
            raise ProtectedTarget(
                f"{target.target_label} holds a protected role ({', '.join(shielding)}), so "
                "their AI access is not removed automatically. Raise it with them, or "
                "change the protected roles on the Settings page."
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
            raise CheckmarxError(
                "The current PR triage and remediation setting for this repository "
                "could not be read, so it was left unchanged: it could not have been "
                "restored to what it was."
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

    raise CheckmarxError(f"Unknown enforcement kind {target.kind!r}")


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

    return fresh


# ---------------------------------------------------------------- reconciliation


def _reconcile(
    session: Session,
    client: CheckmarxClient,
    *,
    action: EnforcementAction,
    target: Target,
    resolver: RoleResolver,
) -> bool:
    """Verify an already-applied restriction is still in force, re-asserting it if
    it drifted back on in Checkmarx One.

    Returns True when the restriction had to be re-asserted, False when it still
    holds. The original ``undo_snapshot`` is deliberately left untouched so a future
    restore still puts back the exact pre-restriction state.
    """
    snapshot = action.undo_snapshot or {}
    kind = action.kind

    if kind == EnforcementKind.REMOVE_USER_ROLES:
        client_uuid = snapshot.get("client_uuid") or resolver.client_uuid
        current = iam.fetch_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid
        )
        to_remove = [role for role in current if role.name in iam.AI_ROLE_NAMES]
        if not to_remove:
            return False
        iam.remove_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid, roles=to_remove
        )
        return True

    project = session.get(CxProject, target.target_id)

    if kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        state = platform.get_auto_triage(client, project_id=target.target_id)
        if not state.enabled:
            return False
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
        return True

    if kind == EnforcementKind.DISABLE_PR_REMEDIATION:
        repo_id = snapshot.get("repo_id") or (project.repo_id if project else None)
        if not repo_id:
            return False
        current = platform.get_pr_remediation_severities(
            client, repo_id=repo_id, project_id=target.target_id
        )
        # None means "cannot read" (re-assert to be safe); a non-empty list means
        # severities were re-enabled, i.e. drift. Empty means already disabled.
        need_reassert = True if current is None else bool(current)
        if need_reassert:
            platform.set_pr_remediation_severities(
                client,
                repo_id=repo_id,
                project_id=target.target_id,
                severities=DISABLED_SEVERITIES,
            )
            if project is not None:
                project.pr_remediation_severities = []
                project.ai_state_checked_at = utcnow()
            return True
        return False

    return False


def _reconciled_title(action: EnforcementAction) -> str:
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        return f"User {action.target_label}: AI roles re-removed"
    if action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        return f"Project {action.target_label}: Auto Triage re-disabled"
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
        select(EnforcementAction).where(
            EnforcementAction.target_type == action.target_type,
            EnforcementAction.target_id == action.target_id,
            EnforcementAction.kind == action.kind,
            EnforcementAction.id != action.id,
            EnforcementAction.status.in_(RESTORABLE_STATUSES),
        )
    )
    return [row for row in rows if may_be_in_force(row)]


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
    if siblings and reason != ADMIN_REASON:
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
        # An admin's Restore means "give this back now", whichever limits took
        # it: all of them are lifted together, from their combined snapshot.
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
                f"{exc}\n\nIt will be tried again on the next cycle. If it keeps failing, "
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
    return f"Project {target.target_label}: PR triage and remediation disabled"


def _enforcement_body(
    limit: CreditLimit, target: Target, period_key: str, snapshot: dict[str, Any]
) -> str:
    entity = limit.entity_label or limit.entity_id
    lines = [
        f"The {limit.entity_type} limit on {entity} was reached in {period_key} "
        f"({limit.credit_limit} credits).",
    ]
    if target.kind == EnforcementKind.REMOVE_USER_ROLES:
        removed = [entry.get("name") for entry in snapshot.get("removed_roles") or []]
        lines.append(
            f"Removed roles: {', '.join(name for name in removed if name)}"
            if removed
            else "The user did not hold the AI roles, so nothing was removed."
        )
    elif target.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        lines.append(
            "Auto Triage was already off for this project."
            if not snapshot.get("enabled_before")
            else "Auto Triage was turned off for this project."
        )
    else:
        before = snapshot.get("severities_before") or []
        lines.append(f"PR remediation severities cleared (were: {', '.join(before) or 'none'}).")
    lines.append("Use Restore access to reverse this.")
    return "\n".join(lines)


def _restoration_title(action: EnforcementAction) -> str:
    if action.kind == EnforcementKind.REMOVE_USER_ROLES:
        return f"User {action.target_label} restored"
    if action.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        return f"Project {action.target_label}: Auto Triage re-enabled"
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
    else:
        severities = snapshot.get("severities_before") or []
        detail = f"PR remediation severities restored to: {', '.join(severities) or 'none'}."
    return f"{explanation}\n{detail}"
