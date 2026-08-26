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
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import iam, platform
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError
from app.db.base import utcnow
from app.models.enums import (
    EnforcementKind,
    EnforcementStatus,
    EntityType,
    Severity,
)
from app.models.limits import CreditLimit, EnforcementAction, Exemption
from app.models.org import CxApplicationProject, CxProject, CxProjectGroup, CxUser
from app.services import notifications
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
        outcome.skipped.append("no targets to restrict (all exempt, or no projects linked)")
        return outcome

    for target in targets:
        key = idempotency_key(
            limit_id=limit.id,
            period_key=period_key,
            kind=str(target.kind),
            target_id=target.target_id,
        )
        action = session.scalar(
            select(EnforcementAction).where(EnforcementAction.idempotency_key == key)
        )
        if action is not None and action.status == EnforcementStatus.APPLIED:
            # Already restricted, but re-verify: a manual (or automated) change in
            # Checkmarx One could have re-enabled the feature or re-granted a role.
            # Re-assert the restriction if it has drifted rather than assume it holds.
            reasserted = False
            try:
                reasserted = _reconcile(
                    session, client, action=action, target=target, resolver=resolver
                )
            except CheckmarxError as exc:
                logger.warning(
                    "Could not verify %s on %s this cycle: %s",
                    target.kind,
                    target.target_label,
                    exc,
                )
                outcome.skipped.append(
                    f"{target.kind} on {target.target_label} could not be "
                    f"verified this cycle: {exc}"
                )
                continue
            if reasserted:
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
            else:
                outcome.skipped.append(
                    f"{target.kind} on {target.target_label} already applied "
                    "and verified in Checkmarx"
                )
            continue
        if action is not None and action.status == EnforcementStatus.REVERSED:
            if action.reversal_reason == EXEMPTED_REASON:
                # The restriction was lifted because an exemption was granted, and
                # this target is in the plan only because it is exempt no longer
                # (exemptions are filtered out above). So the exemption that lifted
                # it is gone and the breach should restrict it again rather than
                # leave it unlocked for the rest of the period.
                action.error = None
                action.reversed_at = None
                action.reversed_by_id = None
                action.reversal_reason = None
            else:
                # An admin restored access during this period. Respect that decision
                # instead of fighting them every cycle.
                outcome.skipped.append(
                    f"{target.kind} on {target.target_label} was restored by an admin this period"
                )
                continue

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
        session.flush()

        try:
            snapshot = _perform(session, client, target=target, resolver=resolver)
        except CheckmarxError as exc:
            action.status = EnforcementStatus.FAILED
            action.error = str(exc)[:2000]
            session.flush()
            outcome.failed.append(f"{target.kind} on {target.target_label}: {exc}")
            notifications.notify(
                session,
                category=notifications.CATEGORY_ENFORCEMENT,
                severity=Severity.ERROR,
                title=f"Could not restrict {target.target_label}",
                body=str(exc),
                entity_type=limit.entity_type,
                entity_id=limit.entity_id,
                entity_label=limit.entity_label,
                enforcement_action_id=action.id,
            )
            record_audit(
                session,
                action="enforcement.failed",
                actor=actor,
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
                detail=f"{target.kind} failed: {exc}",
            )
            continue

        action.undo_snapshot = snapshot
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

    return outcome


def _perform(
    session: Session,
    client: CheckmarxClient,
    *,
    target: Target,
    resolver: RoleResolver,
) -> dict[str, Any]:
    """Make the change and return the snapshot needed to undo it."""
    if target.kind == EnforcementKind.REMOVE_USER_ROLES:
        client_uuid = resolver.client_uuid
        current = iam.fetch_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid
        )
        current_names = {role.name for role in current}
        to_remove = [role for role in current if role.name in iam.AI_ROLE_NAMES]
        iam.remove_user_client_roles(
            client, user_id=target.target_id, client_uuid=client_uuid, roles=to_remove
        )
        return {
            "kind": str(target.kind),
            "client_uuid": client_uuid,
            "removed_roles": [role.as_payload() for role in to_remove],
            "roles_before": sorted(current_names),
        }

    project = session.get(CxProject, target.target_id)

    if target.kind == EnforcementKind.DISABLE_AUTO_TRIAGE:
        state = platform.get_auto_triage(client, project_id=target.target_id)
        if state.enabled:
            platform.set_auto_triage(
                client, project_id=target.target_id, enabled=False, config=state.config
            )
        if project is not None:
            project.auto_triage_enabled = False
            project.auto_triage_config = state.config or None
            project.ai_state_checked_at = utcnow()
        return {
            "kind": str(target.kind),
            # False here means it was already off, so restore leaves it off.
            "enabled_before": bool(state.enabled),
            "config_before": state.config or {},
        }

    if target.kind == EnforcementKind.DISABLE_PR_REMEDIATION:
        if project is None or not project.repo_id:
            raise CheckmarxError(
                "No repository id is known for this project, so PR triage and "
                "remediation cannot be changed."
            )
        read = platform.get_pr_remediation_severities(
            client, repo_id=project.repo_id, project_id=target.target_id
        )
        if read is not None:
            # The real, current severities (captured before disabling) - this is
            # what a Restore must reproduce, including MEDIUM/LOW if configured.
            severities_before = read
        else:
            # No read support on the tenant: fall back to the cached or default set.
            severities_before = list(
                project.pr_remediation_severities or platform.DEFAULT_PR_SEVERITIES
            )
        platform.set_pr_remediation_severities(
            client,
            repo_id=project.repo_id,
            project_id=target.target_id,
            severities=DISABLED_SEVERITIES,
        )
        project.pr_remediation_severities = []
        project.ai_state_checked_at = utcnow()
        return {
            "kind": str(target.kind),
            "repo_id": project.repo_id,
            "severities_before": severities_before,
        }

    raise CheckmarxError(f"Unknown enforcement kind {target.kind!r}")


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


def restore_action(
    session: Session,
    client: CheckmarxClient,
    *,
    action: EnforcementAction,
    actor: AuditActor,
    reason: str = "admin",
    resolver: RoleResolver | None = None,
) -> bool:
    """Undo one enforcement action from its snapshot. Returns False if not needed."""
    if action.status != EnforcementStatus.APPLIED:
        return False

    snapshot = action.undo_snapshot or {}
    resolver = resolver or RoleResolver(client)

    try:
        _undo(session, client, action=action, snapshot=snapshot, resolver=resolver)
    except CheckmarxError as exc:
        action.error = str(exc)[:2000]
        session.flush()
        notifications.notify(
            session,
            category=notifications.CATEGORY_RESTORATION,
            severity=Severity.ERROR,
            title=f"Could not restore {action.target_label}",
            body=(
                f"{exc}\n\nRestore it directly in Checkmarx One, then mark this action "
                "reversed. The snapshot of the previous state is on the audit entry."
            ),
            entity_type=action.entity_type,
            entity_id=action.entity_id,
            entity_label=action.entity_label,
            enforcement_action_id=action.id,
        )
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
        raise

    action.status = EnforcementStatus.REVERSED
    action.reversed_at = utcnow()
    action.reversed_by_id = actor.actor_id
    action.reversal_reason = reason
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
        detail=f"Access restored ({reason}).",
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
    return True


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
        EnforcementAction.status == EnforcementStatus.APPLIED,
    )
    if period_key is not None:
        query = query.where(EnforcementAction.period_key == period_key)

    resolver = RoleResolver(client)
    restored = 0
    for action in list(session.scalars(query)):
        if restore_action(
            session, client, action=action, actor=actor, reason=reason, resolver=resolver
        ):
            restored += 1
    return restored


def active_actions_for(
    session: Session, *, entity_type: str, entity_id: str
) -> list[EnforcementAction]:
    return list(
        session.scalars(
            select(EnforcementAction).where(
                EnforcementAction.entity_type == entity_type,
                EnforcementAction.entity_id == entity_id,
                EnforcementAction.status == EnforcementStatus.APPLIED,
            )
        )
    )


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
        "credit_increased": "The credit limit was increased or consumption is within budget, so the restriction was lifted.",
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
