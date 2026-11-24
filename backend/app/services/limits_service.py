"""Creating, changing and removing limits and exemptions.

Two behaviours here are safety features rather than conveniences:

* A new limit is **monitor only** unless the caller explicitly asks for
  enforcement, and turning enforcement on is audited as its own change.
* Disabling, deleting or switching a limit to monitor only **lifts any
  restriction it caused**, immediately. Leaving someone locked out by a limit that
  no longer exists is the worst failure mode this tool has.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError
from app.db.base import utcnow
from app.models.enums import PROJECT_ACTION_ORDER, EntityType
from app.models.limits import CreditLimit, Exemption, LimitPeriodState
from app.models.org import CxApplication, CxGroup, CxProject, CxUser
from app.services import error_text, evaluation
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

_ENTITY_MODELS = {
    EntityType.USER: CxUser,
    EntityType.GROUP: CxGroup,
    EntityType.PROJECT: CxProject,
    EntityType.APPLICATION: CxApplication,
}

AUDITED_FIELDS = (
    "credit_limit",
    "period_type",
    "custom_period_start",
    "custom_period_end",
    "warning_threshold_pct",
    "enforce",
    "is_active",
    "include_member_usage",
    "hold_until_released",
    "count_existing_usage",
    "notes",
    "business_unit",
    "project_actions",
)


# Far above any real budget, and comfortably inside a 32-bit integer column: a
# larger number in an imported file used to fail the whole import on PostgreSQL.
MAX_CREDIT_LIMIT = 1_000_000_000


class LimitError(ValueError):
    """The requested limit change is not valid."""


# A change made from the GUI lifts at most this many restrictions while the
# admin waits; the cycle lifts the rest (it finds them the same way), so a large
# group's limit can be switched off without a request that runs for minutes.
API_RESTORE_BATCH = 200

# The fields whose change alters what a limit applies in Checkmarx One: its
# restrictions in force are then read back first on the next cycle.
REVERIFY_FIELDS = ("enforce", "is_active", "project_actions")


class LimitRestoreError(LimitError):
    """The change needs a restriction lifted first, and Checkmarx refused."""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


@dataclass(frozen=True, slots=True)
class LimitInput:
    entity_type: EntityType
    entity_id: str
    credit_limit: int
    period_type: str
    warning_threshold_pct: int = 80
    enforce: bool = False
    include_member_usage: bool = False
    hold_until_released: bool = False
    count_existing_usage: bool = False
    custom_period_start: datetime | None = None
    custom_period_end: datetime | None = None
    notes: str | None = None
    business_unit: str | None = None
    # What a project, group or application limit turns off; None = the legacy
    # pair (Auto Triage, PR triage and remediation). Must be None for users.
    project_actions: list[str] | None = None


def normalise_project_actions(value: object) -> list[str] | None:
    """A stored, ordered, de-duplicated list of project actions, or None.

    Raises LimitError for anything that is not a list of known actions, and
    for an empty list (a limit that enforces must turn something off).
    """
    if value is None:
        return None
    if isinstance(value, str):
        value = [part for part in value.replace(";", ",").split(",") if part.strip()]
    if not isinstance(value, list | tuple | set | frozenset):
        raise LimitError("project_actions must be a list.")
    names = {str(item).strip().lower() for item in value}
    unknown = sorted(names - set(PROJECT_ACTION_ORDER))
    if unknown:
        raise LimitError(
            f"Unknown project action(s): {', '.join(unknown)}. "
            f"Choose from: {', '.join(PROJECT_ACTION_ORDER)}."
        )
    if not names:
        raise LimitError(
            "Choose at least one thing for this limit to turn off on its projects, or make the "
            "limit monitor only."
        )
    return [action for action in PROJECT_ACTION_ORDER if action in names]


def resolve_entity_label(session: Session, *, entity_type: str, entity_id: str) -> str | None:
    """Human readable name for an entity, or None when it is not synced yet."""
    model = _ENTITY_MODELS.get(EntityType(entity_type))
    if model is None:
        return None
    row = session.get(model, entity_id)
    if row is None:
        return None
    return row.display_name if isinstance(row, CxUser) else row.name


def _validate(session: Session, data: LimitInput) -> None:
    if data.credit_limit < 0:
        raise LimitError("A credit limit cannot be negative.")
    if data.credit_limit > MAX_CREDIT_LIMIT:
        raise LimitError(f"A credit limit cannot be more than {MAX_CREDIT_LIMIT:,}.")
    if not 1 <= data.warning_threshold_pct <= 100:
        raise LimitError("The warning threshold must be between 1 and 100 percent.")
    if data.period_type == "custom":
        if data.custom_period_start is None:
            raise LimitError("A custom period needs a start date.")
        if (
            data.custom_period_end is not None
            and data.custom_period_end <= data.custom_period_start
        ):
            raise LimitError("The custom period's end date must be after its start date.")
    if data.include_member_usage and data.entity_type != EntityType.GROUP:
        raise LimitError("Member usage can only be counted for group limits.")
    if data.project_actions is not None:
        if data.entity_type == EntityType.USER:
            raise LimitError(
                "What to turn off for projects can only be chosen for project, group and "
                "application limits."
            )
        normalise_project_actions(data.project_actions)
    if (
        resolve_entity_label(session, entity_type=data.entity_type, entity_id=data.entity_id)
        is None
    ):
        # Not fatal: an entity may be created in the tenant before the next sync.
        logger.info(
            "Limit created for %s %s which is not in the synced org model yet",
            data.entity_type,
            data.entity_id,
        )


def create_limit(session: Session, *, data: LimitInput, actor: AuditActor) -> CreditLimit:
    _validate(session, data)
    existing = session.scalar(
        select(CreditLimit).where(
            CreditLimit.entity_type == data.entity_type,
            CreditLimit.entity_id == data.entity_id,
        )
    )
    if existing is not None:
        raise LimitError(
            f"A limit already exists for this {data.entity_type}. Edit that limit instead."
        )

    limit = CreditLimit(
        entity_type=data.entity_type,
        entity_id=data.entity_id,
        entity_label=resolve_entity_label(
            session, entity_type=data.entity_type, entity_id=data.entity_id
        ),
        credit_limit=data.credit_limit,
        period_type=data.period_type,
        custom_period_start=data.custom_period_start,
        custom_period_end=data.custom_period_end,
        warning_threshold_pct=data.warning_threshold_pct,
        enforce=data.enforce,
        include_member_usage=data.include_member_usage,
        hold_until_released=data.hold_until_released,
        count_existing_usage=data.count_existing_usage,
        notes=data.notes,
        business_unit=data.business_unit,
        project_actions=normalise_project_actions(data.project_actions),
        created_by_id=actor.actor_id,
    )
    session.add(limit)
    session.flush()

    record_audit(
        session,
        action="limit.created",
        actor=actor,
        target_type="credit_limit",
        target_id=str(limit.id),
        target_label=limit.entity_label or limit.entity_id,
        after=_snapshot(limit),
        detail=(
            "Created in enforce mode."
            if limit.enforce
            else "Created in monitor only mode, no restrictions will be applied."
        ),
    )
    return limit


def update_limit(
    session: Session,
    *,
    limit: CreditLimit,
    changes: dict[str, Any],
    actor: AuditActor,
    client: CheckmarxClient | None = None,
    lift: bool = True,
) -> CreditLimit:
    """Change a limit, then lift any restriction the change makes unjustified.

    Lifting talks to Checkmarx and commits as it goes, starting with everything
    written so far. A caller for whom this change is one step of a larger unit of
    work (approving a request, importing a file) passes ``lift=False`` and calls
    :func:`lift_unjustified_restrictions` itself once its own writes are done, so
    its work is committed as a whole rather than cut in two.
    """
    before = _snapshot(limit)
    for field, value in changes.items():
        if field not in AUDITED_FIELDS:
            raise LimitError(f"{field} cannot be changed.")
        if field == "project_actions":
            try:
                value = normalise_project_actions(value)
            except LimitError:
                session.expire(limit)
                raise
        setattr(limit, field, value)

    # Any change to the budget makes this a deliberate value, so it is no longer
    # owned by the grant that may have set it. A credit request's approval
    # re-stamps the limit itself after calling this, so the grant path is
    # unaffected; every other caller (manual edit, bulk edit) drops the stamp.
    if "credit_limit" in changes:
        limit.granted_by_request_id = None

    try:
        _validate(
            session,
            LimitInput(
                entity_type=EntityType(limit.entity_type),
                entity_id=limit.entity_id,
                credit_limit=limit.credit_limit,
                period_type=limit.period_type,
                warning_threshold_pct=limit.warning_threshold_pct,
                enforce=limit.enforce,
                include_member_usage=limit.include_member_usage,
                count_existing_usage=limit.count_existing_usage,
                custom_period_start=limit.custom_period_start,
                custom_period_end=limit.custom_period_end,
                project_actions=limit.project_actions,
            ),
        )
    except LimitError:
        # The rejected values are already on the object. Drop them, or a caller
        # that carries on after the error (a bulk edit) would commit them anyway.
        session.expire(limit)
        raise
    session.flush()

    # Anything that stops this limit from applying must release its restrictions.
    became_harmless = (before["enforce"] and not limit.enforce) or (
        before["is_active"] and not limit.is_active
    )

    # The change and its audit entry are written first and become durable
    # together, before Checkmarx is asked to lift anything. Restoring commits as
    # it goes (so no lock is held while it waits on the tenant), which would
    # otherwise leave a saved limit change with no audit entry if it then failed.
    record_audit(
        session,
        action="limit.updated",
        actor=actor,
        target_type="credit_limit",
        target_id=str(limit.id),
        target_label=limit.entity_label or limit.entity_id,
        before=before,
        after=_snapshot(limit),
        detail=(
            "This limit no longer enforces, so any restriction it applied is lifted."
            if became_harmless
            else None
        ),
    )

    # An admin changed what the limit applies: what it restricts is read back
    # first on the next cycle, ahead of the usual rotation (pacing.py). A
    # change that leaves the restrictions as they are (a note, the budget, the
    # period) leaves the rotation alone.
    after = _snapshot(limit)
    if any(before[field] != after[field] for field in REVERIFY_FIELDS):
        from sqlalchemy import update

        from app.models.enums import EnforcementStatus
        from app.models.limits import EnforcementAction

        session.execute(
            update(EnforcementAction)
            .where(
                EnforcementAction.limit_id == limit.id,
                EnforcementAction.status == EnforcementStatus.APPLIED,
            )
            .values(last_verified_at=None, last_checked_at=None)
        )
    if lift:
        lift_unjustified_restrictions(session, client, limit=limit, actor=actor)
    return limit


def lift_unjustified_restrictions(
    session: Session,
    client: CheckmarxClient | None,
    *,
    limit: CreditLimit,
    actor: AuditActor,
) -> int:
    """Lift this limit's restrictions if nothing justifies them any more.

    That is: the limit no longer enforces, or its budget now covers the usage it
    was breached on. Commits everything pending first, then once per restriction
    lifted. Returns how many were lifted.

    A failure to reach Checkmarx does not undo the limit change. It is recorded
    (audit entry and an error in the Notification Center) and the next cycle
    tries again, so nobody stays restricted by a limit that no longer applies
    just because Checkmarx was unreachable at this moment.
    """
    if client is None:
        return 0
    from app.services import enforcement

    # At most API_RESTORE_BATCH now; the next cycles lift the rest. The
    # request is not the cycle's: a cycle running past its own time budget
    # meanwhile does not stop it (respect_deadline).
    budget = enforcement.EnforcementBudget(writes=API_RESTORE_BATCH, respect_deadline=False)
    lifted = 0
    if limit.is_active and limit.enforce:
        # What the limit no longer turns off is put back now, whatever its usage.
        limit_id = limit.id
        try:
            lifted = enforcement.restore_deselected(
                session, client, limit=limit, actor=actor, budget=budget
            )
        except CheckmarxError as exc:
            logger.warning(
                "Limit %s no longer turns some things off, but they could not be put back yet: %s",
                limit_id,
                exc,
            )
    if not limit.is_active or not limit.enforce:
        reason = "limit_removed"
    else:
        from app.models.enums import LimitStatus

        states = session.scalars(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id,
                LimitPeriodState.status.in_([LimitStatus.RESTRICTED, LimitStatus.BREACHED]),
            )
        )
        if not any(state.credits_used < Decimal(limit.credit_limit) for state in states):
            return lifted
        reason = "credit_increased"

    limit_id = limit.id
    try:
        return lifted + evaluation.restore_on_limit_change(
            session, client, limit=limit, actor=actor, reason=reason, budget=budget
        )
    except CheckmarxError as exc:
        logger.warning(
            "Limit %s was changed but its restrictions could not be lifted yet: %s",
            limit_id,
            exc,
        )
        return lifted


def delete_limit(
    session: Session,
    *,
    limit: CreditLimit,
    actor: AuditActor,
    client: CheckmarxClient | None = None,
) -> int:
    """Remove a limit, lifting anything it restricted first.

    If Checkmarx will not lift a restriction the limit is kept, so the
    restriction never outlives the only record of why it is there. Nor is a
    limit with more restrictions in force than one request lifts deleted: it
    is to be switched off first (the cycles then lift them, a batch at a time).
    """
    from app.services import enforcement

    # Everything that is, or may be, in force: applied, and any attempt whose
    # outcome is unknown and may have taken something (it is lifted the same way).
    in_force = len(enforcement.active_actions_for_limit(session, limit_id=limit.id))
    if client is not None and in_force > API_RESTORE_BATCH:
        raise LimitRestoreError(
            f"This limit has {in_force:,} restrictions in force, more than are lifted while you "
            "wait. Switch it off (or to monitor only) first: they are then lifted over the next "
            "cycles, and the limit can be deleted once they are."
        )
    try:
        restored = evaluation.restore_on_limit_change(
            session, client, limit=limit, actor=actor, reason="limit_removed"
        )
    except CheckmarxError as exc:
        raise LimitRestoreError(
            "The limit was not deleted because the restrictions it applied could not be "
            f"lifted in Checkmarx One: {error_text.public_error(exc)}"
        ) from exc
    record_audit(
        session,
        action="limit.deleted",
        actor=actor,
        target_type="credit_limit",
        target_id=str(limit.id),
        target_label=limit.entity_label or limit.entity_id,
        before=_snapshot(limit),
        detail=f"{restored} restriction(s) lifted." if restored else None,
    )
    session.delete(limit)
    session.flush()
    return restored


def _snapshot(limit: CreditLimit) -> dict[str, Any]:
    return {
        "entity_type": limit.entity_type,
        "entity_id": limit.entity_id,
        "entity_label": limit.entity_label,
        "credit_limit": limit.credit_limit,
        "period_type": limit.period_type,
        "custom_period_start": limit.custom_period_start.isoformat()
        if limit.custom_period_start
        else None,
        "custom_period_end": limit.custom_period_end.isoformat()
        if limit.custom_period_end
        else None,
        "warning_threshold_pct": limit.warning_threshold_pct,
        "enforce": limit.enforce,
        "is_active": limit.is_active,
        "include_member_usage": limit.include_member_usage,
        "hold_until_released": limit.hold_until_released,
        "count_existing_usage": limit.count_existing_usage,
        "notes": limit.notes,
        "business_unit": limit.business_unit,
        "project_actions": list(limit.project_actions)
        if limit.project_actions is not None
        else None,
    }


def current_state(session: Session, *, limit_id: int, period_key: str) -> LimitPeriodState | None:
    return session.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit_id, LimitPeriodState.period_key == period_key
        )
    )


# ------------------------------------------------------------------- exemptions


def add_exemption(
    session: Session,
    *,
    entity_type: EntityType,
    entity_id: str,
    reason: str | None,
    actor: AuditActor,
    expires_at: datetime | None = None,
    client: CheckmarxClient | None = None,
) -> Exemption:
    if expires_at is not None and expires_at <= utcnow():
        raise LimitError("An override's expiry must be in the future.")
    existing = session.scalar(
        select(Exemption).where(
            Exemption.entity_type == entity_type, Exemption.entity_id == entity_id
        )
    )
    if existing is not None:
        # Let an admin extend or re-scope an existing override rather than silently
        # keeping the old one. No need to lift restrictions here: enforcement
        # skips exempt entities, and a restriction left in place because Checkmarx
        # was unreachable when the exemption was created is lifted by the cycle.
        before = {"expires_at": _iso(existing.expires_at), "reason": existing.reason}
        if expires_at != existing.expires_at or (reason and reason != existing.reason):
            existing.expires_at = expires_at
            if reason:
                existing.reason = reason
            session.flush()
            record_audit(
                session,
                action="exemption.updated",
                actor=actor,
                target_type="exemption",
                target_id=str(existing.id),
                target_label=existing.entity_label or existing.entity_id,
                before=before,
                after={"expires_at": _iso(existing.expires_at), "reason": existing.reason},
                detail="Override re-scoped.",
            )
        return existing

    exemption = Exemption(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=resolve_entity_label(session, entity_type=entity_type, entity_id=entity_id),
        reason=reason,
        expires_at=expires_at,
        created_by_id=actor.actor_id,
    )
    session.add(exemption)
    session.flush()

    # Audited before anything is lifted: restoring commits as it goes, and the
    # exemption must never be durable without its audit entry.
    record_audit(
        session,
        action="exemption.created",
        actor=actor,
        target_type="exemption",
        target_id=str(exemption.id),
        target_label=exemption.entity_label or entity_id,
        after={"entity_type": entity_type, "entity_id": entity_id, "reason": reason},
        detail="Any active restriction on this entity is lifted.",
    )

    # An exemption that leaves an existing restriction in place would be a trap.
    if client is not None:
        from app.services import enforcement

        for action in enforcement.active_actions_for(
            session, entity_type=entity_type, entity_id=entity_id
        ):
            try:
                enforcement.restore_action(
                    session,
                    client,
                    action=action,
                    actor=actor,
                    reason=enforcement.EXEMPTED_REASON,
                )
            except CheckmarxError as exc:
                # Recorded by restore_action, and retried by the next cycle.
                logger.warning(
                    "Exemption %s was created but a restriction could not be lifted yet: %s",
                    exemption.id,
                    exc,
                )
    return exemption


def remove_exemption(session: Session, *, exemption: Exemption, actor: AuditActor) -> None:
    record_audit(
        session,
        action="exemption.deleted",
        actor=actor,
        target_type="exemption",
        target_id=str(exemption.id),
        target_label=exemption.entity_label or exemption.entity_id,
        before={
            "entity_type": exemption.entity_type,
            "entity_id": exemption.entity_id,
            "reason": exemption.reason,
        },
    )
    session.delete(exemption)
    session.flush()


def expire_overrides(session: Session, *, now: datetime | None = None) -> int:
    """Remove time-boxed overrides (exemptions) whose expiry has passed.

    Nothing to lift: removing an exemption only restores the ability to enforce,
    so the next evaluation re-applies a restriction if the entity is still over
    budget. Returns the number removed.
    """
    moment = now or utcnow()
    expired = list(
        session.scalars(
            select(Exemption).where(
                Exemption.expires_at.is_not(None), Exemption.expires_at < moment
            )
        )
    )
    actor = AuditActor.system("override-expiry")
    for exemption in expired:
        record_audit(
            session,
            action="exemption.expired",
            actor=actor,
            target_type="exemption",
            target_id=str(exemption.id),
            target_label=exemption.entity_label or exemption.entity_id,
            detail="Temporary override expired; normal enforcement resumes.",
        )
        session.delete(exemption)
    session.flush()
    return len(expired)
