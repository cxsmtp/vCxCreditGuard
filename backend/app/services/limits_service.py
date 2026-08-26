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
from app.models.enums import EntityType
from app.models.limits import CreditLimit, Exemption, LimitPeriodState
from app.models.org import CxApplication, CxGroup, CxProject, CxUser
from app.services import evaluation
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
)


class LimitError(ValueError):
    """The requested limit change is not valid."""


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
) -> CreditLimit:
    before = _snapshot(limit)
    for field, value in changes.items():
        if field not in AUDITED_FIELDS:
            raise LimitError(f"{field} cannot be changed.")
        setattr(limit, field, value)

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
        ),
    )
    session.flush()

    # Anything that stops this limit from applying must release its restrictions.
    became_harmless = (before["enforce"] and not limit.enforce) or (
        before["is_active"] and not limit.is_active
    )
    credit_increased = limit.credit_limit > before["credit_limit"]

    restored = 0
    if became_harmless:
        restored = evaluation.restore_on_limit_change(
            session,
            client,
            limit=limit,
            actor=actor,
            reason="limit_removed" if not limit.is_active else "limit_removed",
        )
    elif credit_increased and client is not None:
        from app.models.enums import LimitStatus

        states = list(
            session.scalars(
                select(LimitPeriodState).where(
                    LimitPeriodState.limit_id == limit.id,
                    LimitPeriodState.status.in_([LimitStatus.RESTRICTED, LimitStatus.BREACHED]),
                )
            )
        )
        if any(st.credits_used < Decimal(limit.credit_limit) for st in states):
            restored = evaluation.restore_on_limit_change(
                session,
                client,
                limit=limit,
                actor=actor,
                reason="credit_increased",
            )

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
            f"{restored} restriction(s) lifted because this limit no longer enforces."
            if became_harmless and restored
            else (
                f"{restored} restriction(s) lifted because credit limit was increased."
                if credit_increased and restored
                else None
            )
        ),
    )
    return limit


def delete_limit(
    session: Session,
    *,
    limit: CreditLimit,
    actor: AuditActor,
    client: CheckmarxClient | None = None,
) -> int:
    """Remove a limit, lifting anything it restricted first."""
    restored = evaluation.restore_on_limit_change(
        session, client, limit=limit, actor=actor, reason="limit_removed"
    )
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
    client: CheckmarxClient | None = None,
) -> Exemption:
    existing = session.scalar(
        select(Exemption).where(
            Exemption.entity_type == entity_type, Exemption.entity_id == entity_id
        )
    )
    if existing is not None:
        return existing

    exemption = Exemption(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=resolve_entity_label(session, entity_type=entity_type, entity_id=entity_id),
        reason=reason,
        created_by_id=actor.actor_id,
    )
    session.add(exemption)
    session.flush()

    # An exemption that leaves an existing restriction in place would be a trap.
    lifted = 0
    if client is not None:
        from app.services import enforcement

        for action in enforcement.active_actions_for(
            session, entity_type=entity_type, entity_id=entity_id
        ):
            if enforcement.restore_action(
                session,
                client,
                action=action,
                actor=actor,
                reason=enforcement.EXEMPTED_REASON,
            ):
                lifted += 1

    record_audit(
        session,
        action="exemption.created",
        actor=actor,
        target_type="exemption",
        target_id=str(exemption.id),
        target_label=exemption.entity_label or entity_id,
        after={"entity_type": entity_type, "entity_id": entity_id, "reason": reason},
        detail=f"{lifted} active restriction(s) lifted." if lifted else None,
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
