"""Credit request / approval workflow.

A request asks to raise (or create) one entity's budget. An admin approves it -
in full or part, and optionally only until an expiry - which applies the budget
to the entity's :class:`CreditLimit`, or denies it with a reason. A temporary
grant is rolled back to the pre-grant budget once it expires, but only if nobody
changed the limit in the meantime, so an expiry can never silently undo a later
deliberate change.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType, RequestStatus
from app.models.limits import CreditLimit, CreditRequest
from app.services import limits_service
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)


class RequestError(ValueError):
    """A credit request could not be created or decided (invalid input)."""


class RequestStateError(RequestError):
    """A request is not in a state where the attempted decision is allowed."""


@dataclass(frozen=True, slots=True)
class RequestInput:
    entity_type: EntityType
    entity_id: str
    requested_limit: int
    reason: str | None = None


def create_request(session: Session, *, data: RequestInput, actor: AuditActor) -> CreditRequest:
    if data.requested_limit < 0:
        raise RequestError("A requested limit cannot be negative.")
    now = utcnow()
    request = CreditRequest(
        entity_type=str(data.entity_type),
        entity_id=data.entity_id,
        entity_label=limits_service.resolve_entity_label(
            session, entity_type=str(data.entity_type), entity_id=data.entity_id
        ),
        requested_limit=data.requested_limit,
        reason=(data.reason or None),
        status=RequestStatus.PENDING,
        requested_by_id=actor.actor_id,
        requested_by_name=actor.actor_name,
        requested_at=now,
        created_at=now,
    )
    session.add(request)
    session.flush()
    record_audit(
        session,
        action="credit_request.created",
        actor=actor,
        target_type="credit_request",
        target_id=str(request.id),
        target_label=request.entity_label or request.entity_id,
        after={"entity_id": request.entity_id, "requested_limit": request.requested_limit},
        detail=f"Requested a budget of {request.requested_limit} credits.",
    )
    return request


def _existing_limit(session: Session, request: CreditRequest) -> CreditLimit | None:
    return session.scalar(
        select(CreditLimit).where(
            CreditLimit.entity_type == request.entity_type,
            CreditLimit.entity_id == request.entity_id,
        )
    )


def _active_temporary_grant(session: Session, request: CreditRequest) -> CreditRequest | None:
    """The newest still-in-force temporary grant for this entity, if any."""
    return session.scalar(
        select(CreditRequest)
        .where(
            CreditRequest.id != request.id,
            CreditRequest.entity_type == request.entity_type,
            CreditRequest.entity_id == request.entity_id,
            CreditRequest.status == RequestStatus.APPROVED,
            CreditRequest.reverted.is_(False),
            CreditRequest.expires_at.is_not(None),
        )
        .order_by(CreditRequest.id.desc())
    )


def approve_request(
    session: Session,
    *,
    request: CreditRequest,
    actor: AuditActor,
    approved_limit: int | None = None,
    expires_at: datetime | None = None,
    note: str | None = None,
    client: CheckmarxClient | None = None,
) -> CreditRequest:
    """Grant the request and apply the budget to the entity's limit.

    ``client`` lets the grant lift a restriction straight away: if raising the
    budget means an enforced limit no longer bites, the live Checkmarx restriction
    is reversed now rather than at the next cycle, which is the whole point of
    unblocking someone. Without a client the budget is still applied and the next
    cycle catches up.
    """
    if request.status != RequestStatus.PENDING:
        raise RequestStateError("Only a pending request can be approved.")
    target = request.requested_limit if approved_limit is None else approved_limit
    if target < 0:
        raise RequestError("An approved limit cannot be negative.")
    if expires_at is not None and expires_at <= utcnow():
        raise RequestError("A temporary grant's expiry must be in the future.")

    existing = _existing_limit(session, request)
    # Chain the rollback baseline. If the current budget was set by an earlier
    # temporary grant that is still in force, this new grant supersedes it, and
    # the value to restore to on expiry is that earlier grant's own baseline, not
    # the interim granted figure. Only trust the link when the stamp confirms the
    # limit still belongs to that grant (an admin edit clears it).
    prior = _active_temporary_grant(session, request)
    superseded = (
        prior
        if prior is not None and existing is not None and existing.granted_by_request_id == prior.id
        else None
    )

    if existing is not None:
        request.previous_limit = (
            superseded.previous_limit if superseded is not None else existing.credit_limit
        )
        if target != existing.credit_limit:
            limits_service.update_limit(
                session,
                limit=existing,
                changes={"credit_limit": target},
                actor=actor,
                client=client,
            )
        existing.granted_by_request_id = request.id
    else:
        request.previous_limit = None
        # A granted budget is monitor-only: approving a request never silently
        # turns on enforcement for an entity that had no limit before.
        limit = limits_service.create_limit(
            session,
            data=limits_service.LimitInput(
                entity_type=EntityType(request.entity_type),
                entity_id=request.entity_id,
                credit_limit=target,
                period_type=PeriodType.MONTHLY,
            ),
            actor=actor,
        )
        limit.granted_by_request_id = request.id

    if superseded is not None:
        superseded.reverted = True
        record_audit(
            session,
            action="credit_request.superseded",
            actor=actor,
            target_type="credit_request",
            target_id=str(superseded.id),
            target_label=superseded.entity_label or superseded.entity_id,
            detail=f"Superseded by request #{request.id}; its rollback is now that request's.",
        )

    request.status = RequestStatus.APPROVED
    request.approved_limit = target
    request.expires_at = expires_at
    request.decided_by_id = actor.actor_id
    request.decided_by_name = actor.actor_name
    request.decided_at = utcnow()
    request.decision_note = note or None
    session.flush()

    window = f" until {expires_at.isoformat()}" if expires_at else ""
    record_audit(
        session,
        action="credit_request.approved",
        actor=actor,
        target_type="credit_request",
        target_id=str(request.id),
        target_label=request.entity_label or request.entity_id,
        after={
            "approved_limit": target,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
        detail=f"Granted {target} credits{window}.",
    )
    return request


def deny_request(
    session: Session, *, request: CreditRequest, actor: AuditActor, note: str | None = None
) -> CreditRequest:
    if request.status != RequestStatus.PENDING:
        raise RequestStateError("Only a pending request can be denied.")
    request.status = RequestStatus.DENIED
    request.decided_by_id = actor.actor_id
    request.decided_by_name = actor.actor_name
    request.decided_at = utcnow()
    request.decision_note = note or None
    session.flush()
    record_audit(
        session,
        action="credit_request.denied",
        actor=actor,
        target_type="credit_request",
        target_id=str(request.id),
        target_label=request.entity_label or request.entity_id,
        detail=note or "Denied.",
    )
    return request


def revert_expired_grants(
    session: Session, *, now: datetime | None = None, client: CheckmarxClient | None = None
) -> int:
    """Roll back temporary grants whose expiry has passed.

    A grant is only rolled back when the limit still carries this grant's stamp:
    if an admin changed the budget since (which clears the stamp), or a later
    grant took it over, the newer value is left alone and the grant is just marked
    reverted so it is not revisited. The stamp, not the numeric value, is the test,
    so an admin who happens to re-set the same number is never silently undone.

    ``client`` is passed through to the limit change so that, if the granted limit
    had since been put into enforce mode and restricted someone, removing it also
    lifts that restriction - leaving an entity locked out by a limit that no
    longer exists is the one failure this must never cause.
    """
    moment = now or utcnow()
    actor = AuditActor.system("grant-expiry")
    reverted = 0
    rows = session.scalars(
        select(CreditRequest).where(
            CreditRequest.status == RequestStatus.APPROVED,
            CreditRequest.reverted.is_(False),
            CreditRequest.expires_at.is_not(None),
            CreditRequest.expires_at < moment,
        )
    )
    for request in list(rows):
        existing = _existing_limit(session, request)
        unchanged = existing is not None and existing.granted_by_request_id == request.id
        if unchanged:
            if request.previous_limit is None:
                limits_service.delete_limit(session, limit=existing, actor=actor, client=client)
            else:
                limits_service.update_limit(
                    session,
                    limit=existing,
                    changes={"credit_limit": request.previous_limit},
                    actor=actor,
                    client=client,
                )
            reverted += 1
            record_audit(
                session,
                action="credit_request.expired",
                actor=actor,
                target_type="credit_request",
                target_id=str(request.id),
                target_label=request.entity_label or request.entity_id,
                detail=(
                    f"Temporary grant expired; budget restored to "
                    f"{request.previous_limit if request.previous_limit is not None else 'none'}."
                ),
            )
        else:
            # The limit was changed (or removed) since the grant, so there is
            # nothing safe to undo. Record that we stood down.
            record_audit(
                session,
                action="credit_request.expired",
                actor=actor,
                target_type="credit_request",
                target_id=str(request.id),
                target_label=request.entity_label or request.entity_id,
                detail=(
                    "Temporary grant expired; the limit had changed since, so it was left as is."
                ),
            )
        request.reverted = True
    session.flush()
    return reverted
