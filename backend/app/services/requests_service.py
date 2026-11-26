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
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient
from app.db import locking
from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType, RequestStatus, Severity
from app.models.limits import CreditLimit, CreditRequest
from app.services import error_text, limits_service, notifications, settings_store
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


# Automatic approvals are capped in total over this long, per entity and per
# requester, not just per request.
AUTO_APPROVE_WINDOW = timedelta(days=30)
# How many undecided requests one non-admin may have open at once.
MAX_PENDING_PER_REQUESTER = 5


def create_request(
    session: Session, *, data: RequestInput, actor: AuditActor, is_admin: bool = True
) -> CreditRequest:
    if data.requested_limit < 0:
        raise RequestError("A requested limit cannot be negative.")
    # The checks below count pending requests, so two filed at the same moment
    # must not both count before either is written: one filing at a time.
    locking.serialize(session, locking.CREDIT_REQUEST_FILING_LOCK_KEY)
    # One open request per entity: a second one adds nothing an admin can act
    # on, and a stream of them is how a queue gets flooded.
    duplicate = session.scalar(
        select(CreditRequest.id).where(
            CreditRequest.entity_type == str(data.entity_type),
            CreditRequest.entity_id == data.entity_id,
            CreditRequest.status == RequestStatus.PENDING,
        )
    )
    if duplicate is not None:
        raise RequestError(
            "There is already a request waiting for a decision on this entity "
            f"(#{duplicate}). It has to be decided before another can be filed."
        )
    if not is_admin and actor.actor_id is not None:
        open_requests = session.scalar(
            select(func.count())
            .select_from(CreditRequest)
            .where(
                CreditRequest.requested_by_id == actor.actor_id,
                CreditRequest.status == RequestStatus.PENDING,
            )
        )
        if int(open_requests or 0) >= MAX_PENDING_PER_REQUESTER:
            raise RequestError(
                f"You already have {MAX_PENDING_PER_REQUESTER} requests waiting for a "
                "decision. Wait for those before filing more."
            )
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
    auto_approved_increase: int | None = None,
) -> CreditRequest:
    """Grant the request and apply the budget to the entity's limit.

    ``client`` lets the grant lift a restriction straight away: if raising the
    budget means an enforced limit no longer bites, the live Checkmarx restriction
    is reversed now rather than at the next cycle, which is the whole point of
    unblocking someone. Without a client the budget is still applied and the next
    cycle catches up.
    """
    # Locked and read again first: two decisions on one request at the same
    # moment (two admins, or an admin and the automation) must not both find it
    # pending, or it would be granted twice, or end up denied with its grant
    # applied.
    locking.lock_row(session, request)
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
            # lift=False: the restriction is lifted at the very end, once the
            # whole approval is written, so the approval commits as one unit.
            limits_service.update_limit(
                session,
                limit=existing,
                changes={"credit_limit": target},
                actor=actor,
                client=client,
                lift=False,
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
    request.auto_approved_increase = auto_approved_increase
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
    if existing is not None:
        # Unblock the entity now rather than at the next cycle. This commits the
        # approval above as a whole before it talks to Checkmarx.
        limits_service.lift_unjustified_restrictions(session, client, limit=existing, actor=actor)
    return request


def deny_request(
    session: Session, *, request: CreditRequest, actor: AuditActor, note: str | None = None
) -> CreditRequest:
    locking.lock_row(session, request)  # see approve_request
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


def auto_decide_pending(
    session: Session,
    *,
    client: CheckmarxClient | None = None,
    actor: AuditActor | None = None,
    policy: settings_store.AutomationPolicy | None = None,
) -> dict[str, int | bool]:
    """Hands-off automation: auto-approve pending requests within the policy cap.

    Approves only genuine raises whose increase over the entity's current budget
    is within ``auto_approve_max_increase`` credits; larger or non-raise requests
    are left for an admin. At most one request per entity is auto-approved per
    cycle, so several small requests for one entity cannot be compounded past the
    cap in a single run (the rest wait for the next cycle or an admin). Auto-grants
    are made temporary when ``auto_approve_expiry_days`` is set, so they self-revert
    through the existing grant-expiry step. Each decision is audited (via
    ``approve_request``) and surfaced in the Notification Center.

    Concurrency: this runs inside the cycle, which is serialised by the scheduler
    lock, so it is effectively single-writer. The 30-minute stale-lock reclaim and
    a simultaneous manual admin approval are the same pre-existing cycle-level race
    the rest of the pipeline lives with; the per-request savepoint below limits the
    blast radius to one request rather than the batch.
    """
    policy = policy or settings_store.automation_policy(session)
    if not policy.auto_approves:
        return {"enabled": policy.enabled, "auto_approved": 0, "considered": 0}

    actor = actor or AuditActor.system("automation")
    pending = list(
        session.scalars(
            select(CreditRequest)
            .where(CreditRequest.status == RequestStatus.PENDING)
            .order_by(CreditRequest.id.asc())
        )
    )
    approved = 0
    left_pending = 0
    failed = 0
    # Entities already auto-granted this cycle. Because approving one request
    # raises the entity's limit, measuring the next request's increase against
    # that raised limit would let several per-cap requests compound past the cap
    # in one cycle; allowing only one auto-grant per entity per cycle closes that.
    granted_entities: set[tuple[str, str]] = set()
    for request in pending:
        entity_key = (request.entity_type, request.entity_id)
        if entity_key in granted_entities:
            left_pending += 1
            continue
        existing = _existing_limit(session, request)
        current = existing.credit_limit if existing is not None else 0
        increase = request.requested_limit - current
        # Only auto-approve a genuine raise whose size is within the cap...
        if increase <= 0 or increase > policy.auto_approve_max_increase:
            left_pending += 1
            continue
        # ...and only while the cap also holds for everything automation has
        # already granted recently, to this entity and at this requester's
        # asking. Otherwise the same small raise, requested again each cycle,
        # walks a budget up without limit, and anyone allowed to file requests
        # can do that for any entity they like.
        allowance = policy.auto_approve_max_increase - max(
            _auto_granted_recently(
                session,
                CreditRequest.entity_type == request.entity_type,
                CreditRequest.entity_id == request.entity_id,
            ),
            _auto_granted_recently(
                session, CreditRequest.requested_by_id == request.requested_by_id
            )
            if request.requested_by_id is not None
            else 0,
        )
        if increase > allowance:
            left_pending += 1
            continue

        expires_at = (
            utcnow() + timedelta(days=policy.auto_approve_expiry_days)
            if policy.auto_approve_expiry_days > 0
            else None
        )
        window = f" for {policy.auto_approve_expiry_days} day(s)" if expires_at is not None else ""
        # Each grant is its own transaction, so one failure rolls back only that
        # request and the batch continues, rather than half-applying a grant or
        # poisoning the cycle. (Not a savepoint: lifting a restriction commits as
        # it goes, which a savepoint cannot contain.)
        request_id = request.id
        try:
            approve_request(
                session,
                request=request,
                actor=actor,
                expires_at=expires_at,
                note=(
                    f"Auto-approved by hands-off automation: an increase of {increase} "
                    f"credit(s) is within the {policy.auto_approve_max_increase}-credit "
                    f"cap{window}."
                ),
                client=client,
                auto_approved_increase=increase,
            )
            session.commit()
        except RequestStateError:
            # Decided by an admin since the list above was read.
            session.rollback()
            continue
        except Exception:
            session.rollback()
            logger.exception("Auto-approval of credit request %s failed", request_id)
            failed += 1
            continue

        # Raised after the grant is safely committed.
        notifications.notify(
            session,
            category="automation",
            severity=Severity.INFO,
            title="Credit request auto-approved",
            body=(
                f"Request #{request.id} for "
                f"{request.entity_label or request.entity_id} was auto-approved at "
                f"{request.requested_limit} credits{window} under hands-off automation."
            ),
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            entity_label=request.entity_label,
            dedupe_key=f"auto-approve:{request.id}",
        )
        session.commit()
        granted_entities.add(entity_key)
        approved += 1

    return {
        "enabled": True,
        "considered": len(pending),
        "auto_approved": approved,
        "left_pending": left_pending,
        "failed": failed,
    }


def _auto_granted_recently(session: Session, *conditions) -> int:  # type: ignore[no-untyped-def]
    """Credits automation has granted, within the window, to the matching requests."""
    total = session.scalar(
        select(func.coalesce(func.sum(CreditRequest.auto_approved_increase), 0)).where(
            CreditRequest.auto_approved_increase.is_not(None),
            CreditRequest.decided_at >= utcnow() - AUTO_APPROVE_WINDOW,
            *conditions,
        )
    )
    return int(total or 0)


class GrantExpiryError(RuntimeError):
    """Some expired grants could not be rolled back this time."""


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
    failures: list[str] = []
    for request in list(rows):
        # One transaction per grant: a rollback that cannot be completed (Checkmarx
        # refusing to lift a restriction, say) is retried next cycle and does not
        # stop the other expired grants from being rolled back.
        request_id = request.id
        try:
            if _revert_one_grant(session, request, actor=actor, client=client):
                reverted += 1
            session.commit()
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            logger.exception("Rolling back expired grant %s failed", request_id)
            failures.append(f"request {request_id}: {error_text.public_error(exc)}")
    if failures:
        raise GrantExpiryError(
            f"{len(failures)} expired grant(s) could not be rolled back and will be "
            f"retried: {'; '.join(failures)}"
        )
    return reverted


def _revert_one_grant(
    session: Session,
    request: CreditRequest,
    *,
    actor: AuditActor,
    client: CheckmarxClient | None,
) -> bool:
    """Roll back one expired grant. Returns True if the budget was changed."""
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
        detail = (
            f"Temporary grant expired; budget restored to "
            f"{request.previous_limit if request.previous_limit is not None else 'none'}."
        )
    else:
        # The limit was changed (or removed) since the grant, so there is
        # nothing safe to undo. Record that we stood down.
        detail = "Temporary grant expired; the limit had changed since, so it was left as is."
    record_audit(
        session,
        action="credit_request.expired",
        actor=actor,
        target_type="credit_request",
        target_id=str(request.id),
        target_label=request.entity_label or request.entity_id,
        detail=detail,
    )
    request.reverted = True
    session.flush()
    return unchanged
