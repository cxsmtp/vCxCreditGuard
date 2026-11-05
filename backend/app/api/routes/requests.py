"""Credit request & approval workflow.

A request asks to raise (or create) one entity's budget. Admins always see and
decide every request. A viewer may submit and track their own requests only when
an admin has turned self-service on; otherwise the endpoints are admin-only.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.models.enums import RequestStatus
from app.models.limits import CreditRequest
from app.schemas.requests import (
    RequestCreateRequest,
    RequestDecisionRequest,
    RequestResponse,
)
from app.services import connection as connection_service
from app.services import limits_service, requests_service, settings_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/requests", tags=["requests"])


def _to_response(request: CreditRequest) -> RequestResponse:
    return RequestResponse(
        id=request.id,
        entity_type=request.entity_type,  # type: ignore[arg-type]
        entity_id=request.entity_id,
        entity_label=request.entity_label,
        requested_limit=request.requested_limit,
        reason=request.reason,
        status=request.status,  # type: ignore[arg-type]
        requested_by_name=request.requested_by_name,
        requested_at=request.requested_at,
        decided_by_name=request.decided_by_name,
        decided_at=request.decided_at,
        decision_note=request.decision_note,
        approved_limit=request.approved_limit,
        previous_limit=request.previous_limit,
        expires_at=request.expires_at,
        reverted=request.reverted,
        created_at=request.created_at,
    )


@router.get("", response_model=list[RequestResponse])
def list_requests(
    ctx: CurrentUser,
    db: DbSession,
    request_status: RequestStatus | None = Query(default=None, alias="status"),
) -> list[RequestResponse]:
    query = select(CreditRequest).order_by(CreditRequest.created_at.desc())
    # A viewer only ever sees the requests they filed; an admin sees all of them.
    if not ctx.is_admin:
        query = query.where(CreditRequest.requested_by_id == ctx.user.id)
    if request_status is not None:
        query = query.where(CreditRequest.status == request_status)
    return [_to_response(row) for row in db.scalars(query)]


@router.post("", response_model=RequestResponse, status_code=status.HTTP_201_CREATED)
def create_request(
    payload: RequestCreateRequest, ctx: CurrentUser, db: DbSession
) -> RequestResponse:
    # Admins may always file one; a viewer needs self-service switched on.
    if not ctx.is_admin and not settings_store.self_service_requests_enabled(db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "self_service_disabled",
                "message": "Credit requests are not open to non-admins right now.",
            },
        )
    try:
        request = requests_service.create_request(
            db,
            data=requests_service.RequestInput(
                entity_type=payload.entity_type,
                entity_id=payload.entity_id,
                requested_limit=payload.requested_limit,
                reason=payload.reason,
            ),
            actor=ctx.actor,
        )
    except requests_service.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_request", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(request)


def _load_pending(db: Session, request_id: int) -> CreditRequest:
    request = db.get(CreditRequest, request_id)
    if request is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such request.")
    return request


@router.post("/{request_id}/approve", response_model=RequestResponse)
def approve_request(
    request_id: int, payload: RequestDecisionRequest, ctx: AdminUser, db: DbSession
) -> RequestResponse:
    request = _load_pending(db, request_id)
    try:
        requests_service.approve_request(
            db,
            request=request,
            actor=ctx.actor,
            approved_limit=payload.approved_limit,
            expires_at=payload.expires_at,
            note=payload.note,
            client=connection_service.optional_client(db),
        )
    except requests_service.RequestStateError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "not_pending", "message": str(exc)},
        ) from exc
    except (requests_service.RequestError, limits_service.LimitError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_decision", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(request)


@router.post("/{request_id}/deny", response_model=RequestResponse)
def deny_request(
    request_id: int, payload: RequestDecisionRequest, ctx: AdminUser, db: DbSession
) -> RequestResponse:
    request = _load_pending(db, request_id)
    try:
        requests_service.deny_request(db, request=request, actor=ctx.actor, note=payload.note)
    except requests_service.RequestStateError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "not_pending", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(request)
