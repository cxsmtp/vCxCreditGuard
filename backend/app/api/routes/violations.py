"""Policy violations: what was done against a restriction in force.

Admins only: a violation names people and what they did, and acting on it
(acknowledge, resolve) is an admin's decision. Viewers get 403, and the SPA
does not offer the page to them.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, or_, select

from app.api.deps import AdminUser, DbSession
from app.models.limits import CreditLimit
from app.models.violations import KINDS, STATUSES, PolicyViolation
from app.schemas.violations import (
    ViolationListResponse,
    ViolationResponse,
    ViolationStatusRequest,
)
from app.services import violations as violations_service

router = APIRouter(prefix="/violations", tags=["violations"])
MAX_ROWS = 500


def _utc(moment: datetime) -> datetime:
    """A query time as aware UTC; one given without a zone is taken as UTC."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _to_response(row: PolicyViolation, db=None) -> ViolationResponse:  # type: ignore[no-untyped-def]
    limit = db.get(CreditLimit, row.limit_id) if db is not None and row.limit_id else None
    return ViolationResponse(
        limit_entity_type=limit.entity_type if limit is not None else None,
        limit_entity_id=limit.entity_id if limit is not None else None,
        id=row.id,
        kind=row.kind,
        kind_label=violations_service.KIND_LABELS.get(row.kind, row.kind),
        detected_at=row.detected_at,
        updated_at=row.updated_at,
        limit_id=row.limit_id,
        limit_label=row.limit_label,
        enforcement_action_id=row.enforcement_action_id,
        target_type=row.target_type,
        target_id=row.target_id,
        target_label=row.target_label,
        actor=row.actor,
        source=row.source,
        detail=row.detail,
        evidence=row.evidence,
        credits=row.credits,
        severity=row.severity,
        status=row.status,
        acknowledged_by=row.acknowledged_by,
        acknowledged_at=row.acknowledged_at,
        resolved_by=row.resolved_by,
        resolved_at=row.resolved_at,
        note=row.note,
    )


@router.get("", response_model=ViolationListResponse)
def list_violations(
    ctx: AdminUser,
    db: DbSession,
    status_filter: str | None = Query(default=None, alias="status", max_length=16),
    kind: str | None = Query(default=None, max_length=48),
    target: str | None = Query(default=None, max_length=128),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=200, ge=1, le=MAX_ROWS),
) -> ViolationListResponse:
    if status_filter is not None and status_filter not in STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_status", "message": f"status must be one of {STATUSES}."},
        )
    if kind is not None and kind not in KINDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_kind", "message": f"kind must be one of {KINDS}."},
        )
    query = select(PolicyViolation)
    if status_filter:
        query = query.where(PolicyViolation.status == status_filter)
    if kind:
        query = query.where(PolicyViolation.kind == kind)
    if target:
        pattern = f"%{target.strip()}%"
        query = query.where(
            or_(
                PolicyViolation.target_id == target.strip(),
                PolicyViolation.target_label.ilike(pattern),
            )
        )
    if since is not None:
        query = query.where(PolicyViolation.detected_at >= _utc(since))
    if until is not None:
        query = query.where(PolicyViolation.detected_at < _utc(until))
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(PolicyViolation.detected_at.desc(), PolicyViolation.id.desc()).limit(limit)
    )
    return ViolationListResponse(
        items=[_to_response(row, db) for row in rows],
        total=total,
        open=violations_service.open_count(db),
    )


def _get(db, violation_id: int) -> PolicyViolation:  # type: ignore[no-untyped-def]
    row = db.get(PolicyViolation, violation_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such violation.")
    return row


@router.get("/{violation_id}", response_model=ViolationResponse)
def get_violation(violation_id: int, ctx: AdminUser, db: DbSession) -> ViolationResponse:
    return _to_response(_get(db, violation_id), db)


@router.post("/{violation_id}/acknowledge", response_model=ViolationResponse)
def acknowledge_violation(
    violation_id: int,
    ctx: AdminUser,
    db: DbSession,
    payload: ViolationStatusRequest | None = None,
) -> ViolationResponse:
    row = _get(db, violation_id)
    try:
        violations_service.acknowledge(
            db,
            row,
            actor=ctx.actor,
            note=(payload.note.strip() if payload and payload.note else None),
        )
    except violations_service.ViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "invalid_transition", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(row, db)


@router.post("/{violation_id}/resolve", response_model=ViolationResponse)
def resolve_violation(
    violation_id: int,
    ctx: AdminUser,
    db: DbSession,
    payload: ViolationStatusRequest | None = None,
) -> ViolationResponse:
    row = _get(db, violation_id)
    try:
        violations_service.resolve(
            db,
            row,
            actor=ctx.actor,
            note=(payload.note.strip() if payload and payload.note else None),
        )
    except violations_service.ViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "invalid_transition", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(row, db)
