"""Notification Center, including the one click restore."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, or_, select

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx.errors import CheckmarxError
from app.models.audit import Notification
from app.models.enums import Severity
from app.models.limits import EnforcementAction
from app.schemas.limits import (
    EnforcementActionPage,
    EnforcementActionResponse,
    MarkReadRequest,
    NotificationListResponse,
    NotificationResponse,
)
from app.services import connection as connection_service
from app.services import enforcement
from app.services import notifications as notification_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/notifications", tags=["notifications"])


def _to_response(notification: Notification, *, can_restore: bool) -> NotificationResponse:
    return NotificationResponse(
        id=notification.id,
        created_at=notification.created_at,
        severity=notification.severity,  # type: ignore[arg-type]
        category=notification.category,
        entity_type=notification.entity_type,
        entity_id=notification.entity_id,
        entity_label=notification.entity_label,
        title=notification.title,
        body=notification.body,
        read_at=notification.read_at,
        enforcement_action_id=notification.enforcement_action_id,
        can_restore=can_restore,
    )


@router.get("", response_model=NotificationListResponse)
def list_notifications(
    ctx: CurrentUser,
    db: DbSession,
    severity: Severity | None = None,
    category: str | None = Query(default=None, max_length=32),
    entity_type: str | None = Query(default=None, max_length=16),
    unread_only: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> NotificationListResponse:
    query = select(Notification)
    count_query = select(func.count()).select_from(Notification)
    for condition in (
        Notification.severity == severity if severity is not None else None,
        Notification.category == category if category is not None else None,
        Notification.entity_type == entity_type if entity_type is not None else None,
        Notification.read_at.is_(None) if unread_only else None,
    ):
        if condition is not None:
            query = query.where(condition)
            count_query = count_query.where(condition)

    total = int(db.scalar(count_query) or 0)
    rows = list(
        db.scalars(query.order_by(Notification.created_at.desc()).limit(limit).offset(offset))
    )

    # Only actions that are, or may still be, in force can be restored.
    action_ids = [row.enforcement_action_id for row in rows if row.enforcement_action_id]
    restorable: set[int] = set()
    if action_ids:
        restorable = {
            action.id
            for action in db.scalars(
                select(EnforcementAction).where(
                    EnforcementAction.id.in_(action_ids),
                    EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES),
                )
            )
            if enforcement.may_be_in_force(action)
        }

    return NotificationListResponse(
        items=[
            _to_response(row, can_restore=bool(row.enforcement_action_id in restorable))
            for row in rows
        ],
        total=total,
        unread=notification_service.unread_count(db),
    )


@router.post("/read")
def mark_read(payload: MarkReadRequest, ctx: CurrentUser, db: DbSession) -> dict[str, int]:
    marked = notification_service.mark_read(db, notification_ids=payload.notification_ids)
    db.commit()
    return {"marked_read": marked}


@router.get("/enforcements", response_model=list[EnforcementActionResponse])
def list_enforcements(
    ctx: CurrentUser,
    db: DbSession,
    only_active: bool = True,
    limit: int = Query(default=200, ge=1, le=1000),
) -> list[EnforcementActionResponse]:
    if only_active:
        # "Active" includes a restriction whose outcome was never confirmed: it
        # may be in place in Checkmarx, and this is where an admin can undo it.
        # Only those count towards ``limit``.
        rows = enforcement.active_actions(db, limit=limit)
    else:
        rows = list(
            db.scalars(
                select(EnforcementAction)
                .order_by(EnforcementAction.created_at.desc(), EnforcementAction.id.desc())
                .limit(limit)
            )
        )
    return [_action_response(row) for row in rows]


def _action_response(row: EnforcementAction) -> EnforcementActionResponse:
    return EnforcementActionResponse(
        id=row.id,
        kind=row.kind,
        status=row.status,
        entity_type=row.entity_type,  # type: ignore[arg-type]
        entity_id=row.entity_id,
        entity_label=row.entity_label,
        target_type=row.target_type,
        target_id=row.target_id,
        target_label=row.target_label,
        period_key=row.period_key,
        created_at=row.created_at,
        applied_at=row.applied_at,
        reversed_at=row.reversed_at,
        reversal_reason=row.reversal_reason,
        error=row.error,
    )


@router.get("/enforcements/page", response_model=EnforcementActionPage)
def page_enforcements(
    ctx: CurrentUser,
    db: DbSession,
    only_active: bool = True,
    q: str = Query(default="", max_length=200),
    kind: str | None = Query(default=None, max_length=32),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
) -> EnforcementActionPage:
    """Restrictions, newest first, a page at a time, searchable.

    For a tenant with thousands of restrictions in force: the list is filtered
    and counted in the database, and only one page is sent.
    """
    query = select(EnforcementAction.id, EnforcementAction.status, EnforcementAction.kind).order_by(
        EnforcementAction.created_at.desc(), EnforcementAction.id.desc()
    )
    if only_active:
        query = query.where(EnforcementAction.status.in_(enforcement.RESTORABLE_STATUSES))
    term = q.strip()
    if term:
        pattern = f"%{term}%"
        query = query.where(
            or_(
                EnforcementAction.target_label.ilike(pattern),
                EnforcementAction.target_id.ilike(pattern),
                EnforcementAction.entity_label.ilike(pattern),
                EnforcementAction.entity_id.ilike(pattern),
            )
        )
    if kind:
        query = query.where(EnforcementAction.kind == kind)
    rows = db.execute(query).all()
    if only_active:
        # A pending or failed attempt counts only when it may be in force,
        # which its snapshot says: read for those rows alone (there are few).
        unsettled = [row.id for row in rows if row.status != "applied"]
        in_force: set[int] = set()
        for start in range(0, len(unsettled), 1000):
            in_force.update(
                action.id
                for action in db.scalars(
                    select(EnforcementAction).where(
                        EnforcementAction.id.in_(unsettled[start : start + 1000])
                    )
                )
                if enforcement.may_be_in_force(action)
            )
        rows = [row for row in rows if row.status == "applied" or row.id in in_force]
    by_kind: dict[str, int] = {}
    for row in rows:
        by_kind[row.kind] = by_kind.get(row.kind, 0) + 1
    page_ids = [row.id for row in rows[offset : offset + limit]]
    found = (
        {
            action.id: action
            for action in db.scalars(
                select(EnforcementAction).where(EnforcementAction.id.in_(page_ids))
            )
        }
        if page_ids
        else {}
    )
    return EnforcementActionPage(
        items=[_action_response(found[action_id]) for action_id in page_ids if action_id in found],
        total=len(rows),
        offset=offset,
        limit=limit,
        by_kind=by_kind,
    )


@router.post("/enforcements/{action_id}/restore")
def restore_access(action_id: int, ctx: AdminUser, db: DbSession) -> dict[str, object]:
    """Reverse one enforcement action from its recorded snapshot.

    Deliberately does not also change the limit. Restoring access and deciding
    whether the budget was wrong are two separate calls, and the runbook tells the
    admin to do both.
    """
    action = db.get(EnforcementAction, action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No such enforcement action."
        )
    if not enforcement.may_be_in_force(action):
        return {
            "restored": False,
            "message": f"This action is already {action.status}, so there is nothing to undo.",
        }

    try:
        client = connection_service.get_client(db)
    except CheckmarxError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "no_connection",
                "message": f"Cannot reach Checkmarx One to restore access: {exc}",
            },
        ) from exc

    try:
        restored = enforcement.restore_action(
            db, client, action=action, actor=ctx.actor, reason=enforcement.ADMIN_REASON
        )
    except CheckmarxError as exc:
        db.commit()  # keep the failure notification and audit entry
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "code": "restore_failed",
                "message": (
                    f"{exc} The previous state is recorded in the audit log, so you can "
                    "restore it manually in Checkmarx One."
                ),
            },
        ) from exc

    db.commit()
    return {
        "restored": restored,
        "message": f"Access restored for {action.target_label or action.target_id}.",
    }
