"""Dashboard, entity search, audit log and the SPA bootstrap endpoint."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, or_, select

from app import __version__, scheduler
from app.api.deps import AdminUser, CurrentUser, DbSession
from app.db.base import utcnow
from app.models.audit import AuditLogEntry
from app.models.connection import CxConnection
from app.models.enums import ConnectionStatus, EnforcementStatus, EntityType, UsageView
from app.models.limits import CreditLimit, EnforcementAction, Exemption
from app.models.org import CxApplication, CxGroup, CxProject, CxUser
from app.models.usage import SchedulerRun, UnresolvedSubject
from app.schemas.dashboard import (
    ActionBreakdownItem,
    AuditEntryResponse,
    AuditListResponse,
    DashboardResponse,
    MapSubjectRequest,
    MeResponse,
    OrgEntity,
    StatusTiles,
    TopConsumerItem,
    TrendPoint,
    UnresolvedSubjectResponse,
)
from app.services import dashboard as dashboard_service
from app.services import notifications as notification_service
from app.services import settings_store
from app.services.audit import record_audit

logger = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])

_ENTITY_MODELS = {
    EntityType.USER: CxUser,
    EntityType.GROUP: CxGroup,
    EntityType.PROJECT: CxProject,
    EntityType.APPLICATION: CxApplication,
}


@router.get("/me", response_model=MeResponse)
def me(ctx: CurrentUser, db: DbSession) -> MeResponse:
    """Bootstrap payload for the SPA: who you are and whether setup is done."""
    connection = db.scalar(select(CxConnection).limit(1))
    return MeResponse(
        username=ctx.user.username,
        role=ctx.user.role,  # type: ignore[arg-type]
        totp_enabled=ctx.user.totp_enabled,
        must_change_password=ctx.user.must_change_password,
        connection_configured=connection is not None,
        connection_status=connection.status if connection else ConnectionStatus.UNCONFIGURED,
        tenant_name=connection.tenant_name if connection else None,
        version=__version__,
        # Drives the redirect to Setup on first login.
        setup_required=connection is None,
    )


def _to_consumer(consumer) -> TopConsumerItem:  # type: ignore[no-untyped-def]
    return TopConsumerItem(
        entity_type=consumer.entity_type,
        entity_id=consumer.entity_id,
        label=consumer.label,
        credits=consumer.credits,
        percent_of_total=consumer.percent_of_total,
        limit=consumer.limit,
        limit_id=consumer.limit_id,
        credits_used_in_period=consumer.credits_used_in_period,
        status=consumer.status,
        resolved=consumer.resolved,
    )


@router.get("/dashboard", response_model=DashboardResponse)
def get_dashboard(
    ctx: CurrentUser,
    db: DbSession,
    top: int = Query(default=10, ge=1, le=50),
    trend_points: int = Query(default=60, ge=2, le=500),
) -> DashboardResponse:
    total, collected_at = dashboard_service.tenant_total(db)
    warned, restricted = dashboard_service.warning_and_restriction_counts(db)

    last_run = db.scalar(select(SchedulerRun).order_by(SchedulerRun.started_at.desc()).limit(1))
    last_success = db.scalar(
        select(SchedulerRun.finished_at)
        .where(SchedulerRun.status.in_(["success", "partial"]))
        .order_by(SchedulerRun.started_at.desc())
        .limit(1)
    )
    active_restrictions = int(
        db.scalar(
            select(func.count())
            .select_from(EnforcementAction)
            .where(EnforcementAction.status == EnforcementStatus.APPLIED)
        )
        or 0
    )
    limits_configured = int(db.scalar(select(func.count()).select_from(CreditLimit)) or 0)
    limits_enforcing = int(
        db.scalar(
            select(func.count())
            .select_from(CreditLimit)
            .where(CreditLimit.enforce.is_(True), CreditLimit.is_active.is_(True))
        )
        or 0
    )
    unresolved = int(
        db.scalar(
            select(func.count())
            .select_from(UnresolvedSubject)
            .where(UnresolvedSubject.mapped_user_id.is_(None))
        )
        or 0
    )

    return DashboardResponse(
        generated_at=utcnow(),
        period_label=dashboard_service.period_label(db),
        lookback_window=settings_store.usage_period(db),
        tenant_total_credits=total,
        collected_at=collected_at,
        breakdown=[
            ActionBreakdownItem(
                action_type=item.action_type,
                credits=item.credits,
                transactions=item.transactions,
                percent_of_total=item.percent_of_total,
            )
            for item in dashboard_service.action_breakdown(db)
        ],
        trend=[
            TrendPoint(collected_at=point[0], cumulative_credits=point[1], delta_credits=point[2])
            for point in dashboard_service.trend(db, points=trend_points)
        ],
        top_users=[_to_consumer(item) for item in dashboard_service.top_users(db, limit=top)],
        top_projects=[_to_consumer(item) for item in dashboard_service.top_projects(db, limit=top)],
        top_groups=[_to_consumer(item) for item in dashboard_service.top_groups(db, limit=top)],
        top_applications=[
            _to_consumer(item) for item in dashboard_service.top_applications(db, limit=top)
        ],
        tiles=StatusTiles(
            entities_in_warning=warned,
            entities_restricted=restricted,
            active_restrictions=active_restrictions,
            unresolved_subjects=unresolved,
            unread_notifications=notification_service.unread_count(db),
            limits_configured=limits_configured,
            limits_enforcing=limits_enforcing,
            next_run_at=scheduler.next_run_time(),
            last_success_at=last_success,
            last_run_status=last_run.status if last_run else None,
            schedule=scheduler.describe_schedule(),
        ),
        unavailable_dimensions=dashboard_service.unavailable_dimensions(db),
    )


@router.get("/org/entities", response_model=list[OrgEntity])
def search_entities(
    ctx: CurrentUser,
    db: DbSession,
    entity_type: EntityType,
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=25, ge=1, le=100),
    include_deleted: bool = False,
) -> list[OrgEntity]:
    """Entity picker for the Limits page, backed by the synced org model."""
    model = _ENTITY_MODELS[entity_type]
    query = select(model)
    if not include_deleted:
        query = query.where(model.is_deleted.is_(False))

    term = q.strip()
    if term:
        pattern = f"%{term}%"
        if entity_type == EntityType.USER:
            query = query.where(
                or_(
                    CxUser.username.ilike(pattern),
                    CxUser.email.ilike(pattern),
                    CxUser.first_name.ilike(pattern),
                    CxUser.last_name.ilike(pattern),
                )
            )
        else:
            query = query.where(model.name.ilike(pattern))

    rows = list(db.scalars(query.limit(limit)))
    entity_ids = [row.id for row in rows]
    limited = set(
        db.scalars(
            select(CreditLimit.entity_id).where(
                CreditLimit.entity_type == entity_type,
                CreditLimit.entity_id.in_(entity_ids),
            )
        )
    )
    exempt = set(
        db.scalars(
            select(Exemption.entity_id).where(
                Exemption.entity_type == entity_type, Exemption.entity_id.in_(entity_ids)
            )
        )
    )

    entities: list[OrgEntity] = []
    for row in rows:
        if entity_type == EntityType.USER:
            label = row.display_name
            secondary = row.email or row.username
        elif entity_type == EntityType.GROUP:
            label = row.name
            secondary = row.path
        else:
            label = row.name
            secondary = getattr(row, "repo_url", None) or getattr(row, "description", None)
        entities.append(
            OrgEntity(
                entity_type=entity_type,
                entity_id=row.id,
                label=label,
                secondary=secondary,
                has_limit=row.id in limited,
                is_exempt=row.id in exempt,
                is_deleted=row.is_deleted,
            )
        )
    entities.sort(key=lambda entity: entity.label.lower())
    return entities


@router.get("/audit", response_model=AuditListResponse)
def list_audit(
    ctx: CurrentUser,
    db: DbSession,
    action: str | None = Query(default=None, max_length=64),
    target_type: str | None = Query(default=None, max_length=32),
    target_id: str | None = Query(default=None, max_length=64),
    actor: str | None = Query(default=None, max_length=128),
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditListResponse:
    query = select(AuditLogEntry)
    count_query = select(func.count()).select_from(AuditLogEntry)

    conditions = []
    if action:
        conditions.append(AuditLogEntry.action == action)
    if target_type:
        conditions.append(AuditLogEntry.target_type == target_type)
    if target_id:
        conditions.append(AuditLogEntry.target_id == target_id)
    if actor:
        conditions.append(AuditLogEntry.actor_name == actor)
    if q:
        pattern = f"%{q.strip()}%"
        conditions.append(
            or_(
                AuditLogEntry.target_label.ilike(pattern),
                AuditLogEntry.detail.ilike(pattern),
                AuditLogEntry.action.ilike(pattern),
            )
        )
    for condition in conditions:
        query = query.where(condition)
        count_query = count_query.where(condition)

    total = int(db.scalar(count_query) or 0)
    rows = list(
        db.scalars(query.order_by(AuditLogEntry.occurred_at.desc()).limit(limit).offset(offset))
    )
    known_actions = sorted(set(db.scalars(select(AuditLogEntry.action).distinct())))

    return AuditListResponse(
        items=[
            AuditEntryResponse(
                id=row.id,
                occurred_at=row.occurred_at,
                actor_type=row.actor_type,  # type: ignore[arg-type]
                actor_name=row.actor_name,
                action=row.action,
                target_type=row.target_type,
                target_id=row.target_id,
                target_label=row.target_label,
                before=row.before,
                after=row.after,
                detail=row.detail,
                ip_address=row.ip_address,
            )
            for row in rows
        ],
        total=total,
        actions=known_actions,
    )


@router.get("/usage/unresolved", response_model=list[UnresolvedSubjectResponse])
def list_unresolved(ctx: CurrentUser, db: DbSession) -> list[UnresolvedSubjectResponse]:
    rows = list(
        db.scalars(select(UnresolvedSubject).order_by(UnresolvedSubject.credits_used.desc()))
    )
    responses: list[UnresolvedSubjectResponse] = []
    for row in rows:
        label = None
        if row.mapped_user_id:
            user = db.get(CxUser, row.mapped_user_id)
            label = user.display_name if user else row.mapped_user_id
        responses.append(
            UnresolvedSubjectResponse(
                id=row.id,
                subject_key=row.subject_key,
                subject_name=row.subject_name,
                subject_email=row.subject_email,
                credits_used=row.credits_used,
                first_seen_at=row.first_seen_at,
                last_seen_at=row.last_seen_at,
                times_seen=row.times_seen,
                mapped_user_id=row.mapped_user_id,
                mapped_user_label=label,
            )
        )
    return responses


@router.post("/usage/unresolved/{subject_id}/map", response_model=UnresolvedSubjectResponse)
def map_unresolved(
    subject_id: int, payload: MapSubjectRequest, ctx: AdminUser, db: DbSession
) -> UnresolvedSubjectResponse:
    """Pin an unmatched consumption subject to a known user.

    From the next poll onwards its credits count towards that user's limits. This
    is the fix for a user whose AI actions are reported under a different address
    than their IAM email.
    """
    row = db.get(UnresolvedSubject, subject_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such subject.")

    user = None
    if payload.user_id:
        user = db.get(CxUser, payload.user_id)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "unknown_user",
                    "message": "That user is not in the synced organisation model.",
                },
            )

    before = {"mapped_user_id": row.mapped_user_id}
    row.mapped_user_id = payload.user_id
    db.flush()
    record_audit(
        db,
        action="usage.subject_mapped",
        actor=ctx.actor,
        target_type="unresolved_subject",
        target_id=str(row.id),
        target_label=row.subject_key,
        before=before,
        after={"mapped_user_id": row.mapped_user_id},
        detail=(
            f"Credit usage reported as {row.subject_key} now counts towards "
            f"{user.display_name if user else 'nobody'}."
        ),
    )
    db.commit()

    return UnresolvedSubjectResponse(
        id=row.id,
        subject_key=row.subject_key,
        subject_name=row.subject_name,
        subject_email=row.subject_email,
        credits_used=row.credits_used,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        times_seen=row.times_seen,
        mapped_user_id=row.mapped_user_id,
        mapped_user_label=user.display_name if user else None,
    )


@router.get("/usage/dimensions")
def usage_dimensions(ctx: CurrentUser, db: DbSession) -> dict[str, object]:
    """Which consumption dimensions this tenant supports, and why not."""
    from app.models.usage import DimensionState

    states = {row.view_by: row for row in db.scalars(select(DimensionState))}
    return {
        str(view): {
            "supported": states[str(view)].supported if str(view) in states else None,
            "last_checked_at": states[str(view)].last_checked_at if str(view) in states else None,
            "last_error": states[str(view)].last_error if str(view) in states else None,
        }
        for view in (UsageView.USER, UsageView.ACTION, UsageView.APPLICATION, UsageView.PROJECT)
    }
