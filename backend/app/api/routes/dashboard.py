"""Dashboard, entity search, audit log and the SPA bootstrap endpoint."""

from __future__ import annotations

import logging
from decimal import Decimal

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
from app.models.usage import (
    AutoTriageCharge,
    SchedulerRun,
    UnresolvedSubject,
    UsageRecord,
    UsageSnapshot,
)
from app.schemas.dashboard import (
    ActionBreakdownItem,
    AuditEntryResponse,
    AuditListResponse,
    AutoTriageAttributionOverview,
    AutoTriageChargeResponse,
    AutoTriageInitiator,
    AutoTriageProjectAttribution,
    AutoTriageUserAttribution,
    AutoTriageUserPart,
    CreditPoolInfo,
    DashboardResponse,
    MapSubjectRequest,
    MeResponse,
    OrgEntity,
    StatusTiles,
    SubjectSuggestion,
    TopConsumerItem,
    TrendPoint,
    UnresolvedSubjectResponse,
)
from app.services import auto_triage_attribution, key_permissions, settings_store, violations
from app.services import dashboard as dashboard_service
from app.services import notifications as notification_service
from app.services.audit import record_audit

logger = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])

_ENTITY_MODELS = {
    EntityType.USER: CxUser,
    EntityType.GROUP: CxGroup,
    EntityType.PROJECT: CxProject,
    EntityType.APPLICATION: CxApplication,
}


def _pause_reason(db) -> str | None:  # type: ignore[no-untyped-def]
    guard = settings_store.enforcement_guard(db)
    if not guard.paused:
        return None
    return guard.pause_reason or "Paused by an administrator."


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
        ui_accent=settings_store.ui_accent(db),
        can_request_credits=(ctx.is_admin or settings_store.self_service_requests_enabled(db)),
        demo_mode=settings_store.demo_mode(db),
        enforcement_paused=_pause_reason(db),
        key_permissions=key_permissions.summary(db) if connection is not None else None,
        open_violations=violations.open_count(db) if ctx.is_admin else None,
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
        auto_triage_attributed=consumer.auto_triage_attributed,
    )


def _pool_info(pool) -> CreditPoolInfo:  # type: ignore[no-untyped-def]
    return CreditPoolInfo(
        total=pool.total,
        used=pool.used,
        available=pool.available,
        collected_at=pool.collected_at,
        assigned=pool.assigned,
        over_allocation=pool.over_allocation,
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
    # Subjects whose credits count towards nobody: not mapped by an admin, not
    # auto-matched, and not automation handles. Auto-matched rows are attributed
    # (just not manually), so they do not belong in the "unmatched" banner.
    unresolved = int(
        db.scalar(
            select(func.count())
            .select_from(UnresolvedSubject)
            .where(
                UnresolvedSubject.mapped_user_id.is_(None),
                UnresolvedSubject.status != "auto_matched",
                UnresolvedSubject.is_bot.is_(False),
                UnresolvedSubject.view_by != auto_triage_attribution.SOURCE_SCAN_INITIATOR,
            )
        )
        or 0
    )
    unresolved_initiators = (
        int(
            db.scalar(
                select(func.count())
                .select_from(UnresolvedSubject)
                .where(
                    UnresolvedSubject.mapped_user_id.is_(None),
                    UnresolvedSubject.status != "auto_matched",
                    UnresolvedSubject.is_bot.is_(False),
                    UnresolvedSubject.view_by == auto_triage_attribution.SOURCE_SCAN_INITIATOR,
                )
            )
            or 0
        )
        if settings_store.auto_triage_to_initiator(db)
        else 0
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
            unresolved_scan_initiators=unresolved_initiators,
        ),
        unavailable_dimensions=dashboard_service.unavailable_dimensions(db),
        credit_pool=_pool_info(dashboard_service.credit_pool(db)),
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

    # Ordered before the cut, so the first ``limit`` matches are always the same
    # ones (a tenant can have thousands: the picker asks the user to type more).
    order = CxUser.username if entity_type == EntityType.USER else model.name
    rows = list(db.scalars(query.order_by(order, model.id).limit(limit)))
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
                entry_hash=row.entry_hash,
            )
            for row in rows
        ],
        total=total,
        actions=known_actions,
    )


def _subject_response(db, row: UnresolvedSubject) -> UnresolvedSubjectResponse:  # type: ignore[no-untyped-def]
    """Serialise a subject, resolving user ids to display names as we go."""

    def label_for(user_id: str | None) -> str | None:
        if not user_id:
            return None
        user = db.get(CxUser, user_id)
        return user.display_name if user else user_id

    mapped_label = label_for(row.mapped_user_id)
    suggested_label = label_for(row.suggested_user_id)
    suggestions = [
        SubjectSuggestion(
            user_id=str(entry.get("user_id")),
            label=str(entry.get("label") or entry.get("user_id")),
            score=float(entry.get("score") or 0.0),
        )
        for entry in (row.suggestions or [])
        if isinstance(entry, dict) and entry.get("user_id")
    ]

    # What actually counts today: an admin mapping wins, then an auto-match.
    if row.mapped_user_id:
        counts_id, counts_label = row.mapped_user_id, mapped_label
    elif row.status == "auto_matched" and row.suggested_user_id:
        counts_id, counts_label = row.suggested_user_id, suggested_label
    else:
        counts_id, counts_label = None, None

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
        mapped_user_label=mapped_label,
        status=row.status,
        is_bot=row.is_bot,
        match_score=row.match_score,
        suggested_user_id=row.suggested_user_id,
        suggested_user_label=suggested_label,
        suggestions=suggestions,
        counts_towards_user_id=counts_id,
        counts_towards_label=counts_label,
        source=(
            auto_triage_attribution.SOURCE_SCAN_INITIATOR
            if row.view_by == auto_triage_attribution.SOURCE_SCAN_INITIATOR
            else "consumption"
        ),
    )


@router.get("/usage/unresolved", response_model=list[UnresolvedSubjectResponse])
def list_unresolved(ctx: CurrentUser, db: DbSession) -> list[UnresolvedSubjectResponse]:
    rows = list(
        db.scalars(select(UnresolvedSubject).order_by(UnresolvedSubject.credits_used.desc()))
    )
    return [_subject_response(db, row) for row in rows]


def _reattribute_latest_snapshot(db, subject_key: str, user_id: str | None) -> None:  # type: ignore[no-untyped-def]
    """Point the newest user snapshot's rows for this subject at ``user_id``.

    A mapping is a pin that the next poll honours, but an admin who just fixed an
    attribution expects the dashboard and limits to reflect it now, not after the
    next cycle. So the latest snapshot is re-pointed immediately; ``None`` clears
    it back to unattributed.
    """
    latest = db.scalar(
        select(UsageSnapshot)
        .where(
            UsageSnapshot.view_by == str(UsageView.USER),
            UsageSnapshot.held_reason.is_(None),
        )
        .order_by(UsageSnapshot.collected_at.desc(), UsageSnapshot.id.desc())
        .limit(1)
    )
    if latest is None:
        return
    records = db.scalars(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == latest.id,
            UsageRecord.view_by == str(UsageView.USER),
            UsageRecord.subject_key == subject_key,
        )
    )
    for record in records:
        record.entity_type = EntityType.USER
        record.entity_id = user_id


@router.post("/usage/unresolved/{subject_id}/map", response_model=UnresolvedSubjectResponse)
def map_unresolved(
    subject_id: int, payload: MapSubjectRequest, ctx: AdminUser, db: DbSession
) -> UnresolvedSubjectResponse:
    """Pin an unmatched consumption subject to a known user.

    Its credits count towards that user's limits immediately - the latest
    snapshot is re-attributed on the spot - and every future poll honours the
    pin. This is the fix for a user whose AI actions are reported under a
    different address than their IAM email. A null ``user_id`` clears the mapping.
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
    _reattribute_latest_snapshot(db, row.subject_key, payload.user_id)
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

    return _subject_response(db, row)


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


@router.get("/usage/auto-triage-attribution", response_model=AutoTriageAttributionOverview)
def auto_triage_attribution_overview(
    ctx: CurrentUser,
    db: DbSession,
    user_id: str | None = Query(default=None, max_length=64),
    project_id: str | None = Query(default=None, max_length=64),
    charges: int = Query(default=50, ge=0, le=500),
) -> AutoTriageAttributionOverview:
    """How each project's auto-triage credits are charged to the people who scanned.

    Read only, from stored data. Filter by ``user_id`` or ``project_id`` to
    explain one figure. Empty (``enabled`` false) while the setting is off.
    """
    model = auto_triage_attribution.build_model(db)
    if not model.enabled:
        return AutoTriageAttributionOverview(enabled=False, available=False)

    # Every name at once: the model can hold thousands of projects and people.
    names: dict[tuple[str, str], str | None] = {
        (CxProject.__tablename__, project_id): name
        for project_id, name in db.execute(select(CxProject.id, CxProject.name))
    }
    names.update(
        ((CxUser.__tablename__, user.id), user.display_name) for user in db.scalars(select(CxUser))
    )

    def label(kind, entity_id: str) -> str | None:  # type: ignore[no-untyped-def]
        return names.get((kind.__tablename__, entity_id))

    projects = [
        AutoTriageProjectAttribution(
            project_id=item.project_id,
            project_label=label(CxProject, item.project_id),
            auto_triage_credits=item.auto_triage_credits,
            observed=item.observed,
            estimated=item.estimated,
            unattributed=item.unattributed,
            unresolved=item.unresolved,
            charged_to_people=item.charged_to_people,
            scale=float(item.scale),
            history_status=item.history_status,
            observing_since=item.observing_since,
        )
        for item in sorted(model.projects.values(), key=lambda p: -p.auto_triage_credits)
        if (project_id is None or item.project_id == project_id) and item.auto_triage_credits > 0
    ]

    users: list[AutoTriageUserAttribution] = []
    for uid, parts in model.parts_by_user.items():
        if user_id is not None and uid != user_id:
            continue
        selected = [part for part in parts if project_id is None or part.project_id == project_id]
        if not selected:
            continue
        grouped: dict[tuple[str, str], Decimal] = {}
        for part in selected:
            key = (part.project_id, part.basis)
            grouped[key] = grouped.get(key, Decimal("0")) + part.credits
        users.append(
            AutoTriageUserAttribution(
                user_id=uid,
                user_label=label(CxUser, uid),
                total=sum((part.credits for part in selected), Decimal("0")),
                observed=sum(
                    (part.credits for part in selected if part.basis == "observed"),
                    Decimal("0"),
                ),
                estimated=sum(
                    (part.credits for part in selected if part.basis == "estimated"),
                    Decimal("0"),
                ),
                parts=[
                    AutoTriageUserPart(
                        project_id=pid,
                        project_label=label(CxProject, pid),
                        basis=basis,
                        credits=credits,
                    )
                    for (pid, basis), credits in sorted(grouped.items())
                ],
            )
        )
    users.sort(key=lambda item: -item.total)

    initiators: list[AutoTriageInitiator] = []
    if user_id is None and model.initiators:
        subject_ids = {
            row.subject_key: row.id
            for row in db.scalars(
                select(UnresolvedSubject).where(
                    UnresolvedSubject.subject_key.in_(list(model.initiators))
                )
            )
        }
        for key, info in sorted(model.initiators.items(), key=lambda kv: -kv[1].credits):
            counted = info.outcome.counted_user_id
            initiators.append(
                AutoTriageInitiator(
                    initiator=info.initiator,
                    credits=info.credits,
                    status=info.outcome.method,
                    counts_towards_user_id=counted,
                    counts_towards_label=label(CxUser, counted) if counted else None,
                    subject_id=subject_ids.get(key),
                )
            )

    recent: list[AutoTriageChargeResponse] = []
    if charges:
        query = select(AutoTriageCharge).order_by(AutoTriageCharge.id.desc()).limit(charges)
        if project_id is not None:
            query = query.where(AutoTriageCharge.project_id == project_id)
        if user_id is not None:
            keys = [
                key
                for key, info in model.initiators.items()
                if info.outcome.counted_user_id == user_id
            ]
            query = query.where(AutoTriageCharge.initiator_key.in_(keys or [""]))
        recent = [
            AutoTriageChargeResponse(
                id=row.id,
                project_id=row.project_id,
                basis=row.basis,
                initiator=row.initiator,
                scan_ids=[str(scan) for scan in (row.scan_ids or [])[:50]],
                scan_count=row.scan_count,
                credits=row.credits,
                window_start=row.window_start,
                window_end=row.window_end,
                detail=row.detail,
            )
            for row in db.scalars(query)
        ]

    return AutoTriageAttributionOverview(
        enabled=True,
        available=model.available,
        reference_at=model.reference_at,
        window_start=model.window_start,
        projects=projects,
        users=users,
        initiators=initiators,
        recent_charges=recent,
    )
