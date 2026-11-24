"""Limits and exemptions management."""

from __future__ import annotations

import logging
from decimal import Decimal

from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx.client import CheckmarxClient
from app.db.base import utcnow
from app.models.enums import EnforcementStatus, EntityType, LimitStatus
from app.models.limits import (
    CreditLimit,
    EnforcementAction,
    Exemption,
    LimitPeriodState,
    effective_project_actions,
)
from app.models.org import CxProject, CxUser
from app.schemas.dashboard import (
    BulkLimitResultResponse,
    BulkLimitUpdateRequest,
    CsvImportResultResponse,
)
from app.schemas.limits import (
    AutoTriageAttributionResponse,
    AutoTriagePartResponse,
    ExemptionCreateRequest,
    ExemptionResponse,
    LimitCreateRequest,
    LimitPeriodStateResponse,
    LimitResponse,
    LimitUpdateRequest,
)
from app.services import connection as connection_service
from app.services import evaluation, limits_csv, limits_service, settings_store
from app.services.periods import PeriodError, PeriodWindow, current_window

logger = logging.getLogger(__name__)
# A limits CSV is a few hundred rows at most. This is a guard, not a target.
MAX_IMPORT_BYTES = 1_048_576
router = APIRouter(prefix="/limits", tags=["limits"])
exemptions_router = APIRouter(prefix="/exemptions", tags=["limits"])


def _optional_client(db: Session) -> CheckmarxClient | None:
    """The Checkmarx client if one is configured, else None (shared helper)."""
    return connection_service.optional_client(db)


def _attribution_index(db: Session) -> evaluation.UsageIndex | None:
    """A usage index for explaining auto-triage charges, only when they are on."""
    if not settings_store.auto_triage_to_initiator(db):
        return None
    return evaluation.UsageIndex(db)


def _auto_triage_response(
    db: Session,
    *,
    index: evaluation.UsageIndex,
    limit: CreditLimit,
    window: PeriodWindow,
    state: LimitPeriodState,
) -> AutoTriageAttributionResponse | None:
    attributed = index.attributed_usage(limit, window=window, state=state, moment=utcnow())
    if attributed is None:
        return None
    labels: dict[tuple[str, str], str | None] = {}

    def label(model, entity_id: str) -> str | None:  # type: ignore[no-untyped-def]
        key = (model.__tablename__, entity_id)
        if key not in labels:
            row = db.get(model, entity_id)
            labels[key] = (
                (row.display_name if isinstance(row, CxUser) else row.name) if row else None
            )
        return labels[key]

    # Every figure here is from one live rebuild, so counted, not_counted and
    # the parts always agree with each other. ``evaluated_counted`` is what the
    # period's credits_used included at its last evaluation; the two differ
    # only between cycles (an initiator mapped since, a reading since).
    return AutoTriageAttributionResponse(
        counted=attributed.counted,
        evaluated_counted=state.attributed_credits,
        window_total=attributed.window_total,
        not_counted=max(Decimal("0"), attributed.not_counted),
        counts_existing_usage=attributed.counts_existing,
        counted_since=attributed.since,
        parts=[
            AutoTriagePartResponse(
                user_id=part.user_id,
                user_label=label(CxUser, part.user_id),
                project_id=part.project_id,
                project_label=label(CxProject, part.project_id),
                basis=part.basis,
                credits=part.credits,
                counted=part.counted,
            )
            for part in attributed.parts
        ],
    )


def _to_response(
    db: Session, limit: CreditLimit, *, index: evaluation.UsageIndex | None = None
) -> LimitResponse:
    exempt = (
        db.scalar(
            select(Exemption.id).where(
                Exemption.entity_type == limit.entity_type,
                Exemption.entity_id == limit.entity_id,
            )
        )
        is not None
    )
    active_restrictions = len(
        list(
            db.scalars(
                select(EnforcementAction.id).where(
                    EnforcementAction.limit_id == limit.id,
                    EnforcementAction.status == EnforcementStatus.APPLIED,
                )
            )
        )
    )

    period_response: LimitPeriodStateResponse | None = None
    try:
        window = current_window(limit)
    except PeriodError:
        window = None
    if window is not None:
        state = db.scalar(
            select(LimitPeriodState).where(
                LimitPeriodState.limit_id == limit.id,
                LimitPeriodState.period_key == window.key,
            )
        )
        if state is not None:
            percent = (
                float(state.credits_used) / limit.credit_limit * 100
                if limit.credit_limit > 0 and state.usage_available
                else None
            )
            period_response = LimitPeriodStateResponse(
                period_key=state.period_key,
                period_start=state.period_start,
                period_end=state.period_end,
                credits_used=state.credits_used,
                baseline_credits=state.baseline_credits,
                reported_total=state.reported_total,
                usage_available=state.usage_available,
                status=state.status,  # type: ignore[arg-type]
                percent_used=percent,
                last_evaluated_at=state.last_evaluated_at,
                warned_at=state.warned_at,
                breached_at=state.breached_at,
                restricted_at=state.restricted_at,
            )
            if index is None and limit.entity_type in {EntityType.USER, EntityType.GROUP}:
                index = _attribution_index(db)
            if index is not None:
                period_response.auto_triage_attributed = _auto_triage_response(
                    db, index=index, limit=limit, window=window, state=state
                )

    return LimitResponse(
        id=limit.id,
        entity_type=limit.entity_type,  # type: ignore[arg-type]
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        credit_limit=limit.credit_limit,
        period_type=limit.period_type,  # type: ignore[arg-type]
        custom_period_start=limit.custom_period_start,
        custom_period_end=limit.custom_period_end,
        warning_threshold_pct=limit.warning_threshold_pct,
        enforce=limit.enforce,
        is_active=limit.is_active,
        include_member_usage=limit.include_member_usage,
        hold_until_released=limit.hold_until_released,
        count_existing_usage=limit.count_existing_usage,
        exempt=exempt,
        notes=limit.notes,
        business_unit=limit.business_unit,
        project_actions=list(limit.project_actions) if limit.project_actions is not None else None,
        effective_project_actions=list(effective_project_actions(limit)),
        created_at=limit.created_at,
        updated_at=limit.updated_at,
        current_period=period_response,
        active_restrictions=active_restrictions,
    )


@router.get("", response_model=list[LimitResponse])
def list_limits(
    ctx: CurrentUser,
    db: DbSession,
    entity_type: EntityType | None = None,
    only_breached: bool = Query(default=False),
) -> list[LimitResponse]:
    query = select(CreditLimit)
    if entity_type is not None:
        query = query.where(CreditLimit.entity_type == entity_type)
    limits = list(db.scalars(query.order_by(CreditLimit.entity_type, CreditLimit.entity_label)))
    # Built once for the whole list, and only when auto-triage charging is on.
    index = _attribution_index(db)
    responses = [_to_response(db, limit, index=index) for limit in limits]
    if only_breached:
        responses = [
            response
            for response in responses
            if response.current_period is not None
            and response.current_period.status in {LimitStatus.BREACHED, LimitStatus.RESTRICTED}
        ]
    return responses


@router.post("", response_model=LimitResponse, status_code=status.HTTP_201_CREATED)
def create_limit(payload: LimitCreateRequest, ctx: AdminUser, db: DbSession) -> LimitResponse:
    try:
        limit = limits_service.create_limit(
            db,
            data=limits_service.LimitInput(
                entity_type=payload.entity_type,
                entity_id=payload.entity_id,
                credit_limit=payload.credit_limit,
                period_type=payload.period_type,
                warning_threshold_pct=payload.warning_threshold_pct,
                enforce=payload.enforce,
                include_member_usage=payload.include_member_usage,
                hold_until_released=payload.hold_until_released,
                count_existing_usage=payload.count_existing_usage,
                custom_period_start=payload.custom_period_start,
                custom_period_end=payload.custom_period_end,
                notes=payload.notes,
                business_unit=payload.business_unit,
                project_actions=(
                    [str(action) for action in payload.project_actions]
                    if payload.project_actions is not None
                    else None
                ),
            ),
            actor=ctx.actor,
        )
    except limits_service.LimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_limit", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(db, limit)


@router.patch("/{limit_id}", response_model=LimitResponse)
def update_limit(
    limit_id: int, payload: LimitUpdateRequest, ctx: AdminUser, db: DbSession
) -> LimitResponse:
    limit = db.get(CreditLimit, limit_id)
    if limit is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such limit.")
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return _to_response(db, limit)
    if changes.get("project_actions") is not None:
        changes["project_actions"] = [str(action) for action in changes["project_actions"]]
    try:
        limits_service.update_limit(
            db, limit=limit, changes=changes, actor=ctx.actor, client=_optional_client(db)
        )
    except limits_service.LimitError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_limit", "message": str(exc)},
        ) from exc
    db.commit()
    return _to_response(db, limit)


@router.delete("/{limit_id}")
def delete_limit(limit_id: int, ctx: AdminUser, db: DbSession) -> dict[str, object]:
    limit = db.get(CreditLimit, limit_id)
    if limit is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such limit.")
    try:
        restored = limits_service.delete_limit(
            db, limit=limit, actor=ctx.actor, client=_optional_client(db)
        )
    except limits_service.LimitRestoreError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"code": "restore_failed", "message": str(exc)},
        ) from exc
    db.commit()
    return {
        "message": "Limit deleted.",
        "restrictions_lifted": restored,
    }


# ------------------------------------------------------------------- exemptions


@router.post("/bulk", response_model=BulkLimitResultResponse)
def bulk_update(
    payload: BulkLimitUpdateRequest, ctx: AdminUser, db: DbSession
) -> BulkLimitResultResponse:
    """Apply the same change to many limits.

    Each limit is updated through the same service path as a single edit, so bulk
    edits lift restrictions and write audit rows exactly like individual ones do.
    """
    changes = payload.model_dump(exclude_unset=True, exclude={"limit_ids"})
    if not changes:
        return BulkLimitResultResponse(updated=0, restrictions_lifted=0, errors=[])

    client = _optional_client(db)
    updated = 0
    lifted = 0
    errors: list[str] = []

    for limit_id in payload.limit_ids:
        limit = db.get(CreditLimit, limit_id)
        if limit is None:
            errors.append(f"Limit {limit_id} no longer exists.")
            continue
        was_enforcing = limit.enforce and limit.is_active
        try:
            limits_service.update_limit(
                db, limit=limit, changes=dict(changes), actor=ctx.actor, client=client
            )
        except limits_service.LimitError as exc:
            errors.append(f"{limit.entity_label or limit.entity_id}: {exc}")
            continue
        updated += 1
        if was_enforcing and not (limit.enforce and limit.is_active):
            lifted += 1

    db.commit()
    return BulkLimitResultResponse(updated=updated, restrictions_lifted=lifted, errors=errors)


@router.get("/export")
def export_limits(ctx: CurrentUser, db: DbSession) -> Response:
    """Download every limit as CSV, with current period usage for context."""
    content = limits_csv.export_limits(db)
    stamp = utcnow().strftime("%Y%m%d-%H%M")
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="cxcreditguard-limits-{stamp}.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/import", response_model=CsvImportResultResponse)
async def import_limits(
    ctx: AdminUser,
    db: DbSession,
    file: UploadFile = File(...),
    dry_run: bool = True,
) -> CsvImportResultResponse:
    """Validate a CSV of limits, and apply it when ``dry_run`` is false.

    Validation is all or nothing. A file with any bad row applies none of it, so an
    admin never ends up with half a policy.
    """
    if file.size is not None and file.size > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "file_too_large",
                "message": f"The file must be under {MAX_IMPORT_BYTES // 1024} KB.",
            },
        )

    raw = await file.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "code": "file_too_large",
                "message": f"The file must be under {MAX_IMPORT_BYTES // 1024} KB.",
            },
        )
    try:
        content = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "not_utf8",
                "message": "The file must be UTF-8 encoded text.",
            },
        ) from exc

    result = limits_csv.import_limits(
        db,
        content=content,
        actor=ctx.actor,
        dry_run=dry_run,
        client=_optional_client(db),
    )
    if result.dry_run or result.errors:
        db.rollback()
    else:
        db.commit()

    return CsvImportResultResponse(
        created=result.created,
        updated=result.updated,
        skipped=result.skipped,
        errors=result.errors,
        dry_run=result.dry_run,
    )


@router.get("/{limit_id}", response_model=LimitResponse)
def get_limit(limit_id: int, ctx: CurrentUser, db: DbSession) -> LimitResponse:
    """One limit with its current period, including what makes up the figure."""
    limit = db.get(CreditLimit, limit_id)
    if limit is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such limit.")
    return _to_response(db, limit)


@exemptions_router.get("", response_model=list[ExemptionResponse])
def list_exemptions(ctx: CurrentUser, db: DbSession) -> list[ExemptionResponse]:
    rows = db.scalars(select(Exemption).order_by(Exemption.entity_type, Exemption.entity_label))
    return [
        ExemptionResponse(
            id=row.id,
            entity_type=row.entity_type,  # type: ignore[arg-type]
            entity_id=row.entity_id,
            entity_label=row.entity_label,
            reason=row.reason,
            expires_at=row.expires_at,
            created_at=row.created_at,
        )
        for row in rows
    ]


@exemptions_router.post("", response_model=ExemptionResponse, status_code=status.HTTP_201_CREATED)
def create_exemption(
    payload: ExemptionCreateRequest, ctx: AdminUser, db: DbSession
) -> ExemptionResponse:
    try:
        exemption = limits_service.add_exemption(
            db,
            entity_type=payload.entity_type,
            entity_id=payload.entity_id,
            reason=payload.reason,
            expires_at=payload.expires_at,
            actor=ctx.actor,
            client=_optional_client(db),
        )
    except limits_service.LimitError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_override", "message": str(exc)},
        ) from exc
    db.commit()
    return ExemptionResponse(
        id=exemption.id,
        entity_type=exemption.entity_type,  # type: ignore[arg-type]
        entity_id=exemption.entity_id,
        entity_label=exemption.entity_label,
        reason=exemption.reason,
        expires_at=exemption.expires_at,
        created_at=exemption.created_at,
    )


@exemptions_router.delete("/{exemption_id}")
def delete_exemption(exemption_id: int, ctx: AdminUser, db: DbSession) -> dict[str, str]:
    exemption = db.get(Exemption, exemption_id)
    if exemption is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such exemption.")
    limits_service.remove_exemption(db, exemption=exemption, actor=ctx.actor)
    db.commit()
    return {"message": "Exemption removed. This entity can be restricted again."}
