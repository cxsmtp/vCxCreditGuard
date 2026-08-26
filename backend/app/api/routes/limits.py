"""Limits and exemptions management."""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError
from app.db.base import utcnow
from app.models.enums import EnforcementStatus, EntityType, LimitStatus
from app.models.limits import CreditLimit, EnforcementAction, Exemption, LimitPeriodState
from app.schemas.dashboard import (
    BulkLimitResultResponse,
    BulkLimitUpdateRequest,
    CsvImportResultResponse,
)
from app.schemas.limits import (
    ExemptionCreateRequest,
    ExemptionResponse,
    LimitCreateRequest,
    LimitPeriodStateResponse,
    LimitResponse,
    LimitUpdateRequest,
)
from app.services import connection as connection_service
from app.services import limits_csv, limits_service
from app.services.periods import PeriodError, current_window

logger = logging.getLogger(__name__)
# A limits CSV is a few hundred rows at most. This is a guard, not a target.
MAX_IMPORT_BYTES = 1_048_576
router = APIRouter(prefix="/limits", tags=["limits"])
exemptions_router = APIRouter(prefix="/exemptions", tags=["limits"])


def _optional_client(db: Session) -> CheckmarxClient | None:
    """The Checkmarx client if one is configured, else None.

    Limit administration must keep working when the tenant connection is down, so
    a missing client degrades to "cannot lift restrictions right now" rather than
    failing the request.
    """
    try:
        return connection_service.get_client(db)
    except CheckmarxError as exc:
        logger.warning("No usable Checkmarx client for this request: %s", exc)
        return None


def _to_response(db: Session, limit: CreditLimit) -> LimitResponse:
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
    responses = [_to_response(db, limit) for limit in limits]
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
    restored = limits_service.delete_limit(
        db, limit=limit, actor=ctx.actor, client=_optional_client(db)
    )
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
            created_at=row.created_at,
        )
        for row in rows
    ]


@exemptions_router.post("", response_model=ExemptionResponse, status_code=status.HTTP_201_CREATED)
def create_exemption(
    payload: ExemptionCreateRequest, ctx: AdminUser, db: DbSession
) -> ExemptionResponse:
    exemption = limits_service.add_exemption(
        db,
        entity_type=payload.entity_type,
        entity_id=payload.entity_id,
        reason=payload.reason,
        actor=ctx.actor,
        client=_optional_client(db),
    )
    db.commit()
    return ExemptionResponse(
        id=exemption.id,
        entity_type=exemption.entity_type,  # type: ignore[arg-type]
        entity_id=exemption.entity_id,
        entity_label=exemption.entity_label,
        reason=exemption.reason,
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
