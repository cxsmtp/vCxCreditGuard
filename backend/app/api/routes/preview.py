"""Read-only enforcement previews: blast radius and a dry run of the next cycle."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import CurrentUser, DbSession
from app.models.enums import EntityType
from app.schemas.preview import (
    BlastRadiusResponse,
    DryRunResponse,
    DryRunRowResponse,
    TargetPreviewResponse,
)
from app.services import preview_service

router = APIRouter(prefix="/preview", tags=["preview"])


def _blast_to_response(blast: preview_service.BlastRadius) -> BlastRadiusResponse:
    return BlastRadiusResponse(
        entity_type=blast.entity_type,  # type: ignore[arg-type]
        entity_id=blast.entity_id,
        entity_label=blast.entity_label,
        exempt=blast.exempt,
        affected_users=blast.affected_users,
        affected_projects=blast.affected_projects,
        remove_user_roles=blast.remove_user_roles,
        disable_auto_triage=blast.disable_auto_triage,
        disable_pr_remediation=blast.disable_pr_remediation,
        total_actions=blast.total_actions,
        targets=[
            TargetPreviewResponse(
                kind=target.kind,
                target_type=target.target_type,
                target_id=target.target_id,
                target_label=target.target_label,
            )
            for target in blast.targets
        ],
    )


@router.get("/blast-radius", response_model=BlastRadiusResponse)
def get_blast_radius(
    ctx: CurrentUser,
    db: DbSession,
    entity_type: EntityType = Query(...),
    entity_id: str = Query(..., min_length=1, max_length=64),
) -> BlastRadiusResponse:
    """What enforcing this entity's limit would restrict, computed read-only."""
    if not entity_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_entity", "message": "An entity id is required."},
        )
    blast = preview_service.blast_radius(db, entity_type=str(entity_type), entity_id=entity_id)
    return _blast_to_response(blast)


@router.get("/dry-run", response_model=DryRunResponse)
def get_dry_run(ctx: CurrentUser, db: DbSession) -> DryRunResponse:
    """Project what the next cycle would decide, without writing anything."""
    result = preview_service.dry_run(db)
    return DryRunResponse(
        generated_at=result.generated_at,
        would_enforce_count=result.would_enforce_count,
        would_warn_count=result.would_warn_count,
        affected_projects=result.affected_projects,
        affected_users=result.affected_users,
        rows=[
            DryRunRowResponse(
                limit_id=row.limit_id,
                entity_type=row.entity_type,  # type: ignore[arg-type]
                entity_id=row.entity_id,
                entity_label=row.entity_label,
                credit_limit=row.credit_limit,
                enforce=row.enforce,
                exempt=row.exempt,
                usage_available=row.usage_available,
                credits_used=row.credits_used,
                percent_used=row.percent_used,
                projected_status=row.projected_status,  # type: ignore[arg-type]
                would_enforce=row.would_enforce,
                blast=_blast_to_response(row.blast) if row.blast is not None else None,
                note=row.note,
            )
            for row in result.rows
        ],
    )
