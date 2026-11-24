"""Read-only enforcement previews: blast radius and a dry run of the next cycle."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import CurrentUser, DbSession
from app.models.enums import EntityType
from app.schemas.preview import (
    BlastRadiusResponse,
    DryRunResponse,
    DryRunRowResponse,
    KeptRolePreviewResponse,
    ProjectWarningResponse,
    RemovedRolePreviewResponse,
    TargetPreviewResponse,
    UserRolesPreviewResponse,
)
from app.services import connection as connection_service
from app.services import limits_service, preview_service, settings_store

logger = logging.getLogger(__name__)

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
        disable_fusion=blast.disable_fusion,
        disable_repo_fusion=blast.disable_repo_fusion,
        total_actions=blast.total_actions,
        project_actions=blast.project_actions,
        ai_roles=blast.ai_roles,
        user_roles=[
            UserRolesPreviewResponse(
                user_id=user.user_id,
                user_label=user.user_label,
                read=user.read,
                removed=[
                    RemovedRolePreviewResponse(
                        name=role.name, description=role.description, grants=role.grants
                    )
                    for role in user.removed
                ],
                kept=[
                    KeptRolePreviewResponse(name=role.name, sources=role.sources)
                    for role in user.kept
                ],
                not_held=user.not_held,
                unread=user.unread,
                note=user.note,
            )
            for user in blast.user_roles
        ],
        user_roles_truncated=blast.user_roles_truncated,
        user_roles_note=blast.user_roles_note,
        warnings=[
            ProjectWarningResponse(
                project_id=warning.project_id,
                project_label=warning.project_label,
                message=warning.message,
            )
            for warning in blast.warnings
        ],
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


def _roles_previewer(db) -> preview_service.RolePreviewer:  # type: ignore[no-untyped-def]
    """Reads users' roles from Checkmarx One for this request, when it can.

    A preview never fails because the tenant cannot be reached: the roles are
    then simply not read, and the preview says so.
    """
    if settings_store.demo_mode(db):
        return preview_service.RolePreviewer(
            db, None, why_not_read="Demo mode is on, so the user's roles were not read."
        )
    try:
        client = connection_service.optional_client(db)
    except Exception:  # noqa: BLE001 - a preview must render without the tenant
        logger.warning("No Checkmarx client for the preview", exc_info=True)
        client = None
    return preview_service.RolePreviewer(db, client)


@router.get("/blast-radius", response_model=BlastRadiusResponse)
def get_blast_radius(
    ctx: CurrentUser,
    db: DbSession,
    entity_type: EntityType = Query(...),
    entity_id: str = Query(..., min_length=1, max_length=64),
    project_actions: str | None = Query(default=None, max_length=128),
) -> BlastRadiusResponse:
    """What enforcing this entity's limit would restrict, computed read-only.

    ``project_actions`` (comma separated: auto_triage, pr_remediation, fusion)
    previews a choice the limit form has not saved yet.
    """
    if not entity_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_entity", "message": "An entity id is required."},
        )
    actions: list[str] | None = None
    if project_actions is not None:
        try:
            actions = limits_service.normalise_project_actions(project_actions)
        except limits_service.LimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "invalid_project_actions", "message": str(exc)},
            ) from exc
    blast = preview_service.blast_radius(
        db,
        entity_type=str(entity_type),
        entity_id=entity_id,
        project_actions=actions,
        roles=_roles_previewer(db),
    )
    return _blast_to_response(blast)


@router.get("/dry-run", response_model=DryRunResponse)
def get_dry_run(ctx: CurrentUser, db: DbSession) -> DryRunResponse:
    """Project what the next cycle would decide, without writing anything."""
    result = preview_service.dry_run(db, roles=_roles_previewer(db))
    return DryRunResponse(
        generated_at=result.generated_at,
        user_roles_truncated=result.user_roles_truncated,
        user_roles_note=result.user_roles_note,
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
                auto_triage_attributed=row.auto_triage_attributed,
            )
            for row in result.rows
        ],
    )
