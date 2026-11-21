"""Setup and health of the Checkmarx One connection.

The API key is write only across this API: it can be submitted and replaced, and
its fingerprint can be read back, but there is no endpoint that returns it.
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, status
from pydantic import ValidationError

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx.errors import ApiKeyError, CheckmarxError
from app.checkmarx.regions import UntrustedHostError
from app.models.enums import ConnectionStatus
from app.schemas.connection import (
    ApiBaseUrlRequest,
    ApiKeyRequest,
    ConnectionPreviewResponse,
    ConnectionStatusResponse,
    ConnectionTestResponse,
    KeyPermissionReport,
    KeyPermissionsResponse,
    SaveConnectionRequest,
)
from app.services import connection as connection_service
from app.services import key_permissions

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/connection", tags=["connection"])


@router.post("/preview", response_model=ConnectionPreviewResponse)
def preview(payload: ApiKeyRequest, ctx: AdminUser) -> ConnectionPreviewResponse:
    """Parse a pasted API key locally and return the derived tenant details.

    Nothing is stored and no call is made to Checkmarx, so the admin can confirm
    the tenant and region before committing to them.
    """
    try:
        result = connection_service.preview_api_key(payload.api_key)
    except ApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_api_key", "message": str(exc)},
        ) from exc
    return ConnectionPreviewResponse(**asdict(result))


@router.get("", response_model=ConnectionStatusResponse)
def read_connection(ctx: CurrentUser, db: DbSession) -> ConnectionStatusResponse:
    conn = connection_service.get_connection(db)
    if conn is None:
        return ConnectionStatusResponse(configured=False, status=ConnectionStatus.UNCONFIGURED)
    return ConnectionStatusResponse(
        configured=True,
        status=conn.status,  # type: ignore[arg-type]
        tenant_name=conn.tenant_name,
        iam_base_url=conn.iam_base_url,
        api_base_url=conn.api_base_url,
        api_base_url_overridden=conn.api_base_url_overridden,
        api_key_fingerprint=conn.api_key_fingerprint,
        last_success_at=conn.last_success_at,
        last_failure_at=conn.last_failure_at,
        last_error=conn.last_error,
    )


@router.put("", response_model=ConnectionTestResponse)
def save_connection(
    payload: SaveConnectionRequest, ctx: AdminUser, db: DbSession
) -> ConnectionTestResponse:
    """Store the API key (encrypted) and immediately verify it.

    The connection is saved even if verification fails, so the admin can fix a
    wrong regional base URL on the Settings page without re-pasting the key. The
    failure detail comes back in the response and is recorded on the connection.
    """
    try:
        connection_service.save_connection(
            db,
            api_key=payload.api_key,
            api_base_url_override=payload.api_base_url,
            actor=ctx.actor,
        )
    except ApiKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "invalid_api_key", "message": str(exc)},
        ) from exc
    except UntrustedHostError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "untrusted_host", "message": str(exc)},
        ) from exc
    except CheckmarxError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "connection_error", "message": str(exc)},
        ) from exc
    db.commit()

    result = connection_service.test_connection(db)
    db.commit()
    return _with_permissions(result, ctx, db, trigger=key_permissions.TRIGGER_CONNECTION_SAVED)


@router.post("/test", response_model=ConnectionTestResponse)
def test_connection(ctx: AdminUser, db: DbSession) -> ConnectionTestResponse:
    result = connection_service.test_connection(db)
    db.commit()
    return _with_permissions(result, ctx, db, trigger=key_permissions.TRIGGER_CONNECTION_TEST)


def _with_permissions(result, ctx, db, *, trigger: str) -> ConnectionTestResponse:  # type: ignore[no-untyped-def]
    """The test result, plus what the key may do once a token could be had.

    The check commits before its first Checkmarx call and never raises, so a
    probe failure cannot undo or fail the save that came before it.
    """
    response = ConnectionTestResponse(**asdict(result))
    if result.token_acquired:
        report = key_permissions.run_check(db, trigger=trigger, actor=ctx.actor)
        if report is not None:
            response.permissions = _safe_report_model(report, details=True)
    return response


def _safe_report_model(report: dict, *, details: bool) -> KeyPermissionReport | None:  # type: ignore[type-arg]
    """report_model, or None (logged) for a stored report that does not fit the
    schema any more: a broken report must never fail the page that shows it."""
    try:
        return report_model(report, details=details)
    except (ValidationError, KeyError, TypeError, ValueError):
        logger.warning("The stored API key permission report could not be shown", exc_info=True)
        return None


def report_model(report: dict, *, details: bool) -> KeyPermissionReport:  # type: ignore[type-arg]
    """The assessed report as the API returns it; details only for an admin."""
    if details:
        return KeyPermissionReport(**report, details_visible=True)
    explanation = dict(report.get("explanation") or {})
    explanation["roles"] = []
    return KeyPermissionReport(
        verdict=report["verdict"],
        attention=bool(report.get("attention")),
        summary=report["summary"],
        missing=report["missing"],
        checked_at=report["checked_at"],
        problem_key=report["problem_key"],
        details_visible=False,
        explanation=explanation,
    )


@router.get("/permissions", response_model=KeyPermissionsResponse)
def read_permissions(ctx: CurrentUser, db: DbSession) -> KeyPermissionsResponse:
    """The last API key permission report. Anyone signed in sees the summary and
    what stops working; an admin also sees each call, the key's roles and the
    refusals seen at run time."""
    try:
        report = key_permissions.current_report(db)
    except Exception:  # noqa: BLE001 - a broken stored report reads as no report
        logger.warning("The stored API key permission report could not be read", exc_info=True)
        report = None
    model = _safe_report_model(report, details=ctx.is_admin) if report is not None else None
    if model is None:
        return KeyPermissionsResponse(available=False)
    return KeyPermissionsResponse(available=True, report=model)


@router.post("/permissions", response_model=KeyPermissionsResponse)
def check_permissions(ctx: AdminUser, db: DbSession) -> KeyPermissionsResponse:
    """Check the key again now ("Check again"). Every read is tried again; a
    change refused at run time stays listed until it next goes through."""
    if connection_service.get_connection(db) is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "not_configured", "message": "No Checkmarx connection is configured."},
        )
    report = key_permissions.run_check(
        db, trigger=key_permissions.TRIGGER_MANUAL, actor=ctx.actor, clear_runtime=True
    )
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "code": "check_failed",
                "message": (
                    "The permission check could not run. Use Test connection to see whether "
                    "the tenant can be reached."
                ),
            },
        )
    model = _safe_report_model(report, details=True)
    return KeyPermissionsResponse(available=model is not None, report=model)


@router.patch("/api-base-url", response_model=ConnectionTestResponse)
def override_api_base_url(
    payload: ApiBaseUrlRequest, ctx: AdminUser, db: DbSession
) -> ConnectionTestResponse:
    try:
        connection_service.set_api_base_url(db, api_base_url=payload.api_base_url, actor=ctx.actor)
    except UntrustedHostError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "untrusted_host", "message": str(exc)},
        ) from exc
    except CheckmarxError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "not_configured", "message": str(exc)},
        ) from exc
    db.commit()
    result = connection_service.test_connection(db)
    db.commit()
    # Same key, other address: what the key may do there is checked again.
    return _with_permissions(result, ctx, db, trigger=key_permissions.TRIGGER_CONNECTION_SAVED)
