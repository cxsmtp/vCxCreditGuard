"""Setup and health of the Checkmarx One connection.

The API key is write only across this API: it can be submitted and replaced, and
its fingerprint can be read back, but there is no endpoint that returns it.
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import APIRouter, HTTPException, status

from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx.errors import ApiKeyError, CheckmarxError
from app.models.enums import ConnectionStatus
from app.schemas.connection import (
    ApiBaseUrlRequest,
    ApiKeyRequest,
    ConnectionPreviewResponse,
    ConnectionStatusResponse,
    ConnectionTestResponse,
    SaveConnectionRequest,
)
from app.services import connection as connection_service

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
    except CheckmarxError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "connection_error", "message": str(exc)},
        ) from exc
    db.commit()

    result = connection_service.test_connection(db)
    db.commit()
    return ConnectionTestResponse(**asdict(result))


@router.post("/test", response_model=ConnectionTestResponse)
def test_connection(ctx: AdminUser, db: DbSession) -> ConnectionTestResponse:
    result = connection_service.test_connection(db)
    db.commit()
    return ConnectionTestResponse(**asdict(result))


@router.patch("/api-base-url", response_model=ConnectionTestResponse)
def override_api_base_url(
    payload: ApiBaseUrlRequest, ctx: AdminUser, db: DbSession
) -> ConnectionTestResponse:
    try:
        connection_service.set_api_base_url(db, api_base_url=payload.api_base_url, actor=ctx.actor)
    except CheckmarxError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "not_configured", "message": str(exc)},
        ) from exc
    db.commit()
    result = connection_service.test_connection(db)
    db.commit()
    return ConnectionTestResponse(**asdict(result))
