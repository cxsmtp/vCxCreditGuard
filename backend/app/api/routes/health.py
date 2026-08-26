"""Liveness and readiness endpoint.

Unauthenticated by design so an orchestrator can poll it, and therefore
deliberately terse: it reports whether the process can reach its database and
whether a Checkmarx connection exists, with no tenant details, versions of
dependencies or error strings that would help an unauthenticated caller.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Response, status
from sqlalchemy import select, text

from app import __version__
from app.db.session import session_scope
from app.models.connection import CxConnection

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=False)
def healthz(response: Response) -> dict[str, object]:
    database_ok = False
    connection_configured = False
    try:
        with session_scope() as db:
            db.execute(text("SELECT 1"))
            database_ok = True
            connection_configured = db.scalar(select(CxConnection.id).limit(1)) is not None
    except Exception:
        logger.exception("Health check could not reach the database")

    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if database_ok else "unhealthy",
        "version": __version__,
        "database": database_ok,
        "checkmarx_connection_configured": connection_configured,
    }
