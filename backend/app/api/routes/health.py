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
from app.services import ops_hardening

logger = logging.getLogger(__name__)
router = APIRouter(tags=["health"])


@router.get("/healthz", include_in_schema=False)
def healthz(response: Response) -> dict[str, object]:
    database_ok = False
    connection_configured = False
    scheduler_ok = True
    try:
        with session_scope() as db:
            db.execute(text("SELECT 1"))
            database_ok = True
            connection_configured = db.scalar(select(CxConnection.id).limit(1)) is not None
            # Scheduler liveness, reported alongside process health. A stuck or
            # dead scheduler does not flip the status code (the process is still
            # up), but an external monitor can alert on this flag. Isolated so a
            # watchdog bug is not misreported as a database failure, and defaults
            # to alive (fail-open) so it never makes a healthy process look down.
            try:
                scheduler_ok = ops_hardening.scheduler_alive(db)
            except Exception:
                logger.exception("Watchdog check failed")
    except Exception:
        logger.exception("Health check could not reach the database")

    if not database_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ok" if database_ok else "unhealthy",
        "version": __version__,
        "database": database_ok,
        "checkmarx_connection_configured": connection_configured,
        "scheduler_alive": scheduler_ok,
    }
