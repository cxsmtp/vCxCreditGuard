"""Application factory and startup wiring."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import OperationalError

from app import __version__, scheduler
from app.api.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.api.routes import (
    accounts,
    auth,
    connection,
    dashboard,
    fastpath,
    health,
    limits,
    notifications,
    ops,
    preview,
    readiness,
    reports,
    requests,
    selftest,
    updates,
    violations,
    webhooks,
)
from app.api.routes import (
    settings as settings_routes,
)
from app.core.config import ConfigError, Settings, get_settings
from app.core.logging import configure_logging
from app.db import instance_guard
from app.db.migrate import upgrade_to_head
from app.db.session import get_engine, session_scope
from app.services import connection as connection_service
from app.services import settings_store
from app.services.auth import bootstrap_admin_if_needed
from app.services.master_key import verify_master_key

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _startup(settings: Settings) -> None:
    # Fail fast and loudly: without the master key we cannot read or write any
    # stored secret, and starting anyway would look healthy while being useless.
    settings.master_key_bytes()
    upgrade_to_head(settings.database_url)
    with session_scope() as db:
        # ...and with the wrong key it would look just as healthy while every
        # cycle failed to read the Checkmarx API key.
        verify_master_key(db)
        settings_store.encrypt_legacy_secrets(db)
        connection_service.warn_if_untrusted(db)
        bootstrap_admin_if_needed(db, settings)
    _report_update_events()


def _report_update_events() -> None:
    """What the launcher did before this start (a switch, a rollback) goes into
    the audit log and the notifications now. Never stops the app from starting."""
    try:
        from app.updates.service import get_service

        with session_scope() as db:
            get_service().report_launcher_events(db)
    except Exception:  # noqa: BLE001 - reporting is best effort
        logger.exception("Could not report the launcher's update events")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    # One instance per database, claimed before anything else touches it.
    try:
        instance_guard.acquire(get_engine())
    except ConfigError as exc:
        logger.critical("CxCreditGuard cannot start: %s", exc)
        raise
    try:
        try:
            _startup(settings)
        except ConfigError as exc:
            # Said plainly, on its own line, before the server's traceback.
            logger.critical("CxCreditGuard cannot start: %s", exc)
            raise
        if app.state.run_scheduler:
            scheduler.start()
        logger.info("CxCreditGuard %s started in %s mode", __version__, settings.env)
        yield
        if app.state.run_scheduler:
            scheduler.shutdown()
        logger.info("CxCreditGuard shutting down")
    finally:
        instance_guard.release()


def create_app(settings: Settings | None = None, *, run_scheduler: bool = True) -> FastAPI:
    """Build the application.

    ``run_scheduler`` is False in tests, which drive cycles explicitly rather than
    racing a background thread.
    """
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="CxCreditGuard",
        version=__version__,
        description="Governance of Checkmarx One AI credit consumption.",
        lifespan=lifespan,
        # No interactive docs in production: the schema is an inventory of the
        # admin API and there is nothing to gain from exposing it publicly.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.state.settings = settings
    app.state.run_scheduler = run_scheduler

    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(RequestContextMiddleware)
    if settings.cors_origins:
        # Only needed when the SPA runs on a separate dev server. Credentials are
        # allowed, so the origin list must stay explicit; "*" is never accepted.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )

    api = APIRouter(prefix="/api")
    api.include_router(auth.router)
    api.include_router(accounts.router)
    api.include_router(connection.router)
    api.include_router(limits.router)
    api.include_router(limits.exemptions_router)
    api.include_router(preview.router)
    api.include_router(reports.router)
    api.include_router(requests.router)
    api.include_router(notifications.router)
    api.include_router(ops.router)
    api.include_router(selftest.router)
    api.include_router(readiness.router)
    api.include_router(settings_routes.router)
    api.include_router(dashboard.router)
    api.include_router(violations.router)
    api.include_router(updates.router)
    api.include_router(fastpath.router)
    api.include_router(webhooks.router)
    app.include_router(api)
    app.include_router(health.router)

    _register_error_handlers(app)
    _mount_spa(app)
    return app


def _register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ConfigError)
    async def _config_error(_request: Request, exc: ConfigError) -> JSONResponse:
        logger.error("Configuration error: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": {"code": "misconfigured", "message": str(exc)}},
        )

    @app.exception_handler(OperationalError)
    async def _database_busy(request: Request, exc: OperationalError) -> JSONResponse:
        # A lock or statement timeout, or the database being briefly unreachable.
        # That is "try again in a moment", not a fault in the request, so it gets
        # a 503 with Retry-After rather than an opaque 500.
        request_id = getattr(request.state, "request_id", "unknown")
        logger.warning(
            "Database busy or unavailable on %s %s (request %s): %s",
            request.method,
            request.url.path,
            request_id,
            str(exc.orig).splitlines()[0] if exc.orig else exc,
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": "5"},
            content={
                "detail": {
                    "code": "database_busy",
                    "message": "The service is busy. Please try again in a few seconds.",
                    "request_id": request_id,
                }
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Log the detail, return none of it: exception text can carry URLs,
        # identifiers and occasionally payload fragments.
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception(
            "Unhandled error on %s %s (request %s)", request.method, request.url.path, request_id
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": {
                    "code": "internal_error",
                    "message": "Something went wrong. Check the server logs.",
                    "request_id": request_id,
                }
            },
        )


def _mount_spa(app: FastAPI) -> None:
    """Serve the built React bundle when it is present.

    Absent in a backend only checkout or during API tests, so this is optional
    rather than a hard requirement.

    Client side routes such as /limits have no file behind them, so unknown paths
    fall back to index.html. API paths deliberately do not: a mistyped endpoint
    must return a JSON 404 rather than a page of HTML that a client would then
    fail to parse.
    """
    if not STATIC_DIR.is_dir():
        logger.info("No built frontend at %s, serving the API only", STATIC_DIR)
        return

    index_file = STATIC_DIR / "index.html"
    assets_dir = STATIC_DIR / "assets"
    if assets_dir.is_dir():
        # Asset filenames are content hashed by the bundler, so they are immutable.
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{spa_path:path}", include_in_schema=False)
    async def serve_spa(spa_path: str) -> Response:
        if spa_path.startswith(("api/", "api", "healthz", "assets/")):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")

        if spa_path:
            candidate = (STATIC_DIR / spa_path).resolve()
            # Containment check: a crafted path must not escape the static root.
            if candidate.is_file() and candidate.is_relative_to(STATIC_DIR.resolve()):
                return FileResponse(candidate)

        # index.html must never be cached, or a deployed update would keep serving
        # the previous bundle's asset references.
        return FileResponse(index_file, headers={"Cache-Control": "no-store"})

    logger.info("Serving the built frontend from %s", STATIC_DIR)


app = create_app()
