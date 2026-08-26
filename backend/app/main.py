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

from app import __version__, scheduler
from app.api.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
from app.api.routes import (
    accounts,
    auth,
    connection,
    dashboard,
    health,
    limits,
    notifications,
    ops,
)
from app.api.routes import (
    settings as settings_routes,
)
from app.core.config import ConfigError, Settings, get_settings
from app.core.logging import configure_logging
from app.db.migrate import upgrade_to_head
from app.db.session import session_scope
from app.services.auth import bootstrap_admin_if_needed

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _startup(settings: Settings) -> None:
    # Fail fast and loudly: without the master key we cannot read or write any
    # stored secret, and starting anyway would look healthy while being useless.
    settings.master_key_bytes()
    upgrade_to_head(settings.database_url)
    with session_scope() as db:
        bootstrap_admin_if_needed(db, settings)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    _startup(settings)
    if app.state.run_scheduler:
        scheduler.start()
    logger.info("CxCreditGuard %s started in %s mode", __version__, settings.env)
    yield
    if app.state.run_scheduler:
        scheduler.shutdown()
    logger.info("CxCreditGuard shutting down")


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
    api.include_router(notifications.router)
    api.include_router(ops.router)
    api.include_router(settings_routes.router)
    api.include_router(dashboard.router)
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
