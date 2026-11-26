"""Settings → Enforcement → Run self-test (admins only).

``GET`` lists the last results; ``POST .../check`` says what a self-test of the
chosen targets would change, or why it is refused (it reads the tenant, never
writes); ``POST .../run`` runs it, once the admin has typed each target's name.
See ``app.services.enforcement_selftest``.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import Field

from app.api.deps import AdminUser, DbSession
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError
from app.schemas.auth import StrictModel
from app.services import connection as connection_service
from app.services import demo_tenant, settings_store
from app.services import enforcement_selftest as selftest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings/selftest", tags=["settings"])


class SelfTestTargets(StrictModel):
    user_id: str | None = Field(default=None, max_length=64)
    project_id: str | None = Field(default=None, max_length=64)
    project_actions: list[str] | None = Field(default=None, max_length=3)

    def as_request(self) -> selftest.SelfTestRequest:
        actions = (
            tuple(dict.fromkeys(self.project_actions))
            if self.project_actions is not None
            else selftest.ALL_PROJECT_ACTIONS
        )
        return selftest.SelfTestRequest(
            user_id=self.user_id or None,
            project_id=self.project_id or None,
            project_actions=actions,
        )


class SelfTestRun(SelfTestTargets):
    # The target's name, typed by the admin: its display name, or the project's name.
    confirm_user: str | None = Field(default=None, max_length=512)
    confirm_project: str | None = Field(default=None, max_length=512)


def _client(db: DbSession, *, demo: bool) -> CheckmarxClient:
    if demo:
        return demo_tenant.client()
    try:
        return connection_service.get_client(db)
    except CheckmarxError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "no_connection",
                "message": f"Cannot reach Checkmarx One to run a self-test: {exc}",
            },
        ) from exc


def _error(exc: selftest.SelfTestError) -> HTTPException:
    if isinstance(exc, selftest.SelfTestRefused):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": exc.code,
                "message": "The self-test was refused. Nothing was changed.",
                "problems": [refusal.sentence() for refusal in exc.refusals],
            },
        )
    code = (
        status.HTTP_409_CONFLICT
        if isinstance(exc, selftest.SelfTestBusy)
        else status.HTTP_400_BAD_REQUEST
    )
    return HTTPException(status_code=code, detail={"code": exc.code, "message": str(exc)})


@router.get("")
def list_selftests(ctx: AdminUser, db: DbSession) -> dict[str, object]:
    return {
        "running": selftest.is_running(db),
        "demo": settings_store.demo_mode(db),
        "notes": selftest.enforcement_notes(db),
        "keep": selftest.KEEP_RESULTS,
        "results": [selftest.as_dict(row) for row in selftest.recent(db)],
    }


@router.post("/check")
def check_selftest(body: SelfTestTargets, ctx: AdminUser, db: DbSession) -> dict[str, object]:
    demo = settings_store.demo_mode(db)
    client: CheckmarxClient | None
    if demo:
        client = demo_tenant.client()
    else:
        try:
            client = connection_service.get_client(db)
        except CheckmarxError as exc:
            logger.info("Self-test check without the tenant: %s", exc)
            client = None
    try:
        preflight = selftest.check(db, client, body.as_request(), demo=demo)
    except selftest.SelfTestError as exc:
        raise _error(exc) from exc
    result = preflight.as_dict()
    if client is None:
        result["warnings"] = [
            "Checkmarx One cannot be reached now, so the current state was not read.",
            *result["warnings"],  # type: ignore[misc]
        ]
    return result


@router.post("/run")
def run_selftest(body: SelfTestRun, ctx: AdminUser, db: DbSession) -> dict[str, object]:
    demo = settings_store.demo_mode(db)
    client = _client(db, demo=demo)
    try:
        row = selftest.run(
            db,
            client,
            body.as_request(),
            actor=ctx.actor,
            confirm={"user": body.confirm_user, "project": body.confirm_project},
            demo=demo,
        )
    except selftest.SelfTestError as exc:
        raise _error(exc) from exc
    return {"result": selftest.as_dict(row)}
