"""The fast check and the Checkmarx One webhook: settings, status, secret.

The inbound webhook itself is app/api/routes/webhooks.py.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import Field

from app import scheduler
from app.api.deps import AdminUser, CurrentUser, DbSession
from app.schemas.auth import StrictModel
from app.services import cx_webhook, fastcheck, settings_store
from app.services.audit import record_audit

router = APIRouter(prefix="/fastpath", tags=["fastpath"])


class FastPathUpdateRequest(StrictModel):
    fast_check_enabled: bool | None = None
    fast_check_interval_seconds: int | None = Field(
        default=None, ge=fastcheck.MIN_SECONDS, le=fastcheck.MAX_SECONDS
    )
    webhook_enabled: bool | None = None


def _read(db) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    return {"fast_check": fastcheck.describe(db), "webhook": cx_webhook.describe(db)}


@router.get("")
def read_fastpath(ctx: CurrentUser, db: DbSession) -> dict[str, Any]:
    return _read(db)


@router.put("")
def update_fastpath(
    payload: FastPathUpdateRequest, ctx: AdminUser, db: DbSession
) -> dict[str, Any]:
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    before = fastcheck.config(db)
    if "fast_check_enabled" in changes:
        settings_store.set_value(
            db, settings_store.KEY_FAST_CHECK_ENABLED, bool(changes["fast_check_enabled"])
        )
    if "fast_check_interval_seconds" in changes:
        settings_store.set_value(
            db,
            settings_store.KEY_FAST_CHECK_SECONDS,
            fastcheck.normalise_seconds(changes["fast_check_interval_seconds"]),
        )
    after = fastcheck.config(db)
    if after != before:
        record_audit(
            db,
            action="settings.updated",
            actor=ctx.actor,
            target_type="settings",
            before={
                "fast_check_enabled": before.enabled,
                "fast_check_seconds": before.interval_seconds,
            },
            after={
                "fast_check_enabled": after.enabled,
                "fast_check_seconds": after.interval_seconds,
            },
        )
    if "webhook_enabled" in changes:
        cx_webhook.set_enabled(db, bool(changes["webhook_enabled"]), actor=ctx.actor)
    db.commit()
    if after != before:
        scheduler.reconfigure()
    return _read(db)


@router.post("/webhook-secret")
def rotate_webhook_secret(ctx: AdminUser, db: DbSession) -> dict[str, str]:
    """A new secret, shown this once: paste it into Checkmarx One's webhook."""
    secret = cx_webhook.rotate_secret(db, actor=ctx.actor)
    db.commit()
    return {"secret": secret, "path": cx_webhook.PATH}
