"""Runtime settings, changeable from the GUI without a restart."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from app import scheduler
from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx import usage as usage_api
from app.models.enums import Severity
from app.schemas.dashboard import SettingsResponse, SettingsUpdateRequest
from app.services import delivery, settings_store
from app.services.audit import record_audit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["settings"])

# Mapping between the API field names and the storage keys. Explicit so a new
# setting cannot be written under a name the reader does not know about.
_PUBLIC_FIELDS: dict[str, str] = {
    "scheduler_enabled": settings_store.KEY_SCHEDULER_ENABLED,
    "schedule_mode": settings_store.KEY_SCHEDULE_MODE,
    "schedule_interval_minutes": settings_store.KEY_SCHEDULE_INTERVAL_MINUTES,
    "schedule_cron": settings_store.KEY_SCHEDULE_CRON,
    "org_refresh_minutes": settings_store.KEY_ORG_REFRESH_MINUTES,
    "usage_period_param": settings_store.KEY_USAGE_PERIOD,
    "usage_page_size": settings_store.KEY_USAGE_PAGE_SIZE,
    "retention_days": settings_store.KEY_RETENTION_DAYS,
    "notify_min_severity": settings_store.KEY_NOTIFY_MIN_SEVERITY,
    "smtp_host": settings_store.KEY_SMTP_HOST,
    "smtp_port": settings_store.KEY_SMTP_PORT,
    "smtp_username": settings_store.KEY_SMTP_USERNAME,
    "smtp_use_tls": settings_store.KEY_SMTP_USE_TLS,
    "smtp_from": settings_store.KEY_SMTP_FROM,
    "smtp_recipients": settings_store.KEY_SMTP_RECIPIENTS,
    "webhook_url": settings_store.KEY_WEBHOOK_URL,
}

_SECRET_FIELDS: dict[str, str] = {
    "smtp_password": settings_store.KEY_SMTP_PASSWORD,
    "webhook_secret": settings_store.KEY_WEBHOOK_SECRET,
}

# Fields whose value is never echoed back into the audit log.
_REDACT_IN_AUDIT = frozenset(_SECRET_FIELDS)


def _read(db) -> SettingsResponse:  # type: ignore[no-untyped-def]
    values = settings_store.all_public_settings(db)
    return SettingsResponse(
        scheduler_enabled=bool(values.get(settings_store.KEY_SCHEDULER_ENABLED, True)),
        schedule_mode=str(values.get(settings_store.KEY_SCHEDULE_MODE) or "interval"),
        schedule_interval_minutes=int(values.get(settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)),
        schedule_cron=values.get(settings_store.KEY_SCHEDULE_CRON),
        org_refresh_minutes=int(values.get(settings_store.KEY_ORG_REFRESH_MINUTES, 30)),
        usage_period_param=str(values.get(settings_store.KEY_USAGE_PERIOD) or "last_year"),
        usage_page_size=int(values.get(settings_store.KEY_USAGE_PAGE_SIZE, 100)),
        retention_days=int(values.get(settings_store.KEY_RETENTION_DAYS, 365)),
        notify_min_severity=values.get(settings_store.KEY_NOTIFY_MIN_SEVERITY) or Severity.WARNING,
        smtp_host=values.get(settings_store.KEY_SMTP_HOST),
        smtp_port=int(values.get(settings_store.KEY_SMTP_PORT, 587)),
        smtp_username=values.get(settings_store.KEY_SMTP_USERNAME),
        smtp_use_tls=bool(values.get(settings_store.KEY_SMTP_USE_TLS, True)),
        smtp_from=values.get(settings_store.KEY_SMTP_FROM),
        smtp_recipients=values.get(settings_store.KEY_SMTP_RECIPIENTS),
        smtp_password_configured=bool(values.get(f"{settings_store.KEY_SMTP_PASSWORD}.configured")),
        webhook_url=values.get(settings_store.KEY_WEBHOOK_URL),
        webhook_secret_configured=bool(
            values.get(f"{settings_store.KEY_WEBHOOK_SECRET}.configured")
        ),
        allowed_interval_minutes=list(settings_store.ALLOWED_INTERVAL_MINUTES),
        allowed_usage_periods=list(usage_api.SUPPORTED_PERIODS),
        current_schedule_description=scheduler.describe_schedule(),
    )


@router.get("", response_model=SettingsResponse)
def read_settings(ctx: CurrentUser, db: DbSession) -> SettingsResponse:
    return _read(db)


@router.put("", response_model=SettingsResponse)
def update_settings(
    payload: SettingsUpdateRequest, ctx: AdminUser, db: DbSession
) -> SettingsResponse:
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        return _read(db)

    if changes.get("schedule_mode") == "cron" and not (
        changes.get("schedule_cron") or settings_store.schedule_config(db).cron
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "cron_required",
                "message": "Cron mode needs a cron expression, for example */10 * * * *",
            },
        )

    if "schedule_cron" in changes and changes["schedule_cron"]:
        _validate_cron(changes["schedule_cron"])

    if "usage_period_param" in changes:
        window = str(changes["usage_period_param"])
        if window not in usage_api.SUPPORTED_PERIODS:
            # The endpoint rejects an unknown window with a 400, which would break
            # ingestion until someone noticed. Catch it at the point of change.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "invalid_period",
                    "message": (
                        f"{window!r} is not a lookback window Checkmarx accepts. "
                        f"Choose one of: {', '.join(usage_api.SUPPORTED_PERIODS)}."
                    ),
                },
            )

    before = _read(db).model_dump(exclude={"current_schedule_description"})
    audited_changes: dict[str, object] = {}

    for field, value in changes.items():
        if field in _SECRET_FIELDS:
            # An empty string clears the secret; None means "leave it alone".
            settings_store.set_secret(db, _SECRET_FIELDS[field], value or None)
            audited_changes[field] = "set" if value else "cleared"
            continue
        key = _PUBLIC_FIELDS.get(field)
        if key is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "unknown_setting", "message": f"{field} cannot be changed."},
            )
        settings_store.set_value(db, key, value)
        audited_changes[field] = value

    after = _read(db).model_dump(exclude={"current_schedule_description"})
    record_audit(
        db,
        action="settings.updated",
        actor=ctx.actor,
        target_type="settings",
        before={key: before[key] for key in audited_changes if key in before},
        after={
            key: ("[REDACTED]" if key in _REDACT_IN_AUDIT else after.get(key))
            for key in audited_changes
        },
        detail=f"{len(audited_changes)} setting(s) changed.",
    )
    db.commit()

    # A settings change is a new chance for a previously failing channel to work,
    # so the retry counters start again.
    if any(field.startswith(("smtp_", "webhook_", "notify_")) for field in changes):
        delivery.reset_attempts()

    # Apply the schedule immediately rather than waiting for a restart.
    schedule_touched = any(
        field.startswith("schedule") or field == "scheduler_enabled" for field in changes
    )
    if schedule_touched:
        try:
            description = scheduler.reconfigure()
            logger.info("Scheduler reconfigured to %s", description)
        except Exception:  # noqa: BLE001 - a bad schedule must not lose the settings
            logger.exception("Could not apply the new schedule to the running scheduler")

    return _read(db)


@router.post("/test-notification")
def test_notification(ctx: AdminUser, db: DbSession) -> dict[str, object]:
    """Deliver a sample notification over every configured channel.

    Nothing is written to the Notification Center: a test that leaves rows behind
    makes the feed less trustworthy, not more.
    """
    outcome = delivery.send_test_notification(db)
    record_audit(
        db,
        action="settings.notification_tested",
        actor=ctx.actor,
        target_type="settings",
        after=dict(outcome),
        detail="Test notification sent.",
    )
    db.commit()
    return {
        "channels": outcome,
        "ok": bool(outcome) and all(str(value) == "sent" for value in outcome.values()),
    }


def _validate_cron(expression: str) -> None:
    from apscheduler.triggers.cron import CronTrigger

    try:
        CronTrigger.from_crontab(expression, timezone="UTC")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_cron",
                "message": f"{expression!r} is not a valid cron expression: {exc}",
            },
        ) from exc
