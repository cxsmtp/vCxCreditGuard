"""Runtime settings that an admin changes from the GUI without a restart.

Environment variables cover deployment concerns (database, master key, TLS).
These cover operational ones: how often to poll, how wide a usage window to ask
for, where to send notifications. They live in ``app_setting`` as JSON text, with
secret values encrypted under their own purpose and never returned unmasked.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.usage import DEFAULT_PERIOD
from app.core.crypto import PURPOSE_SMTP_PASSWORD, PURPOSE_WEBHOOK_SECRET, get_secret_box
from app.models.connection import AppSetting

logger = logging.getLogger(__name__)

# Scheduler
KEY_SCHEDULE_MODE = "scheduler.mode"  # "interval" or "cron"
KEY_SCHEDULE_INTERVAL_MINUTES = "scheduler.interval_minutes"
KEY_SCHEDULE_CRON = "scheduler.cron"
KEY_ORG_REFRESH_MINUTES = "scheduler.org_refresh_minutes"
KEY_SCHEDULER_ENABLED = "scheduler.enabled"

# Ingestion
KEY_USAGE_PERIOD = "usage.period_param"
KEY_USAGE_PAGE_SIZE = "usage.page_size"

# Retention
KEY_RETENTION_DAYS = "retention.days"

# Notifications
KEY_SMTP_HOST = "notify.smtp.host"
KEY_SMTP_PORT = "notify.smtp.port"
KEY_SMTP_USERNAME = "notify.smtp.username"
KEY_SMTP_PASSWORD = "notify.smtp.password"  # secret
KEY_SMTP_USE_TLS = "notify.smtp.use_tls"
KEY_SMTP_FROM = "notify.smtp.from"
KEY_SMTP_RECIPIENTS = "notify.smtp.recipients"
KEY_WEBHOOK_URL = "notify.webhook.url"
KEY_WEBHOOK_SECRET = "notify.webhook.secret"  # secret
KEY_NOTIFY_MIN_SEVERITY = "notify.min_severity"

SECRET_KEYS: dict[str, str] = {
    KEY_SMTP_PASSWORD: PURPOSE_SMTP_PASSWORD,
    KEY_WEBHOOK_SECRET: PURPOSE_WEBHOOK_SECRET,
}

ALLOWED_INTERVAL_MINUTES: tuple[int, ...] = (2, 5, 15, 60)

DEFAULTS: dict[str, Any] = {
    KEY_SCHEDULER_ENABLED: True,
    KEY_SCHEDULE_MODE: "interval",
    KEY_SCHEDULE_INTERVAL_MINUTES: 15,
    KEY_SCHEDULE_CRON: None,
    KEY_ORG_REFRESH_MINUTES: 30,
    KEY_USAGE_PERIOD: DEFAULT_PERIOD,
    KEY_USAGE_PAGE_SIZE: 100,
    KEY_RETENTION_DAYS: 365,
    KEY_SMTP_PORT: 587,
    KEY_SMTP_USE_TLS: True,
    KEY_NOTIFY_MIN_SEVERITY: "warning",
}


@dataclass(frozen=True, slots=True)
class ScheduleConfig:
    enabled: bool
    mode: str
    interval_minutes: int
    cron: str | None
    org_refresh_minutes: int


def get_raw(session: Session, key: str) -> AppSetting | None:
    return session.get(AppSetting, key)


def get_value(session: Session, key: str, default: Any = None) -> Any:
    """Decoded value, falling back to DEFAULTS then the supplied default."""
    row = get_raw(session, key)
    if row is None or row.value is None:
        return DEFAULTS.get(key, default)
    if row.is_secret:
        # Callers that genuinely need the plaintext use get_secret().
        return "********"
    try:
        return json.loads(row.value)
    except json.JSONDecodeError:
        logger.warning("Setting %s holds invalid JSON, using the default", key)
        return DEFAULTS.get(key, default)


def get_secret(session: Session, key: str) -> str | None:
    purpose = SECRET_KEYS.get(key)
    if purpose is None:
        raise ValueError(f"{key} is not a secret setting")
    row = get_raw(session, key)
    if row is None or not row.value:
        return None
    return get_secret_box().decrypt(row.value, purpose=purpose)


def set_value(session: Session, key: str, value: Any, *, description: str | None = None) -> None:
    """Store a non secret setting as JSON."""
    if key in SECRET_KEYS:
        raise ValueError(f"{key} is a secret; use set_secret()")
    row = get_raw(session, key)
    encoded = json.dumps(value)
    if row is None:
        session.add(AppSetting(key=key, value=encoded, is_secret=False, description=description))
    else:
        row.value = encoded
        if description:
            row.description = description
    session.flush()


def set_secret(session: Session, key: str, value: str | None) -> None:
    """Store or clear a secret setting, encrypted under its own purpose."""
    purpose = SECRET_KEYS.get(key)
    if purpose is None:
        raise ValueError(f"{key} is not a secret setting")
    row = get_raw(session, key)
    ciphertext = get_secret_box().encrypt(value, purpose=purpose) if value else None
    if row is None:
        session.add(AppSetting(key=key, value=ciphertext, is_secret=True))
    else:
        row.value = ciphertext
    session.flush()


def all_public_settings(session: Session) -> dict[str, Any]:
    """Every setting with secrets masked, for the Settings page."""
    stored = {row.key: row for row in session.scalars(select(AppSetting))}
    result: dict[str, Any] = dict(DEFAULTS)
    for key, row in stored.items():
        if key in SECRET_KEYS:
            result[key] = "********" if row.value else None
        elif row.value is not None:
            try:
                result[key] = json.loads(row.value)
            except json.JSONDecodeError:
                result[key] = None
    # Report whether each secret is configured without revealing it.
    for key in SECRET_KEYS:
        row = stored.get(key)
        result[f"{key}.configured"] = bool(row and row.value)
    return result


def schedule_config(session: Session) -> ScheduleConfig:
    interval = get_value(session, KEY_SCHEDULE_INTERVAL_MINUTES)
    if not isinstance(interval, int) or interval < 1:
        interval = DEFAULTS[KEY_SCHEDULE_INTERVAL_MINUTES]
    org_refresh = get_value(session, KEY_ORG_REFRESH_MINUTES)
    if not isinstance(org_refresh, int) or org_refresh < 1:
        org_refresh = DEFAULTS[KEY_ORG_REFRESH_MINUTES]
    mode = get_value(session, KEY_SCHEDULE_MODE)
    cron = get_value(session, KEY_SCHEDULE_CRON)
    return ScheduleConfig(
        enabled=bool(get_value(session, KEY_SCHEDULER_ENABLED)),
        mode="cron" if mode == "cron" and isinstance(cron, str) and cron.strip() else "interval",
        interval_minutes=interval,
        cron=cron.strip() if isinstance(cron, str) and cron.strip() else None,
        org_refresh_minutes=org_refresh,
    )


def usage_period(session: Session) -> str:
    value = get_value(session, KEY_USAGE_PERIOD)
    return value if isinstance(value, str) and value.strip() else DEFAULT_PERIOD


def usage_page_size(session: Session) -> int:
    value = get_value(session, KEY_USAGE_PAGE_SIZE)
    return value if isinstance(value, int) and 1 <= value <= 1000 else 100
