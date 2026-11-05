"""Operations hardening: attestation, a scheduler watchdog, and config backup.

Three self-contained operational aids for running CxCreditGuard as a single-node
service:

* **Attestation** reports exactly what is running - the version, the applied
  migration head, and a reproducible digest over the non-secret configuration
  surface - so an operator can verify an instance and spot configuration drift,
  plus an update-awareness check against a recorded "latest" version.
* **Watchdog** turns the scheduler's run history into a liveness verdict, so a
  dead or stuck scheduler is visible (in ``/healthz`` and in-app) rather than
  silently starving governance.
* **Backup/restore** exports the portable configuration - settings (no secrets),
  credit limits and overrides - as JSON an operator can download, email, or feed
  back in to rebuild an instance. It is deliberately a *configuration* backup:
  secrets, password hashes, accounts and the audit ledger are never exported.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import __version__
from app.db.base import utcnow
from app.models.enums import EntityType
from app.models.limits import CreditLimit, Exemption
from app.models.usage import SchedulerRun
from app.services import limits_service, settings_store
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

# Optional "latest available version", recorded by a deploy pipeline or an admin.
# Update application itself is deployment-driven; this only makes staleness visible.
KEY_LATEST_VERSION = "ops.latest_version"

BACKUP_VERSION = 1


# --------------------------------------------------------------- attestation


@dataclass(frozen=True, slots=True)
class Attestation:
    version: str
    migration_head: str | None
    config_digest: str
    generated_at: datetime


def _applied_migration_head(session: Session) -> str | None:
    try:
        return session.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
    except Exception:  # noqa: BLE001 - absence of the table is not an error here
        logger.debug("Could not read the applied migration head", exc_info=True)
        return None


def attestation(session: Session) -> Attestation:
    """A verifiable fingerprint of the running instance.

    The digest covers the version, the applied migration head and the non-secret
    configuration surface (secrets appear only as their configured-ness, never
    their values), so two instances that agree on it are configured identically.
    """
    head = _applied_migration_head(session)
    surface = settings_store.all_public_settings(session)
    payload = json.dumps(
        {"version": __version__, "head": head, "settings": surface},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return Attestation(
        version=__version__, migration_head=head, config_digest=digest, generated_at=utcnow()
    )


def _version_tuple(value: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in value.strip().split("."))
    except (AttributeError, ValueError):
        return None


def update_status(session: Session) -> dict[str, Any]:
    """Compare the running version to a recorded latest version, if any."""
    latest = settings_store.get_value(session, KEY_LATEST_VERSION, None)
    current = __version__
    if not latest:
        return {"current": current, "latest": None, "update_available": False}
    current_t, latest_t = _version_tuple(current), _version_tuple(str(latest))
    if current_t is not None and latest_t is not None:
        # Pad to equal length so "1.2" and "1.2.0" compare equal, not "newer".
        width = max(len(current_t), len(latest_t))
        current_p = current_t + (0,) * (width - len(current_t))
        latest_p = latest_t + (0,) * (width - len(latest_t))
        available = latest_p > current_p
    else:
        # Unparseable version strings: treat any difference as an update.
        available = str(latest) != current
    return {"current": current, "latest": str(latest), "update_available": available}


def set_latest_version(session: Session, *, version: str, actor: AuditActor) -> None:
    settings_store.set_value(session, KEY_LATEST_VERSION, version.strip())
    record_audit(
        session,
        action="ops.latest_version_set",
        actor=actor,
        target_type="ops",
        detail=f"Recorded latest available version as {version.strip()!r}.",
    )


# ------------------------------------------------------------------ watchdog


@dataclass(frozen=True, slots=True)
class WatchdogStatus:
    state: str  # "ok" | "stale" | "down" | "disabled"
    enabled: bool
    seconds_since_last_run: int | None
    last_run_at: datetime | None
    last_status: str | None
    tolerance_seconds: int
    detail: str


def watchdog_status(session: Session, *, now: datetime | None = None) -> WatchdogStatus:
    """Judge scheduler liveness from its run history.

    ``tolerance_seconds`` is a few missed intervals (matching the diagnostics
    staleness window); beyond it the scheduler is ``stale``, and well beyond it
    ``down``. A disabled scheduler is reported as such, not as a failure.
    """
    moment = now or utcnow()
    config = settings_store.schedule_config(session)
    tolerance = max(config.interval_minutes * 3, 60) * 60
    last = session.scalar(select(SchedulerRun).order_by(SchedulerRun.started_at.desc()).limit(1))

    if not config.enabled:
        return WatchdogStatus(
            "disabled",
            False,
            None,
            last.started_at if last else None,
            last.status if last else None,
            tolerance,
            "The scheduler is disabled, so nothing runs automatically.",
        )
    if last is None:
        return WatchdogStatus(
            "down", True, None, None, None, tolerance, "Enabled, but no cycle has ever run."
        )

    reference = last.finished_at or last.started_at
    gap = max(0, int((moment - reference).total_seconds()))
    if gap <= tolerance:
        state, detail = "ok", f"Last cycle {gap}s ago."
    elif gap <= tolerance * 3:
        state, detail = "stale", f"No cycle for {gap}s (tolerance {tolerance}s); it may be stuck."
    else:
        state, detail = "down", f"No cycle for {gap}s; the scheduler may have died."
    return WatchdogStatus(state, True, gap, last.started_at, last.status, tolerance, detail)


def scheduler_alive(session: Session, *, now: datetime | None = None) -> bool:
    """Terse boolean for the unauthenticated health endpoint.

    A disabled scheduler counts as alive (it is not a fault); only a stuck or
    dead enabled scheduler is not.
    """
    return watchdog_status(session, now=now).state in {"ok", "disabled"}


# -------------------------------------------------------------- backup/restore


class BackupError(ValueError):
    """A backup payload could not be parsed or restored."""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


_LIMIT_FIELDS = (
    "credit_limit",
    "period_type",
    "warning_threshold_pct",
    "enforce",
    "is_active",
    "include_member_usage",
    "hold_until_released",
    "count_existing_usage",
    "notes",
    "business_unit",
)


def _limit_to_dict(limit: CreditLimit) -> dict[str, Any]:
    data = {field: getattr(limit, field) for field in _LIMIT_FIELDS}
    data.update(
        entity_type=limit.entity_type,
        entity_id=limit.entity_id,
        entity_label=limit.entity_label,
        custom_period_start=_iso(limit.custom_period_start),
        custom_period_end=_iso(limit.custom_period_end),
    )
    return data


def _exemption_to_dict(exemption: Exemption) -> dict[str, Any]:
    return {
        "entity_type": exemption.entity_type,
        "entity_id": exemption.entity_id,
        "entity_label": exemption.entity_label,
        "reason": exemption.reason,
        "expires_at": _iso(exemption.expires_at),
    }


def export_config_backup(session: Session) -> dict[str, Any]:
    """A portable, secret-free snapshot of the configuration."""
    public = settings_store.all_public_settings(session)
    # The whitelist is the restore map: only non-secret, restorable keys, so a
    # masked secret or a ".configured" flag can never reach the output.
    settings_out = {key: value for key, value in public.items() if key in _SETTING_FIELD_BY_KEY}
    limits = [_limit_to_dict(limit) for limit in session.scalars(select(CreditLimit))]
    now = utcnow()
    exemptions = [
        _exemption_to_dict(exemption)
        for exemption in session.scalars(select(Exemption))
        # Skip overrides that have already lapsed: they cannot be re-created with a
        # past expiry and carry no meaning to restore.
        if exemption.expires_at is None or exemption.expires_at > now
    ]
    return {
        "backup_version": BACKUP_VERSION,
        "generated_at": now.isoformat(),
        "app_version": __version__,
        "settings": settings_out,
        "limits": limits,
        "exemptions": exemptions,
    }


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise BackupError(f"Invalid date in backup: {value!r}") from exc


def _dict_list(value: Any, section: str) -> list[dict[str, Any]]:
    """Coerce a backup section to a list of dicts, rejecting anything else as a
    bad backup (a 400) rather than letting a str/dict iterate into a 500."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise BackupError(f"The backup's {section} section must be a list of objects.")
    return value


def _limit_input(row: dict[str, Any]) -> limits_service.LimitInput:
    try:
        return limits_service.LimitInput(
            entity_type=EntityType(row["entity_type"]),
            entity_id=str(row["entity_id"]),
            credit_limit=int(row["credit_limit"]),
            period_type=str(row.get("period_type") or "monthly"),
            warning_threshold_pct=int(row.get("warning_threshold_pct", 80)),
            enforce=bool(row.get("enforce", False)),
            include_member_usage=bool(row.get("include_member_usage", False)),
            hold_until_released=bool(row.get("hold_until_released", False)),
            count_existing_usage=bool(row.get("count_existing_usage", False)),
            custom_period_start=_parse_dt(row.get("custom_period_start")),
            custom_period_end=_parse_dt(row.get("custom_period_end")),
            notes=row.get("notes"),
            business_unit=row.get("business_unit"),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupError(f"Invalid limit entry in backup: {exc}") from exc


# The non-secret settings that are backed up and restored, each mapped to its
# SettingsUpdateRequest field so a restore validates through the same bounds as
# the settings form. This map is the single whitelist for both export and
# restore: secret keys (SMTP/webhook secrets) are deliberately absent, so they
# can never be exported or set from a backup. Includes the non-secret delivery
# destinations (SMTP host/from/recipients, webhook URL) so a backup is enough to
# rebuild an instance's configuration.
_SETTING_FIELD_BY_KEY: dict[str, str] = {
    settings_store.KEY_SCHEDULER_ENABLED: "scheduler_enabled",
    settings_store.KEY_SCHEDULE_MODE: "schedule_mode",
    settings_store.KEY_SCHEDULE_INTERVAL_MINUTES: "schedule_interval_minutes",
    settings_store.KEY_SCHEDULE_CRON: "schedule_cron",
    settings_store.KEY_ORG_REFRESH_MINUTES: "org_refresh_minutes",
    settings_store.KEY_USAGE_PERIOD: "usage_period_param",
    settings_store.KEY_USAGE_PAGE_SIZE: "usage_page_size",
    settings_store.KEY_RETENTION_DAYS: "retention_days",
    settings_store.KEY_SMTP_HOST: "smtp_host",
    settings_store.KEY_SMTP_PORT: "smtp_port",
    settings_store.KEY_SMTP_USERNAME: "smtp_username",
    settings_store.KEY_SMTP_USE_TLS: "smtp_use_tls",
    settings_store.KEY_SMTP_FROM: "smtp_from",
    settings_store.KEY_SMTP_RECIPIENTS: "smtp_recipients",
    settings_store.KEY_WEBHOOK_URL: "webhook_url",
    settings_store.KEY_NOTIFY_MIN_SEVERITY: "notify_min_severity",
    settings_store.KEY_UI_ACCENT: "ui_accent",
    settings_store.KEY_SELF_SERVICE_REQUESTS: "self_service_requests",
    settings_store.KEY_REPORT_EMAIL_ENABLED: "report_email_enabled",
    settings_store.KEY_CREDIT_UNIT_COST: "credit_unit_cost",
    settings_store.KEY_DEMO_MODE: "demo_mode",
    settings_store.KEY_AUTOMATION_ENABLED: "automation_enabled",
    settings_store.KEY_AUTO_APPROVE_MAX_INCREASE: "auto_approve_max_increase",
    settings_store.KEY_AUTO_APPROVE_EXPIRY_DAYS: "auto_approve_expiry_days",
}


def _validate_restored_settings(settings_in: dict[str, Any]) -> None:
    """Run the recognised settings through the settings-form schema and the usage
    window allow-list, raising BackupError on any value the form would reject."""
    from pydantic import ValidationError

    from app.checkmarx import usage as usage_api
    from app.schemas.dashboard import SettingsUpdateRequest

    fields = {
        _SETTING_FIELD_BY_KEY[key]: value
        for key, value in settings_in.items()
        if key in _SETTING_FIELD_BY_KEY
    }
    if fields:
        try:
            SettingsUpdateRequest(**fields)
        except ValidationError as exc:
            raise BackupError(
                f"Backup contains settings that fail validation: {exc.error_count()} issue(s)."
            ) from exc
    window = settings_in.get(settings_store.KEY_USAGE_PERIOD)
    if window is not None and str(window) not in usage_api.SUPPORTED_PERIODS:
        raise BackupError(f"Backup's usage window {window!r} is not one Checkmarx accepts.")


def restore_config_backup(session: Session, *, data: Any, actor: AuditActor) -> dict[str, int]:
    """Apply a configuration backup: upsert settings, limits and overrides.

    Idempotent by entity: a limit or override for an entity already present is
    updated in place rather than duplicated. Unknown or secret settings keys are
    ignored. Everything is applied through the normal services, so each change is
    audited. The whole restore shares the caller's transaction, committed once.
    """
    if not isinstance(data, dict) or data.get("backup_version") != BACKUP_VERSION:
        raise BackupError("Unrecognised or unsupported backup format.")

    settings_in = data.get("settings") or {}
    if not isinstance(settings_in, dict):
        raise BackupError("The backup's settings section is malformed.")
    # Validate the restored settings with the same bounds the settings form uses,
    # BEFORE applying anything, so a hand-edited or foreign backup cannot slip an
    # out-of-range interval or unsupported window past the normal validators and
    # wedge the instance. Only recognised, non-secret keys are ever applied.
    _validate_restored_settings(settings_in)
    restored_settings = 0
    for key, value in settings_in.items():
        if key in _SETTING_FIELD_BY_KEY:
            settings_store.set_value(session, key, value)
            restored_settings += 1

    created = updated = 0
    for row in _dict_list(data.get("limits"), "limits"):
        limit_input = _limit_input(row)
        existing = session.scalar(
            select(CreditLimit).where(
                CreditLimit.entity_type == str(limit_input.entity_type),
                CreditLimit.entity_id == limit_input.entity_id,
            )
        )
        # A semantically invalid limit (negative budget, bad threshold, custom
        # period without a start, member usage on a non-group) raises LimitError
        # from the service; surface it as a clean bad-backup error, not a 500.
        try:
            if existing is None:
                created_limit = limits_service.create_limit(session, data=limit_input, actor=actor)
                # create_limit always makes an active limit; honour an inactive backup.
                if row.get("is_active") is False:
                    limits_service.update_limit(
                        session, limit=created_limit, changes={"is_active": False}, actor=actor
                    )
                created += 1
            else:
                # is_active lives on the model, not on LimitInput, so set it from the
                # row; every other audited field maps straight from the parsed input.
                changes: dict[str, Any] = {
                    field: getattr(limit_input, field)
                    for field in limits_service.AUDITED_FIELDS
                    if field != "is_active"
                }
                changes["is_active"] = bool(row.get("is_active", True))
                limits_service.update_limit(session, limit=existing, changes=changes, actor=actor)
                updated += 1
        except limits_service.LimitError as exc:
            raise BackupError(f"Invalid limit entry in backup: {exc}") from exc

    exemptions_restored = 0
    now = utcnow()
    for row in _dict_list(data.get("exemptions"), "exemptions"):
        expires_at = _parse_dt(row.get("expires_at"))
        if expires_at is not None and expires_at <= now:
            continue  # a lapsed override cannot be re-created
        try:
            limits_service.add_exemption(
                session,
                entity_type=EntityType(row["entity_type"]),
                entity_id=str(row["entity_id"]),
                reason=row.get("reason"),
                expires_at=expires_at,
                actor=actor,
            )
        except (KeyError, ValueError, TypeError, limits_service.LimitError) as exc:
            raise BackupError(f"Invalid override entry in backup: {exc}") from exc
        exemptions_restored += 1

    stats = {
        "settings": restored_settings,
        "limits_created": created,
        "limits_updated": updated,
        "exemptions": exemptions_restored,
    }
    record_audit(
        session,
        action="ops.config_restored",
        actor=actor,
        target_type="ops",
        after=stats,
        detail=(
            f"Restored configuration from a backup: {restored_settings} setting(s), "
            f"{created} limit(s) created, {updated} updated, {exemptions_restored} override(s)."
        ),
    )
    return stats
