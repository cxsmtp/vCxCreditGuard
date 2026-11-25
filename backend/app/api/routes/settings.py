"""Runtime settings, changeable from the GUI without a restart."""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, status

from app import scheduler
from app.api.deps import AdminUser, CurrentUser, DbSession
from app.checkmarx import iam
from app.checkmarx import usage as usage_api
from app.models.enums import Severity
from app.schemas.dashboard import (
    ClientRoleResponse,
    ClientRolesResponse,
    SettingsResponse,
    SettingsUpdateRequest,
)
from app.services import activity_source, delivery, pacing, role_sources, settings_store
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
    "usage_source": settings_store.KEY_USAGE_SOURCE,
    "activity_max_pages_per_cycle": settings_store.KEY_ACTIVITY_MAX_PAGES,
    "integration_accounts": settings_store.KEY_INTEGRATION_ACCOUNTS,
    "retention_days": settings_store.KEY_RETENTION_DAYS,
    "retention_thin_snapshots": settings_store.KEY_RETENTION_THIN_SNAPSHOTS,
    "notify_min_severity": settings_store.KEY_NOTIFY_MIN_SEVERITY,
    "smtp_host": settings_store.KEY_SMTP_HOST,
    "smtp_port": settings_store.KEY_SMTP_PORT,
    "smtp_username": settings_store.KEY_SMTP_USERNAME,
    "smtp_use_tls": settings_store.KEY_SMTP_USE_TLS,
    "smtp_from": settings_store.KEY_SMTP_FROM,
    "smtp_recipients": settings_store.KEY_SMTP_RECIPIENTS,
    "ui_accent": settings_store.KEY_UI_ACCENT,
    "self_service_requests": settings_store.KEY_SELF_SERVICE_REQUESTS,
    "report_email_enabled": settings_store.KEY_REPORT_EMAIL_ENABLED,
    "credit_unit_cost": settings_store.KEY_CREDIT_UNIT_COST,
    "demo_mode": settings_store.KEY_DEMO_MODE,
    "automation_enabled": settings_store.KEY_AUTOMATION_ENABLED,
    "auto_approve_max_increase": settings_store.KEY_AUTO_APPROVE_MAX_INCREASE,
    "auto_approve_expiry_days": settings_store.KEY_AUTO_APPROVE_EXPIRY_DAYS,
    "enforcement_paused": settings_store.KEY_ENFORCEMENT_PAUSED,
    "max_new_enforcements_per_cycle": settings_store.KEY_MAX_NEW_ENFORCEMENTS,
    "max_new_targets_per_cycle": settings_store.KEY_MAX_NEW_TARGETS,
    "protected_roles": settings_store.KEY_PROTECTED_ROLES,
    "fusion_lock_override": settings_store.KEY_FUSION_LOCK,
    "ai_roles": settings_store.KEY_AI_ROLES,
    "charge_auto_triage_to_scan_initiator": settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR,
    "verify_interval_minutes": settings_store.KEY_VERIFY_INTERVAL_MINUTES,
    "max_verifications_per_cycle": settings_store.KEY_MAX_VERIFICATIONS,
    "max_writes_per_cycle": settings_store.KEY_MAX_WRITES,
    "violation_projects_per_cycle": settings_store.KEY_VIOLATION_PROJECTS,
    "attribution_projects_per_cycle": settings_store.KEY_ATTRIBUTION_PROJECTS,
    "attribution_requests_per_cycle": settings_store.KEY_ATTRIBUTION_REQUESTS,
    "read_concurrency": settings_store.KEY_READ_CONCURRENCY,
    "cycle_time_budget_pct": settings_store.KEY_CYCLE_TIME_BUDGET_PCT,
}

_SECRET_FIELDS: dict[str, str] = {
    "smtp_password": settings_store.KEY_SMTP_PASSWORD,
    "webhook_secret": settings_store.KEY_WEBHOOK_SECRET,
    # Write only, like the others: a webhook URL lets its holder post to the
    # channel, so it is never sent back to the browser or written to the audit log.
    "webhook_url": settings_store.KEY_WEBHOOK_URL,
}

# Fields whose value is never echoed back into the audit log.
_REDACT_IN_AUDIT = frozenset(_SECRET_FIELDS)


def _webhook_host(db) -> str | None:  # type: ignore[no-untyped-def]
    """Just the host of the configured webhook, so an admin can tell which one it
    is without the secret part of the URL ever leaving the server."""
    url = settings_store.get_secret(db, settings_store.KEY_WEBHOOK_URL)
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _read(db) -> SettingsResponse:  # type: ignore[no-untyped-def]
    values = settings_store.all_public_settings(db)
    policy = settings_store.automation_policy(db)
    guard = settings_store.enforcement_guard(db)
    paced = pacing.pacing(db)
    return SettingsResponse(
        scheduler_enabled=bool(values.get(settings_store.KEY_SCHEDULER_ENABLED, True)),
        schedule_mode=str(values.get(settings_store.KEY_SCHEDULE_MODE) or "interval"),
        schedule_interval_minutes=int(values.get(settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)),
        schedule_cron=values.get(settings_store.KEY_SCHEDULE_CRON),
        org_refresh_minutes=int(values.get(settings_store.KEY_ORG_REFRESH_MINUTES, 30)),
        usage_period_param=str(values.get(settings_store.KEY_USAGE_PERIOD) or "last_year"),
        usage_page_size=int(values.get(settings_store.KEY_USAGE_PAGE_SIZE, 100)),
        usage_source=settings_store.usage_source(db),
        allowed_usage_sources=list(settings_store.USAGE_SOURCES),
        activity_max_pages_per_cycle=settings_store.activity_max_pages(db),
        integration_accounts=settings_store.integration_accounts(db),
        usage_source_status=activity_source.describe(db),
        retention_days=int(values.get(settings_store.KEY_RETENTION_DAYS, 365)),
        retention_thin_snapshots=settings_store.thin_snapshots(db),
        notify_min_severity=values.get(settings_store.KEY_NOTIFY_MIN_SEVERITY) or Severity.WARNING,
        smtp_host=values.get(settings_store.KEY_SMTP_HOST),
        smtp_port=int(values.get(settings_store.KEY_SMTP_PORT, 587)),
        smtp_username=values.get(settings_store.KEY_SMTP_USERNAME),
        smtp_use_tls=bool(values.get(settings_store.KEY_SMTP_USE_TLS, True)),
        smtp_from=values.get(settings_store.KEY_SMTP_FROM),
        smtp_recipients=values.get(settings_store.KEY_SMTP_RECIPIENTS),
        smtp_password_configured=bool(values.get(f"{settings_store.KEY_SMTP_PASSWORD}.configured")),
        webhook_url_configured=bool(values.get(f"{settings_store.KEY_WEBHOOK_URL}.configured")),
        webhook_host=_webhook_host(db),
        webhook_secret_configured=bool(
            values.get(f"{settings_store.KEY_WEBHOOK_SECRET}.configured")
        ),
        allowed_interval_minutes=list(settings_store.ALLOWED_INTERVAL_MINUTES),
        allowed_usage_periods=list(usage_api.SUPPORTED_PERIODS),
        ui_accent=settings_store.ui_accent(db),
        allowed_accents=list(settings_store.ALLOWED_ACCENTS),
        self_service_requests=settings_store.self_service_requests_enabled(db),
        report_email_enabled=settings_store.report_email_enabled(db),
        credit_unit_cost=settings_store.credit_unit_cost(db),
        demo_mode=settings_store.demo_mode(db),
        automation_enabled=policy.enabled,
        auto_approve_max_increase=policy.auto_approve_max_increase,
        auto_approve_expiry_days=policy.auto_approve_expiry_days,
        enforcement_paused=guard.paused,
        enforcement_pause_reason=guard.pause_reason if guard.paused else None,
        max_new_enforcements_per_cycle=guard.max_new_per_cycle,
        max_new_targets_per_cycle=guard.max_new_targets_per_cycle,
        protected_roles=", ".join(sorted(guard.protected_roles)),
        fusion_lock_override=settings_store.fusion_lock_enabled(db),
        ai_roles=list(settings_store.ai_role_names(db)),
        default_ai_roles=list(iam.DEFAULT_AI_ROLE_NAMES),
        charge_auto_triage_to_scan_initiator=bool(
            values.get(settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR) is True
        ),
        current_schedule_description=scheduler.describe_schedule(),
        verify_interval_minutes=paced.verify_interval_minutes,
        max_verifications_per_cycle=paced.max_verifications_per_cycle,
        max_writes_per_cycle=paced.max_writes_per_cycle,
        violation_projects_per_cycle=paced.violation_projects_per_cycle,
        attribution_projects_per_cycle=paced.attribution_projects_per_cycle,
        attribution_requests_per_cycle=paced.attribution_requests_per_cycle,
        read_concurrency=paced.read_concurrency,
        cycle_time_budget_pct=paced.time_budget_pct,
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

    if "usage_source" in changes and changes["usage_source"] not in settings_store.USAGE_SOURCES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_usage_source",
                "message": (
                    f"{changes['usage_source']!r} is not a usage source. "
                    f"Choose one of: {', '.join(settings_store.USAGE_SOURCES)}."
                ),
            },
        )
    if "integration_accounts" in changes:
        changes["integration_accounts"] = settings_store.normalise_account_names(
            changes["integration_accounts"] or []
        )

    if "ui_accent" in changes:
        accent = str(changes["ui_accent"])
        if accent not in settings_store.ALLOWED_ACCENTS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "invalid_accent",
                    "message": (
                        f"{accent!r} is not a known accent theme. "
                        f"Choose one of: {', '.join(settings_store.ALLOWED_ACCENTS)}."
                    ),
                },
            )

    confirm_admin_roles = bool(changes.pop("confirm_admin_roles", None))
    if "ai_roles" in changes:
        protected = (
            settings_store.parse_protected_roles(changes["protected_roles"])
            if changes.get("protected_roles") is not None
            else settings_store.enforcement_guard(db).protected_roles
        )
        changes["ai_roles"] = _validated_ai_roles(
            db,
            changes["ai_roles"],
            protected=protected,
            confirm_admin_roles=confirm_admin_roles,
        )
    elif changes.get("protected_roles") is not None:
        # The other way round: protecting a role the list already names.
        _refuse_protected_ai_roles(
            list(settings_store.ai_role_names(db)),
            settings_store.parse_protected_roles(changes["protected_roles"]),
        )
    if not changes:
        return _read(db)

    before = _read(db).model_dump(exclude={"current_schedule_description"})
    audited_changes: dict[str, object] = {}

    for field, value in changes.items():
        if field in _SECRET_FIELDS:
            # An empty (or blank) string clears the secret; None means "leave it alone".
            secret_value = value.strip() if isinstance(value, str) else value
            settings_store.set_secret(db, _SECRET_FIELDS[field], secret_value or None)
            audited_changes[field] = "set" if secret_value else "cleared"
            continue
        key = _PUBLIC_FIELDS.get(field)
        if key is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "unknown_setting", "message": f"{field} cannot be changed."},
            )
        if field == "enforcement_paused":
            was_paused = settings_store.enforcement_guard(db).paused
            if value and not was_paused:
                # Pausing by hand records who. An existing pause keeps its own
                # reason (the safety ceiling's explanation is worth more).
                settings_store.set_value(
                    db,
                    settings_store.KEY_ENFORCEMENT_PAUSE_REASON,
                    f"Paused by {ctx.actor.actor_name}.",
                )
            elif not value and was_paused:
                # Resuming means an admin has looked at what was held back: that
                # batch goes through once, without tripping the ceiling again.
                settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSE_REASON, None)
                settings_store.set_value(db, settings_store.KEY_CEILING_WAIVED_ONCE, True)
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


@router.get("/client-roles", response_model=ClientRolesResponse)
def client_roles(ctx: AdminUser, db: DbSession) -> ClientRolesResponse:
    """The tenant's roles on the platform client, for choosing the AI roles.

    Cached briefly; a failed read is reported in the answer, never as an error.
    """
    listing = role_sources.tenant_client_roles(db)
    protected = settings_store.enforcement_guard(db).protected_roles
    return ClientRolesResponse(
        available=listing.available,
        message=listing.message,
        roles=[
            ClientRoleResponse(
                name=role.name,
                description=role.description,
                composite=role.composite,
                known_description=iam.ROLE_DESCRIPTIONS.get(role.name),
                admin_like=settings_store.admin_like_role(role.name),
                protected=role.name.lower() in protected,
            )
            for role in listing.roles
        ],
        ai_roles=list(settings_store.ai_role_names(db)),
        default_ai_roles=list(iam.DEFAULT_AI_ROLE_NAMES),
    )


def _refuse_protected_ai_roles(names: list[str], protected: frozenset[str]) -> None:
    """An AI role may not be a protected role: a person holding a protected
    role is never restricted, so the restriction would silently do nothing."""
    clashing = [name for name in names if name.lower() in protected]
    if clashing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "protected_ai_roles",
                "message": (
                    f"{', '.join(clashing)} "
                    + ("is a protected role" if len(clashing) == 1 else "are protected roles")
                    + " (Settings → Enforcement): a person holding a protected role is never "
                    "restricted, so naming it here would make a user restriction do nothing for "
                    "everyone who holds it. Remove it from this list, or from the protected "
                    "roles."
                ),
            },
        )


def _validated_ai_roles(  # type: ignore[no-untyped-def]
    db,
    value: object,
    *,
    protected: frozenset[str] = frozenset(),
    confirm_admin_roles: bool = False,
) -> list[str]:
    """The AI role list, checked against the roles the tenant actually has.

    A protected role is refused: its holders are never restricted, so a list
    that names it would silently restrict nobody who holds it. A role that looks
    like an administration role (settings_store.ADMIN_ROLE_PATTERNS) is refused
    unless the request confirms it (``confirm_admin_roles``). When the tenant's
    roles cannot be read, only names already trusted (the current list or the
    default one) are accepted: nothing unknown gets in.
    """
    names = settings_store.normalise_role_names(value)
    if not names:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "invalid_ai_roles",
                "message": "Name at least one role: with none, a user restriction would "
                "remove nothing.",
            },
        )
    _refuse_protected_ai_roles(names, protected)
    admin_like = [name for name in names if settings_store.admin_like_role(name)]
    if admin_like and not confirm_admin_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "admin_ai_roles_unconfirmed",
                "message": (
                    f"{', '.join(admin_like)} "
                    + (
                        "looks like an administration role"
                        if len(admin_like) == 1
                        else "look like administration roles"
                    )
                    + ": a user restriction would take it from anyone over a budget, along "
                    "with everything it allows besides AI features. Confirm to save it anyway."
                ),
                "roles": admin_like,
            },
        )
    listing = role_sources.tenant_client_roles(db, fresh=True)
    if listing.available:
        unknown = [name for name in names if name not in listing.names()]
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "code": "unknown_ai_roles",
                    "message": (
                        f"Not a role on the tenant's {iam.PLATFORM_CLIENT_ID} client: "
                        f"{', '.join(unknown)}. Pick roles from the list."
                    ),
                },
            )
        return names
    trusted = set(settings_store.ai_role_names(db)) | set(iam.DEFAULT_AI_ROLE_NAMES)
    unchecked = [name for name in names if name not in trusted]
    if unchecked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "ai_roles_unverifiable",
                "message": (
                    f"{', '.join(unchecked)} could not be checked against the tenant's roles "
                    f"({listing.message or 'they could not be read'}). Try again when the "
                    "Checkmarx One connection works."
                ),
            },
        )
    return names


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
