"""Pushing notifications out over email and a generic webhook.

The Notification Center is always the record of truth: it holds everything,
whether or not delivery works. These channels are copies, so a broken SMTP server
can never lose a warning or hide an enforcement action.

Delivery outcome is written back onto each notification, per channel, so the
Notification Center can show that a copy failed to send without pretending the
notification itself failed.

Two things worth knowing:

* **Nothing is retried forever.** After ``MAX_ATTEMPTS`` the notification is marked
  as given up on, because an unreachable webhook should not make the utility retry
  the same payload every two minutes for a week.
* **The cloud metadata address is refused.** The webhook URL is admin configured,
  so it is trusted by design, but posting a signed payload to a link-local
  metadata endpoint is never a legitimate use and is the one case worth blocking
  outright.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import smtplib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import __version__
from app.core.logging import register_secret
from app.models.audit import Notification
from app.models.connection import CxConnection
from app.models.enums import Severity
from app.services import settings_store

logger = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {
    Severity.INFO: 0,
    Severity.WARNING: 1,
    Severity.ERROR: 2,
    Severity.CRITICAL: 3,
}

MAX_ATTEMPTS = 3
DEFAULT_BATCH = 25
SMTP_TIMEOUT_SECONDS = 15.0
WEBHOOK_TIMEOUT_SECONDS = 10.0
SIGNATURE_HEADER = "X-CxCreditGuard-Signature"
TIMESTAMP_HEADER = "X-CxCreditGuard-Timestamp"

# Cloud instance metadata. Never a legitimate webhook target.
BLOCKED_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal", "fd00:ec2::254"})

SmtpFactory = Callable[[str, int, float], smtplib.SMTP]


class DeliveryError(RuntimeError):
    """A channel could not deliver. Recorded per notification, never raised upward."""


@dataclass(frozen=True, slots=True)
class DeliveryConfig:
    min_severity: str
    smtp_host: str | None
    smtp_port: int
    smtp_username: str | None
    smtp_password: str | None
    smtp_use_tls: bool
    smtp_from: str | None
    smtp_recipients: tuple[str, ...]
    webhook_url: str | None
    webhook_secret: str | None
    tenant_name: str | None

    @property
    def email_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from and self.smtp_recipients)

    @property
    def webhook_enabled(self) -> bool:
        return bool(self.webhook_url)

    @property
    def any_channel(self) -> bool:
        return self.email_enabled or self.webhook_enabled


@dataclass
class DeliveryResult:
    considered: int = 0
    delivered: int = 0
    failed: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    def as_stats(self) -> dict[str, Any]:
        return {
            "considered": self.considered,
            "delivered": self.delivered,
            "failed": self.failed,
            "skipped": self.skipped,
            "errors": self.errors[:5],
        }


def load_config(session: Session) -> DeliveryConfig:
    recipients_raw = settings_store.get_value(session, settings_store.KEY_SMTP_RECIPIENTS) or ""
    recipients = tuple(
        address.strip()
        for address in str(recipients_raw).replace(";", ",").split(",")
        if address.strip()
    )
    password = settings_store.get_secret(session, settings_store.KEY_SMTP_PASSWORD)
    secret = settings_store.get_secret(session, settings_store.KEY_WEBHOOK_SECRET)
    # Registered so neither can appear in a log line even by accident.
    register_secret(password)
    register_secret(secret)

    connection = session.scalar(select(CxConnection).limit(1))
    return DeliveryConfig(
        min_severity=str(
            settings_store.get_value(session, settings_store.KEY_NOTIFY_MIN_SEVERITY)
            or Severity.WARNING
        ),
        smtp_host=_string(settings_store.get_value(session, settings_store.KEY_SMTP_HOST)),
        smtp_port=int(settings_store.get_value(session, settings_store.KEY_SMTP_PORT) or 587),
        smtp_username=_string(settings_store.get_value(session, settings_store.KEY_SMTP_USERNAME)),
        smtp_password=password,
        smtp_use_tls=bool(settings_store.get_value(session, settings_store.KEY_SMTP_USE_TLS)),
        smtp_from=_string(settings_store.get_value(session, settings_store.KEY_SMTP_FROM)),
        smtp_recipients=recipients,
        webhook_url=_string(settings_store.get_value(session, settings_store.KEY_WEBHOOK_URL)),
        webhook_secret=secret,
        tenant_name=connection.tenant_name if connection else None,
    )


def _string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def meets_threshold(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 1)


def pending_notifications(
    session: Session, *, config: DeliveryConfig, limit: int = DEFAULT_BATCH
) -> list[Notification]:
    """Undelivered notifications at or above the configured severity, oldest first."""
    rows = session.scalars(
        select(Notification)
        .where(Notification.delivery.is_(None))
        .order_by(Notification.created_at)
        .limit(limit * 4)
    )
    return [row for row in rows if meets_threshold(row.severity, config.min_severity)][:limit]


def deliver_pending(
    session: Session,
    *,
    config: DeliveryConfig | None = None,
    limit: int = DEFAULT_BATCH,
    smtp_factory: SmtpFactory | None = None,
    http_client: httpx.Client | None = None,
) -> DeliveryResult:
    """Send undelivered notifications over every configured channel."""
    result = DeliveryResult()
    config = config or load_config(session)

    candidates = pending_notifications(session, config=config, limit=limit)
    result.considered = len(candidates)
    if not candidates:
        return result

    if not config.any_channel:
        # Mark them so the same rows are not rescanned on every cycle.
        for notification in candidates:
            notification.delivery = {"skipped": "no delivery channel configured"}
            result.skipped += 1
        session.flush()
        return result

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=WEBHOOK_TIMEOUT_SECONDS)
    try:
        for notification in candidates:
            outcome: dict[str, Any] = {"attempts": 1}
            failures: list[str] = []

            if config.email_enabled:
                try:
                    send_email(notification, config=config, smtp_factory=smtp_factory)
                    outcome["email"] = "sent"
                except DeliveryError as exc:
                    outcome["email"] = f"failed: {exc}"
                    failures.append(f"email: {exc}")

            if config.webhook_enabled:
                try:
                    post_webhook(notification, config=config, client=client)
                    outcome["webhook"] = "sent"
                except DeliveryError as exc:
                    outcome["webhook"] = f"failed: {exc}"
                    failures.append(f"webhook: {exc}")

            if failures:
                result.failed += 1
                result.errors.extend(failures)
                attempts = _record_attempt(notification.id)
                outcome["attempts"] = attempts
                if attempts >= MAX_ATTEMPTS:
                    # Stop retrying. Writing the outcome takes the row out of the
                    # pending set, so a dead webhook cannot make the utility resend
                    # the same payload every cycle indefinitely.
                    outcome["given_up"] = True
                    notification.delivery = outcome
                    _clear_attempts(notification.id)
                # Otherwise delivery stays null, so the next cycle retries it.
            else:
                result.delivered += 1
                _clear_attempts(notification.id)
                notification.delivery = outcome

        session.flush()
    finally:
        if owns_client:
            client.close()

    return result


# Attempt counters for rows that are still pending. Kept in memory rather than in a
# column: a restart resetting a retry count is harmless, and it keeps delivery
# bookkeeping out of the notification table. A pending row is identified by its
# delivery column being null, which is the one piece of state that must persist.
_attempts: dict[int, int] = {}


def _record_attempt(notification_id: int) -> int:
    _attempts[notification_id] = _attempts.get(notification_id, 0) + 1
    return _attempts[notification_id]


def _clear_attempts(notification_id: int) -> None:
    _attempts.pop(notification_id, None)


def attempts_for(notification_id: int) -> int:
    return _attempts.get(notification_id, 0)


def reset_attempts() -> None:
    """Test helper, and used when the delivery settings change."""
    _attempts.clear()


# ---------------------------------------------------------------------- email


def _header_safe(value: str, *, limit: int = 200) -> str:
    """Collapse anything that could split or inject a mail header.

    Titles are built from Checkmarx entity names, so a project or group named with
    an embedded newline would otherwise either break message serialisation or, on a
    less strict library, inject a header of the attacker's choosing.
    """
    collapsed = " ".join(str(value).split())
    return collapsed[:limit]


def build_email(notification: Notification, *, config: DeliveryConfig) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = _header_safe(f"[CxCreditGuard] {notification.title}")
    message["From"] = _header_safe(config.smtp_from or "", limit=320)
    message["To"] = _header_safe(", ".join(config.smtp_recipients), limit=2048)
    # Lets a mail client thread related notifications together.
    message["X-CxCreditGuard-Category"] = _header_safe(notification.category, limit=64)
    message["X-CxCreditGuard-Severity"] = _header_safe(notification.severity, limit=32)

    lines = [notification.title, ""]
    if notification.body:
        lines.extend([notification.body, ""])
    if notification.entity_label or notification.entity_id:
        lines.append(
            f"Entity: {notification.entity_type or 'unknown'} "
            f"{notification.entity_label or notification.entity_id}"
        )
    if config.tenant_name:
        lines.append(f"Tenant: {config.tenant_name}")
    lines.append(f"Raised at: {notification.created_at:%Y-%m-%d %H:%M UTC}")
    if notification.enforcement_action_id:
        lines.extend(
            [
                "",
                "This was an enforcement action. It can be reversed from the "
                "Notification Center in CxCreditGuard.",
            ]
        )
    message.set_content("\n".join(lines))
    return message


def send_email(
    notification: Notification,
    *,
    config: DeliveryConfig,
    smtp_factory: SmtpFactory | None = None,
) -> None:
    if not config.email_enabled:
        raise DeliveryError("email is not configured")

    factory = smtp_factory or _default_smtp_factory
    message = build_email(notification, config=config)
    try:
        server = factory(config.smtp_host or "", config.smtp_port, SMTP_TIMEOUT_SECONDS)
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(
            f"could not connect to {config.smtp_host}: {type(exc).__name__}"
        ) from exc

    try:
        if config.smtp_use_tls:
            server.starttls()
        if config.smtp_username and config.smtp_password:
            server.login(config.smtp_username, config.smtp_password)
        server.send_message(message)
    except smtplib.SMTPAuthenticationError as exc:
        raise DeliveryError("SMTP authentication was rejected") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(f"SMTP send failed: {type(exc).__name__}") from exc
    finally:
        try:
            server.quit()
        except (OSError, smtplib.SMTPException):
            logger.debug("SMTP connection did not close cleanly")


def _default_smtp_factory(host: str, port: int, timeout: float) -> smtplib.SMTP:
    return smtplib.SMTP(host=host, port=port, timeout=timeout)


# -------------------------------------------------------------------- webhook


def build_payload(notification: Notification, *, config: DeliveryConfig) -> dict[str, Any]:
    return {
        "id": notification.id,
        "created_at": notification.created_at.isoformat(),
        "severity": notification.severity,
        "category": notification.category,
        "title": notification.title,
        "body": notification.body,
        "entity": {
            "type": notification.entity_type,
            "id": notification.entity_id,
            "label": notification.entity_label,
        },
        "enforcement_action_id": notification.enforcement_action_id,
        "reversible": notification.enforcement_action_id is not None,
        "tenant": config.tenant_name,
        "source": {"name": "CxCreditGuard", "version": __version__},
    }


def sign_payload(body: bytes, *, secret: str, timestamp: str) -> str:
    """HMAC-SHA256 over ``timestamp.body``.

    The timestamp is inside the signed material so a captured request cannot be
    replayed later with a fresh timestamp header.
    """
    material = timestamp.encode("ascii") + b"." + body
    digest = hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def assert_webhook_target_allowed(url: str) -> None:
    """Refuse the cloud metadata endpoint. Everything else is the admin's choice.

    Deliberately does no DNS resolution. Resolving here would add a live lookup to
    every delivery, turn a transient DNS failure into a delivery failure, and still
    leave a gap between the check and the connection, since the name can resolve
    differently a moment later. Blocking the known metadata names and any literal
    link-local address covers the case that is never legitimate, without pretending
    to be a general egress control. Posting to an internal host is a supported
    deployment, so private ranges are allowed.
    """
    host = (urlsplit(url).hostname or "").lower()
    if not host:
        raise DeliveryError("the webhook URL has no host")
    if host in BLOCKED_HOSTS:
        raise DeliveryError("refusing to post to a cloud metadata address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if address.is_link_local:
        raise DeliveryError("refusing to post to a link-local address")


def post_webhook(
    notification: Notification, *, config: DeliveryConfig, client: httpx.Client
) -> None:
    if not config.webhook_url:
        raise DeliveryError("no webhook URL is configured")

    assert_webhook_target_allowed(config.webhook_url)

    payload = build_payload(notification, config=config)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(datetime.now(UTC).timestamp()))
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"CxCreditGuard/{__version__}",
        TIMESTAMP_HEADER: timestamp,
    }
    if config.webhook_secret:
        headers[SIGNATURE_HEADER] = sign_payload(
            body, secret=config.webhook_secret, timestamp=timestamp
        )

    try:
        response = client.post(
            config.webhook_url,
            content=body,
            headers=headers,
            timeout=WEBHOOK_TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as exc:
        raise DeliveryError(f"webhook request failed: {type(exc).__name__}") from exc

    if not response.is_success:
        raise DeliveryError(f"webhook returned HTTP {response.status_code}")


# ----------------------------------------------------------------------- test


def send_test_notification(
    session: Session,
    *,
    smtp_factory: SmtpFactory | None = None,
    http_client: httpx.Client | None = None,
) -> dict[str, str]:
    """Deliver a sample notification so an admin can prove the channels work.

    Nothing is stored: this builds a transient notification rather than polluting
    the Notification Center with test rows.
    """
    from app.db.base import utcnow

    config = load_config(session)
    if not config.any_channel:
        return {"result": "No delivery channel is configured."}

    sample = Notification(
        id=0,
        created_at=utcnow(),
        severity=Severity.INFO,
        category="test",
        title="Test notification from CxCreditGuard",
        body=(
            "If you can read this, delivery is working. No limits were evaluated "
            "and nothing was restricted to produce this message."
        ),
    )

    outcome: dict[str, str] = {}
    if config.email_enabled:
        try:
            send_email(sample, config=config, smtp_factory=smtp_factory)
            outcome["email"] = "sent"
        except DeliveryError as exc:
            outcome["email"] = f"failed: {exc}"

    if config.webhook_enabled:
        owns_client = http_client is None
        client = http_client or httpx.Client(timeout=WEBHOOK_TIMEOUT_SECONDS)
        try:
            post_webhook(sample, config=config, client=client)
            outcome["webhook"] = "sent"
        except DeliveryError as exc:
            outcome["webhook"] = f"failed: {exc}"
        finally:
            if owns_client:
                client.close()

    return outcome
