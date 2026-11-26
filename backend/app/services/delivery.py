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
  outright. It is refused however it is written (``2852039166``,
  ``0xa9fea9fe``, ``[::ffff:169.254.169.254]``) and, for a name, at the moment
  of connecting, against the address the name resolves to then: a name that
  resolves to an allowed address when it is saved and to the metadata address
  later (DNS rebinding) is refused as well. The same goes for the mail server.
  Redirects are never followed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import smtplib
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

import httpcore
import httpx
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import __version__
from app.core.config import get_settings
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
# Cloud metadata and platform endpoints, as addresses, so that any spelling of
# them is caught: AWS (IPv4 and IPv6), GCP's IPv6 one, Alibaba Cloud, and
# Azure's WireServer. (169.254.169.254 serves AWS, GCP, Azure and others.)
BLOCKED_ADDRESSES = frozenset(
    ipaddress.ip_address(address)
    for address in (
        "169.254.169.254",
        "fd00:ec2::254",
        "fd20:ce::254",
        "100.100.100.200",
        "168.63.129.16",
    )
)
# NAT64 prefixes, well-known (RFC 6052) and local-use (RFC 8215): the IPv4
# address is carried in the last 32 bits.
_NAT64_PREFIXES = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"))
# IPv4-compatible IPv6 (deprecated, ::a.b.c.d).
_IPV4_COMPATIBLE = ipaddress.ip_network("::/96")

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
    webhook_url = settings_store.get_secret(session, settings_store.KEY_WEBHOOK_URL)
    # Registered so none of them can appear in a log line even by accident.
    register_secret(password)
    register_secret(secret)
    register_secret(webhook_url)

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
        webhook_url=_string(webhook_url),
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
    """Undelivered notifications at or above the configured severity, oldest first.

    Anything below the threshold is marked as skipped first. Left undelivered it
    would sit at the front of the queue for ever, and once enough of it had
    built up, the oldest rows fetched each cycle would all be ones that are
    never sent - and nothing above the threshold would go out again.
    """
    deliverable = [
        severity for severity in SEVERITY_RANK if meets_threshold(severity, config.min_severity)
    ]
    session.execute(
        update(Notification)
        .where(Notification.delivery.is_(None), Notification.severity.notin_(deliverable))
        .values(delivery={"skipped": "below the delivery threshold"})
        .execution_options(synchronize_session=False)
    )
    return list(
        session.scalars(
            select(Notification)
            .where(Notification.delivery.is_(None), Notification.severity.in_(deliverable))
            .order_by(Notification.created_at, Notification.id)
            .limit(limit)
        )
    )


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

    # Built only when there is a webhook to post to, so an email-only setup
    # never depends on the webhook client.
    client = http_client
    client_error: DeliveryError | None = None
    if client is None and config.webhook_enabled:
        try:
            client = webhook_client()
        except DeliveryError as exc:
            client_error = exc
    owns_client = http_client is None and client is not None
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
                    if client is None:
                        raise client_error or DeliveryError("no webhook client")
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

            # Recorded as soon as it is sent. Leaving it to the end of the batch
            # would resend everything already delivered if the process stopped
            # part way through.
            session.commit()
    finally:
        if owns_client and client is not None:
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

    message = build_email(notification, config=config)
    _transmit(message, config=config, smtp_factory=smtp_factory)


def _transmit(
    message: EmailMessage, *, config: DeliveryConfig, smtp_factory: SmtpFactory | None = None
) -> None:
    """Open an SMTP connection, send one already-built message, and close."""
    factory = smtp_factory or _default_smtp_factory
    try:
        server = factory(config.smtp_host or "", config.smtp_port, SMTP_TIMEOUT_SECONDS)
    except DeliveryError:
        raise
    except ssl.SSLCertVerificationError as exc:
        raise DeliveryError(
            "the mail server's TLS certificate could not be verified "
            f"({getattr(exc, 'verify_message', None) or exc}). If it is signed by a private "
            "CA, set CXCG_SMTP_CA_FILE to that CA's certificate."
        ) from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(
            f"could not connect to {config.smtp_host}: {type(exc).__name__}"
        ) from exc

    # Port 465 is TLS from the first byte (see _default_smtp_factory), so there
    # is no STARTTLS step and the connection already counts as encrypted.
    implicit_tls = config.smtp_port == IMPLICIT_TLS_PORT
    try:
        if config.smtp_use_tls and not implicit_tls:
            # With a verifying context. Without one the certificate is not
            # checked at all, and anyone on the path can pose as the mail server
            # and collect the password and every notification.
            server.starttls(context=_tls_context())
        if config.smtp_username and config.smtp_password:
            if not (config.smtp_use_tls or implicit_tls):
                raise DeliveryError(
                    "refusing to send the SMTP password without TLS; turn on STARTTLS "
                    "or remove the credentials"
                )
            server.login(config.smtp_username, config.smtp_password)
        server.send_message(message)
    except ssl.SSLCertVerificationError as exc:
        raise DeliveryError(
            "the mail server's TLS certificate could not be verified "
            f"({getattr(exc, 'verify_message', None) or exc}). If it is signed by a private "
            "CA, set CXCG_SMTP_CA_FILE to that CA's certificate; the name in the certificate "
            "must match the SMTP host configured here."
        ) from exc
    except ssl.SSLError as exc:
        raise DeliveryError(
            f"a secure connection to the mail server could not be set up ({exc})"
        ) from exc
    except smtplib.SMTPAuthenticationError as exc:
        raise DeliveryError("SMTP authentication was rejected") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(f"SMTP send failed: {type(exc).__name__}") from exc
    finally:
        try:
            server.quit()
        except (OSError, smtplib.SMTPException):
            logger.debug("SMTP connection did not close cleanly")


def send_report_email(
    *,
    config: DeliveryConfig,
    subject: str,
    text_body: str,
    smtp_factory: SmtpFactory | None = None,
) -> None:
    """Email a report to the configured recipients. Raises DeliveryError on any
    configuration or transport problem, so callers can record the failure."""
    if not config.email_enabled:
        raise DeliveryError("email is not configured")
    message = EmailMessage()
    message["Subject"] = _header_safe(f"[CxCreditGuard] {subject}")
    message["From"] = _header_safe(config.smtp_from or "", limit=320)
    message["To"] = _header_safe(", ".join(config.smtp_recipients), limit=2048)
    message["X-CxCreditGuard-Category"] = "report"
    message.set_content(text_body)
    _transmit(message, config=config, smtp_factory=smtp_factory)


def send_direct_email(
    *,
    config: DeliveryConfig,
    to: str,
    subject: str,
    text_body: str,
    smtp_factory: SmtpFactory | None = None,
) -> None:
    """Send one message to a specific recipient over the configured SMTP transport.

    Unlike report and notification mail, this does not go to the configured
    recipient list; it targets ``to`` (e.g. the account a password reset is for).
    It only needs the transport to be set up (host and from), not a recipient
    list, so it raises on a missing transport rather than reusing ``email_enabled``.
    """
    if not (config.smtp_host and config.smtp_from):
        raise DeliveryError("email transport is not configured")
    message = EmailMessage()
    message["Subject"] = _header_safe(f"[CxCreditGuard] {subject}")
    message["From"] = _header_safe(config.smtp_from, limit=320)
    message["To"] = _header_safe(to, limit=320)
    message["X-CxCreditGuard-Category"] = "account"
    message.set_content(text_body)
    _transmit(message, config=config, smtp_factory=smtp_factory)


IMPLICIT_TLS_PORT = 465


class _GuardedSMTP(smtplib.SMTP):
    """SMTP that connects only to an address ``guarded_addresses`` allows.

    The TLS handshake (STARTTLS, or SMTPS below) still checks the certificate
    against the configured host name.
    """

    def _get_socket(self, host, port, timeout):  # type: ignore[no-untyped-def]
        try:
            # A relay on this host (loopback) is a common mail setup.
            addresses = guarded_addresses(host, port, allow_loopback=True)
        except TargetRefused as exc:
            raise DeliveryError(str(exc)) from exc
        except httpcore.ConnectError as exc:
            raise OSError(str(exc)) from exc
        last: OSError | None = None
        for address in addresses:
            try:
                return socket.create_connection((address, port), timeout, self.source_address)
            except OSError as exc:
                last = exc
        assert last is not None
        raise last


class _GuardedSMTPSSL(smtplib.SMTP_SSL, _GuardedSMTP):
    """SMTPS over a guarded connection (SMTP_SSL wraps what _GuardedSMTP opens)."""


def _default_smtp_factory(host: str, port: int, timeout: float) -> smtplib.SMTP:
    if port == IMPLICIT_TLS_PORT:
        # "SMTPS": the server expects TLS before anything else is said.
        return _GuardedSMTPSSL(host=host, port=port, timeout=timeout, context=_tls_context())
    return _GuardedSMTP(host=host, port=port, timeout=timeout)


def _tls_context() -> ssl.SSLContext:
    """Verify the mail server's certificate and hostname.

    Trusts the system CAs, plus a private CA when CXCG_SMTP_CA_FILE points at
    one (an internal relay with an internally issued certificate).
    """
    ca_file = get_settings().smtp_ca_file
    try:
        return ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
    except (OSError, ssl.SSLError) as exc:
        raise DeliveryError(
            f"CXCG_SMTP_CA_FILE ({ca_file}) could not be read as a CA certificate: {exc}"
        ) from exc


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


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 one carries and reaches, if any: IPv4-mapped,
    IPv4-compatible, 6to4, Teredo (the client) and NAT64."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address.teredo is not None:
        return address.teredo[1]
    low = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if any(address in prefix for prefix in _NAT64_PREFIXES):
        return low
    if address in _IPV4_COMPATIBLE and int(address) > 1:  # not :: or ::1
        return low
    return None


def forbidden_address(address: IPAddress, *, allow_loopback: bool = False) -> str | None:
    """Why ``address`` may never be connected to (None: it may).

    Cloud metadata and platform endpoints, link-local addresses, the
    unspecified address (0.0.0.0 and :: reach this host) and, unless
    ``allow_loopback`` (a mail relay on this host), loopback; also any of them
    carried inside an IPv6 address. Private ranges are allowed: an internal
    relay is a supported deployment.
    """
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            reason = forbidden_address(embedded, allow_loopback=allow_loopback)
            if reason:
                return reason
    if address in BLOCKED_ADDRESSES:
        return "a cloud metadata address"
    if address.is_link_local:
        return "a link-local address"
    if address.is_unspecified:
        return "the unspecified address"
    if address.is_loopback and not allow_loopback:
        return "a loopback address"
    return None


def _literal_address(host: str) -> IPAddress | None:
    """The address ``host`` spells, read as a connection would read it, or None.

    Besides the usual forms, the resolver takes the old inet_aton spellings of
    an IPv4 address (``2852039166``, ``0xa9fea9fe``, ``0251.0376.0251.0376``,
    ``169.254.43518``), so they are read the same way here.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def assert_webhook_target_allowed(url: str) -> None:
    """Refuse the cloud metadata endpoint. Everything else is the admin's choice.

    A check on the URL as written: the known metadata names, and an address
    written in any form. A name is checked again when the connection is made,
    against what it resolves to at that moment (``guarded_addresses``), so this
    does no DNS lookup of its own. Posting to an internal host is a supported
    deployment, so private ranges are allowed.
    """
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if not host:
        raise DeliveryError("the webhook URL has no host")
    if host in BLOCKED_HOSTS:
        raise DeliveryError("refusing to post to a cloud metadata address")
    address = _literal_address(host)
    reason = forbidden_address(address) if address is not None else None
    if reason:
        raise DeliveryError(f"refusing to post to {reason}")


class TargetRefused(httpcore.ConnectError):
    """A connection was refused because of where it would have gone."""


def guarded_addresses(host: str, port: int, *, allow_loopback: bool = False) -> list[str]:
    """The addresses ``host`` resolves to now, if none of them is forbidden.

    Called at the moment of connecting, and the connection is then made to one
    of exactly these addresses, so a name cannot pass a check and then resolve
    somewhere else (DNS rebinding). If any address is forbidden the name is
    refused outright rather than trying the others. The messages do not repeat
    the host: the webhook URL is a secret.
    """
    name = host.strip("[]").lower().rstrip(".")
    if name in BLOCKED_HOSTS:
        raise TargetRefused("refusing to connect to a cloud metadata address")
    try:
        infos = socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise httpcore.ConnectError(f"the host name could not be resolved ({exc})") from exc
    addresses: list[str] = []
    for _family, _type, _proto, _canonical, sockaddr in infos:
        text = str(sockaddr[0]).split("%", 1)[0]
        reason = forbidden_address(ipaddress.ip_address(text), allow_loopback=allow_loopback)
        if reason:
            raise TargetRefused(f"refusing to connect: the host name resolves to {reason}")
        if text not in addresses:
            addresses.append(text)
    if not addresses:
        raise httpcore.ConnectError("the host name resolved to no address")
    return addresses


class _GuardedBackend(httpcore.NetworkBackend):
    """httpcore's own network backend, connecting only to vetted addresses.

    TLS is started afterwards with the URL's host name, so the certificate is
    still checked against the name, not the address.
    """

    def __init__(self) -> None:
        self._inner = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        last: Exception | None = None
        for address in guarded_addresses(host, port):
            try:
                return self._inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        assert last is not None
        raise last

    def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Any = None
    ) -> httpcore.NetworkStream:
        return self._inner.connect_unix_socket(path, timeout=timeout, socket_options=socket_options)

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def _check_target_before_sending(request: httpx.Request) -> None:
    """Every request: resolve the target and refuse a forbidden address.

    This is what guards a request sent through an HTTP proxy from the
    environment (``HTTPS_PROXY``), which resolves the name itself, where the
    connection guard below never sees the target. A name this host cannot
    resolve is left to the proxy (or fails to connect without one).
    """
    port = request.url.port or (443 if request.url.scheme == "https" else 80)
    try:
        guarded_addresses(request.url.host, port)
    except TargetRefused as exc:
        raise DeliveryError(str(exc)) from exc
    except httpcore.ConnectError:
        return


class _SelfTestReached(Exception):
    """Raised by the self-test backend: the pool connects through it."""


class _SelfTestBackend(httpcore.NetworkBackend):
    def connect_tcp(self, *_args: Any, **_kwargs: Any) -> httpcore.NetworkStream:
        raise _SelfTestReached

    def connect_unix_socket(self, *_args: Any, **_kwargs: Any) -> httpcore.NetworkStream:
        raise _SelfTestReached


def webhook_client() -> httpx.Client:
    """The HTTP client webhooks are posted with: every target is checked before
    the request is sent, direct connections go only to checked addresses, and
    redirects are not followed.

    The connection guard sits in httpx's private connection pool (httpx and
    httpcore are pinned for that). It is proven to be in the request path each
    time a client is built: a request through a backend that only raises must
    end in that backend, with no network involved. If not, no client is built
    and the webhook is reported as failed, never sent unguarded.
    """
    client = httpx.Client(
        timeout=WEBHOOK_TIMEOUT_SECONDS,
        follow_redirects=False,
        event_hooks={"request": [_check_target_before_sending]},
    )
    pool = getattr(client._transport, "_pool", None)  # noqa: SLF001
    reached = False
    if pool is not None and hasattr(pool, "_network_backend"):
        pool._network_backend = _SelfTestBackend()  # noqa: SLF001
        try:
            client._transport.handle_request(  # noqa: SLF001
                httpx.Request("GET", "http://guard-self-test.invalid/")
            )
        except _SelfTestReached:
            reached = True
        except Exception:  # noqa: BLE001 - anything else means the guard is not in the path
            reached = False
        pool._network_backend = _GuardedBackend()  # noqa: SLF001
    if not reached:
        client.close()
        raise DeliveryError("the webhook connection cannot be guarded with this httpx version")
    return client


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
        if isinstance(exc.__cause__, TargetRefused):
            raise DeliveryError(str(exc.__cause__)) from exc
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
        client: httpx.Client | None = http_client
        try:
            if client is None:
                client = webhook_client()
            post_webhook(sample, config=config, client=client)
            outcome["webhook"] = "sent"
        except DeliveryError as exc:
            outcome["webhook"] = f"failed: {exc}"
        finally:
            if owns_client and client is not None:
                client.close()

    return outcome
