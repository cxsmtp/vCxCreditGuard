"""Inbound Checkmarx One webhooks: a hint that a scan just ended.

Checkmarx One can post scan events to a URL (tenant-level webhooks: "Completed
Scan", "Failed Scan", "Partial Scan", "Project Created"; project-level ones:
``scan_completed_successfully`` and ``scan_failed`` in the
``X-Cx-Webhook-Event`` header). There is no "scan started" event. A delivery
is signed with the webhook's secret: ``X-Cx-Webhook-Signature: sha256=<value>``,
an HMAC-SHA256 of the body keyed with the secret. The documentation does not
say how ``<value>`` is encoded; its example is base64, so base64 and hex are
both accepted (both compared in constant time).

What a valid scan event does: it asks for a fast check now
(``fastcheck.request``), and that is all. The request returns at once; no
enforcement work is done in it, and nothing in the payload is trusted beyond a
hint recorded for Diagnose (the project, scan and initiator it names). At most
one fast check is ever queued, so a burst of deliveries costs one tick. A
webhook only speeds up detection: credits appear in Checkmarx only once it
bills the action, and the fast check (every 15 seconds without any webhook) is
what counts and enforces.

Off unless an admin turns it on and sets a secret; while off the route answers
404. Deliveries are limited in size (``MAX_BODY_BYTES``) and rate
(``MAX_PER_MINUTE`` per process). Rejected deliveries are kept in memory only,
so a stranger posting rubbish cannot make the app write to its database.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.services import settings_store
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

PATH = "/api/webhooks/checkmarx"
EVENT_HEADER = "X-Cx-Webhook-Event"
SIGNATURE_HEADER = "X-Cx-Webhook-Signature"
MAX_BODY_BYTES = 64 * 1024
MAX_PER_MINUTE = 60
SECRET_BYTES = 32

# The status of the last deliveries, in this process.
_lock = threading.Lock()
_recent: deque[float] = deque()
_last_rejected: dict[str, Any] | None = None

ACCEPTED = "accepted"
IGNORED = "ignored"

_SAFE = re.compile(r"[^A-Za-z0-9 ._@:/+-]")


def reset_memory() -> None:
    """Forget the process state (tests)."""
    global _last_rejected
    with _lock:
        _recent.clear()
        _last_rejected = None


def enabled(session: Session) -> bool:
    on = settings_store.get_value(session, settings_store.KEY_CX_WEBHOOK_ENABLED, False)
    return on is True and secret_configured(session)


def secret_configured(session: Session) -> bool:
    return bool(settings_store.get_secret(session, settings_store.KEY_CX_WEBHOOK_SECRET))


def set_enabled(session: Session, value: bool, *, actor: AuditActor) -> None:
    before = settings_store.get_value(session, settings_store.KEY_CX_WEBHOOK_ENABLED, False)
    settings_store.set_value(session, settings_store.KEY_CX_WEBHOOK_ENABLED, bool(value))
    if bool(before) != bool(value):
        record_audit(
            session,
            action="settings.updated",
            actor=actor,
            target_type="settings",
            before={"cx_webhook_enabled": bool(before)},
            after={"cx_webhook_enabled": bool(value)},
        )


def rotate_secret(session: Session, *, actor: AuditActor) -> str:
    """A new random secret, stored encrypted and audited (never its value).
    Returned once, to be pasted into Checkmarx One."""
    had = secret_configured(session)
    value = secrets.token_urlsafe(SECRET_BYTES)
    settings_store.set_secret(session, settings_store.KEY_CX_WEBHOOK_SECRET, value)
    record_audit(
        session,
        action="webhook.secret_rotated" if had else "webhook.secret_created",
        actor=actor,
        target_type="settings",
        target_id=settings_store.KEY_CX_WEBHOOK_SECRET,
        detail=(
            "The Checkmarx One webhook secret was replaced; deliveries signed with the old "
            "one are refused from now on."
            if had
            else "A Checkmarx One webhook secret was created."
        ),
    )
    return value


# ----------------------------------------------------------------- checks


def rate_limited(now: float | None = None) -> bool:
    """True when this delivery is over ``MAX_PER_MINUTE`` (it is counted)."""
    moment = time.monotonic() if now is None else now
    with _lock:
        while _recent and moment - _recent[0] > 60:
            _recent.popleft()
        if len(_recent) >= MAX_PER_MINUTE:
            return True
        _recent.append(moment)
        return False


def signature_valid(secret: str, body: bytes, presented: str | None) -> bool:
    """``presented`` is ``sha256=<HMAC-SHA256(body)>``, base64 or hex."""
    if not secret or not presented:
        return False
    value = presented.strip()
    if value.lower().startswith("sha256="):
        value = value[len("sha256=") :]
    if not value or len(value) > 200:
        return False
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).digest()
    expected = (
        base64.b64encode(digest).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
        digest.hex(),
    )
    matched = False
    for candidate in expected:
        # Every form is compared, whatever matched, in constant time.
        matched |= hmac.compare_digest(candidate.encode("ascii"), value.encode("ascii", "replace"))
    return matched


def _clean(value: object, limit: int = 128) -> str | None:
    if not isinstance(value, str | int):
        return None
    text = _SAFE.sub("", str(value))[:limit].strip()
    return text or None


def is_scan_event(event: str | None, payload: dict[str, Any]) -> bool:
    """A scan ended (completed, failed or partial): credits may have been
    billed. A project being created bills nothing."""
    name = (event or "").strip().lower()
    if name:
        return "scan" in name
    # No header: a body with a scan id is a scan event.
    return bool(payload.get("scanId"))


def hint_of(event: str | None, payload: dict[str, Any]) -> dict[str, str]:
    """What the delivery says, for Diagnose only: never trusted for anything."""
    hint = {
        "event": _clean(event, 64),
        "project_id": _clean(payload.get("projectId"), 64),
        "scan_id": _clean(payload.get("scanId"), 64),
        "initiator": _clean(payload.get("initiator"), 128),
    }
    return {key: value for key, value in hint.items() if value}


def parse(body: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


# ----------------------------------------------------------------- status


def note_rejected(reason: str) -> None:
    global _last_rejected
    with _lock:
        _last_rejected = {"at": utcnow().isoformat(), "result": f"rejected: {reason}"}


def note_delivery(session: Session, *, result: str, hint: dict[str, str]) -> None:
    """Record an authenticated delivery (rate limited, so bounded)."""
    settings_store.set_value(
        session,
        settings_store.KEY_CX_WEBHOOK_STATUS,
        {"at": utcnow().isoformat(), "result": result, "hint": hint},
        description="The last Checkmarx One webhook delivery (bookkeeping).",
    )


def describe(session: Session) -> dict[str, Any]:
    stored = settings_store.get_value(session, settings_store.KEY_CX_WEBHOOK_STATUS)
    with _lock:
        rejected = dict(_last_rejected) if _last_rejected else None
    return {
        "enabled": enabled(session),
        "switched_on": settings_store.get_value(
            session, settings_store.KEY_CX_WEBHOOK_ENABLED, False
        )
        is True,
        "secret_configured": secret_configured(session),
        "path": PATH,
        "last_delivery": stored if isinstance(stored, dict) else None,
        "last_rejected": rejected,
    }


def last_delivery_at(session: Session) -> datetime | None:
    stored = settings_store.get_value(session, settings_store.KEY_CX_WEBHOOK_STATUS)
    if not isinstance(stored, dict) or not isinstance(stored.get("at"), str):
        return None
    try:
        return datetime.fromisoformat(stored["at"])
    except ValueError:
        return None
