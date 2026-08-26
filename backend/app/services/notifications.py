"""The Notification Center feed.

Deduplication is the whole point of the ``dedupe_key``: a scheduler running every
two minutes would otherwise raise the same warning 720 times a day. Keys are built
from the condition plus the budget period, so an entity is warned once per period
and warned again next period if it happens again.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import Notification
from app.models.enums import Severity

logger = logging.getLogger(__name__)

CATEGORY_WARNING = "warning"
CATEGORY_ENFORCEMENT = "enforcement"
CATEGORY_RESTORATION = "restoration"
CATEGORY_SYNC_ERROR = "sync_error"
CATEGORY_AUTH_FAILURE = "auth_failure"
CATEGORY_ATTRIBUTION = "attribution"


def notify(
    session: Session,
    *,
    category: str,
    severity: Severity,
    title: str,
    body: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    entity_label: str | None = None,
    dedupe_key: str | None = None,
    enforcement_action_id: int | None = None,
) -> Notification | None:
    """Append a notification, or return None when it was already raised.

    The uniqueness of ``dedupe_key`` is enforced by the database as well as
    checked here, because two scheduler processes racing on the same condition
    must not produce two rows.
    """
    if dedupe_key is not None:
        existing = session.scalar(select(Notification).where(Notification.dedupe_key == dedupe_key))
        if existing is not None:
            return None

    notification = Notification(
        created_at=utcnow(),
        severity=severity,
        category=category,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=entity_label,
        title=title[:256],
        body=body,
        dedupe_key=dedupe_key,
        enforcement_action_id=enforcement_action_id,
    )
    session.add(notification)
    try:
        session.flush()
    except IntegrityError:
        # Lost a race on the dedupe key. That is the correct outcome, not an error.
        session.rollback()
        logger.debug("Notification %s was already recorded by another writer", dedupe_key)
        return None
    return notification


def unread_count(session: Session) -> int:
    return int(
        session.scalar(
            select(func.count()).select_from(Notification).where(Notification.read_at.is_(None))
        )
        or 0
    )


def mark_read(session: Session, *, notification_ids: list[int] | None = None) -> int:
    """Mark specific notifications read, or all of them when ids are omitted."""
    query = select(Notification).where(Notification.read_at.is_(None))
    if notification_ids:
        query = query.where(Notification.id.in_(notification_ids))
    now = utcnow()
    marked = 0
    for notification in session.scalars(query):
        notification.read_at = now
        marked += 1
    session.flush()
    return marked


# ------------------------------------------------------------- key construction


def warning_key(limit_id: int, period_key: str) -> str:
    return f"warn:{limit_id}:{period_key}"


def breach_key(limit_id: int, period_key: str) -> str:
    return f"breach:{limit_id}:{period_key}"


def monitor_only_key(limit_id: int, period_key: str) -> str:
    return f"monitor:{limit_id}:{period_key}"


def enforcement_key(action_id: int) -> str:
    return f"enforced:{action_id}"


def reconcile_key(action_id: int, period_key: str) -> str:
    """One reconciliation alert per restriction per budget period.

    Re-assetting is checked every cycle, so without the period in the key a healthy
    run would raise the same "re-applied" alert hundreds of times a day.
    """
    return f"reconciled:{action_id}:{period_key}"


def restoration_key(action_id: int) -> str:
    return f"restored:{action_id}"


def sync_error_key(step: str, day: str) -> str:
    """One sync error notification per step per day, so an outage is not a flood."""
    return f"sync:{step}:{day}"


def attribution_key(subject_key: str) -> str:
    return f"unresolved:{subject_key}"
