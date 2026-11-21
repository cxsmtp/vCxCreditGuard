"""The Notification Center feed.

Deduplication is the whole point of the ``dedupe_key``: a scheduler running every
two minutes would otherwise raise the same warning 720 times a day. Keys are built
from the condition plus the budget period, so an entity is warned once per period
and warned again next period if it happens again.
"""

from __future__ import annotations

import hashlib
import logging

from sqlalchemy import func, select
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
# The stored Checkmarx API key lacks a permission CreditGuard needs.
CATEGORY_PERMISSIONS = "permissions"


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
    dedupe_key = _bounded_key(dedupe_key)
    if dedupe_key is not None:
        existing = session.scalar(select(Notification).where(Notification.dedupe_key == dedupe_key))
        if existing is not None:
            return None

    values = {
        "created_at": utcnow(),
        "severity": severity,
        "category": category,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "entity_label": entity_label[:512] if entity_label else entity_label,
        "title": title[:256],
        "body": body,
        "dedupe_key": dedupe_key,
        "enforcement_action_id": enforcement_action_id,
    }
    if dedupe_key is None:
        notification = Notification(**values)
        session.add(notification)
        session.flush()
        return notification

    # Another writer can insert the same key between the check above and this
    # insert. The insert therefore ignores a conflict instead of raising: an
    # error here would have to be rolled back, and rolling back would discard
    # everything the caller had done in its transaction so far - an enforcement
    # record, an approval - because a notification happened to be a duplicate.
    new_id = session.execute(
        _insert_ignoring_conflict(session).values(**values).returning(Notification.__table__.c.id)
    ).scalar()
    if new_id is None:
        # Nothing was inserted: the key was taken in the meantime.
        logger.debug("Notification %s was already recorded by another writer", dedupe_key)
        return None
    return session.get(Notification, new_id)


DEDUPE_KEY_LENGTH = 160


def already_raised(session: Session, dedupe_key: str) -> bool:
    """True when ``notify`` would return None for this key: a cheap check for a
    caller whose message is costly to build."""
    key = _bounded_key(dedupe_key)
    return session.scalar(select(Notification.id).where(Notification.dedupe_key == key)) is not None


def _bounded_key(key: str | None) -> str | None:
    """A dedupe key that fits its column, without two long keys colliding.

    Keys are built from identifiers that can be long (an e-mail address used as
    a subject, say). Cutting one off would make different conditions share a
    key, and all but the first would be silently dropped; so the tail of an
    over-long key is replaced by a digest of the whole of it.
    """
    if key is None or len(key) <= DEDUPE_KEY_LENGTH:
        return key
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
    return f"{key[: DEDUPE_KEY_LENGTH - 33]}~{digest}"


def _insert_ignoring_conflict(session: Session):  # type: ignore[no-untyped-def]
    """INSERT ... ON CONFLICT DO NOTHING, in the dialect's own spelling."""
    if session.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    return dialect_insert(Notification.__table__).on_conflict_do_nothing()


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


def enforcement_failed_key(action_id: int, day: str) -> str:
    """One "could not restrict" alert per action per day, however often it is retried."""
    return f"enforcefail:{action_id}:{day}"


def protected_key(limit_id: int, period_key: str) -> str:
    """One "over budget but protected" notice per limit and period."""
    return f"protected:{limit_id}:{period_key}"


def not_restricted_key(action_id: int) -> str:
    """One "deliberately left unchanged" notice per limit, target and period."""
    return f"notrestricted:{action_id}"


def restore_failed_key(action_id: int, day: str) -> str:
    """One "could not restore" alert per action per day, however often it is retried."""
    return f"restorefail:{action_id}:{day}"


def sync_error_key(step: str, day: str) -> str:
    """One sync error notification per step per day, so an outage is not a flood."""
    return f"sync:{step}:{day}"


def key_permissions_key(fingerprint: str, since: str, problem_digest: str) -> str:
    """One "API key is missing permissions" alert per distinct set of missing
    permissions, per episode (``since`` is when the key last stopped being fine)."""
    return f"keyperm:{fingerprint}:{since}:{problem_digest}"


def key_permissions_ok_key(fingerprint: str, at: str) -> str:
    return f"keyperm-ok:{fingerprint}:{at}"


def attribution_key(subject_key: str) -> str:
    return f"unresolved:{subject_key}"
