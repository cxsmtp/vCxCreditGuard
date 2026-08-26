"""Audit log writer.

This module is the only place that inserts into ``audit_log_entry``, and it
offers no update or delete. That is what "append only at the application layer"
means here: there is no code path that can rewrite history, so a reviewer only
has to trust this one file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import AuditLogEntry
from app.models.auth import UtilityUser
from app.models.enums import ActorType


@dataclass(frozen=True, slots=True)
class AuditActor:
    actor_type: ActorType
    actor_id: int | None = None
    actor_name: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None

    @classmethod
    def system(cls, name: str = "scheduler") -> AuditActor:
        return cls(actor_type=ActorType.SYSTEM, actor_name=name)

    @classmethod
    def admin(
        cls,
        user: UtilityUser,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuditActor:
        return cls(
            actor_type=ActorType.ADMIN,
            actor_id=user.id,
            actor_name=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @classmethod
    def anonymous(
        cls, *, ip_address: str | None = None, user_agent: str | None = None
    ) -> AuditActor:
        """For events with no authenticated actor yet, such as a failed login."""
        return cls(
            actor_type=ActorType.ADMIN,
            actor_name=None,
            ip_address=ip_address,
            user_agent=user_agent,
        )


def record_audit(
    session: Session,
    *,
    action: str,
    actor: AuditActor,
    target_type: str | None = None,
    target_id: str | None = None,
    target_label: str | None = None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    detail: str | None = None,
) -> AuditLogEntry:
    """Append one audit row. Flushed, but committed by the caller's transaction.

    Sharing the caller's transaction is deliberate: an action and its audit
    record either both land or neither does.
    """
    entry = AuditLogEntry(
        occurred_at=utcnow(),
        actor_type=actor.actor_type,
        actor_id=actor.actor_id,
        actor_name=actor.actor_name,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        before=before,
        after=after,
        detail=detail,
        ip_address=actor.ip_address,
        user_agent=(actor.user_agent[:256] if actor.user_agent else None),
    )
    session.add(entry)
    session.flush()
    return entry
