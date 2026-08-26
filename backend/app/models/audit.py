"""Audit log and notification feed.

The audit log is append only at the application layer: nothing in the codebase
issues an UPDATE or DELETE against ``audit_log_entry``, and the service that
writes it exposes no mutating operation. Retention pruning, when configured, is
the single exception and is itself audited.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import JSONColumn, UTCDateTime
from app.models.enums import ActorType, Severity


class AuditLogEntry(Base):
    """Immutable record of one action: by the utility, or by an admin using it."""

    __tablename__ = "audit_log_entry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)

    actor_type: Mapped[str] = mapped_column(String(16), nullable=False, default=ActorType.SYSTEM)
    actor_id: Mapped[int | None] = mapped_column(Integer)
    # Denormalised on purpose: the log must stay readable after an account is deleted.
    actor_name: Mapped[str | None] = mapped_column(String(128))

    # Dotted action name, e.g. "limit.created", "enforcement.applied", "auth.login".
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), index=True)
    target_id: Mapped[str | None] = mapped_column(String(64), index=True)
    target_label: Mapped[str | None] = mapped_column(String(512))

    before: Mapped[dict | None] = mapped_column(JSONColumn)
    after: Mapped[dict | None] = mapped_column(JSONColumn)
    detail: Mapped[str | None] = mapped_column(Text)

    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(256))

    __table_args__ = (Index("ix_audit_log_entry_action_time", "action", "occurred_at"),)


class Notification(Base):
    """An entry in the Notification Center."""

    __tablename__ = "notification"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Severity.INFO, index=True
    )
    # "warning", "enforcement", "restoration", "sync_error", "auth_failure".
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    entity_type: Mapped[str | None] = mapped_column(String(16), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), index=True)
    entity_label: Mapped[str | None] = mapped_column(String(512))

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)

    # Suppresses repeat notifications for the same condition in the same period.
    dedupe_key: Mapped[str | None] = mapped_column(String(160), unique=True)

    enforcement_action_id: Mapped[int | None] = mapped_column(
        ForeignKey("enforcement_action.id", ondelete="SET NULL"), index=True
    )
    read_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Delivery outcome per channel: {"email": "sent", "webhook": "failed: 503"}.
    delivery: Mapped[dict | None] = mapped_column(JSONColumn)
