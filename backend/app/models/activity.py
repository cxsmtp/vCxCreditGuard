"""The credit activity log as a usage source (app/services/activity_source.py).

Two tables: how many times each distinct row of the log has been seen
(multiset reconciliation, because the log has no row id and identical rows are
distinct events), and the source's own state (one row).
"""

from __future__ import annotations

import hashlib
from datetime import datetime

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import JSONColumn, UTCDateTime


class ActivityEventCount(Base):
    """How many rows with one identity the log has been seen to hold.

    The identity is every identifying field of a row (``event_key``), hashed.
    A fetch that holds ``n`` such rows counts ``max(0, n - seen)`` new events
    and raises ``seen`` to ``n``; ``seen`` never falls. Pruned once older
    than the log's window (and never counted again after that).
    """

    __tablename__ = "usage_activity_key"

    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    seen: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)

    __table_args__ = (Index("ix_usage_activity_key_event_at", "event_at"),)


class ActivitySourceState(Base):
    """The activity source's state: one row (id 1)."""

    __tablename__ = "usage_activity_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # "inactive" (never the source, or not offered), "active" (the source for
    # the project, user and application views), "fallback" (was the source,
    # the summary feed took over), "off" (the setting says summary only).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="inactive")
    # Bumped by every write, so a fetch is written only over the state it was
    # planned from.
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Events dated before this are never counted from the log: the moment it
    # last became the source (they were counted by the summary feed, or are
    # history).
    floor_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    active_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Where the next read starts: the date it must cover from, and the position
    # (0 based, in the log's ascending order) of the first row of that date.
    resume_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    resume_position: Mapped[int | None] = mapped_column(Integer)
    page_size: Mapped[int | None] = mapped_column(Integer)
    last_total: Mapped[int | None] = mapped_column(Integer)
    last_fetch_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Since when the log has failed in a row, while it was the source.
    failing_since: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # Not asked again before this (a 404 or 403, or a malformed answer).
    retry_after: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)
    last_sweep_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # {view: id of the last summary snapshot read while the log was the
    # source}: the summary feed's next reading of that view counts nothing.
    summary_paused: Mapped[dict | None] = mapped_column(JSONColumn)
    # [[start, end or null], ...]: when the log was the source (ISO times).
    eras: Mapped[list | None] = mapped_column(JSONColumn)
    # The last full comparison of the log's sum with the summary's total.
    reconciliation: Mapped[dict | None] = mapped_column(JSONColumn)
    # What the last fetch did, for Diagnose and the cycle record.
    last_stats: Mapped[dict | None] = mapped_column(JSONColumn)


# A user budget can target an integration account that is no synced user (an
# SCM integration's handle, say): its entity id is this prefix and the
# account's key in Settings → Attribution. Such a budget counts the account's
# usage from the activity log and is monitor only (there is no IAM user to
# restrict).
SUBJECT_PREFIX = "subject:"
_ENTITY_ID_WIDTH = 64


def subject_entity_id(subject_key: str) -> str:
    """The user-budget entity id of a reported account that is no user."""
    key = subject_key.strip().lower()
    entity_id = SUBJECT_PREFIX + key
    if len(entity_id) <= _ENTITY_ID_WIDTH:
        return entity_id
    digest = hashlib.sha256(key.encode()).hexdigest()[:16]
    keep = _ENTITY_ID_WIDTH - len(SUBJECT_PREFIX) - len(digest) - 1
    return f"{SUBJECT_PREFIX}{key[:keep]}~{digest}"


def is_subject_entity(entity_id: str | None) -> bool:
    return bool(entity_id) and str(entity_id).startswith(SUBJECT_PREFIX)
