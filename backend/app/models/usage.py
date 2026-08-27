"""Credit consumption snapshots and scheduler bookkeeping.

Design note, because it drives everything downstream: Checkmarx One's
``GET /api/credits/consumption`` reports **aggregate totals for a lookback
window**, not a stream of individual credit spending events. There are no event
ids, no timestamps and no project ids in the response. So the utility cannot sum
events per budget period. Instead it:

1. Polls the endpoint once per cycle per dimension and stores the reported totals
   (``UsageSnapshot`` plus one ``UsageRecord`` per entity in that snapshot).
2. Records, when a budget period opens, the total reported at that moment as the
   period's baseline (see ``LimitPeriodState.baseline_credits``).
3. Treats period usage as ``latest reported total - baseline``.

That keeps budget periods independent of whatever fixed windows the Checkmarx API
offers, and it keeps the raw payload for audit so a parser change can be replayed
without re-fetching.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import JSONColumn, UTCDateTime
from app.models.enums import RunStatus, UsageView


class UsageSnapshot(Base):
    """One complete poll of the consumption endpoint for one ``viewBy`` dimension."""

    __tablename__ = "usage_snapshot"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    view_by: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    # The Checkmarx lookback window this snapshot was taken with, e.g. "last_year".
    period_param: Mapped[str] = mapped_column(String(32), nullable=False)

    total_items: Mapped[int | None] = mapped_column(Integer)
    total_credits: Mapped[Decimal] = mapped_column(
        Numeric(18, 4), nullable=False, default=Decimal("0")
    )
    pages_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Full response bodies, page by page, kept for audit and reparsing.
    raw: Mapped[list | None] = mapped_column(JSONColumn)

    records: Mapped[list[UsageRecord]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_usage_snapshot_view_time", "view_by", "collected_at"),)


class UsageRecord(Base):
    """One entity's reported credit total inside one snapshot."""

    __tablename__ = "usage_record"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("usage_snapshot.id", ondelete="CASCADE"), nullable=False, index=True
    )
    view_by: Mapped[str] = mapped_column(String(16), nullable=False, index=True)

    # Stable identity for the row as the API reported it: a lowercased email when
    # one is present, otherwise the lowercased display name. This is what lets
    # consecutive snapshots be compared even when the entity cannot be resolved
    # to a synced Checkmarx user.
    subject_key: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    subject_name: Mapped[str | None] = mapped_column(String(320))
    subject_email: Mapped[str | None] = mapped_column(String(320))

    # Set once the subject is resolved against the synced org model. Null means
    # the row could not be matched, which is surfaced rather than silently dropped.
    entity_type: Mapped[str | None] = mapped_column(String(16), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), index=True)

    credits_used: Mapped[Decimal] = mapped_column(
        Numeric(18, 4), nullable=False, default=Decimal("0")
    )
    percent_of_total: Mapped[float | None] = mapped_column()
    transactions: Mapped[int | None] = mapped_column(Integer)
    # Per action breakdown: {"triage": 3, "remediation": 1}
    actions: Mapped[dict | None] = mapped_column(JSONColumn)
    raw: Mapped[dict | None] = mapped_column(JSONColumn)

    snapshot: Mapped[UsageSnapshot] = relationship(back_populates="records")

    __table_args__ = (
        UniqueConstraint("snapshot_id", "view_by", "subject_key", name="snapshot_subject"),
        Index("ix_usage_record_entity", "entity_type", "entity_id"),
    )


class UnresolvedSubject(Base):
    """A consumption row the exact ladder could not attribute to a synced user.

    Tracked deliberately: silently dropping usage would understate a budget, and
    silently guessing would restrict the wrong person. The fuzzy matcher then
    triages each one into a ``status``:

    * ``auto_matched`` - similarity was high and unambiguous, so its credits are
      attributed to ``suggested_user_id`` and it is logged; an admin can still
      override it.
    * ``disputed`` - a plausible but not certain match. It stays uncounted and
      carries ranked ``suggestions`` for a human to confirm.
    * ``unmatched`` - nothing crossed the threshold (or the subject is a bot).

    An admin ``mapped_user_id`` always wins over any of the above.
    """

    __tablename__ = "unresolved_subject"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_key: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    subject_name: Mapped[str | None] = mapped_column(String(320))
    subject_email: Mapped[str | None] = mapped_column(String(320))
    view_by: Mapped[str] = mapped_column(String(16), nullable=False, default=UsageView.USER)
    credits_used: Mapped[Decimal] = mapped_column(
        Numeric(18, 4), nullable=False, default=Decimal("0")
    )
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    times_seen: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # An admin can pin the subject to a known user, which then resolves it forever.
    mapped_user_id: Mapped[str | None] = mapped_column(String(64))

    # Fuzzy-match triage. "unmatched" | "disputed" | "auto_matched".
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unmatched")
    # True for automation handles (dependabot[bot] and similar), so the GUI can
    # keep them out of the human dispute queue.
    is_bot: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The best fuzzy candidate: the user its credits count towards while
    # status is auto_matched, or the leading suggestion while disputed.
    suggested_user_id: Mapped[str | None] = mapped_column(String(64))
    match_score: Mapped[float | None] = mapped_column(Float)
    # Ranked candidates: [{"user_id", "label", "score"}], best first.
    suggestions: Mapped[list | None] = mapped_column(JSONColumn)


class DimensionState(Base):
    """Whether a ``viewBy`` dimension is actually available on this tenant.

    ``viewBy=project`` is not confirmed for every tenant. Rather than assume, the
    first probe records the outcome here: a dimension that answers 4xx is marked
    unsupported, project level limits then report usage as unavailable instead of
    quietly reading zero, and enforcement never fires on a zero it invented.
    """

    __tablename__ = "dimension_state"

    view_by: Mapped[str] = mapped_column(String(16), primary_key=True)
    supported: Mapped[bool | None] = mapped_column()
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_error: Mapped[str | None] = mapped_column(Text)


class SchedulerRun(Base):
    """One scheduler cycle, for the "last successful sync" tile and diagnostics."""

    __tablename__ = "scheduler_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False, default="cycle")
    trigger: Mapped[str] = mapped_column(String(16), nullable=False, default="schedule")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=RunStatus.RUNNING)
    error: Mapped[str | None] = mapped_column(Text)
    # Per step outcome and counters, e.g.
    # {"org_sync": {"users": 270}, "ingest": {"user": 44}, "evaluate": {"breached": 1}}
    stats: Mapped[dict | None] = mapped_column(JSONColumn)


class SchedulerLock(Base):
    """Advisory lock giving the non-overlap guarantee across process restarts.

    APScheduler's ``max_instances=1`` covers a single process. This row also
    covers the case where a container is replaced while a cycle was mid flight:
    a stale lock is reclaimed once its heartbeat goes quiet.
    """

    __tablename__ = "scheduler_lock"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    holder: Mapped[str | None] = mapped_column(String(128))
    acquired_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
