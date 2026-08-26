"""Credit limits, per period evaluation state, exemptions and enforcement records."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin
from app.db.types import JSONColumn, UTCDateTime
from app.models.enums import EnforcementStatus, LimitStatus, PeriodType

DEFAULT_WARNING_THRESHOLD_PCT = 80


class CreditLimit(Base, TimestampMixin):
    """A budget assigned to one user, group, project or application.

    ``enforce`` defaults to False: a newly created limit is monitor only until an
    admin explicitly turns enforcement on. This is the guard against accidental
    lockouts required by the spec.
    """

    __tablename__ = "credit_limit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # Cached label so the GUI can render limits for entities not yet synced.
    entity_label: Mapped[str | None] = mapped_column(String(512))

    credit_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    period_type: Mapped[str] = mapped_column(String(16), nullable=False, default=PeriodType.MONTHLY)
    # Only used when period_type is CUSTOM.
    custom_period_start: Mapped[datetime | None] = mapped_column(UTCDateTime)
    custom_period_end: Mapped[datetime | None] = mapped_column(UTCDateTime)

    warning_threshold_pct: Mapped[int] = mapped_column(
        Integer, nullable=False, default=DEFAULT_WARNING_THRESHOLD_PCT
    )
    enforce: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Groups: also count credits consumed by member users, not just by the
    # group's projects. Off by default to avoid double counting.
    include_member_usage: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Count consumption the API already reported when the period opened, instead of
    # measuring only new consumption from that moment. Off by default for recurring
    # periods: the lookback window is wider than a month, so counting everything in
    # it would let a year of history exhaust a fresh monthly budget on day one and
    # restrict people for consumption that predates the limit. Lifetime and custom
    # periods ignore this flag and always count everything, because that is what
    # those period types mean.
    count_existing_usage: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # When set, a restriction raised by this limit survives the period rollover
    # until an admin releases it from the GUI.
    hold_until_released: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    notes: Mapped[str | None] = mapped_column(String(1024))
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("utility_user.id", ondelete="SET NULL")
    )

    period_states: Mapped[list[LimitPeriodState]] = relationship(
        back_populates="limit", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", name="entity"),
        CheckConstraint("credit_limit >= 0", name="credit_limit_non_negative"),
        CheckConstraint(
            "warning_threshold_pct >= 1 AND warning_threshold_pct <= 100",
            name="warning_threshold_range",
        ),
    )


class Exemption(Base, TimestampMixin):
    """Entities that are never restricted, whatever their usage.

    Kept separate from CreditLimit so an entity can be exempt without having a
    limit configured at all (for example a break glass admin account).
    """

    __tablename__ = "exemption"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_label: Mapped[str | None] = mapped_column(String(512))
    reason: Mapped[str | None] = mapped_column(String(512))
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("utility_user.id", ondelete="SET NULL")
    )

    __table_args__ = (UniqueConstraint("entity_type", "entity_id", name="entity"),)


class LimitPeriodState(Base):
    """Usage and status for one limit within one budget period.

    ``period_key`` is the canonical label for the period ("2026-08", "2026-Q3",
    "lifetime", or "custom:<start>:<end>"). Warning and breach timestamps live
    here, which is what makes notifications fire once per period instead of once
    per cycle.
    """

    __tablename__ = "limit_period_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    limit_id: Mapped[int] = mapped_column(
        ForeignKey("credit_limit.id", ondelete="CASCADE"), nullable=False, index=True
    )
    period_key: Mapped[str] = mapped_column(String(64), nullable=False)
    period_start: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    # Null for lifetime periods.
    period_end: Mapped[datetime | None] = mapped_column(UTCDateTime)

    # Usage attributed to this entity within this period. Derived, not summed:
    # see the module docstring of app/models/usage.py.
    credits_used: Mapped[Decimal] = mapped_column(
        Numeric(18, 4), nullable=False, default=Decimal("0")
    )
    # The cumulative figure the Checkmarx API reported when this period opened.
    # credits_used = reported_total - baseline_credits.
    baseline_credits: Mapped[Decimal] = mapped_column(
        Numeric(18, 4), nullable=False, default=Decimal("0")
    )
    reported_total: Mapped[Decimal] = mapped_column(
        Numeric(18, 4), nullable=False, default=Decimal("0")
    )
    # False when the dimension needed for this entity is unsupported on the
    # tenant or the entity could not be resolved. Enforcement never acts on a
    # period whose usage is unknown.
    usage_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=LimitStatus.OK)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    warned_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    breached_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    restricted_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    restored_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    limit: Mapped[CreditLimit] = relationship(back_populates="period_states")

    __table_args__ = (UniqueConstraint("limit_id", "period_key", name="limit_period"),)


class EnforcementAction(Base):
    """One restrictive change made in Checkmarx One, with the state to undo it.

    ``idempotency_key`` makes re-running enforcement safe: the key is derived from
    the limit, period and target, so a scheduler restart mid cycle finds the
    existing row instead of applying the change twice.

    ``undo_snapshot`` holds whatever is needed to reverse the action: the user's
    prior role mappings, or the project's prior AI toggle value.
    """

    __tablename__ = "enforcement_action"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=EnforcementStatus.PENDING, index=True
    )

    # The entity whose limit was breached.
    entity_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_label: Mapped[str | None] = mapped_column(String(512))

    # The Checkmarx object actually modified. One breach can fan out to many
    # targets, for example an application limit touching every child project.
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_label: Mapped[str | None] = mapped_column(String(512))

    limit_id: Mapped[int | None] = mapped_column(
        ForeignKey("credit_limit.id", ondelete="SET NULL"), index=True
    )
    period_key: Mapped[str | None] = mapped_column(String(64))

    undo_snapshot: Mapped[dict | None] = mapped_column(JSONColumn)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    reversed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    reversed_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("utility_user.id", ondelete="SET NULL")
    )
    # "admin", "exempted", "period_rollover" or "limit_removed".
    reversal_reason: Mapped[str | None] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_enforcement_action_target_status", "target_type", "target_id", "status"),
    )
