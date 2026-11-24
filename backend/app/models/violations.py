"""Policy violations: someone acted against a restriction that is in force.

CreditGuard re-applies its restrictions every cycle, so a setting switched back
on is turned off again within one interval. That is the enforcement; this is
the record of it. Each row says what was found, where, by whom when Checkmarx
One says so, and what it is likely to have cost, so an admin can follow up.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import ForeignKey, Index, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import JSONColumn, UTCDateTime

STATUS_OPEN = "open"
STATUS_ACKNOWLEDGED = "acknowledged"
STATUS_RESOLVED = "resolved"
STATUSES = (STATUS_OPEN, STATUS_ACKNOWLEDGED, STATUS_RESOLVED)

# What was found.
KIND_SETTING_REENABLED = "setting_reenabled"
KIND_FUSION_SCAN = "fusion_scan_during_restriction"
KIND_AI_SCAN = "ai_scan_during_restriction"
KIND_USAGE_AFTER = "usage_after_restriction"
KINDS = (KIND_SETTING_REENABLED, KIND_FUSION_SCAN, KIND_AI_SCAN, KIND_USAGE_AFTER)


class PolicyViolation(Base):
    __tablename__ = "policy_violation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    # Updated when a later cycle adds to the same violation (usage that keeps rising).
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    limit_id: Mapped[int | None] = mapped_column(
        ForeignKey("credit_limit.id", ondelete="SET NULL"), index=True
    )
    enforcement_action_id: Mapped[int | None] = mapped_column(
        ForeignKey("enforcement_action.id", ondelete="SET NULL")
    )
    # Denormalised so the record stays readable when the limit is deleted.
    limit_label: Mapped[str | None] = mapped_column(String(512))
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_label: Mapped[str | None] = mapped_column(String(512))
    # Who did it, as Checkmarx One names them (a scan's initiator). Null when
    # Checkmarx does not say: it does not report who changed a setting.
    actor: Mapped[str | None] = mapped_column(String(320))
    # Where it came from: a scan's origin ("webapp", "PR Webhook") and type.
    source: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    # Scan id, model, engines, before/after values. Never a secret or token.
    evidence: Mapped[dict | None] = mapped_column(JSONColumn)
    # What it is likely to have cost, when the price is known.
    credits: Mapped[Decimal | None] = mapped_column(Numeric(18, 4))
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="warning")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_OPEN, index=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(128))
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    resolved_by: Mapped[str | None] = mapped_column(String(128))
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    note: Mapped[str | None] = mapped_column(Text)
    # One row per finding, whichever cycle (or process) finds it first.
    dedupe_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)

    __table_args__ = (Index("ix_policy_violation_status_detected", "status", "detected_at"),)
