"""What the automatic headroom is computed from (app/services/headroom.py).

The app keeps no raw rows of the credit activity log, only how many rows of
each identity it has seen. The automatic headroom needs what a Fusion scan
costs, so the log's Fusion rows are summed here per scan as they are counted
(the same idempotent multiset count as the budget counters: a row is added
once). Kept for 30 days and pruned with the log's own keys.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import Index, Numeric, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import UTCDateTime


class FusionScanCost(Base):
    """The credits of one Fusion scan, as the activity log billed them."""

    __tablename__ = "fusion_scan_cost"

    # The scan id; a Fusion row without one is a scan of its own (its row key).
    scan_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    # The date of the scan's first billed row.
    event_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    project_id: Mapped[str | None] = mapped_column(String(64))
    application_id: Mapped[str | None] = mapped_column(String(64))
    # The user-budget entity the activity source charged the rows to, if any.
    user_id: Mapped[str | None] = mapped_column(String(64))
    credits: Mapped[Decimal] = mapped_column(Numeric(18, 4), nullable=False, default=0)

    __table_args__ = (
        Index("ix_fusion_scan_cost_event_at", "event_at"),
        Index("ix_fusion_scan_cost_project", "project_id"),
    )
