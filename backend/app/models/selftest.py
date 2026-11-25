"""Enforcement self-test results (Settings → Enforcement → Run self-test).

One row per run: an admin restricts a chosen user and/or project for real,
through the same code a budget breach uses, reads it back, restores it and
reads it back again. The row keeps what each step found (a per-setting diff
before / restricted / restored, pass or fail, timings). Only the last few runs
are kept (``enforcement_selftest.KEEP_RESULTS``); the restrictions themselves
are ordinary ``enforcement_action`` rows, so one whose restore failed stays
tracked (and is retried by the cycle) whatever happens to this row.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Index, Integer, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import JSONColumn, UTCDateTime

STATUS_RUNNING = "running"
STATUS_PASSED = "passed"
# Worked, but something is worth knowing: a role kept through a group or a
# composite (the restriction cannot bite), a setting the tenant would not change.
STATUS_WARNING = "warning"
STATUS_FAILED = "failed"
# The restore failed, or read back incomplete: the target may still be
# restricted. Tracked as a real restriction and retried by the next cycle.
STATUS_RESTORE_FAILED = "restore_failed"
# Shown for a run still "running" long after it started: the process stopped
# mid-run. Anything it left restricted is lifted by the next cycle.
STATUS_INTERRUPTED = "interrupted"


class EnforcementSelfTest(Base):
    __tablename__ = "enforcement_selftest"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=STATUS_RUNNING)
    actor_name: Mapped[str | None] = mapped_column(String(128))
    # Ran against the built-in demo tenant, not Checkmarx One.
    demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    user_id: Mapped[str | None] = mapped_column(String(64))
    user_label: Mapped[str | None] = mapped_column(String(512))
    project_id: Mapped[str | None] = mapped_column(String(64))
    project_label: Mapped[str | None] = mapped_column(String(512))
    # One line: what was found.
    summary: Mapped[str | None] = mapped_column(Text)
    # Every step of every target, with its diff and timings.
    result: Mapped[dict | None] = mapped_column(JSONColumn)

    __table_args__ = (
        # At most one run in progress, enforced by the database itself (a
        # partial unique index, on SQLite and PostgreSQL alike): a second
        # process, or a second worker, cannot start a run while one is going.
        Index(
            "uq_enforcement_selftest_running",
            "status",
            unique=True,
            sqlite_where=text("status = 'running'"),
            postgresql_where=text("status = 'running'"),
        ),
    )
