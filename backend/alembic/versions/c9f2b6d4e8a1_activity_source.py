"""The credit activity log as a usage source

Revision ID: c9f2b6d4e8a1
Revises: e2a7c4f9b1d8
Create Date: 2026-11-25

* ``usage_activity_key`` - how many times each distinct row of the activity
  log (``GET /api/credits/activity``) has been seen. The log has no row id and
  identical rows are distinct events, so new events are counted as the rise
  of each identity's count, never by deduplicating.
* ``usage_activity_state`` - the activity source's state (one row): whether
  it is the source, where the next read starts, the floor before which
  nothing is counted from it, and its last reconciliation with the summary.

Nothing is seeded: the first fetch after the upgrade only records what the
log holds, and counts nothing.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c9f2b6d4e8a1"
down_revision = "e2a7c4f9b1d8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "usage_activity_key" not in tables:
        op.create_table(
            "usage_activity_key",
            sa.Column("key_hash", sa.String(length=64), nullable=False),
            sa.Column("event_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("seen", sa.Integer(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("key_hash", name=op.f("pk_usage_activity_key")),
        )
        op.create_index("ix_usage_activity_key_event_at", "usage_activity_key", ["event_at"])
    if "usage_activity_state" not in tables:
        op.create_table(
            "usage_activity_state",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("floor_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("active_since", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resume_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resume_position", sa.Integer(), nullable=True),
            sa.Column("page_size", sa.Integer(), nullable=True),
            sa.Column("last_total", sa.Integer(), nullable=True),
            sa.Column("last_fetch_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("failing_since", sa.DateTime(timezone=True), nullable=True),
            sa.Column("retry_after", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("last_sweep_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("summary_paused", sa.JSON(), nullable=True),
            sa.Column("eras", sa.JSON(), nullable=True),
            sa.Column("reconciliation", sa.JSON(), nullable=True),
            sa.Column("last_stats", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_usage_activity_state")),
        )


def downgrade() -> None:
    op.drop_table("usage_activity_state")
    op.drop_index("ix_usage_activity_key_event_at", table_name="usage_activity_key")
    op.drop_table("usage_activity_key")
