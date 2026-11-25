"""The credit activity log as a usage source

Revision ID: c9f2b6d4e8a1
Revises: c9f2a6e1d4b7
Create Date: 2026-11-25

* ``usage_activity_key`` - how many times each distinct row of the activity
  log (``GET /api/credits/activity``) has been seen. The log has no row id and
  identical rows are distinct events, so new events are counted as the rise
  of each identity's count, never by deduplicating.
* ``usage_activity_state`` - the activity source's state (one row): whether
  it is the source, where the next read starts, the floor before which
  nothing is counted from it, the highest pruning cutoff, the group budgets
  it feeds through their projects and since when, and its last
  reconciliation with the summary.
* ``usage_activity_counter`` - what of each period counter the activity log
  counted: only that part can start a new restriction of a period budget.
* ``usage_budget_interval`` - when each project budget may have been active,
  as observed, so the integration-account rule decides a past event the
  same way every time.

Nothing is seeded: the first fetch after the upgrade only records what the
log holds, and counts nothing.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c9f2b6d4e8a1"
down_revision = "c9f2a6e1d4b7"
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
            sa.Column("cutoff_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("group_feeds", sa.JSON(), nullable=True),
            sa.Column("noticed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("summary_paused", sa.JSON(), nullable=True),
            sa.Column("eras", sa.JSON(), nullable=True),
            sa.Column("reconciliation", sa.JSON(), nullable=True),
            sa.Column("last_stats", sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_usage_activity_state")),
        )
    if "usage_activity_counter" not in tables:
        op.create_table(
            "usage_activity_counter",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("limit_id", sa.Integer(), nullable=False),
            sa.Column("period_key", sa.String(length=64), nullable=False),
            sa.Column("credits", sa.Numeric(18, 4), nullable=False),
            sa.ForeignKeyConstraint(
                ["limit_id"],
                ["credit_limit.id"],
                name=op.f("fk_usage_activity_counter_limit_id_credit_limit"),
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_usage_activity_counter")),
            sa.UniqueConstraint("limit_id", "period_key", name="usage_activity_counter_period"),
        )
        op.create_index(
            "ix_usage_activity_counter_limit_id", "usage_activity_counter", ["limit_id"]
        )
    if "usage_budget_interval" not in tables:
        op.create_table(
            "usage_budget_interval",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("limit_id", sa.Integer(), nullable=False),
            sa.Column("project_id", sa.String(length=64), nullable=False),
            sa.Column("budget_created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("start_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("end_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_usage_budget_interval")),
        )
        op.create_index("ix_usage_budget_interval_limit_id", "usage_budget_interval", ["limit_id"])
        op.create_index(
            "ix_usage_budget_interval_project_id", "usage_budget_interval", ["project_id"]
        )


def downgrade() -> None:
    op.drop_index("ix_usage_budget_interval_project_id", table_name="usage_budget_interval")
    op.drop_index("ix_usage_budget_interval_limit_id", table_name="usage_budget_interval")
    op.drop_table("usage_budget_interval")
    op.drop_index("ix_usage_activity_counter_limit_id", table_name="usage_activity_counter")
    op.drop_table("usage_activity_counter")
    op.drop_table("usage_activity_state")
    op.drop_index("ix_usage_activity_key_event_at", table_name="usage_activity_key")
    op.drop_table("usage_activity_key")
