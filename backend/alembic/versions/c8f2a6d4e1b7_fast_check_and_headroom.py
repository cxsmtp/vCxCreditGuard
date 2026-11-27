"""Headroom on budgets, and the Fusion scan costs the automatic one uses

Revision ID: c8f2a6d4e1b7
Revises: a4d8e2c6f1b9
Create Date: 2026-11-27

``credit_limit.headroom_credits`` and ``headroom_auto``: restrict once no more
than that many credits are left (app/services/headroom.py). Null and false on
every existing budget, which therefore restricts at its limit exactly as
before. ``limit_period_state.headroom_credits``: the headroom a period was
last judged with, so "restricted early" can be told from "over budget".
``fusion_scan_cost``: the credits of each recent Fusion scan, as the activity
log billed them, from which the automatic headroom is taken.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c8f2a6d4e1b7"
down_revision = "a4d8e2c6f1b9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("credit_limit", schema=None) as batch_op:
        batch_op.add_column(sa.Column("headroom_credits", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("headroom_auto", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    with op.batch_alter_table("limit_period_state", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("headroom_credits", sa.Numeric(precision=18, scale=4), nullable=True)
        )
    op.create_table(
        "fusion_scan_cost",
        sa.Column("scan_key", sa.String(length=128), nullable=False),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("project_id", sa.String(length=64), nullable=True),
        sa.Column("application_id", sa.String(length=64), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("credits", sa.Numeric(precision=18, scale=4), nullable=False),
        sa.PrimaryKeyConstraint("scan_key"),
    )
    op.create_index("ix_fusion_scan_cost_event_at", "fusion_scan_cost", ["event_at"])
    op.create_index("ix_fusion_scan_cost_project", "fusion_scan_cost", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_fusion_scan_cost_project", table_name="fusion_scan_cost")
    op.drop_index("ix_fusion_scan_cost_event_at", table_name="fusion_scan_cost")
    op.drop_table("fusion_scan_cost")
    with op.batch_alter_table("limit_period_state", schema=None) as batch_op:
        batch_op.drop_column("headroom_credits")
    with op.batch_alter_table("credit_limit", schema=None) as batch_op:
        batch_op.drop_column("headroom_auto")
        batch_op.drop_column("headroom_credits")
