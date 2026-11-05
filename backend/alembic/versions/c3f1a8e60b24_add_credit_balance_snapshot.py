"""add credit_balance_snapshot

Revision ID: c3f1a8e60b24
Revises: b7e2c4f9a1d0
Create Date: 2026-11-05

Stores the tenant AI credit pool (total / used / available) read from
``GET /api/credits/info`` each cycle. Every figure is nullable: an unknown
balance is never recorded as zero.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "c3f1a8e60b24"
down_revision = "b7e2c4f9a1d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credit_balance_snapshot",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_credits", sa.Numeric(18, 4), nullable=True),
        sa.Column("used_credits", sa.Numeric(18, 4), nullable=True),
        sa.Column("available_credits", sa.Numeric(18, 4), nullable=True),
        sa.Column("raw", sa.JSON(), nullable=True),
    )
    op.create_index(
        "ix_credit_balance_snapshot_collected_at", "credit_balance_snapshot", ["collected_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_credit_balance_snapshot_collected_at", table_name="credit_balance_snapshot")
    op.drop_table("credit_balance_snapshot")
