"""add count_existing_usage to credit_limit

Revision ID: 41270205d1cb
Revises: ed1ac17aa3b9
Create Date: 2026-08-11 18:27:45.744566
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "41270205d1cb"
down_revision: str | None = "ed1ac17aa3b9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # server_default is required, not cosmetic: without it this NOT NULL column
    # cannot be added to a table that already holds limits. Existing limits keep the
    # safe behaviour of discounting consumption that predates them.
    with op.batch_alter_table("credit_limit", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "count_existing_usage",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table("credit_limit", schema=None) as batch_op:
        batch_op.drop_column("count_existing_usage")
