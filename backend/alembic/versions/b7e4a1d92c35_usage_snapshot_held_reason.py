"""hold back usage reads that look wrong

Revision ID: b7e4a1d92c35
Revises: a2d5f9c31e84
Create Date: 2026-11-14

A consumption read whose total collapses against the previous read is stored as
evidence but not believed until later reads confirm it. ``held_reason`` marks
such a snapshot; a NULL value (every existing row) means the read is believed.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b7e4a1d92c35"
down_revision = "a2d5f9c31e84"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("usage_snapshot", sa.Column("held_reason", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("usage_snapshot", "held_reason")
