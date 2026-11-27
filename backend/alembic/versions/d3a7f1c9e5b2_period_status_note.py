"""Why a budget over its limit is, or is not, restricted

Revision ID: d3a7f1c9e5b2
Revises: c8f2a6d4e1b7
Create Date: 2026-11-27

``limit_period_state.status_note``: the reason the Budgets page shows next to
"Over limit" (held by the recount, deferred, protected, cannot fully bite,
monitor only, ...), the same words as the breach notice. Null on every
existing period until its next evaluation.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d3a7f1c9e5b2"
down_revision = "c8f2a6d4e1b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("limit_period_state", schema=None) as batch_op:
        batch_op.add_column(sa.Column("status_note", sa.String(length=1000), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("limit_period_state", schema=None) as batch_op:
        batch_op.drop_column("status_note")
