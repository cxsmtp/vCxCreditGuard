"""record what hands-off automation granted

Revision ID: d9a3c7e15b62
Revises: c5d8e2f4a917
Create Date: 2026-11-14

Automation capped the size of each raise it approved, but not their sum: an
entity could be raised by the cap again and again. The size of every automatic
grant is now recorded so the cap can be applied to the total over a period.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d9a3c7e15b62"
down_revision = "c5d8e2f4a917"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "credit_request", sa.Column("auto_approved_increase", sa.Integer(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("credit_request", "auto_approved_increase")
