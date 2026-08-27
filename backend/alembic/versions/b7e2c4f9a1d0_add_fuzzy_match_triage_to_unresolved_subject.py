"""add fuzzy match triage to unresolved_subject

Revision ID: b7e2c4f9a1d0
Revises: 41270205d1cb
Create Date: 2026-08-27

Adds the columns the subject fuzzy matcher writes: a triage ``status``
(unmatched / disputed / auto_matched), a ``is_bot`` flag, and the leading
candidate plus the ranked ``suggestions`` a human confirms a dispute from.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "b7e2c4f9a1d0"
down_revision = "41270205d1cb"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("unresolved_subject") as batch:
        batch.add_column(
            sa.Column(
                "status",
                sa.String(length=16),
                nullable=False,
                server_default="unmatched",
            )
        )
        batch.add_column(
            sa.Column(
                "is_bot",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.add_column(sa.Column("suggested_user_id", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("match_score", sa.Float(), nullable=True))
        batch.add_column(sa.Column("suggestions", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("unresolved_subject") as batch:
        batch.drop_column("suggestions")
        batch.drop_column("match_score")
        batch.drop_column("suggested_user_id")
        batch.drop_column("is_bot")
        batch.drop_column("status")
