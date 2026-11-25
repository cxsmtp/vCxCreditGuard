"""The usage ledger: how many display-name-only rows a user subject was read as

Revision ID: d5b1e8a3c7f2
Revises: c9f2a6e1d4b7
Create Date: 2026-11-25

``usage_record.display_rows``: when the number changes between readings, two
people who share a display name were split across pages or joined on one,
and the ledger counts nothing for that reading. Existing rows have none,
which compares with nothing.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "d5b1e8a3c7f2"
down_revision = "c9f2a6e1d4b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("usage_record")}
    if "display_rows" not in columns:
        with op.batch_alter_table("usage_record") as batch:
            batch.add_column(sa.Column("display_rows", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("usage_record") as batch:
        batch.drop_column("display_rows")
