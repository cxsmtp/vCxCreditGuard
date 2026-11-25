"""Enforcement self-test results

Revision ID: a8d4f2c6e9b3
Revises: c9f2a6e1d4b7
Create Date: 2026-11-25

``enforcement_selftest`` keeps the last few runs of Settings → Enforcement →
Run self-test: which user and/or project was restricted for real, read back,
restored and read back again, with a per-setting diff (before / restricted /
restored), pass or fail and timings for every step. New and empty; the
restrictions a self-test makes are ordinary ``enforcement_action`` rows.

A partial unique index on ``status = 'running'`` lets the database itself
refuse a second run in progress (SQLite and PostgreSQL both support partial
indexes), whichever process or worker starts it.

Merge note: the ``activity-feed`` branch adds its own migration
``c9f2b6d4e8a1`` on top of the same parent (``c9f2a6e1d4b7``). Whichever of the
two branches is merged second must re-chain its migration onto the other's
(set its ``down_revision`` to the other revision) so the history keeps a
single head. The two touch different tables, so the order does not matter.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a8d4f2c6e9b3"
down_revision = "c9f2a6e1d4b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enforcement_selftest",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("actor_name", sa.String(128), nullable=True),
        sa.Column("demo", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("user_id", sa.String(64), nullable=True),
        sa.Column("user_label", sa.String(512), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        sa.Column("project_label", sa.String(512), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
    )
    op.create_index("ix_enforcement_selftest_started_at", "enforcement_selftest", ["started_at"])
    # One run in progress at a time, held by the database (partial unique index).
    op.create_index(
        "uq_enforcement_selftest_running",
        "enforcement_selftest",
        ["status"],
        unique=True,
        sqlite_where=sa.text("status = 'running'"),
        postgresql_where=sa.text("status = 'running'"),
    )


def downgrade() -> None:
    op.drop_index("uq_enforcement_selftest_running", table_name="enforcement_selftest")
    op.drop_index("ix_enforcement_selftest_started_at", table_name="enforcement_selftest")
    op.drop_table("enforcement_selftest")
