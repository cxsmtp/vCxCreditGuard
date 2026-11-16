"""charge auto-triage credits to the person who started the scan

Revision ID: e3b8f1c6d2a4
Revises: d9a3c7e15b62
Create Date: 2026-11-16

Auto Triage spend is reported under a synthetic "Auto-triage" user and so only
ever counted against the project. An admin setting (off by default) now also
charges it to whoever started the scan that triggered it. This adds:

* ``auto_triage_charge`` - each observed increase in a project's Auto Triage
  credits, split across the initiators of the scans that explain it.
* ``auto_triage_project_state`` - the per project cursor and the sample of
  earlier scans that pre-existing credits are estimated against.
* ``limit_period_state.baseline_at`` - when a period's baseline was taken, so
  charges are discounted by the same rule as the person's own credits.
* ``limit_period_state.attributed_credits`` - how much of ``credits_used`` came
  from such charges. Null while the setting is off.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e3b8f1c6d2a4"
down_revision = "d9a3c7e15b62"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auto_triage_charge",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.String(64), nullable=False),
        sa.Column("basis", sa.String(16), nullable=False),
        sa.Column("initiator", sa.String(320), nullable=True),
        sa.Column("initiator_key", sa.String(320), nullable=True),
        sa.Column("scan_ids", sa.JSON(), nullable=True),
        sa.Column("scan_count", sa.Integer(), nullable=False),
        sa.Column("credits", sa.Numeric(18, 4), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("snapshot_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detail", sa.String(512), nullable=True),
    )
    op.create_index("ix_auto_triage_charge_project_id", "auto_triage_charge", ["project_id"])
    op.create_index("ix_auto_triage_charge_initiator_key", "auto_triage_charge", ["initiator_key"])
    op.create_index("ix_auto_triage_charge_window_end", "auto_triage_charge", ["window_end"])
    op.create_index(
        "ix_auto_triage_charge_project_window",
        "auto_triage_charge",
        ["project_id", "window_end"],
    )

    op.create_table(
        "auto_triage_project_state",
        sa.Column("project_id", sa.String(64), primary_key=True),
        sa.Column("period_param", sa.String(32), nullable=False),
        sa.Column("last_snapshot_id", sa.Integer(), nullable=True),
        sa.Column("last_collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_credits", sa.Numeric(18, 4), nullable=False),
        sa.Column("observing_since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("history_status", sa.String(16), nullable=False),
        sa.Column("history", sa.JSON(), nullable=True),
        sa.Column("history_collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("branches", sa.JSON(), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    with op.batch_alter_table("limit_period_state") as batch:
        batch.add_column(sa.Column("baseline_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("attributed_credits", sa.Numeric(18, 4), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("limit_period_state") as batch:
        batch.drop_column("attributed_credits")
        batch.drop_column("baseline_at")
    op.drop_table("auto_triage_project_state")
    op.drop_index("ix_auto_triage_charge_project_window", table_name="auto_triage_charge")
    op.drop_index("ix_auto_triage_charge_window_end", table_name="auto_triage_charge")
    op.drop_index("ix_auto_triage_charge_initiator_key", table_name="auto_triage_charge")
    op.drop_index("ix_auto_triage_charge_project_id", table_name="auto_triage_charge")
    op.drop_table("auto_triage_charge")
