"""Fusion: choose what a limit turns off; record policy violations

Revision ID: f4c2a7d1e9b3
Revises: c8e1f5a3d6b2
Create Date: 2026-11-24

A project, group or application limit can now turn off Fusion as well as Auto
Triage and PR triage and remediation, and an admin chooses which of the three
each limit turns off.

* ``credit_limit.project_actions`` - the chosen actions, as a JSON list of
  ``"auto_triage"``, ``"pr_remediation"`` and ``"fusion"``. Existing rows keep
  it null, which means what every limit did before this column: Auto Triage
  and PR triage and remediation, and nothing else. An upgrade therefore
  changes no limit's behaviour.
* ``policy_violation`` - what someone did against a restriction in force (a
  setting switched back on, a scan that ran Fusion, usage that kept rising),
  for admins to follow up. New and empty.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "f4c2a7d1e9b3"
down_revision = "c8e1f5a3d6b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("credit_limit") as batch:
        batch.add_column(sa.Column("project_actions", sa.JSON(), nullable=True))

    op.create_table(
        "policy_violation",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(48), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "limit_id",
            sa.Integer(),
            sa.ForeignKey("credit_limit.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "enforcement_action_id",
            sa.Integer(),
            sa.ForeignKey("enforcement_action.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("limit_label", sa.String(512), nullable=True),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("target_label", sa.String(512), nullable=True),
        sa.Column("actor", sa.String(320), nullable=True),
        sa.Column("source", sa.String(128), nullable=True),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("credits", sa.Numeric(18, 4), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="warning"),
        sa.Column("status", sa.String(16), nullable=False, server_default="open"),
        sa.Column("acknowledged_by", sa.String(128), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(128), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("dedupe_key", sa.String(200), nullable=False),
        sa.UniqueConstraint("dedupe_key", name="uq_policy_violation_dedupe_key"),
    )
    op.create_index("ix_policy_violation_kind", "policy_violation", ["kind"])
    op.create_index("ix_policy_violation_detected_at", "policy_violation", ["detected_at"])
    op.create_index("ix_policy_violation_limit_id", "policy_violation", ["limit_id"])
    op.create_index("ix_policy_violation_target_id", "policy_violation", ["target_id"])
    op.create_index("ix_policy_violation_status", "policy_violation", ["status"])
    op.create_index(
        "ix_policy_violation_status_detected", "policy_violation", ["status", "detected_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_policy_violation_status_detected", table_name="policy_violation")
    op.drop_index("ix_policy_violation_status", table_name="policy_violation")
    op.drop_index("ix_policy_violation_target_id", table_name="policy_violation")
    op.drop_index("ix_policy_violation_limit_id", table_name="policy_violation")
    op.drop_index("ix_policy_violation_detected_at", table_name="policy_violation")
    op.drop_index("ix_policy_violation_kind", table_name="policy_violation")
    op.drop_table("policy_violation")
    with op.batch_alter_table("credit_limit") as batch:
        batch.drop_column("project_actions")
