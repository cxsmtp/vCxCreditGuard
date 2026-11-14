"""add credit_request

Revision ID: d4a2f0b7c915
Revises: c3f1a8e60b24
Create Date: 2026-11-05

The credit request / approval workflow: a request to raise an entity's budget,
approved (full or partial, optionally temporary) or denied by an admin.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "d4a2f0b7c915"
down_revision = "c3f1a8e60b24"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credit_request",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("entity_type", sa.String(length=16), nullable=False),
        sa.Column("entity_id", sa.String(length=64), nullable=False),
        sa.Column("entity_label", sa.String(length=512), nullable=True),
        sa.Column("requested_limit", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=2048), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column(
            "requested_by_id",
            sa.Integer(),
            sa.ForeignKey("utility_user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("requested_by_name", sa.String(length=128), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "decided_by_id",
            sa.Integer(),
            sa.ForeignKey("utility_user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("decided_by_name", sa.String(length=128), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.String(length=2048), nullable=True),
        sa.Column("approved_limit", sa.Integer(), nullable=True),
        sa.Column("previous_limit", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reverted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("requested_limit >= 0", name="requested_limit_non_negative"),
    )
    op.create_index("ix_credit_request_entity_type", "credit_request", ["entity_type"])
    op.create_index("ix_credit_request_entity_id", "credit_request", ["entity_id"])
    op.create_index("ix_credit_request_status", "credit_request", ["status"])

    # Stamp on credit_limit linking a budget to the grant that set it, so a
    # temporary grant's rollback can tell "still mine" from "an admin changed it".
    op.add_column("credit_limit", sa.Column("granted_by_request_id", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("credit_limit", "granted_by_request_id")
    op.drop_index("ix_credit_request_status", table_name="credit_request")
    op.drop_index("ix_credit_request_entity_id", table_name="credit_request")
    op.drop_index("ix_credit_request_entity_type", table_name="credit_request")
    op.drop_table("credit_request")
