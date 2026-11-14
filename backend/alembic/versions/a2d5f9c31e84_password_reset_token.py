"""self-service password reset tokens

Revision ID: a2d5f9c31e84
Revises: f1b6e8c0a73d
Create Date: 2026-11-05

A single-use, time-limited token table backing self-service and admin-initiated
password resets. Only the token's digest is stored.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a2d5f9c31e84"
down_revision = "f1b6e8c0a73d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "password_reset_token",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("requested_ip", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["utility_user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_password_reset_token_user_id", "password_reset_token", ["user_id"], unique=False
    )
    op.create_index(
        "ix_password_reset_token_token_hash", "password_reset_token", ["token_hash"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_password_reset_token_token_hash", table_name="password_reset_token")
    op.drop_index("ix_password_reset_token_user_id", table_name="password_reset_token")
    op.drop_table("password_reset_token")
