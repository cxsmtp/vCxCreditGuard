"""lock out the source of failed sign-ins, not the account

Revision ID: c5d8e2f4a917
Revises: b7e4a1d92c35
Create Date: 2026-11-14

Failed sign-ins used to lock the account itself, so anyone who knew an
administrator's username could keep them locked out indefinitely. The failure
count and lockout now live on the (username, client address) row.

Also adds the store for two factor recovery codes, so losing an authenticator
does not mean losing the account.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c5d8e2f4a917"
down_revision = "b7e4a1d92c35"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "login_attempt",
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "login_attempt", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True)
    )
    # One-time recovery codes for two factor authentication (digests only).
    op.add_column("utility_user", sa.Column("totp_recovery_codes", sa.JSON(), nullable=True))
    # Last accepted authenticator time step, so a code cannot be replayed.
    op.add_column("utility_user", sa.Column("totp_last_step", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("utility_user", "totp_last_step")
    op.drop_column("utility_user", "totp_recovery_codes")
    op.drop_column("login_attempt", "locked_until")
    op.drop_column("login_attempt", "failure_count")
