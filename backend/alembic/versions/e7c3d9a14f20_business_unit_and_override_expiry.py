"""business unit on credit_limit, expiry on exemption

Revision ID: e7c3d9a14f20
Revises: d4a2f0b7c915
Create Date: 2026-11-05

Business-unit attribution for chargeback, and a time-boxed override (an
exemption that expires and is then removed so normal enforcement resumes).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "e7c3d9a14f20"
down_revision = "d4a2f0b7c915"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("credit_limit", sa.Column("business_unit", sa.String(length=128), nullable=True))
    op.add_column("exemption", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("exemption", "expires_at")
    op.drop_column("credit_limit", "business_unit")
