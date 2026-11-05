"""tamper-evident hash chain on the audit log

Revision ID: f1b6e8c0a73d
Revises: e7c3d9a14f20
Create Date: 2026-11-05

Each audit row carries the hash of its own content and the hash of the chain
tip that preceded it, so that editing, deleting, or reordering any row is
detectable by re-walking the chain.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "f1b6e8c0a73d"
down_revision = "e7c3d9a14f20"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_log_entry", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_log_entry", sa.Column("entry_hash", sa.String(length=64), nullable=True))
    op.create_index(
        "ix_audit_log_entry_entry_hash", "audit_log_entry", ["entry_hash"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_audit_log_entry_entry_hash", table_name="audit_log_entry")
    op.drop_column("audit_log_entry", "entry_hash")
    op.drop_column("audit_log_entry", "prev_hash")
