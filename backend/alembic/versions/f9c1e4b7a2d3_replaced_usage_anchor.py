"""Replaced: the unreleased usage-anchor schema

Revision ID: f9c1e4b7a2d3
Revises: d8b3f6a2c5e1
Create Date: 2026-11-25

This revision id was once an unreleased migration (usage anchors, name states
and held rows) that the usage ledger replaced. It is kept, empty, so that a
database already stamped with it still finds its place in the chain: the next
revision (``b3e8d1f6a9c4``, the usage ledger) removes whatever that schema
added, and builds the ledger, whichever way the database got here.
"""

from __future__ import annotations

revision = "f9c1e4b7a2d3"
down_revision = "d8b3f6a2c5e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
