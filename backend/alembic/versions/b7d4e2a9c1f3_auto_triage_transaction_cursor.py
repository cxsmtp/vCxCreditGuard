"""auto-triage attribution: a transaction cursor and an observation epoch

Revision ID: b7d4e2a9c1f3
Revises: e3b8f1c6d2a4
Create Date: 2026-11-16

The per project cursor of auto-triage attribution moves to what the consumption
feed actually reports per project, the Auto Triage *transaction count*, so a
change in the tenant-wide credits per transaction can no longer look like new
auto triage. Each state also records the enablement it belongs to, so turning
the setting off and on again restarts observation instead of charging the gap
as one observed rise.

* ``auto_triage_project_state.last_transactions`` - the cursor.
* ``auto_triage_project_state.observation_epoch`` - the enablement stamp.

Existing rows keep both null, which the collector reads as "observation
restarts now": their cursor is reset to the next reading and anything before it
is estimated, never observed.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "b7d4e2a9c1f3"
down_revision = "e3b8f1c6d2a4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("auto_triage_project_state") as batch:
        batch.add_column(sa.Column("last_transactions", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("observation_epoch", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("auto_triage_project_state") as batch:
        batch.drop_column("observation_epoch")
        batch.drop_column("last_transactions")
