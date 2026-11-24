"""Pacing for large tenants: rotating verification and batched rollouts

Revision ID: a6c2e9f4b8d1
Revises: f4c2a7d1e9b3
Create Date: 2026-11-24

* ``enforcement_action.last_verified_at`` - when the restriction was last read
  back from Checkmarx One and found in force (or re-asserted). Restrictions in
  force are verified in rotation, oldest first, rather than every cycle. Null
  for rows from before this column: they are verified first.
* ``limit_period_state.rollout_total`` / ``rollout_done`` - for a limit whose
  first enforcement is spread over several cycles (more targets than one
  cycle's write budget), how many users or projects it restricts and how many
  have been dealt with. Null for every limit that never needed it.

Downgrading drops the three columns; nothing else depends on them.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "a6c2e9f4b8d1"
down_revision = "f4c2a7d1e9b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enforcement_action") as batch:
        batch.add_column(sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_enforcement_action_status_verified", ["status", "last_verified_at"])
    with op.batch_alter_table("limit_period_state") as batch:
        batch.add_column(sa.Column("rollout_total", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("rollout_done", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("limit_period_state") as batch:
        batch.drop_column("rollout_done")
        batch.drop_column("rollout_total")
    with op.batch_alter_table("enforcement_action") as batch:
        batch.drop_index("ix_enforcement_action_status_verified")
        batch.drop_column("last_verified_at")
