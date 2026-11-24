"""Verification for every restriction in force, rollout identities, pinned baselines

Revision ID: c4e7a2d9f1b6
Revises: a6c2e9f4b8d1
Create Date: 2026-11-24

* ``enforcement_action.last_checked_at`` - when the verification rotation last
  chose the restriction and could not read it back: its place in the rotation
  only (behind the others), never whether it is due (``last_verified_at``).
* ``enforcement_action.baseline_snapshot_id`` - the usage snapshot that was the
  latest reading when the restriction was applied, which a rise in usage since
  is measured from. The retention job's thinning never removes it. Null on rows
  from before this column: the newest snapshot at or before ``applied_at`` is
  used, as before (and the retention job fills it in before it thins).
* ``limit_period_state.rollout_pending`` - the users or projects a rollout
  spread over several cycles still has to restrict, by id, so the safety
  ceiling knows exactly which it let through (it used to subtract a count).
  Null for rows from before: the ceiling then judges every remaining target
  again, which can only stop more, never let more through.

No data is rewritten here: usage_snapshot.raw (no longer stored) and old
usage_record.raw values are cleared by the retention job in batches.
Downgrading drops the three columns; nothing else depends on them.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c4e7a2d9f1b6"
down_revision = "a6c2e9f4b8d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enforcement_action") as batch:
        batch.add_column(sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("baseline_snapshot_id", sa.Integer(), nullable=True))
    with op.batch_alter_table("limit_period_state") as batch:
        batch.add_column(sa.Column("rollout_pending", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("limit_period_state") as batch:
        batch.drop_column("rollout_pending")
    with op.batch_alter_table("enforcement_action") as batch:
        batch.drop_column("baseline_snapshot_id")
        batch.drop_column("last_checked_at")
