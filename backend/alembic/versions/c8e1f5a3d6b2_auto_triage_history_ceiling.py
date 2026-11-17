"""auto-triage attribution: a ceiling on the history that is estimated

Revision ID: c8e1f5a3d6b2
Revises: b7d4e2a9c1f3
Create Date: 2026-11-16

Credits a project reported before observation began are estimated against the
scans from before that moment. Those older transactions age out of the lookback
window first, so the estimate must shrink with them and never grow: whatever
the project reports beyond what is left of its history is newer auto triage
that no recorded charge explains, and stays on the project.

* ``auto_triage_project_state.history_ceiling`` - the most Auto Triage
  transactions from before observation began still inside the window: the
  reading observation started at, less every fall followed since.

Existing rows keep it null, which the read side takes as the current reading
(the estimate is then bounded exactly as before this column), and the next fall
the cursor follows sets it.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "c8e1f5a3d6b2"
down_revision = "b7d4e2a9c1f3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("auto_triage_project_state") as batch:
        batch.add_column(sa.Column("history_ceiling", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("auto_triage_project_state") as batch:
        batch.drop_column("history_ceiling")
