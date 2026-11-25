"""The default AI roles become the Fusion and LLM roles

Revision ID: c9f2a6e1d4b7
Revises: b3e8d1f6a9c4
Create Date: 2026-11-25

The roles a user restriction removes by default change from the three general
Risk Management roles (``view-risk-management``, ``-dashboard``, ``-tab``),
which do not gate spending AI credits, to ``create-fusion-scan``,
``manage-fusion``, ``update-llm-scan-mode`` and ``manage-llm-configuration``.

An install that never stored the setting picks the new default up from the
code; nothing here is needed for it. The Settings page's "Back to the default"
button, though, saves the default list itself, so an install can hold the old
default as a stored value while meaning "the default". This migration moves
exactly those rows:
``enforcement.ai_roles`` holding the old default list, the same three names in
the same order, becomes the new default. Any other stored list - a choice an
admin made - is left exactly as it is.

Restrictions already in force are not touched: each keeps, and gives back,
exactly the roles it recorded (one recorded without its own list goes by the
old default, see ``enforcement.snapshot_ai_roles``).

Downgrading moves a row holding exactly the new default back to the old one.

Data only, no schema change, so it commutes with any schema migration. If
another branch adds a revision on ``b3e8d1f6a9c4`` (the ledger's
``e2a7c4f9b1d8`` on realfix), merging gives two heads: set this file's
``down_revision`` to that revision so the chain stays single.
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "c9f2a6e1d4b7"
down_revision = "b3e8d1f6a9c4"
branch_labels = None
depends_on = None

KEY = "enforcement.ai_roles"
OLD_DEFAULT = [
    "view-risk-management",
    "view-risk-management-dashboard",
    "view-risk-management-tab",
]
NEW_DEFAULT = [
    "create-fusion-scan",
    "manage-fusion",
    "update-llm-scan-mode",
    "manage-llm-configuration",
]

_settings = sa.table(
    "app_setting",
    sa.column("key", sa.String),
    sa.column("value", sa.Text),
    sa.column("is_secret", sa.Boolean),
)


def _move(source: list[str], target: list[str]) -> None:
    bind = op.get_bind()
    row = bind.execute(
        sa.select(_settings.c.value, _settings.c.is_secret).where(_settings.c.key == KEY)
    ).first()
    if row is None or row.value is None or row.is_secret:
        return
    try:
        stored = json.loads(row.value)
    except (TypeError, ValueError):
        return
    if stored != source:
        return
    bind.execute(
        sa.update(_settings).where(_settings.c.key == KEY).values(value=json.dumps(target))
    )


def upgrade() -> None:
    _move(OLD_DEFAULT, NEW_DEFAULT)


def downgrade() -> None:
    _move(NEW_DEFAULT, OLD_DEFAULT)
