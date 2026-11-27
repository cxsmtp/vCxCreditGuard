"""No role shields a user from a restriction by default

Revision ID: a4d8e2c6f1b9
Revises: b3e7f1a9c2d5
Create Date: 2026-11-27

``enforcement.protected_roles`` used to default to ``ast-admin, iam-admin``:
holders of those roles were never restricted, however far over budget. The
default is now empty: everyone over budget is restricted, and where a user
keeps an AI role through a composite role (``ast-admin`` contains
``create-fusion-scan``) or a group, that is recorded and reported as a
restriction that cannot fully bite. The API key's own account is still never
restricted (``enforcement.protected_user_ids``); that is not a setting.

An install that never stored the setting picks the new default up from the
code. One that stored exactly the old default (the same two names, in any
order, case or spacing) meant "the default", so it is switched to empty. Any
other stored list is an admin's choice and is left exactly as it is.

Downgrading puts the old default back on a stored empty value. That cannot
tell an empty list this migration wrote from one an admin saved, so an admin's
explicit empty list is also turned back into the old default.

Data only, no schema change.
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "a4d8e2c6f1b9"
down_revision = "b3e7f1a9c2d5"
branch_labels = None
depends_on = None

KEY = "enforcement.protected_roles"
OLD_DEFAULT = "ast-admin, iam-admin"
NEW_DEFAULT = ""

_settings = sa.table(
    "app_setting",
    sa.column("key", sa.String),
    sa.column("value", sa.Text),
    sa.column("is_secret", sa.Boolean),
)


def _names(value: str) -> frozenset[str]:
    return frozenset(
        name.strip().lower() for name in value.replace(";", ",").split(",") if name.strip()
    )


def _stored() -> str | None:
    """The stored text, or None when there is no usable stored value."""
    row = (
        op.get_bind()
        .execute(sa.select(_settings.c.value, _settings.c.is_secret).where(_settings.c.key == KEY))
        .first()
    )
    if row is None or row.value is None or row.is_secret:
        return None
    try:
        stored = json.loads(row.value)
    except (TypeError, ValueError):
        return None
    return stored if isinstance(stored, str) else None


def _write(value: str) -> None:
    op.get_bind().execute(
        sa.update(_settings).where(_settings.c.key == KEY).values(value=json.dumps(value))
    )


def upgrade() -> None:
    stored = _stored()
    if stored is not None and _names(stored) == _names(OLD_DEFAULT):
        _write(NEW_DEFAULT)


def downgrade() -> None:
    stored = _stored()
    if stored is not None and not _names(stored):
        _write(OLD_DEFAULT)
