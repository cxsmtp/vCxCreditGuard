"""Refuse to start with a master key that cannot read what is already stored.

Every stored secret (the Checkmarx API key, SMTP password, webhook secret, TOTP
secrets) is encrypted under the master key. If the process is started with a
different key - a restored backup paired with the wrong ``.env``, a regenerated
key, a typo - everything looks healthy: the web UI comes up, the health check
passes, and only the scheduled cycle fails, quietly, every few minutes. Nothing
is governed and nobody is told.

A small check value encrypted under the key is kept in the database. At start-up
it must decrypt; if it does not, the process stops with an explanation instead.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import ConfigError
from app.core.crypto import (
    PURPOSE_CX_API_KEY,
    PURPOSE_KEY_CHECK,
    PURPOSE_TOTP_SECRET,
    DecryptionError,
    get_secret_box,
)
from app.models.auth import UtilityUser
from app.models.connection import AppSetting, CxConnection
from app.services import settings_store

logger = logging.getLogger(__name__)

CHECK_KEY = "crypto.key_check"
CHECK_VALUE = "cxcreditguard-master-key-check-v1"

_WRONG_KEY = (
    "The master key (CXCG_MASTER_KEY / CXCG_MASTER_KEY_FILE) is not the one this database "
    "was encrypted with, so the stored Checkmarx API key and notification secrets cannot "
    "be read. Start with the original key. If that key is lost, the stored secrets are "
    "unrecoverable: run `python -m scripts.reset_secrets --yes` in the container to clear "
    "them, then start again and re-enter the API key and notification secrets (see "
    '"Losing the master key" in the README).'
)


def verify_master_key(session: Session) -> None:
    """Raise :class:`ConfigError` if the configured key cannot read stored secrets."""
    box = get_secret_box()
    row = session.get(AppSetting, CHECK_KEY)
    if row is not None and row.value:
        try:
            matches = box.decrypt(row.value, purpose=PURPOSE_KEY_CHECK) == CHECK_VALUE
        except DecryptionError:
            matches = False
        if not matches:
            raise ConfigError(_WRONG_KEY)
        return

    # No check value yet: a first start, or the first start after an upgrade.
    # Before vouching for this key, make sure it reads whatever is already there.
    for ciphertext, purpose in _stored_secrets(session):
        try:
            box.decrypt(ciphertext, purpose=purpose)
        except DecryptionError as exc:
            raise ConfigError(_WRONG_KEY) from exc

    token = box.encrypt(CHECK_VALUE, purpose=PURPOSE_KEY_CHECK)
    if row is None:
        session.add(AppSetting(key=CHECK_KEY, value=token, is_secret=True))
    else:
        row.value = token
        row.is_secret = True
    session.flush()
    logger.info("Recorded the master key check value")


def _stored_secrets(session: Session) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    connection = session.scalar(select(CxConnection).limit(1))
    if connection is not None and connection.api_key_encrypted:
        found.append((connection.api_key_encrypted, PURPOSE_CX_API_KEY))
    for key, purpose in settings_store.SECRET_KEYS.items():
        row = session.get(AppSetting, key)
        # A row not flagged as secret is a value an older version stored in the
        # clear (it is encrypted later in start-up). It is not ciphertext, so
        # failing to decrypt it says nothing about the key.
        if row is not None and row.value and row.is_secret:
            found.append((row.value, purpose))
    for ciphertext in session.scalars(
        select(UtilityUser.totp_secret_encrypted)
        .where(UtilityUser.totp_secret_encrypted.is_not(None))
        .limit(5)
    ):
        if ciphertext:
            found.append((ciphertext, PURPOSE_TOTP_SECRET))
    return found
