"""Secret encryption at rest.

AES-256-GCM with per-purpose keys derived from the master key via HKDF-SHA256.
The purpose string is also bound in as additional authenticated data, so a
ciphertext written for one purpose (say the Checkmarx API key) cannot be
replayed into a column read with another purpose (say an SMTP password).
"""

from __future__ import annotations

import base64
import os
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings

TOKEN_VERSION: Final = "v1"
NONCE_BYTES: Final = 12
KEY_BYTES: Final = 32

# Purposes. Add new ones here rather than passing ad hoc strings around.
PURPOSE_CX_API_KEY: Final = "cx-api-key"
PURPOSE_SMTP_PASSWORD: Final = "smtp-password"
PURPOSE_WEBHOOK_SECRET: Final = "webhook-secret"
PURPOSE_TOTP_SECRET: Final = "totp-secret"


class DecryptionError(RuntimeError):
    """Ciphertext could not be authenticated with the configured master key."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


class SecretBox:
    """Encrypts and decrypts short secrets for storage in the database."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != KEY_BYTES:
            raise ValueError(f"master key must be {KEY_BYTES} bytes")
        self._master_key = master_key

    def _derive(self, purpose: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_BYTES,
            salt=None,
            info=f"cxcreditguard:{purpose}".encode(),
        ).derive(self._master_key)

    def encrypt(self, plaintext: str, *, purpose: str) -> str:
        """Return a self describing token: ``v1.<nonce>.<ciphertext>``."""
        nonce = os.urandom(NONCE_BYTES)
        aesgcm = AESGCM(self._derive(purpose))
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), purpose.encode("utf-8"))
        return f"{TOKEN_VERSION}.{_b64e(nonce)}.{_b64e(ciphertext)}"

    def decrypt(self, token: str, *, purpose: str) -> str:
        try:
            version, nonce_b64, ciphertext_b64 = token.split(".")
        except ValueError as exc:
            raise DecryptionError("malformed ciphertext token") from exc
        if version != TOKEN_VERSION:
            raise DecryptionError(f"unsupported ciphertext version {version!r}")
        aesgcm = AESGCM(self._derive(purpose))
        try:
            plaintext = aesgcm.decrypt(
                _b64d(nonce_b64), _b64d(ciphertext_b64), purpose.encode("utf-8")
            )
        except (InvalidTag, ValueError) as exc:
            raise DecryptionError(
                "could not decrypt stored secret. The master key may have changed, "
                "or the value was written for a different purpose."
            ) from exc
        return plaintext.decode("utf-8")


_box: SecretBox | None = None


def get_secret_box() -> SecretBox:
    """Process wide SecretBox built from the configured master key."""
    global _box
    if _box is None:
        _box = SecretBox(get_settings().master_key_bytes())
    return _box


def reset_secret_box() -> None:
    """Test helper: force the SecretBox to be rebuilt from current settings."""
    global _box
    _box = None
