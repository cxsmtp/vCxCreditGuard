"""Opaque token generation and hashing for sessions and CSRF.

Session and CSRF tokens are random 256 bit values. Only their SHA-256 digests
are stored, so a database dump does not hand an attacker live sessions.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

TOKEN_BYTES = 32


def new_token() -> str:
    """A URL safe random token with 256 bits of entropy."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """SHA-256 of a high entropy token. No salt or stretching needed: the input
    is already unguessable, and lookups must be by exact digest."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(expected_hash: str, presented_token: str) -> bool:
    """Constant time comparison of a stored digest against a presented token."""
    return hmac.compare_digest(expected_hash, hash_token(presented_token))
