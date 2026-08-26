"""Parsing of the Checkmarx One API key.

The API key is a Keycloak refresh token. We decode it *without verifying the
signature*, purely to read the ``iss`` claim, which carries the IAM base URL and
the tenant (realm) name. We are not making a trust decision here: the real proof
that the key is valid is the token exchange succeeding against IAM. Anything read
out of the unverified payload is treated as a hint to show the admin for
confirmation, never as an authorisation input.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from app.checkmarx.errors import ApiKeyError

# iss looks like: https://<iam-base-url>/auth/realms/<tenant-name>
# The IAM base URL can itself contain a path segment on dedicated deployments,
# so the group is non greedy up to the /auth/realms/ marker.
_ISSUER_RE: Final = re.compile(
    r"^(?P<iam_base_url>https?://[^\s]+?)/auth/realms/(?P<tenant>[^/\s]+)/?$"
)

_JWT_SEGMENTS: Final = 3


@dataclass(frozen=True, slots=True)
class ParsedApiKey:
    """Everything we can learn from an API key without contacting Checkmarx."""

    iam_base_url: str
    tenant_name: str
    issuer: str
    subject: str | None
    client_id: str | None
    token_type: str | None
    expires_at: datetime | None
    fingerprint: str

    @property
    def is_expired(self) -> bool:
        """True only when the key carries an expiry that has already passed.

        Offline tokens (the usual shape for a Checkmarx One API key) have no
        expiry, in which case this is False.
        """
        return self.expires_at is not None and self.expires_at <= datetime.now(UTC)

    @property
    def token_endpoint(self) -> str:
        return f"{self.iam_base_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"


def fingerprint_api_key(api_key: str) -> str:
    """Short, non reversible identifier for a key.

    Lets the GUI and audit log say *which* key is in use ("key a1b2c3d4e5f6 was
    replaced") without storing or displaying any part of the key itself.
    """
    return hashlib.sha256(api_key.strip().encode("utf-8")).hexdigest()[:12]


def _decode_segment(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise ApiKeyError("API key is not valid base64url encoded JWT.") from exc
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ApiKeyError("API key payload is not valid JSON.") from exc
    if not isinstance(payload, dict):
        raise ApiKeyError("API key payload is not a JSON object.")
    return payload


def parse_api_key(api_key: str) -> ParsedApiKey:
    """Extract IAM base URL and tenant name from an API key.

    Raises ApiKeyError with an actionable message for every malformed input, so
    the Setup page can tell the admin what is wrong with what they pasted.
    """
    if not api_key or not api_key.strip():
        raise ApiKeyError("No API key supplied.")

    token = api_key.strip()
    segments = token.split(".")
    if len(segments) != _JWT_SEGMENTS or not all(segments[:2]):
        raise ApiKeyError(
            "API key does not look like a JWT (expected three dot separated segments). "
            "Copy the key exactly as generated in Identity and Access Management."
        )

    payload = _decode_segment(segments[1])

    issuer = payload.get("iss")
    if not isinstance(issuer, str) or not issuer:
        raise ApiKeyError("API key has no 'iss' claim, so the tenant cannot be determined.")

    match = _ISSUER_RE.match(issuer.strip())
    if not match:
        raise ApiKeyError(
            "API key issuer is not in the expected form "
            "https://<iam-base-url>/auth/realms/<tenant-name>. "
            f"Issuer was: {issuer}"
        )

    exp = payload.get("exp")
    expires_at: datetime | None = None
    # Keycloak offline tokens carry exp=0, which means "does not expire".
    if isinstance(exp, int | float) and exp > 0:
        expires_at = datetime.fromtimestamp(float(exp), tz=UTC)

    typ = payload.get("typ")
    if isinstance(typ, str) and typ.lower() not in {"refresh", "offline"}:
        raise ApiKeyError(
            f"This looks like a {typ} token, not a refresh token. The API key is "
            "generated under Identity and Access Management, not copied from a browser session."
        )

    return ParsedApiKey(
        iam_base_url=match.group("iam_base_url").rstrip("/"),
        tenant_name=match.group("tenant"),
        issuer=issuer,
        subject=payload.get("sub") if isinstance(payload.get("sub"), str) else None,
        client_id=payload.get("azp") if isinstance(payload.get("azp"), str) else None,
        token_type=typ if isinstance(typ, str) else None,
        expires_at=expires_at,
        fingerprint=fingerprint_api_key(token),
    )
