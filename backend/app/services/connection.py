"""Checkmarx One connection lifecycle: preview, save, test, and client provisioning.

The API key is stored encrypted and decrypted only in memory here. A process wide
client cache keyed by the key fingerprint and URLs means the access token is
reused across requests and scheduler cycles instead of being re-exchanged per
call, and is torn down whenever the connection changes.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.checkmarx.apikey import ParsedApiKey, parse_api_key
from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxError, NotConfiguredError
from app.checkmarx.regions import derive_api_base_url, normalise_api_base_url
from app.checkmarx.token import TokenManager
from app.core.crypto import PURPOSE_CX_API_KEY, get_secret_box
from app.core.logging import register_secret
from app.db.base import utcnow
from app.models.connection import CxConnection
from app.models.enums import ConnectionStatus
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

CONNECTION_ID = 1
# Cheapest known-good platform call for a health check.
PROBE_PATH = "/projects"


@dataclass(frozen=True, slots=True)
class ConnectionPreview:
    """What the Setup page shows for confirmation before anything is saved."""

    iam_base_url: str
    tenant_name: str
    derived_api_base_url: str | None
    region_label: str
    derivation_confident: bool
    api_key_fingerprint: str
    key_expires_at: Any | None
    client_id: str | None


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    ok: bool
    token_acquired: bool
    api_reachable: bool
    message: str
    tenant_name: str | None = None
    iam_base_url: str | None = None
    api_base_url: str | None = None
    token_seconds_remaining: float | None = None
    projects_visible: int | None = None


def preview_api_key(api_key: str) -> ConnectionPreview:
    """Parse an API key locally. No network call, nothing persisted."""
    parsed = parse_api_key(api_key)
    derived = derive_api_base_url(parsed.iam_base_url)
    return ConnectionPreview(
        iam_base_url=parsed.iam_base_url,
        tenant_name=parsed.tenant_name,
        derived_api_base_url=derived.api_base_url,
        region_label=derived.region_label,
        derivation_confident=derived.confident,
        api_key_fingerprint=parsed.fingerprint,
        key_expires_at=parsed.expires_at,
        client_id=parsed.client_id,
    )


def get_connection(session: Session) -> CxConnection | None:
    return session.get(CxConnection, CONNECTION_ID)


def _resolve_api_base_url(parsed: ParsedApiKey, override: str | None) -> tuple[str, bool]:
    if override and override.strip():
        return normalise_api_base_url(override), True
    derived = derive_api_base_url(parsed.iam_base_url)
    if derived.api_base_url is None:
        raise CheckmarxError(
            "Could not derive the platform API base URL from the IAM URL "
            f"{parsed.iam_base_url}. Enter it manually, for example "
            "https://eu.ast.checkmarx.net/api."
        )
    return normalise_api_base_url(derived.api_base_url), False


def save_connection(
    session: Session,
    *,
    api_key: str,
    api_base_url_override: str | None = None,
    actor: AuditActor,
) -> CxConnection:
    """Persist the connection, encrypting the API key.

    Rotating the key or changing the base URL invalidates the cached client so
    the next call re-authenticates with the new details.
    """
    parsed = parse_api_key(api_key)
    if parsed.is_expired:
        raise CheckmarxError(
            f"This API key expired at {parsed.expires_at:%Y-%m-%d %H:%M UTC}. "
            "Generate a new one in Identity and Access Management."
        )

    api_base_url, overridden = _resolve_api_base_url(parsed, api_base_url_override)
    ciphertext = get_secret_box().encrypt(api_key.strip(), purpose=PURPOSE_CX_API_KEY)

    connection = get_connection(session)
    before: dict[str, Any] | None = None
    if connection is None:
        connection = CxConnection(id=CONNECTION_ID)
        session.add(connection)
    else:
        before = {
            "iam_base_url": connection.iam_base_url,
            "tenant_name": connection.tenant_name,
            "api_base_url": connection.api_base_url,
            "api_key_fingerprint": connection.api_key_fingerprint,
        }

    connection.api_key_encrypted = ciphertext
    connection.iam_base_url = parsed.iam_base_url
    connection.tenant_name = parsed.tenant_name
    connection.api_base_url = api_base_url
    connection.api_base_url_overridden = overridden
    connection.api_key_fingerprint = parsed.fingerprint
    connection.status = ConnectionStatus.UNCONFIGURED
    connection.last_error = None
    session.flush()

    record_audit(
        session,
        action="connection.saved",
        actor=actor,
        target_type="connection",
        target_id=str(CONNECTION_ID),
        target_label=parsed.tenant_name,
        before=before,
        after={
            "iam_base_url": connection.iam_base_url,
            "tenant_name": connection.tenant_name,
            "api_base_url": connection.api_base_url,
            "api_base_url_overridden": overridden,
            "api_key_fingerprint": parsed.fingerprint,
        },
        detail="Checkmarx One API key stored (encrypted) and tenant details derived.",
    )
    reset_client_cache()
    return connection


def set_api_base_url(session: Session, *, api_base_url: str, actor: AuditActor) -> CxConnection:
    """Override the platform API base URL for a dedicated or regional tenant."""
    connection = get_connection(session)
    if connection is None:
        raise NotConfiguredError("No Checkmarx connection has been configured yet.")
    before = {"api_base_url": connection.api_base_url}
    connection.api_base_url = normalise_api_base_url(api_base_url)
    connection.api_base_url_overridden = True
    session.flush()
    record_audit(
        session,
        action="connection.api_base_url_changed",
        actor=actor,
        target_type="connection",
        target_id=str(CONNECTION_ID),
        before=before,
        after={"api_base_url": connection.api_base_url},
    )
    reset_client_cache()
    return connection


def decrypt_api_key(connection: CxConnection) -> str:
    api_key = get_secret_box().decrypt(connection.api_key_encrypted, purpose=PURPOSE_CX_API_KEY)
    register_secret(api_key)
    return api_key


# --------------------------------------------------------------- client cache

_cache_lock = threading.Lock()
_cached_client: CheckmarxClient | None = None
_cached_token_manager: TokenManager | None = None
_cached_key: tuple[str, str, str, str] | None = None


def reset_client_cache() -> None:
    """Drop the cached client and token. Called whenever the connection changes."""
    global _cached_client, _cached_token_manager, _cached_key
    with _cache_lock:
        if _cached_client is not None:
            _cached_client.close()
        if _cached_token_manager is not None:
            _cached_token_manager.close()
        _cached_client = None
        _cached_token_manager = None
        _cached_key = None


def build_client(connection: CxConnection) -> CheckmarxClient:
    """Build an un-cached client. Used by the connection test and by tests."""
    api_key = decrypt_api_key(connection)
    parsed = parse_api_key(api_key)
    token_manager = TokenManager(api_key=api_key, token_endpoint=parsed.token_endpoint)
    return CheckmarxClient(
        api_base_url=connection.api_base_url,
        iam_base_url=connection.iam_base_url,
        tenant_name=connection.tenant_name,
        token_manager=token_manager,
    )


def get_client(session: Session) -> CheckmarxClient:
    """Shared client for the configured connection, reusing its access token."""
    connection = get_connection(session)
    if connection is None:
        raise NotConfiguredError(
            "No Checkmarx One connection configured. Add an API key on the Setup page."
        )

    identity = (
        connection.api_key_fingerprint or "",
        connection.iam_base_url,
        connection.tenant_name,
        connection.api_base_url,
    )
    global _cached_client, _cached_token_manager, _cached_key
    with _cache_lock:
        if _cached_client is not None and _cached_key == identity:
            return _cached_client

        if _cached_client is not None:
            _cached_client.close()
        if _cached_token_manager is not None:
            _cached_token_manager.close()

        api_key = decrypt_api_key(connection)
        parsed = parse_api_key(api_key)
        _cached_token_manager = TokenManager(api_key=api_key, token_endpoint=parsed.token_endpoint)
        _cached_client = CheckmarxClient(
            api_base_url=connection.api_base_url,
            iam_base_url=connection.iam_base_url,
            tenant_name=connection.tenant_name,
            token_manager=_cached_token_manager,
        )
        _cached_key = identity
        return _cached_client


# --------------------------------------------------------------------- testing


def test_connection(
    session: Session,
    *,
    client: CheckmarxClient | None = None,
    record_result: bool = True,
) -> ConnectionTestResult:
    """Exchange the API key and make one read only platform call.

    Two separate checks, reported separately, because they fail for different
    reasons: a bad key fails the token exchange, while a wrong regional base URL
    or a missing permission fails the platform call.
    """
    connection = get_connection(session)
    if connection is None:
        return ConnectionTestResult(
            ok=False,
            token_acquired=False,
            api_reachable=False,
            message="No Checkmarx connection configured yet.",
        )

    cx = client or get_client(session)
    token_acquired = False
    try:
        cx.tokens.get_access_token()
        token_acquired = True
        payload = cx.get_json(PROBE_PATH, params={"limit": 1, "offset": 0})
        projects_visible = _total_from(payload)
    except CheckmarxError as exc:
        message = str(exc)
        if record_result:
            connection.status = ConnectionStatus.FAILED
            connection.last_failure_at = utcnow()
            connection.last_error = message[:2000]
            session.flush()
        return ConnectionTestResult(
            ok=False,
            token_acquired=token_acquired,
            api_reachable=False,
            message=message,
            tenant_name=connection.tenant_name,
            iam_base_url=connection.iam_base_url,
            api_base_url=connection.api_base_url,
        )

    if record_result:
        connection.status = ConnectionStatus.HEALTHY
        connection.last_success_at = utcnow()
        connection.last_error = None
        session.flush()

    return ConnectionTestResult(
        ok=True,
        token_acquired=True,
        api_reachable=True,
        message=f"Connected to tenant {connection.tenant_name}.",
        tenant_name=connection.tenant_name,
        iam_base_url=connection.iam_base_url,
        api_base_url=connection.api_base_url,
        token_seconds_remaining=cx.tokens.cached_token_seconds_remaining,
        projects_visible=projects_visible,
    )


def _total_from(payload: Any) -> int | None:
    if isinstance(payload, dict):
        for key in ("totalCount", "filteredTotalCount", "total"):
            value = payload.get(key)
            if isinstance(value, int):
                return value
    if isinstance(payload, list):
        return len(payload)
    return None
