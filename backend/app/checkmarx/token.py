"""Access token acquisition and proactive refresh.

The API key (a refresh token) is exchanged for a bearer access token at
``/auth/realms/<tenant>/protocol/openid-connect/token``. Access tokens are held
in memory only, never written to the database, and both the key and the tokens
are registered with the log redaction filter the moment we see them.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx

from app.checkmarx.errors import CheckmarxAuthError, CheckmarxUnavailableError
from app.core.config import Settings, get_settings
from app.core.logging import register_secret

logger = logging.getLogger(__name__)

GRANT_TYPE_REFRESH_TOKEN = "refresh_token"  # noqa: S105 - OAuth grant type name, not a secret
# Used when IAM omits expires_in, which should not happen but must not crash us.
FALLBACK_TOKEN_LIFETIME_SECONDS = 1800


@dataclass(frozen=True, slots=True)
class AccessToken:
    value: str
    expires_at: datetime

    def expires_within(self, seconds: int) -> bool:
        return datetime.now(UTC) + timedelta(seconds=seconds) >= self.expires_at

    @property
    def seconds_remaining(self) -> float:
        return max(0.0, (self.expires_at - datetime.now(UTC)).total_seconds())


class TokenManager:
    """Caches one access token per tenant connection and refreshes it ahead of expiry.

    Thread safe: the FastAPI worker threads and the scheduler thread share one
    instance, and the lock stops a stampede of refresh calls when the token
    expires under concurrent load.
    """

    def __init__(
        self,
        *,
        api_key: str,
        token_endpoint: str,
        client: httpx.Client | None = None,
        settings: Settings | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._api_key = api_key
        self._token_endpoint = token_endpoint
        self._client = client
        self._owns_client = client is None
        self._lock = threading.Lock()
        self._token: AccessToken | None = None
        register_secret(api_key)

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._settings.cx_request_timeout_seconds)
        return self._client

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    def get_access_token(self) -> str:
        """Return a valid bearer token, refreshing it if it is close to expiry."""
        margin = self._settings.cx_token_refresh_margin_seconds
        with self._lock:
            token = self._token
            if token is not None and not token.expires_within(margin):
                return token.value
            refreshed = self._exchange()
            self._token = refreshed
            return refreshed.value

    def invalidate(self) -> None:
        """Drop the cached token so the next call re-exchanges.

        Called when the platform API answers 401, which means the token was
        revoked or the clock drifted further than our refresh margin.
        """
        with self._lock:
            self._token = None

    @property
    def cached_token_seconds_remaining(self) -> float | None:
        token = self._token
        return None if token is None else token.seconds_remaining

    def _exchange(self) -> AccessToken:
        payload = {
            "grant_type": GRANT_TYPE_REFRESH_TOKEN,
            "client_id": self._settings.cx_client_id,
            "refresh_token": self._api_key,
        }
        logger.debug("Exchanging API key for an access token at %s", self._token_endpoint)
        try:
            response = self._http().post(
                self._token_endpoint,
                data=payload,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            # Network level: worth retrying on the next cycle.
            raise CheckmarxUnavailableError(
                f"Could not reach Checkmarx IAM at {self._token_endpoint}: {type(exc).__name__}"
            ) from exc

        if response.status_code != httpx.codes.OK:
            raise CheckmarxAuthError(self._describe_failure(response))

        try:
            body = response.json()
        except ValueError as exc:
            raise CheckmarxAuthError(
                "Token endpoint returned a non JSON response. Check that the IAM base "
                "URL points at Checkmarx IAM and not at a proxy error page."
            ) from exc

        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise CheckmarxAuthError("Token endpoint response contained no access_token.")

        expires_in = body.get("expires_in")
        lifetime = (
            int(expires_in)
            if isinstance(expires_in, int | float) and int(expires_in) > 0
            else FALLBACK_TOKEN_LIFETIME_SECONDS
        )

        register_secret(access_token)
        logger.info("Obtained Checkmarx access token, valid for %s seconds", lifetime)
        return AccessToken(
            value=access_token,
            expires_at=datetime.now(UTC) + timedelta(seconds=lifetime),
        )

    @staticmethod
    def _describe_failure(response: httpx.Response) -> str:
        """Turn an IAM error response into something an admin can act on."""
        error = ""
        description = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                error = str(body.get("error", ""))
                description = str(body.get("error_description", ""))
        except ValueError:
            pass

        if error == "invalid_grant":
            return (
                "Checkmarx rejected the API key (invalid_grant). The key has been "
                "revoked, has expired, or belongs to a different tenant. Generate a "
                "new API key in Identity and Access Management and paste it again."
            )
        if error == "invalid_client":
            return (
                "Checkmarx rejected the OAuth client id (invalid_client). Confirm "
                "CXCG_CX_CLIENT_ID matches the client your tenant issues API keys for."
            )
        if response.status_code == httpx.codes.NOT_FOUND:
            return (
                "Token endpoint returned 404. The tenant name derived from the API key "
                "does not resolve to a realm on this IAM host."
            )
        suffix = f": {error} {description}".rstrip() if error or description else ""
        return f"Token exchange failed with HTTP {response.status_code}{suffix}"
