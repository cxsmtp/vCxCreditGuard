"""Single typed HTTP client for every Checkmarx One call.

Responsibilities kept in one place so no caller has to remember them:

* base URL selection (platform API vs IAM admin API)
* bearer token injection and re-exchange on 401
* retry with exponential backoff and full jitter
* 429 handling that respects Retry-After
* request and response logging with secrets redacted
* offset/limit pagination

Every higher level service (org sync, usage ingestion, enforcement) goes through
this class, which is why it takes an injectable ``httpx.Client`` and ``sleep``:
the unit tests drive it with ``httpx.MockTransport`` and a no-op sleep.
"""

from __future__ import annotations

import email.utils
import logging
import random
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

import httpx

from app.checkmarx.errors import (
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxRateLimitError,
    CheckmarxResponseError,
    CheckmarxUnavailableError,
)
from app.checkmarx.token import TokenManager
from app.core.config import Settings, get_settings
from app.core.logging import redact

logger = logging.getLogger(__name__)

# Three distinct URL spaces:
#   "api"   the platform API, e.g. https://eu.ast.checkmarx.net/api/projects
#   "realm" Checkmarx's own IAM endpoints, /auth/realms/<tenant>/users/v2
#   "iam"   the Keycloak admin API, /auth/admin/realms/<tenant>/users
Base = Literal["api", "realm", "iam"]

# Waiting longer than this inside a single request would stall a scheduler cycle,
# so we surface the rate limit to the caller instead and let the next cycle retry.
MAX_HONOURED_RETRY_AFTER_SECONDS = 60.0
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 507, 509})
DEFAULT_PAGE_SIZE = 100
# Guard against a server that never stops returning pages.
MAX_PAGES = 1000


class CheckmarxClient:
    def __init__(
        self,
        *,
        api_base_url: str,
        iam_base_url: str,
        tenant_name: str,
        token_manager: TokenManager,
        client: httpx.Client | None = None,
        settings: Settings | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._settings = settings or get_settings()
        self.api_base_url = api_base_url.rstrip("/")
        self.iam_base_url = iam_base_url.rstrip("/")
        self.tenant_name = tenant_name
        self._tokens = token_manager
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep

    @property
    def tokens(self) -> TokenManager:
        return self._tokens

    # ------------------------------------------------------------------ URLs

    def api_url(self, path: str) -> str:
        return f"{self.api_base_url}/{path.lstrip('/')}"

    def iam_admin_url(self, path: str) -> str:
        """URL under /auth/admin/realms/<tenant>/ on the IAM host."""
        realm = quote(self.tenant_name, safe="")
        return f"{self.iam_base_url}/auth/admin/realms/{realm}/{path.lstrip('/')}"

    def realm_url(self, path: str) -> str:
        """URL under /auth/realms/<tenant>/ on the IAM host."""
        realm = quote(self.tenant_name, safe="")
        return f"{self.iam_base_url}/auth/realms/{realm}/{path.lstrip('/')}"

    def _resolve(self, path: str, base: Base) -> str:
        if path.startswith(("http://", "https://")):
            return path
        if base == "api":
            return self.api_url(path)
        if base == "realm":
            return self.realm_url(path)
        return self.iam_admin_url(path)

    # --------------------------------------------------------------- plumbing

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._settings.cx_request_timeout_seconds)
        return self._client

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    def _backoff_seconds(self, attempt: int) -> float:
        """Full jitter: uniform(0, base * 2**attempt), capped."""
        ceiling = min(
            self._settings.cx_backoff_max_seconds,
            self._settings.cx_backoff_base_seconds * (2**attempt),
        )
        return random.uniform(0, ceiling)  # noqa: S311 - jitter, not a security decision

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> float | None:
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return max(0.0, float(raw.strip()))
        except ValueError:
            pass
        try:
            parsed = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return max(0.0, (parsed - datetime.now(UTC)).total_seconds())

    # ---------------------------------------------------------------- request

    def request(
        self,
        method: str,
        path: str,
        *,
        base: Base = "api",
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        allow_404: bool = False,
    ) -> httpx.Response:
        """Perform one authenticated call, retrying transient failures.

        Raises a typed CheckmarxError subclass on failure. Returns the response
        for any 2xx, and for 404 when ``allow_404`` is set.
        """
        url = self._resolve(path, base)
        attempts = self._settings.cx_max_retries + 1
        reauthenticated = False
        last_error: Exception | None = None

        for attempt in range(attempts):
            request_headers = {
                "Authorization": f"Bearer {self._tokens.get_access_token()}",
                "Accept": "application/json",
                **(headers or {}),
            }
            started = time.monotonic()
            try:
                response = self._http().request(
                    method.upper(),
                    url,
                    params=params,
                    json=json,
                    data=data,
                    headers=request_headers,
                )
            except httpx.HTTPError as exc:
                last_error = exc
                logger.warning(
                    "%s %s failed at the transport layer (%s), attempt %d of %d",
                    method.upper(),
                    redact(url),
                    type(exc).__name__,
                    attempt + 1,
                    attempts,
                )
                if attempt + 1 < attempts:
                    self._sleep(self._backoff_seconds(attempt))
                    continue
                raise CheckmarxUnavailableError(
                    f"{method.upper()} {url} failed after {attempts} attempts: {type(exc).__name__}"
                ) from exc

            elapsed_ms = (time.monotonic() - started) * 1000
            logger.debug(
                "%s %s -> %d in %.0f ms",
                method.upper(),
                redact(url),
                response.status_code,
                elapsed_ms,
            )

            if response.is_success:
                return response

            status = response.status_code

            if status == httpx.codes.UNAUTHORIZED and not reauthenticated:
                # Token revoked or expired sooner than advertised. Re-exchange once.
                logger.info("Checkmarx returned 401 for %s, re-exchanging the token", redact(url))
                reauthenticated = True
                self._tokens.invalidate()
                continue

            if status == httpx.codes.FORBIDDEN:
                raise CheckmarxPermissionError(
                    f"Checkmarx denied {method.upper()} {url} with 403. The API key's "
                    "service account is missing a required permission.",
                    method=method.upper(),
                    url=url,
                )

            if status == httpx.codes.NOT_FOUND:
                if allow_404:
                    return response
                raise CheckmarxNotFoundError(f"{method.upper()} {url} returned 404.")

            if status in _RETRYABLE_STATUS:
                retry_after = self._retry_after_seconds(response)
                if status == httpx.codes.TOO_MANY_REQUESTS:
                    if retry_after is not None and retry_after > MAX_HONOURED_RETRY_AFTER_SECONDS:
                        raise CheckmarxRateLimitError(
                            f"Checkmarx asked us to wait {retry_after:.0f}s on "
                            f"{method.upper()} {url}. Deferring to the next cycle.",
                            retry_after_seconds=retry_after,
                        )
                    logger.warning(
                        "Rate limited on %s, waiting %s",
                        redact(url),
                        f"{retry_after:.1f}s" if retry_after is not None else "with backoff",
                    )
                if attempt + 1 < attempts:
                    delay = (
                        retry_after if retry_after is not None else self._backoff_seconds(attempt)
                    )
                    self._sleep(delay)
                    continue
                if status == httpx.codes.TOO_MANY_REQUESTS:
                    raise CheckmarxRateLimitError(
                        f"Still rate limited on {method.upper()} {url} after {attempts} attempts.",
                        retry_after_seconds=retry_after,
                    )
                raise CheckmarxUnavailableError(
                    f"{method.upper()} {url} returned {status} on all {attempts} attempts."
                )

            raise CheckmarxResponseError(
                f"{method.upper()} {url} returned {status}: {redact(response.text[:500])}",
                status_code=status,
            )

        # Only reachable if the retry loop exhausted itself on repeated 401s.
        raise CheckmarxUnavailableError(
            f"{method.upper()} {url} could not be completed: {last_error or 'authentication loop'}"
        )

    # -------------------------------------------------------------- shortcuts

    def get_json(self, path: str, *, base: Base = "api", **kwargs: Any) -> Any:
        response = self.request("GET", path, base=base, **kwargs)
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise CheckmarxResponseError(
                f"GET {self._resolve(path, base)} returned a body that is not JSON.",
                status_code=response.status_code,
            ) from exc

    def paginate(
        self,
        path: str,
        *,
        base: Base = "api",
        params: dict[str, Any] | None = None,
        items_key: str | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
        offset_param: str = "offset",
        limit_param: str = "limit",
        offset_is_page_number: bool = False,
    ) -> Iterator[dict[str, Any]]:
        """Yield items across an offset/limit paginated collection.

        Handles both shapes Checkmarx uses: a bare JSON array, and an envelope
        object with a total count plus a named list. ``items_key`` pins the list
        name; when omitted the first list valued field is used.

        ``offset_is_page_number`` covers the IAM style endpoints that page by
        index rather than by record offset.
        """
        offset = 0
        page = 0
        seen = 0
        while page < MAX_PAGES:
            page_params = dict(params or {})
            page_params[limit_param] = page_size
            page_params[offset_param] = page if offset_is_page_number else offset

            payload = self.get_json(path, base=base, params=page_params)
            items = _extract_items(payload, items_key)
            if not items:
                return

            yield from items
            seen += len(items)
            page += 1
            offset += len(items)

            if len(items) < page_size:
                return

            total = _extract_total(payload)
            if total is not None and seen >= total:
                return

        logger.warning(
            "Pagination of %s stopped at the %d page safety limit", redact(path), MAX_PAGES
        )


def _extract_items(payload: Any, items_key: str | None) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    if items_key is not None:
        value = payload.get(items_key)
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []
    for value in payload.values():
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _extract_total(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    for key in ("totalCount", "filteredTotalCount", "total", "totalItems"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    return None
