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
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
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

# Called with (method, url, key fingerprint) whenever Checkmarx answers 403,
# before the error is raised. The API key permission checker registers here so a
# permission that is only exercised at run time (a write it cannot probe) is
# still noticed, whoever made the call and whether or not the caller swallows
# the error. The fingerprint names the API key the call was made with (None for
# a client built without one), so a refusal of a replaced key is not pinned on
# its successor. A listener must be cheap and must never raise; it touches no
# database.
_forbidden_listeners: list[Callable[[str, str, str | None], None]] = []
# Called the same way for every successful call, so a refused change that later
# goes through (or a read refused on one project that later succeeds on that same
# project) can be cleared. Same rules: cheap, no raising, no database; a
# listener returns at once for a call it has no interest in.
_success_listeners: list[Callable[[str, str, str | None], None]] = []


_quiet = threading.local()


@contextmanager
def listeners_paused() -> Iterator[None]:
    """Calls made inside (on this thread) are not reported to the listeners.

    For calls that are themselves a test of the key (the permission probes, the
    connection test): what they meet is their result, not a run-time event.
    """
    previous = getattr(_quiet, "paused", False)
    _quiet.paused = True
    try:
        yield
    finally:
        _quiet.paused = previous


@contextmanager
def single_attempt(timeout_seconds: float | None = None) -> Iterator[None]:
    """Calls made inside (on this thread) are tried once, with a short timeout.

    For optional reads made while someone waits on a page (the Simulation's
    role reads): a transient failure (a transport error, 429, 5xx) is raised at
    once instead of being retried with backoff, and ``timeout_seconds`` replaces
    the configured request timeout. A 401 still re-exchanges the token once.
    Everything outside this block (enforcement included) keeps the full retry
    policy.
    """
    previous = getattr(_quiet, "single_attempt", None)
    _quiet.single_attempt = (timeout_seconds,)
    try:
        yield
    finally:
        _quiet.single_attempt = previous


def add_forbidden_listener(listener: Callable[[str, str, str | None], None]) -> None:
    if listener not in _forbidden_listeners:
        _forbidden_listeners.append(listener)


def add_success_listener(listener: Callable[[str, str, str | None], None]) -> None:
    if listener not in _success_listeners:
        _success_listeners.append(listener)


def _notify(
    listeners: list[Callable[[str, str, str | None], None]],
    method: str,
    url: str,
    fingerprint: str | None,
) -> None:
    if getattr(_quiet, "paused", False):
        return
    for listener in list(listeners):
        try:
            listener(method, url, fingerprint)
        except Exception:  # noqa: BLE001 - a listener must never change the call's outcome
            logger.debug("A call listener failed", exc_info=True)


def _full_url(response: httpx.Response, fallback: str) -> str:
    """The URL a response answered, query included (a read that names its
    project in the query, such as the project configuration, needs it)."""
    try:
        return str(response.request.url)
    except RuntimeError:  # a response built without a request
        return fallback


class CallStats:
    """Calls made through one client, for the cycle's record. Thread safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests = 0
        self.rate_limited = 0
        self.retries = 0
        self.waited_seconds = 0.0

    def add(
        self, *, requests: int = 0, rate_limited: int = 0, retries: int = 0, waited: float = 0.0
    ) -> None:
        with self._lock:
            self.requests += requests
            self.rate_limited += rate_limited
            self.retries += retries
            self.waited_seconds += waited

    def snapshot(self) -> dict[str, float]:
        with self._lock:
            return {
                "requests": self.requests,
                "rate_limited": self.rate_limited,
                "retries": self.retries,
                "waited_seconds": round(self.waited_seconds, 1),
            }


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
        key_fingerprint: str | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        # Which API key this client calls with; only passed to the listeners.
        self.key_fingerprint = key_fingerprint
        self.api_base_url = api_base_url.rstrip("/")
        self.iam_base_url = iam_base_url.rstrip("/")
        self.tenant_name = tenant_name
        self._tokens = token_manager
        self._client = client
        self._owns_client = client is None
        self._sleep = sleep
        # Every attempt sent, every 429 met, every retry and the time spent
        # waiting before one: what a cycle spent on the tenant.
        self.stats = CallStats()

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
        single = getattr(_quiet, "single_attempt", None)
        # Inside ``single_attempt``: no retry of a transient failure (the second
        # pass is only for a 401's token re-exchange), and its own timeout.
        retry_transient = single is None
        if single is not None:
            attempts = 2
        timeout = {"timeout": single[0]} if single is not None and single[0] else {}
        reauthenticated = False
        last_error: Exception | None = None

        for attempt in range(attempts):
            request_headers = {
                "Authorization": f"Bearer {self._tokens.get_access_token()}",
                "Accept": "application/json",
                **(headers or {}),
            }
            started = time.monotonic()
            self.stats.add(requests=1, retries=1 if attempt else 0)
            try:
                response = self._http().request(
                    method.upper(),
                    url,
                    params=params,
                    json=json,
                    data=data,
                    headers=request_headers,
                    **timeout,
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
                if retry_transient and attempt + 1 < attempts:
                    delay = self._backoff_seconds(attempt)
                    self.stats.add(waited=delay)
                    self._sleep(delay)
                    continue
                raise CheckmarxUnavailableError(
                    f"{method.upper()} {url} failed after {attempt + 1} attempt"
                    f"{'s' if attempt else ''}: {type(exc).__name__}"
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
                if _success_listeners:
                    _notify(
                        _success_listeners,
                        method.upper(),
                        _full_url(response, url),
                        self.key_fingerprint,
                    )
                return response

            status = response.status_code

            if status == httpx.codes.UNAUTHORIZED and not reauthenticated:
                # Token revoked or expired sooner than advertised. Re-exchange once.
                logger.info("Checkmarx returned 401 for %s, re-exchanging the token", redact(url))
                reauthenticated = True
                self._tokens.invalidate()
                continue

            if status == httpx.codes.FORBIDDEN:
                _notify(
                    _forbidden_listeners,
                    method.upper(),
                    _full_url(response, url),
                    self.key_fingerprint,
                )
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
                    self.stats.add(rate_limited=1)
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
                if retry_transient and attempt + 1 < attempts:
                    delay = (
                        retry_after if retry_after is not None else self._backoff_seconds(attempt)
                    )
                    # Never sleep longer than the cap, whatever status carried the
                    # header. A 503 with "Retry-After: 3600" must not park the cycle
                    # (and its scheduler lock) for an hour.
                    delay = min(delay, MAX_HONOURED_RETRY_AFTER_SECONDS)
                    self.stats.add(waited=delay)
                    self._sleep(delay)
                    continue
                if status == httpx.codes.TOO_MANY_REQUESTS:
                    raise CheckmarxRateLimitError(
                        f"Still rate limited on {method.upper()} {url} after {attempt + 1} "
                        f"attempt{'s' if attempt else ''}.",
                        retry_after_seconds=retry_after,
                    )
                raise CheckmarxUnavailableError(
                    f"{method.upper()} {url} returned {status} on all {attempt + 1} attempt"
                    f"{'s' if attempt else ''}."
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
        listing: Listing | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield items across an offset/limit paginated collection.

        Handles both shapes Checkmarx uses: a bare JSON array, and an envelope
        object with a total count plus a named list. ``items_key`` pins the list
        name; when omitted the first list valued field is used.

        ``offset_is_page_number`` covers the IAM style endpoints that page by
        index rather than by record offset.

        A page shorter than asked for is not taken as the last one while the
        reported total (``filteredTotalCount``, else ``totalCount``) says more
        rows exist: a server that caps its pages below ``limit`` is read to the
        end. Without a total, a short page is followed by one more request,
        and only an empty answer ends the listing. ``listing`` (when given) is
        told whether the read was complete: a caller must not treat rows it
        did not get as gone (soft-delete them) after an incomplete one.
        """
        listing = listing if listing is not None else Listing()
        offset = 0
        page = 0
        seen = 0
        total: int | None = None
        previous_first: Any = None
        while page < MAX_PAGES:
            page_params = dict(params or {})
            page_params[limit_param] = page_size
            page_params[offset_param] = page if offset_is_page_number else offset

            payload = self.get_json(path, base=base, params=page_params)
            items = _extract_items(payload, items_key)
            reported = _extract_total(payload)
            if reported is not None:
                total = reported
            listing.total = total
            if not items:
                distinct = len(listing.ids) if listing.ids else seen
                if total is not None and distinct < total:
                    listing.incomplete(f"{distinct} of {total} rows could be read", "shortfall")
                return
            first = items[0].get("id", items[0]) if isinstance(items[0], dict) else items[0]
            if page and first == previous_first:
                # The same page again: the server ignores the offset.
                listing.incomplete(f"the listing repeated itself after {seen} rows", "repeated")
                return
            previous_first = first

            yield from items
            for item in items:
                if isinstance(item, dict) and item.get("id") is not None:
                    listing.ids.add(str(item["id"]))
            seen += len(items)
            # Rows told apart by id: a listing whose order shifts while it is
            # read can repeat one row and skip another, and must not then look
            # complete by its count alone.
            distinct = len(listing.ids) if listing.ids else seen
            listing.read = distinct
            page += 1
            offset += len(items)

            if total is not None:
                if distinct >= total:
                    return
                if offset_is_page_number and len(items) < page_size:
                    # A short page by index cannot be continued without
                    # skipping rows.
                    listing.incomplete(f"{distinct} of {total} rows could be read", "shortfall")
                    return
                continue
            if len(items) < page_size and offset_is_page_number:
                return

        listing.incomplete(
            f"stopped at the {MAX_PAGES} page safety limit after {seen} rows", "page_limit"
        )
        logger.warning(
            "Pagination of %s stopped at the %d page safety limit", redact(path), MAX_PAGES
        )


@dataclass
class Listing:
    """Whether a paginated read got every row the collection has."""

    complete: bool = True
    total: int | None = None
    read: int = 0
    note: str | None = None
    # "shortfall" (fewer distinct rows than the reported total), "repeated"
    # (the server ignored the offset) or "page_limit".
    reason: str | None = None
    ids: set[str] = field(default_factory=set)

    def incomplete(self, note: str, reason: str) -> None:
        self.complete = False
        self.note = note
        self.reason = reason


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
    # The filtered count is what the listing's rows add up to when both exist.
    for key in ("filteredTotalCount", "totalCount", "total", "totalItems"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
    return None
