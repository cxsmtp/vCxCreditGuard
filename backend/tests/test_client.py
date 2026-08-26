"""Retry, rate limiting, re-authentication and pagination in the Checkmarx client."""

from __future__ import annotations

import httpx
import pytest

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import (
    CheckmarxNotFoundError,
    CheckmarxPermissionError,
    CheckmarxRateLimitError,
    CheckmarxResponseError,
    CheckmarxUnavailableError,
)
from app.checkmarx.token import TokenManager
from app.core.config import get_settings
from tests.conftest import make_api_key, token_response

API_BASE = "https://eu.ast.checkmarx.net/api"
IAM_BASE = "https://eu.iam.checkmarx.net"
TENANT = "acme-corp"


class Recorder:
    """Collects the sleeps the client would have taken, so tests stay instant."""

    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.sleeps.append(seconds)


def build_client(handler, *, sleeper: Recorder | None = None) -> tuple[CheckmarxClient, Recorder]:
    """Client whose transport serves both the token endpoint and the API."""
    recorder = sleeper or Recorder()

    def routed(request: httpx.Request) -> httpx.Response:
        if "openid-connect/token" in str(request.url):
            return token_response()
        return handler(request)

    transport = httpx.MockTransport(routed)
    http = httpx.Client(transport=transport)
    api_key = make_api_key()
    tokens = TokenManager(
        api_key=api_key,
        token_endpoint=f"{IAM_BASE}/auth/realms/{TENANT}/protocol/openid-connect/token",
        client=http,
        settings=get_settings(),
    )
    client = CheckmarxClient(
        api_base_url=API_BASE,
        iam_base_url=IAM_BASE,
        tenant_name=TENANT,
        token_manager=tokens,
        client=http,
        settings=get_settings(),
        sleep=recorder,
    )
    return client, recorder


class TestUrlBuilding:
    def test_api_paths_resolve_against_the_platform_base(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(200, json={}))
        assert client.api_url("/projects") == f"{API_BASE}/projects"
        assert client.api_url("projects") == f"{API_BASE}/projects"

    def test_iam_paths_resolve_under_the_admin_realm(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(200, json={}))
        assert client.iam_admin_url("users") == f"{IAM_BASE}/auth/admin/realms/{TENANT}/users"

    def test_tenant_names_are_url_encoded(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(200, json={}))
        client.tenant_name = "tenant with space"
        assert "tenant%20with%20space" in client.iam_admin_url("users")

    def test_absolute_urls_pass_through(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, json={})

        client, _ = build_client(handler)
        client.request("GET", "https://other.example/thing")
        assert seen == ["https://other.example/thing"]


class TestAuthInjection:
    def test_bearer_token_is_attached(self) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("Authorization", "")
            return httpx.Response(200, json={})

        client, _ = build_client(handler)
        client.get_json("/projects")
        assert seen["auth"] == "Bearer test-access-token"

    def test_401_triggers_exactly_one_reauthentication(self) -> None:
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(401, json={"message": "expired"})
            return httpx.Response(200, json={"ok": True})

        client, _ = build_client(handler)
        assert client.get_json("/projects") == {"ok": True}
        assert attempts == 2

    def test_persistent_401_does_not_loop_forever(self) -> None:
        """A revoked key must surface as an error, not spin through the retry budget."""
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(401, json={"message": "nope"})

        client, _ = build_client(handler)
        with pytest.raises(CheckmarxResponseError) as exc_info:
            client.get_json("/projects")
        assert exc_info.value.status_code == 401
        # One initial attempt plus exactly one re-authenticated attempt.
        assert attempts == 2


class TestRetries:
    def test_transient_500_is_retried_then_succeeds(self) -> None:
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                return httpx.Response(503, text="unavailable")
            return httpx.Response(200, json={"ok": True})

        client, recorder = build_client(handler)
        assert client.get_json("/projects") == {"ok": True}
        assert attempts == 3
        assert len(recorder.sleeps) == 2

    def test_backoff_grows_and_is_jittered(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        client, recorder = build_client(handler)
        with pytest.raises(CheckmarxUnavailableError, match="on all 5 attempts"):
            client.get_json("/projects")
        settings = get_settings()
        assert len(recorder.sleeps) == settings.cx_max_retries
        # Full jitter: each wait is bounded by base * 2**attempt, never negative.
        for attempt, waited in enumerate(recorder.sleeps):
            ceiling = min(
                settings.cx_backoff_max_seconds, settings.cx_backoff_base_seconds * (2**attempt)
            )
            assert 0 <= waited <= ceiling

    def test_network_errors_are_retried(self) -> None:
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts < 2:
                raise httpx.ReadTimeout("timed out")
            return httpx.Response(200, json={"ok": True})

        client, _ = build_client(handler)
        assert client.get_json("/projects") == {"ok": True}

    def test_persistent_network_error_raises_unavailable(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        client, _ = build_client(handler)
        with pytest.raises(CheckmarxUnavailableError, match="failed after 5 attempts"):
            client.get_json("/projects")


class TestRateLimiting:
    def test_retry_after_seconds_is_honoured(self) -> None:
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": "7"}, text="slow down")
            return httpx.Response(200, json={"ok": True})

        client, recorder = build_client(handler)
        assert client.get_json("/projects") == {"ok": True}
        assert recorder.sleeps == [7.0]

    def test_retry_after_http_date_is_honoured(self) -> None:
        from datetime import UTC, datetime, timedelta
        from email.utils import format_datetime

        when = format_datetime(datetime.now(UTC) + timedelta(seconds=12))
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(429, headers={"Retry-After": when})
            return httpx.Response(200, json={"ok": True})

        client, recorder = build_client(handler)
        client.get_json("/projects")
        assert 8 <= recorder.sleeps[0] <= 13

    def test_absurd_retry_after_defers_to_the_next_cycle(self) -> None:
        """Blocking a scheduler cycle for minutes is worse than trying again later."""
        client, recorder = build_client(
            lambda _r: httpx.Response(429, headers={"Retry-After": "600"})
        )
        with pytest.raises(CheckmarxRateLimitError) as exc_info:
            client.get_json("/projects")
        assert exc_info.value.retry_after_seconds == 600
        assert recorder.sleeps == []

    def test_429_without_retry_after_uses_backoff(self) -> None:
        client, recorder = build_client(lambda _r: httpx.Response(429))
        with pytest.raises(CheckmarxRateLimitError, match="Still rate limited"):
            client.get_json("/projects")
        assert len(recorder.sleeps) == get_settings().cx_max_retries


class TestErrorMapping:
    def test_403_names_the_missing_permission_problem(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(403, json={"message": "denied"}))
        with pytest.raises(CheckmarxPermissionError, match="missing a required permission"):
            client.get_json("/projects")

    def test_403_is_not_retried(self) -> None:
        attempts = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(403)

        client, _ = build_client(handler)
        with pytest.raises(CheckmarxPermissionError):
            client.get_json("/projects")
        assert attempts == 1

    def test_404_raises_by_default(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(404))
        with pytest.raises(CheckmarxNotFoundError):
            client.get_json("/projects/missing")

    def test_404_can_be_allowed(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(404))
        response = client.request("GET", "/projects/missing", allow_404=True)
        assert response.status_code == 404

    def test_unmodelled_4xx_includes_the_status(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(422, text="unprocessable"))
        with pytest.raises(CheckmarxResponseError) as exc_info:
            client.get_json("/projects")
        assert exc_info.value.status_code == 422

    def test_non_json_success_body_is_reported(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(200, text="<html>hi</html>"))
        with pytest.raises(CheckmarxResponseError, match="not JSON"):
            client.get_json("/projects")

    def test_empty_body_returns_none(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(204))
        assert client.get_json("/projects") is None

    def test_error_bodies_are_redacted_in_the_message(self) -> None:
        leaked = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig"
        client, _ = build_client(lambda _r: httpx.Response(422, text=f"token {leaked} rejected"))
        with pytest.raises(CheckmarxResponseError) as exc_info:
            client.get_json("/projects")
        assert leaked not in str(exc_info.value)


class TestPagination:
    def test_walks_an_envelope_collection(self) -> None:
        pages = {
            0: {"totalCount": 5, "projects": [{"id": "1"}, {"id": "2"}]},
            2: {"totalCount": 5, "projects": [{"id": "3"}, {"id": "4"}]},
            4: {"totalCount": 5, "projects": [{"id": "5"}]},
        }

        def handler(request: httpx.Request) -> httpx.Response:
            offset = int(request.url.params.get("offset", 0))
            return httpx.Response(200, json=pages[offset])

        client, _ = build_client(handler)
        items = list(client.paginate("/projects", items_key="projects", page_size=2))
        assert [item["id"] for item in items] == ["1", "2", "3", "4", "5"]

    def test_stops_when_the_total_is_reached(self) -> None:
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(
                200, json={"totalCount": 2, "projects": [{"id": "1"}, {"id": "2"}]}
            )

        client, _ = build_client(handler)
        items = list(client.paginate("/projects", items_key="projects", page_size=2))
        assert len(items) == 2
        assert calls == 1

    def test_walks_a_bare_array_collection(self) -> None:
        pages = {0: [{"id": "1"}, {"id": "2"}], 2: [{"id": "3"}], 3: []}

        def handler(request: httpx.Request) -> httpx.Response:
            offset = int(request.url.params.get("offset", 0))
            return httpx.Response(200, json=pages.get(offset, []))

        client, _ = build_client(handler)
        assert len(list(client.paginate("/applications", page_size=2))) == 3

    def test_infers_the_collection_key(self) -> None:
        client, _ = build_client(
            lambda _r: httpx.Response(200, json={"totalCount": 1, "applications": [{"id": "a"}]})
        )
        assert list(client.paginate("/applications", page_size=10)) == [{"id": "a"}]

    def test_empty_first_page_yields_nothing(self) -> None:
        client, _ = build_client(lambda _r: httpx.Response(200, json={"projects": []}))
        assert list(client.paginate("/projects", items_key="projects")) == []

    def test_iam_style_page_numbering(self) -> None:
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            first = request.url.params.get("first", "0")
            seen.append(first)
            return httpx.Response(200, json=[{"id": first}] if first in {"0", "1"} else [])

        client, _ = build_client(handler)
        list(
            client.paginate(
                "users",
                base="iam",
                page_size=1,
                offset_param="first",
                limit_param="max",
                offset_is_page_number=True,
            )
        )
        assert seen[:3] == ["0", "1", "2"]
