"""Token exchange, caching and proactive refresh."""

from __future__ import annotations

import base64
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.checkmarx.apikey import parse_api_key
from app.checkmarx.errors import CheckmarxAuthError, CheckmarxUnavailableError
from app.checkmarx.token import TokenManager
from app.core.config import get_settings
from app.core.logging import configure_logging
from tests.conftest import make_api_key, token_response

TOKEN_ENDPOINT = "https://eu.iam.checkmarx.net/auth/realms/acme-corp/protocol/openid-connect/token"


def build_manager(handler, api_key: str | None = None) -> TokenManager:
    key = api_key or make_api_key()
    return TokenManager(
        api_key=key,
        token_endpoint=parse_api_key(key).token_endpoint,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        settings=get_settings(),
    )


class TestExchange:
    def test_posts_the_refresh_token_grant(self) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["content_type"] = request.headers["Content-Type"]
            seen["body"] = request.content.decode()
            return token_response(access_token="abc.def.ghi")

        api_key = make_api_key()
        manager = build_manager(handler, api_key)
        assert manager.get_access_token() == "abc.def.ghi"
        assert seen["url"] == TOKEN_ENDPOINT
        assert seen["content_type"] == "application/x-www-form-urlencoded"
        assert "grant_type=refresh_token" in seen["body"]
        assert "client_id=ast-app" in seen["body"]
        assert "refresh_token=" in seen["body"]

    def test_token_is_cached_between_calls(self) -> None:
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return token_response()

        manager = build_manager(handler)
        manager.get_access_token()
        manager.get_access_token()
        manager.get_access_token()
        assert calls == 1

    def test_refresh_happens_before_expiry(self) -> None:
        """A token with less than the refresh margin left is replaced eagerly."""
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            # 4 minutes of validity, inside the default 5 minute margin.
            return token_response(access_token=f"token-{calls}", expires_in=240)

        manager = build_manager(handler)
        assert manager.get_access_token() == "token-1"
        assert manager.get_access_token() == "token-2"
        assert calls == 2

    def test_a_fresh_token_is_not_refreshed(self) -> None:
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return token_response(access_token=f"token-{calls}", expires_in=1800)

        manager = build_manager(handler)
        assert manager.get_access_token() == "token-1"
        assert manager.get_access_token() == "token-1"
        assert calls == 1

    def test_invalidate_forces_a_new_exchange(self) -> None:
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return token_response(access_token=f"token-{calls}")

        manager = build_manager(handler)
        assert manager.get_access_token() == "token-1"
        manager.invalidate()
        assert manager.get_access_token() == "token-2"

    def test_missing_expires_in_uses_a_conservative_default(self) -> None:
        manager = build_manager(lambda _r: token_response(expires_in=None))
        manager.get_access_token()
        remaining = manager.cached_token_seconds_remaining
        assert remaining is not None
        assert 1700 < remaining <= 1800

    def test_expiry_is_tracked(self) -> None:
        manager = build_manager(lambda _r: token_response(expires_in=600))
        manager.get_access_token()
        remaining = manager.cached_token_seconds_remaining
        assert remaining is not None
        assert 590 < remaining <= 600


class TestExchangeFailures:
    def test_invalid_grant_gets_an_actionable_message(self) -> None:
        manager = build_manager(
            lambda _r: httpx.Response(
                400, json={"error": "invalid_grant", "error_description": "Token is not active"}
            )
        )
        with pytest.raises(CheckmarxAuthError, match="revoked, has expired"):
            manager.get_access_token()

    def test_invalid_client_mentions_the_client_id_setting(self) -> None:
        manager = build_manager(lambda _r: httpx.Response(401, json={"error": "invalid_client"}))
        with pytest.raises(CheckmarxAuthError, match="CXCG_CX_CLIENT_ID"):
            manager.get_access_token()

    def test_404_points_at_the_tenant_name(self) -> None:
        manager = build_manager(lambda _r: httpx.Response(404, text="not found"))
        with pytest.raises(CheckmarxAuthError, match="does not resolve to a realm"):
            manager.get_access_token()

    def test_html_error_page_is_reported_clearly(self) -> None:
        manager = build_manager(lambda _r: httpx.Response(200, text="<html>proxy error</html>"))
        with pytest.raises(CheckmarxAuthError, match="non JSON response"):
            manager.get_access_token()

    def test_response_without_access_token_is_rejected(self) -> None:
        manager = build_manager(lambda _r: httpx.Response(200, json={"token_type": "Bearer"}))
        with pytest.raises(CheckmarxAuthError, match="no access_token"):
            manager.get_access_token()

    def test_network_failure_is_retryable_not_an_auth_error(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        with pytest.raises(CheckmarxUnavailableError, match="Could not reach Checkmarx IAM"):
            build_manager(handler).get_access_token()

    def test_unmodelled_status_still_reports_the_code(self) -> None:
        manager = build_manager(lambda _r: httpx.Response(502, text="bad gateway"))
        with pytest.raises(CheckmarxAuthError, match="HTTP 502"):
            manager.get_access_token()


class TestSecrecy:
    def test_neither_key_nor_token_reaches_a_log_sink(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Asserted against a configured handler, which is where redaction applies."""
        configure_logging("DEBUG")
        api_key = make_api_key()
        # Build a JWT-shaped fixture at runtime so no token-like literal is
        # committed to source (a hardcoded value trips secret scanners even
        # though this is a throwaway test string).
        access_token = ".".join(
            (
                base64.urlsafe_b64encode(b'{"access":"token"}').decode().rstrip("="),
                base64.urlsafe_b64encode(b"payload").decode().rstrip("="),
                "sig",
            )
        )
        manager = build_manager(lambda _r: token_response(access_token=access_token), api_key)
        manager.get_access_token()
        # Simulate a careless log line added later in the codebase.
        logging.getLogger("app.checkmarx.token").info(
            "diagnostic dump: key=%s token=%s", api_key, access_token
        )
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert api_key not in combined
        assert access_token not in combined
        assert "REDACTED" in combined


def test_expires_within_boundary() -> None:
    from app.checkmarx.token import AccessToken

    token = AccessToken(value="x", expires_at=datetime.now(UTC) + timedelta(seconds=100))
    assert token.expires_within(200) is True
    assert token.expires_within(50) is False
