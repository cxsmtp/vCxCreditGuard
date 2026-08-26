"""Serving the built single page application alongside the API."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main
from app.core.config import get_settings


@pytest.fixture
def built_frontend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stand-in for the Vite build output."""
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text(
        "<!doctype html><title>CxCreditGuard</title>", encoding="utf-8"
    )
    (static / "assets" / "index-abc123.js").write_text("console.log('app');", encoding="utf-8")
    (static / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    monkeypatch.setattr(main, "STATIC_DIR", static)
    return static


@pytest.fixture
def spa_client(built_frontend: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(main, "upgrade_to_head", lambda *_args, **_kwargs: None)
    app = main.create_app(get_settings(), run_scheduler=False)
    return TestClient(app)


def test_root_serves_the_app_shell(spa_client: TestClient) -> None:
    response = spa_client.get("/")
    assert response.status_code == httpx.codes.OK
    assert "CxCreditGuard" in response.text


def test_client_side_routes_fall_back_to_the_shell(spa_client: TestClient) -> None:
    """A deep link such as /limits has no file behind it and must still load."""
    for path in ("/limits", "/settings", "/notifications", "/audit", "/setup"):
        response = spa_client.get(path)
        assert response.status_code == httpx.codes.OK, path
        assert "CxCreditGuard" in response.text


def test_index_is_not_cached(spa_client: TestClient) -> None:
    """A cached index.html would keep pointing at the previous bundle after a deploy."""
    assert spa_client.get("/").headers["Cache-Control"] == "no-store"


def test_real_files_are_served(spa_client: TestClient) -> None:
    assert spa_client.get("/favicon.svg").status_code == httpx.codes.OK
    assert spa_client.get("/assets/index-abc123.js").status_code == httpx.codes.OK


def test_unknown_api_paths_still_return_json_not_html(spa_client: TestClient) -> None:
    response = spa_client.get("/api/does-not-exist")
    assert response.status_code == httpx.codes.NOT_FOUND
    assert response.headers["content-type"].startswith("application/json")


def test_api_routes_are_not_shadowed_by_the_fallback(spa_client: TestClient) -> None:
    # Unauthenticated, so 401 rather than the HTML shell.
    assert spa_client.get("/api/me").status_code == httpx.codes.UNAUTHORIZED


def test_healthz_is_not_shadowed(spa_client: TestClient) -> None:
    response = spa_client.get("/healthz")
    assert response.status_code == httpx.codes.OK
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize(
    "path",
    [
        "/../../../../etc/passwd",
        "/..%2f..%2fetc%2fpasswd",
        "/assets/../../index.html",
    ],
)
def test_path_traversal_cannot_escape_the_static_root(spa_client: TestClient, path: str) -> None:
    """A crafted path must never read a file outside the build output."""
    response = spa_client.get(path)
    # Either the shell, or a refusal. Never the contents of another file.
    assert response.status_code in {
        httpx.codes.OK,
        httpx.codes.NOT_FOUND,
        httpx.codes.BAD_REQUEST,
        httpx.codes.MOVED_PERMANENTLY,
        httpx.codes.PERMANENT_REDIRECT,
    }
    if response.status_code == httpx.codes.OK:
        assert "root:" not in response.text


def test_security_headers_apply_to_the_app_shell(spa_client: TestClient) -> None:
    headers = spa_client.get("/").headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"


def test_the_bundle_does_not_rely_on_inline_scripts() -> None:
    """The CSP has no 'unsafe-inline', so an inline script would break the app."""
    index = Path(__file__).resolve().parents[2] / "frontend" / "index.html"
    if not index.is_file():
        pytest.skip("frontend/index.html is not present in this checkout")
    markup = index.read_text(encoding="utf-8")
    # The only script tag may be the module entry point with a src attribute.
    scripts = [line for line in markup.splitlines() if "<script" in line]
    assert scripts
    assert all("src=" in line for line in scripts), scripts
