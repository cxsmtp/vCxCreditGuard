"""Shared test fixtures.

Environment is set before any application module is imported, because Settings is
read once and cached. Each test gets its own SQLite file so nothing leaks between
tests, and the process wide caches (settings, secret box, engine, Checkmarx
client) are reset around every test.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable, Iterator
from typing import Any

os.environ.setdefault("CXCG_ENV", "development")
os.environ.setdefault("CXCG_COOKIE_SECURE", "false")
os.environ.setdefault("CXCG_MASTER_KEY", base64.b64encode(bytes(range(32))).decode())
os.environ.setdefault("CXCG_LOG_LEVEL", "WARNING")
# Keep Argon2 verification honest but do not let bootstrap variables leak in from
# a developer's shell.
os.environ.pop("CXCG_BOOTSTRAP_ADMIN_USERNAME", None)
os.environ.pop("CXCG_BOOTSTRAP_ADMIN_PASSWORD", None)

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core import crypto  # noqa: E402
from app.core.config import get_settings, reset_settings_cache  # noqa: E402
from app.db import session as db_session  # noqa: E402
from app.models import Base, UtilityUser  # noqa: E402
from app.models.enums import UtilityRole  # noqa: E402
from app.services import auth as auth_service  # noqa: E402
from app.services import connection as connection_service  # noqa: E402
from app.services.audit import AuditActor  # noqa: E402

ADMIN_PASSWORD = "Str0ng!Adm1n#Pass"
VIEWER_PASSWORD = "Str0ng!V1ewer#Pass"


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("CXCG_DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    reset_settings_cache()
    crypto.reset_secret_box()
    db_session.reset_engine()
    connection_service.reset_client_cache()

    Base.metadata.create_all(db_session.get_engine())
    yield
    db_session.reset_engine()
    connection_service.reset_client_cache()
    crypto.reset_secret_box()
    reset_settings_cache()


@pytest.fixture
def db() -> Iterator[Session]:
    session = db_session.get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def admin_user(db: Session) -> UtilityUser:
    user = auth_service.create_user(
        db,
        username="admin",
        password=ADMIN_PASSWORD,
        role=UtilityRole.ADMIN,
        actor=AuditActor.system("test"),
    )
    db.commit()
    return user


@pytest.fixture
def viewer_user(db: Session) -> UtilityUser:
    user = auth_service.create_user(
        db,
        username="viewer",
        password=VIEWER_PASSWORD,
        role=UtilityRole.VIEWER,
        actor=AuditActor.system("test"),
    )
    db.commit()
    return user


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """App instance with schema already created, so the app does not re-migrate.

    The migration path itself is covered by tests/test_migrations.py.
    """
    from app import main

    monkeypatch.setattr(main, "upgrade_to_head", lambda *_args, **_kwargs: None)
    # No background scheduler in tests: cycles are driven explicitly so nothing
    # races with assertions.
    app = main.create_app(get_settings(), run_scheduler=False)
    with TestClient(app) as test_client:
        yield test_client


def login(
    client: TestClient, username: str, password: str, totp_code: str | None = None
) -> httpx.Response:
    payload: dict[str, Any] = {"username": username, "password": password}
    if totp_code is not None:
        payload["totp_code"] = totp_code
    response = client.post("/api/auth/login", json=payload)
    if response.status_code == httpx.codes.OK:
        # Mirror what the SPA does: echo the CSRF cookie back as a header.
        client.headers["X-CSRF-Token"] = client.cookies.get("cxcg_csrf", "")
    return response


@pytest.fixture
def admin_client(client: TestClient, admin_user: UtilityUser) -> TestClient:
    response = login(client, admin_user.username, ADMIN_PASSWORD)
    assert response.status_code == httpx.codes.OK, response.text
    return client


@pytest.fixture
def viewer_client(client: TestClient, viewer_user: UtilityUser) -> TestClient:
    response = login(client, viewer_user.username, VIEWER_PASSWORD)
    assert response.status_code == httpx.codes.OK, response.text
    return client


# ------------------------------------------------------- Checkmarx test helpers


def b64url(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_api_key(
    *,
    iam_base_url: str = "https://eu.iam.checkmarx.net",
    tenant: str = "acme-corp",
    exp: int = 0,
    typ: str | None = "Refresh",
    issuer: str | None = None,
    subject: str = "11111111-2222-3333-4444-555555555555",
    azp: str = "ast-app",
) -> str:
    """Build a JWT shaped API key. The signature is a placeholder: nothing in the
    utility verifies it, which is exactly the behaviour under test."""
    payload: dict[str, Any] = {
        "iss": issuer if issuer is not None else f"{iam_base_url}/auth/realms/{tenant}",
        "sub": subject,
        "azp": azp,
        "exp": exp,
        "iat": 1700000000,
        "jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "scope": "offline_access roles profile",
    }
    if typ is not None:
        payload["typ"] = typ
    header = b64url({"alg": "HS256", "typ": "JWT", "kid": "test-key"})
    return f"{header}.{b64url(payload)}.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"


@pytest.fixture
def api_key() -> str:
    return make_api_key()


def mock_transport(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def token_response(
    *, access_token: str = "test-access-token", expires_in: int | None = 1800
) -> httpx.Response:
    body: dict[str, Any] = {"access_token": access_token, "token_type": "Bearer"}
    if expires_in is not None:
        body["expires_in"] = expires_in
    return httpx.Response(200, json=body)
