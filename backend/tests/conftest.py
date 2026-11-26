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
from app.updates import service as update_service  # noqa: E402

ADMIN_PASSWORD = "Str0ng!Adm1n#Pass"
VIEWER_PASSWORD = "Str0ng!V1ewer#Pass"


# Set CXCG_TEST_DATABASE_URL to run the whole suite against a real PostgreSQL
# database instead of a per-test SQLite file, for example
#   CXCG_TEST_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost/cxcg_test
# The database must exist and be disposable: its public schema is dropped and
# recreated before every test. CI runs the suite both ways, because the two
# engines disagree on exactly the things that matter here (locking, column
# widths, constraint names).
TEST_DATABASE_URL = os.environ.get("CXCG_TEST_DATABASE_URL", "").strip()
USING_SQLITE = not TEST_DATABASE_URL

sqlite_only = pytest.mark.skipif(
    not USING_SQLITE, reason="observes SQLite's single-writer lock directly"
)
postgres_only = pytest.mark.skipif(USING_SQLITE, reason="needs CXCG_TEST_DATABASE_URL")


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    if USING_SQLITE:
        db_file = tmp_path / "test.db"
        monkeypatch.setenv("CXCG_DATABASE_URL", f"sqlite:///{db_file.as_posix()}")
    else:
        monkeypatch.setenv("CXCG_DATABASE_URL", TEST_DATABASE_URL)
    # The updater's files (versions, launcher state) in a folder of this test's own.
    monkeypatch.setenv("CXCG_DATA_DIR", str(tmp_path / "app-data"))
    update_service.set_service(None)
    reset_settings_cache()
    crypto.reset_secret_box()
    db_session.reset_engine()
    connection_service.reset_client_cache()

    engine = db_session.get_engine()
    if not USING_SQLITE:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
    Base.metadata.create_all(engine)
    yield
    update_service.set_service(None)
    db_session.reset_engine()
    connection_service.reset_client_cache()
    crypto.reset_secret_box()
    reset_settings_cache()


# Test modules written for the credit activity log as the usage source (the
# default of a fresh install). Every other test was written for the
# consumption summary and its old enforcement, which a fresh install no
# longer has by default: they run with the usage source at "summary" and
# restrictions from summary totals allowed, which is exactly that behaviour
# (app/services/evaluation.py ``summary_hold``).
ACTIVITY_DEFAULT_MODULES = (
    "test_activity_source",
    "test_activity_properties",
    "test_review_activity_attacks",
    "test_summary_hold",
    "test_review2_activity_attacks",
    "test_log_fed_enforcement",
    "test_recount_gate",
)


@pytest.fixture(autouse=True)
def legacy_usage_source(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import settings_store

    if os.environ.get("REVIEW_REAL_DEFAULTS") == "1":
        # The whole suite under the real defaults (review switch).
        return
    if request.module.__name__.rsplit(".", 1)[-1] in ACTIVITY_DEFAULT_MODULES:
        return
    monkeypatch.setitem(
        settings_store.DEFAULTS,
        settings_store.KEY_USAGE_SOURCE,
        settings_store.USAGE_SOURCE_SUMMARY,
    )
    monkeypatch.setitem(settings_store.DEFAULTS, settings_store.KEY_SUMMARY_RESTRICTS, True)


# Test modules that run the independent recount before a new restriction
# (app/services/recount.py) for real, against the fake tenant's activity log.
REAL_RECOUNT_MODULES = ACTIVITY_DEFAULT_MODULES


@pytest.fixture(autouse=True)
def matching_activity_log(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every other test was written before the recount: for them the activity
    log's rows match CreditGuard's own count, so a new restriction is
    confirmed exactly as the recount would confirm it on a tenant whose log
    agrees. The recount's own rules are tested in the modules above."""
    from decimal import Decimal

    from app.services import recount

    if os.environ.get("REVIEW_REAL_DEFAULTS") == "1":
        return
    if request.module.__name__.rsplit(".", 1)[-1] in REAL_RECOUNT_MODULES:
        return

    def prepare(self, session, periods):  # type: ignore[no-untyped-def]
        return None

    def check(self, session, limit, window):  # type: ignore[no-untyped-def]
        return recount.Verdict(agrees=True, recount=Decimal(limit.credit_limit))

    monkeypatch.setattr(recount.Recounter, "prepare", prepare)
    monkeypatch.setattr(recount.Recounter, "check", check)


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
