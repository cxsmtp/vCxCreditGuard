"""Follow-up to the Fusion scan fixes (28673c6), from their security review.

Sign-ins no longer hold a lock across Argon2; every lock is taken in one order
(auth.py, LOCK ORDER); TOTP and recovery codes are spent in the database; the
webhook target is checked even through an environment proxy; more addresses are
refused; Checkmarx error text is redacted wherever it is shown.
"""

from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Any

import httpcore
import httpx
import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api.routes import accounts as accounts_routes
from app.checkmarx.errors import CheckmarxResponseError
from app.checkmarx.regions import UntrustedHostError
from app.db import session as db_session
from app.models import CreditRequest, Notification, UtilityUser
from app.models.auth import LoginAttempt
from app.models.enums import EntityType, RunStatus
from app.services import (
    audit_chain,
    connection,
    cycle,
    delivery,
    enforcement,
    evaluation,
    limits_service,
    requests_service,
    role_sources,
)
from app.services import auth as auth_service
from app.services.audit import AuditActor
from tests.conftest import ADMIN_PASSWORD, make_api_key, postgres_only, sqlite_only
from tests.test_cycle_transactions import _enforced_user_limit, _watch_for_write_locks
from tests.test_cycle_transactions import tenant as tenant  # noqa: F401 - fixture
from tests.test_resilience import AUGUST, PERIOD, _restricted, alice_limit, synced
from tests.test_scan_fusion_findings import (
    _ctx,
    _in_threads,
    _new_session,
    _sign_in,
    _slow_password_checks,
)

ACTOR = AuditActor.system("review")
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzZWNyZXQtdXNlciJ9.c2lnbmF0dXJl"


def _timed_sign_in(username: str, password: str, ip: str) -> tuple[str, float]:
    start = time.monotonic()
    outcome = _sign_in(username, password, ip)
    return outcome, round(time.monotonic() - start, 2)


# ------------------------------------------ no lock is held across Argon2


class TestSignInsDoNotQueueBehindArgon2:
    def test_victim_waits_behind_attackers_on_same_username(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Three wrong guesses for 'admin' from other addresses are being
        verified; the owner's sign-in from a fourth takes one verification, not
        four in a row."""
        assert _sign_in("admin", "wrong", "198.51.100.200") == "InvalidCredentials"
        _slow_password_checks(monkeypatch, seconds=1.0)

        def victim() -> tuple[str, float]:
            time.sleep(0.2)
            return _timed_sign_in("admin", ADMIN_PASSWORD, "192.0.2.77")

        results = _in_threads(
            *(
                (lambda n=n: _timed_sign_in("admin", f"wrong{n}", f"198.51.100.{n}"))
                for n in (1, 2, 3)
            ),
            victim,
        )
        assert [r[0] for r in results[:3]] == ["InvalidCredentials"] * 3
        assert results[-1][0] == "ok"
        assert results[-1][1] < 2.0, f"owner's sign-in took {results[-1][1]}s"

    def test_other_users_sign_ins_are_not_serialised(
        self,
        db: Session,
        admin_user: UtilityUser,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Nor behind other usernames' (on SQLite the write lock is global)."""
        _slow_password_checks(monkeypatch, seconds=1.0)
        results = _in_threads(
            *(
                (lambda n=n: _timed_sign_in(f"ghost{n}", "wrong", f"198.51.100.{n}"))
                for n in (1, 2, 3)
            ),
            lambda: (time.sleep(0.2), _timed_sign_in("admin", ADMIN_PASSWORD, "192.0.2.78"))[1],
        )
        assert results[-1][0] == "ok"
        assert results[-1][1] < 2.0, f"unrelated owner's sign-in took {results[-1][1]}s"

    @postgres_only
    def test_a_short_lock_timeout_does_not_fail_the_owner(
        self, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(db_session, "PG_LOCK_TIMEOUT_MS", 1500)
        db_session.reset_engine()
        assert _sign_in("admin", "wrong", "198.51.100.210") == "InvalidCredentials"
        _slow_password_checks(monkeypatch, seconds=1.0)

        def victim() -> tuple[str, float]:
            time.sleep(0.2)
            return _timed_sign_in("admin", ADMIN_PASSWORD, "192.0.2.79")

        results = _in_threads(
            *(
                (lambda n=n: _timed_sign_in("admin", f"wrong{n}", f"198.51.100.{n}"))
                for n in (1, 2, 3)
            ),
            victim,
        )
        assert results[-1][0] == "ok", results[-1]

    def test_a_lockout_reached_meanwhile_still_stops_a_right_password(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lockouts are re-checked once the counters are locked again: a
        right password whose address was locked while it was being verified is
        answered like any other attempt from a locked address."""
        ip = "203.0.113.90"
        real_verify = auth_service.verify_password

        def verify_then_lock(stored: str, password: str) -> bool:
            ok = real_verify(stored, password)
            session = _new_session()
            try:
                row = session.scalar(
                    select(LoginAttempt).where(
                        LoginAttempt.identifier == "admin", LoginAttempt.ip_address == ip
                    )
                )
                assert row is not None
                row.locked_until = auth_service.utcnow() + dt.timedelta(minutes=5)
                session.commit()
            finally:
                session.close()
            return ok

        monkeypatch.setattr(auth_service, "verify_password", verify_then_lock)
        assert _sign_in("admin", ADMIN_PASSWORD, ip) == "AccountLocked"


# --------------------------------------------------- one global lock order


@postgres_only
@pytest.mark.parametrize("other", ["reset", "unlock"])
def test_sign_in_does_not_deadlock_with_reset_or_unlock(
    db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch, other: str
) -> None:
    ip = "203.0.113.70"
    assert _sign_in("admin", "wrong", ip) == "InvalidCredentials"
    # A later update moves the per-address row's live tuple after the
    # account-wide one, so a single DELETE would meet the account-wide row first.
    db.execute(
        text("UPDATE login_attempt SET attempt_count = attempt_count WHERE ip_address = :ip"),
        {"ip": ip},
    )
    db.commit()
    token = auth_service.admin_issue_reset_token(db, user=admin_user, actor=ACTOR)
    db.commit()

    real = auth_service._account_row

    def slow_account_row(session: Session, identifier: str) -> Any:
        time.sleep(1.0)  # between the per-address lock and the account-wide one
        return real(session, identifier)

    monkeypatch.setattr(auth_service, "_account_row", slow_account_row)

    def other_side() -> str:
        time.sleep(0.3)
        session = _new_session()
        try:
            if other == "reset":
                auth_service.complete_password_reset(
                    session, token=token, new_password="Zq7!vTn#8kLm2Wp"
                )
            else:
                accounts_routes.unlock_account(admin_user.id, _ctx(session, "admin"), session)
            session.commit()
            return "ok"
        finally:
            session.close()

    outcomes = _in_threads(lambda: _sign_in("admin", "wrong", ip), other_side)
    assert not any(
        isinstance(o, OperationalError) and "deadlock" in str(o).lower() for o in outcomes
    ), outcomes
    assert outcomes == ["InvalidCredentials", "ok"], outcomes


# ----------------------------------------------------- 2FA spent once


class TestSecondFactorSpentOnce:
    def test_a_recovery_code_signs_in_once(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        auth_service.provision_totp(db, user=admin_user)
        admin_user.totp_enabled = True
        codes = auth_service.issue_recovery_codes(db, user=admin_user)
        db.commit()
        assert _sign_in("admin", "wrong", "192.0.2.90") == "InvalidCredentials"
        _slow_password_checks(monkeypatch, seconds=0.3)
        outcomes = _in_threads(
            *(
                (lambda n=n: _sign_in("admin", ADMIN_PASSWORD, f"192.0.2.{91 + n}", codes[0]))
                for n in range(3)
            )
        )
        assert outcomes.count("ok") == 1, outcomes

    def test_a_totp_code_signs_in_once_from_three_new_addresses(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No counter rows yet: the account-wide one is created concurrently."""
        secret, _ = auth_service.provision_totp(db, user=admin_user)
        admin_user.totp_enabled = True
        db.commit()
        code = pyotp.TOTP(secret).now()
        _slow_password_checks(monkeypatch, seconds=0.3)
        outcomes = _in_threads(
            *(
                (lambda n=n: _sign_in("admin", ADMIN_PASSWORD, f"192.0.2.{120 + n}", code))
                for n in range(3)
            )
        )
        assert outcomes.count("ok") == 1, outcomes

    def test_an_older_code_is_refused_after_a_newer_one(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        secret, _ = auth_service.provision_totp(db, user=admin_user)
        admin_user.totp_enabled = True
        db.commit()
        totp = pyotp.TOTP(secret)
        now = time.time()
        assert _sign_in("admin", ADMIN_PASSWORD, "192.0.2.140", totp.at(now)) == "ok"
        older = totp.at(now - totp.interval)
        assert _sign_in("admin", ADMIN_PASSWORD, "192.0.2.141", older) == "InvalidCredentials"


# ------------------------------------------------------- audit chain intact


def test_the_audit_chain_stays_valid_with_concurrent_writers(
    db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
) -> None:
    _slow_password_checks(monkeypatch, seconds=0.05)

    def file(n: int) -> str:
        session = _new_session()
        try:
            requests_service.create_request(
                session,
                data=requests_service.RequestInput(
                    entity_type=EntityType.USER, entity_id=f"u-{n}", requested_limit=5
                ),
                actor=ACTOR,
            )
            session.commit()
            return "filed"
        finally:
            session.close()

    work: list[Any] = []
    for n in range(6):
        work.append(lambda n=n: _sign_in(f"user{n}", "wrong", f"198.51.100.{n}"))
        work.append(lambda n=n: _sign_in("admin", "wrong", f"203.0.113.{n}"))
        work.append(lambda n=n: file(n))
    outcomes = _in_threads(*work)
    assert not any(isinstance(o, BaseException) for o in outcomes), outcomes
    db.expire_all()
    result = audit_chain.verify_chain(db)
    assert result.ok, result


@sqlite_only
def test_approving_a_request_lifts_without_a_write_lock(db: Session, tenant: Any) -> None:  # noqa: F811
    assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
    _enforced_user_limit(db, credit_limit=1)
    cycle.run_cycle(trigger="manual")
    tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=50)
    cycle.run_cycle(trigger="manual")
    request = requests_service.create_request(
        db,
        data=requests_service.RequestInput(
            entity_type=EntityType.USER, entity_id="user-alice", requested_limit=100000
        ),
        actor=ACTOR,
    )
    db.commit()
    held = _watch_for_write_locks(tenant)
    before = len(tenant.requests)
    session = _new_session()
    try:
        requests_service.approve_request(
            session,
            request=session.get(CreditRequest, request.id),
            actor=ACTOR,
            client=tenant.client(),
        )
        session.commit()
    finally:
        session.close()
    assert len(tenant.requests) > before, "expected the approval to call Checkmarx"
    assert held == []


# ----------------------------------------------------------- reset path


def test_a_weak_password_does_not_hand_back_the_reset_attempt(
    db: Session, admin_user: UtilityUser, client: TestClient
) -> None:
    token = auth_service.admin_issue_reset_token(db, user=admin_user, actor=ACTOR)
    db.commit()
    response = client.post(
        "/api/auth/reset-password", json={"token": token, "new_password": "aaaaaaaaaaaaaaaa"}
    )
    assert response.status_code == httpx.codes.BAD_REQUEST
    assert response.json()["detail"]["code"] == "weak_password"
    db.expire_all()
    row = db.scalar(select(LoginAttempt).where(LoginAttempt.identifier == "reset-redeem"))
    assert row is not None and row.attempt_count == 1
    # And the token is still unspent, for a retry with a stronger password.
    response = client.post(
        "/api/auth/reset-password", json={"token": token, "new_password": "Zq7!vTn#8kLm2Wp"}
    )
    assert response.status_code == httpx.codes.OK, response.text


# --------------------------------------------------------------- addresses


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("2002:a9fe:a9fe::1", "metadata"),  # 6to4 of 169.254.169.254
        ("::a9fe:a9fe", "metadata"),  # IPv4-compatible
        ("64:ff9b:1::a9fe:a9fe", "metadata"),  # RFC 8215 local-use NAT64
        ("fd20:ce::254", "metadata"),  # GCP IPv6 metadata server
        ("100.100.100.200", "metadata"),  # Alibaba Cloud
        ("168.63.129.16", "metadata"),  # Azure WireServer
        ("0.0.0.0", "unspecified"),  # noqa: S104 - an address under test
        ("::", "unspecified"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("::ffff:127.0.0.1", "loopback"),
    ],
)
def test_more_addresses_are_refused(address: str, reason: str) -> None:
    found = delivery.forbidden_address(ipaddress.ip_address(address))
    assert found is not None and reason in found


@pytest.mark.parametrize(
    "address", ["fd12::1", "fd20:ce::1", "10.0.0.1", "8.8.8.8", "64:ff9b::808:808"]
)
def test_other_ulas_private_and_public_addresses_stay_allowed(address: str) -> None:
    assert delivery.forbidden_address(ipaddress.ip_address(address)) is None


def test_loopback_is_allowed_for_a_mail_relay_only() -> None:
    assert (
        delivery.forbidden_address(ipaddress.ip_address("127.0.0.1"), allow_loopback=True) is None
    )
    unspecified = ipaddress.ip_address("0.0.0.0")  # noqa: S104 - an address under test
    assert delivery.forbidden_address(unspecified, allow_loopback=True)


def test_a_name_resolving_to_good_and_bad_addresses_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(host: str, port: Any, *a: Any, **k: Any) -> Any:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:169.254.169.254", port, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(delivery.TargetRefused):
        delivery.guarded_addresses("mixed.example.test", 443)


def test_a_scoped_link_local_address_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(host: str, port: Any, *a: Any, **k: Any) -> Any:
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%lo", port, 0, 1))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(delivery.TargetRefused):
        delivery.guarded_addresses("scoped.example.test", 80)
    with pytest.raises(delivery.DeliveryError):
        delivery.assert_webhook_target_allowed("http://[fe80::1%25eth0]/x")


# ------------------------------------------------- proxy, redirects, TLS


class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []
    status = 200
    location = ""

    def _handle(self) -> None:
        type(self).seen.append(f"{self.command} {self.path}")
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(type(self).status)
        if type(self).location:
            self.send_header("Location", type(self).location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = _handle
    do_GET = _handle
    do_CONNECT = _handle

    def log_message(self, *_args: Any) -> None:
        pass


def _serve(handler: type, tls: ssl.SSLContext | None = None) -> tuple[Any, int]:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    if tls is not None:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def _resolve(monkeypatch: pytest.MonkeyPatch, answers: dict[str, str]) -> None:
    real = socket.getaddrinfo

    def fake(host: str, port: Any, *a: Any, **k: Any) -> Any:
        for suffix, address in answers.items():
            if host == suffix or host.endswith(suffix):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]
        return real(host, port, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.fixture
def no_env_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def local_test_servers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The test servers listen on loopback, which webhooks may not reach."""
    real = delivery.forbidden_address
    monkeypatch.setattr(
        delivery,
        "forbidden_address",
        lambda address, allow_loopback=False: real(address, allow_loopback=True),
    )


def test_through_an_environment_proxy_the_target_is_still_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = type("P", (_Recorder,), {"seen": []})
    server, port = _serve(handler)
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{port}")
    for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    _resolve(monkeypatch, {"rebind.example.test": "169.254.169.254"})
    try:
        with (
            delivery.webhook_client() as client,
            pytest.raises(delivery.DeliveryError, match="refusing"),
        ):
            client.post("http://rebind.example.test/hook", content=b"{}")
        # A harmless target still goes through the proxy.
        _resolve(monkeypatch, {"hooks.example.test": "10.20.30.40"})
        with delivery.webhook_client() as client:
            assert client.post("http://hooks.example.test/hook", content=b"{}").status_code == 200
    finally:
        server.shutdown()
    assert handler.seen == ["POST http://hooks.example.test/hook"]


def test_through_a_proxy_an_unresolvable_name_is_left_to_the_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = type("P2", (_Recorder,), {"seen": []})
    server, port = _serve(handler)
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{port}")
    for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    real = socket.getaddrinfo

    def fake(host: str, p: Any, *a: Any, **k: Any) -> Any:
        if host == "only-the-proxy-knows.example.test":
            raise socket.gaierror(socket.EAI_NONAME, "not known")
        return real(host, p, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    try:
        with delivery.webhook_client() as client:
            response = client.post("http://only-the-proxy-knows.example.test/h", content=b"{}")
    finally:
        server.shutdown()
    assert response.status_code == 200 and len(handler.seen) == 1


@pytest.mark.usefixtures("no_env_proxy", "local_test_servers")
def test_a_redirect_to_the_metadata_address_is_not_followed() -> None:
    handler = type(
        "R",
        (_Recorder,),
        {"seen": [], "status": 307, "location": "http://169.254.169.254/latest/meta-data/"},
    )
    server, port = _serve(handler)
    try:
        with delivery.webhook_client() as client:
            response = client.post(f"http://127.0.0.1:{port}/hook", content=b"{}")
    finally:
        server.shutdown()
    assert response.status_code == 307
    assert len(handler.seen) == 1


@pytest.mark.usefixtures("no_env_proxy")
def test_a_webhook_to_loopback_is_refused() -> None:
    with delivery.webhook_client() as client, pytest.raises(delivery.DeliveryError, match="loop"):
        client.post("http://127.0.0.1:9/hook", content=b"{}")


def _certificates(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A throwaway CA and a leaf for hooks.example.test and smtp.example.test."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(name("Test CA"))
        .issuer_name(name("Test CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name("hooks.example.test"))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("hooks.example.test"), x509.DNSName("smtp.example.test")]
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, leaf_path, key_path = tmp_path / "ca.pem", tmp_path / "leaf.pem", tmp_path / "leaf.key"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, leaf_path, key_path


def _server_tls(tmp_path: Path, sni_seen: list[str]) -> tuple[ssl.SSLContext, Path]:
    ca, leaf, key = _certificates(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(leaf), str(key))
    ctx.sni_callback = lambda _sock, server_name, _ctx: sni_seen.append(str(server_name))
    return ctx, ca


@pytest.mark.usefixtures("no_env_proxy", "local_test_servers")
def test_the_webhook_certificate_is_checked_against_the_url_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Connecting to the vetted address does not weaken TLS: the name in the
    URL is sent (SNI) and checked against the certificate."""
    sni_seen: list[str] = []
    server_ctx, ca = _server_tls(tmp_path, sni_seen)
    handler = type("T", (_Recorder,), {"seen": []})
    server, port = _serve(handler, server_ctx)
    _resolve(monkeypatch, {".example.test": "127.0.0.1"})
    try:
        with delivery.webhook_client() as client:
            client._transport._pool._ssl_context = ssl.create_default_context(cafile=str(ca))  # noqa: SLF001
            ok = client.post(f"https://hooks.example.test:{port}/hook", content=b"{}")
            assert ok.status_code == 200
            with pytest.raises(httpx.ConnectError, match="certificate|hostname|match"):
                client.post(f"https://wrong.example.test:{port}/hook", content=b"{}")
    finally:
        server.shutdown()
    assert sni_seen[0] == "hooks.example.test", sni_seen


class _SMTPHandler(socketserver.StreamRequestHandler):
    tls: ssl.SSLContext
    log: list[str]

    def handle(self) -> None:
        conn = self.connection
        stream = conn.makefile("rwb")

        def send(line: str) -> None:
            stream.write((line + "\r\n").encode())
            stream.flush()

        send("220 test ESMTP")
        while True:
            line = stream.readline().decode().strip()
            if not line:
                return
            type(self).log.append(line)
            verb = line.split(" ")[0].upper()
            if verb in ("EHLO", "HELO"):
                send("250-test")
                send("250 STARTTLS")
            elif verb == "STARTTLS":
                send("220 go ahead")
                try:
                    conn = type(self).tls.wrap_socket(conn, server_side=True)
                except ssl.SSLError:
                    return
                stream = conn.makefile("rwb")
            elif verb == "QUIT":
                send("221 bye")
                return
            elif verb == "DATA":
                send("354 go")
                while stream.readline().strip() != b".":
                    pass
                send("250 ok")
            else:
                send("250 ok")


def test_smtp_starttls_checks_the_certificate_against_the_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sni_seen: list[str] = []
    server_ctx, ca = _server_tls(tmp_path, sni_seen)
    handler = type("S", (_SMTPHandler,), {"tls": server_ctx, "log": []})
    server, port = _serve(handler)
    _resolve(monkeypatch, {".example.test": "127.0.0.1"})
    monkeypatch.setattr(
        delivery, "_tls_context", lambda: ssl.create_default_context(cafile=str(ca))
    )

    def config(host: str) -> delivery.DeliveryConfig:
        return delivery.DeliveryConfig(
            min_severity="warning",
            smtp_host=host,
            smtp_port=port,
            smtp_username=None,
            smtp_password=None,
            smtp_use_tls=True,
            smtp_from="a@example.com",
            smtp_recipients=("b@example.com",),
            webhook_url=None,
            webhook_secret=None,
            tenant_name=None,
        )

    try:
        delivery.send_direct_email(
            config=config("smtp.example.test"), to="x@example.com", subject="s", text_body="b"
        )
        with pytest.raises(delivery.DeliveryError, match="certificate"):
            delivery.send_direct_email(
                config=config("bad.example.test"), to="x@example.com", subject="s", text_body="b"
            )
    finally:
        server.shutdown()
    assert "smtp.example.test" in sni_seen, sni_seen


# --------------------------------------------- the webhook client's guard


def test_the_client_is_not_built_when_the_guard_is_not_in_the_request_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulates an httpx/httpcore change: the pool connects through a backend
    of its own, not the one the guard replaces."""
    real = httpcore.ConnectionPool.create_connection

    def own_backend(self: Any, origin: Any) -> Any:
        self._network_backend = httpcore.SyncBackend()
        return real(self, origin)

    monkeypatch.setattr(httpcore.ConnectionPool, "create_connection", own_backend)

    def no_dns(*_args: Any, **_kwargs: Any) -> Any:
        raise socket.gaierror(socket.EAI_NONAME, "no network in tests")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    with pytest.raises(delivery.DeliveryError, match="cannot be guarded"):
        delivery.webhook_client()


def test_an_email_only_setup_does_not_need_the_webhook_client(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_delivery import FakeSmtp, configure_email, make_notification

    def broken() -> httpx.Client:
        raise delivery.DeliveryError("the webhook connection cannot be guarded")

    monkeypatch.setattr(delivery, "webhook_client", broken)
    configure_email(db)
    make_notification(db)
    result = delivery.deliver_pending(db, smtp_factory=FakeSmtp)
    db.commit()
    assert result.delivered == 1 and result.failed == 0


def test_a_webhook_without_a_guarded_client_fails_and_is_not_sent(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.test_delivery import configure_webhook, make_notification

    def broken() -> httpx.Client:
        raise delivery.DeliveryError("the webhook connection cannot be guarded")

    monkeypatch.setattr(delivery, "webhook_client", broken)
    configure_webhook(db)
    make_notification(db)
    result = delivery.deliver_pending(db)
    db.commit()
    assert result.failed == 1
    assert any("cannot be guarded" in error for error in result.errors)


# ------------------------------------- Checkmarx error text is redacted


def _refusing(client: Any, monkeypatch: pytest.MonkeyPatch, method: str, path_part: str) -> None:
    real = client.request

    def request(verb: str, path: str, *args: Any, **kwargs: Any) -> Any:
        if verb.upper() == method and path_part in path:
            raise CheckmarxResponseError(f"{verb} {path} returned 400: echoed {TOKEN}")
        return real(verb, path, *args, **kwargs)

    monkeypatch.setattr(client, "request", request)


def _body(db: Session, title_like: str) -> str:
    db.expire_all()
    row = db.scalar(select(Notification).where(Notification.title.like(title_like)))
    assert row is not None
    return row.body or ""


class TestCheckmarxErrorsAreRedacted:
    def test_could_not_restrict(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        _tenant, client = synced(db)
        limit = alice_limit(db)
        _refusing(client, monkeypatch, "DELETE", "role-mappings")
        outcome = enforcement.apply_enforcement(
            db, client, limit=limit, period_key=PERIOD, actor=ACTOR
        )
        assert outcome.failed
        body = _body(db, "Could not restrict%")
        assert "returned 400" in body and TOKEN not in body

    def test_could_not_restore(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        _tenant, client, limit = _restricted(db)
        limits_service.update_limit(
            db, limit=limit, changes={"enforce": False}, actor=ACTOR, client=None
        )
        db.commit()
        _refusing(client, monkeypatch, "POST", "role-mappings")
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        body = _body(db, "Could not restore%")
        assert "returned 400" in body and TOKEN not in body

    def test_deleting_a_limit(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        _tenant, client, limit = _restricted(db)
        _refusing(client, monkeypatch, "POST", "role-mappings")
        with pytest.raises(limits_service.LimitRestoreError) as caught:
            limits_service.delete_limit(db, limit=limit, actor=ACTOR, client=client)
        assert "returned 400" in str(caught.value) and TOKEN not in str(caught.value)

    def test_listing_the_tenant_roles(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        connection.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
        db.commit()

        def refuse(*_args: Any, **_kwargs: Any) -> Any:
            raise CheckmarxResponseError(f"GET /clients returned 400: echoed {TOKEN}")

        monkeypatch.setattr(connection, "get_client", lambda _session: object())
        monkeypatch.setattr(role_sources.iam, "resolve_platform_client_uuid", refuse)
        listing = role_sources.tenant_client_roles(db, fresh=True)
        assert listing.available is False
        assert "returned 400" in (listing.message or "") and TOKEN not in (listing.message or "")

    def test_a_blocked_connection(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        connection.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
        db.commit()

        def refuse(url: str, *, what: str) -> None:
            raise UntrustedHostError(f"{what} is not trusted: echoed {TOKEN}")

        monkeypatch.setattr(connection, "_check_trusted", refuse)
        assert connection.warn_if_untrusted(db) is True
        db.commit()
        body = _body(db, "The Checkmarx One connection is blocked%")
        assert "not trusted" in body and TOKEN not in body
        stored = connection.get_connection(db)
        assert stored is not None and TOKEN not in (stored.last_error or "")
