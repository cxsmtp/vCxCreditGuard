"""Regression tests for the Checkmarx One Fusion scan of commit 9534257.

Each test fails on that commit and passes with the fix. The race tests run real
threads, each with its own database session, against SQLite here and against
PostgreSQL with CXCG_TEST_DATABASE_URL; where the race needs a wider window than
a fast machine gives, the slow step (password hashing, label lookup, a count) is
stretched, never skipped.
"""

from __future__ import annotations

import contextlib
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

import httpcore
import httpx
import pyotp
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext
from app.api.routes import accounts as accounts_routes
from app.core.config import ConfigError, Settings
from app.db import session as db_session
from app.models import CreditLimit, CreditRequest, UtilityUser
from app.models.auth import LoginAttempt, PasswordResetToken
from app.models.enums import EntityType, RequestStatus, UtilityRole
from app.schemas.auth import UpdateUserRequest
from app.services import auth as auth_service
from app.services import delivery, limits_service, notifications, requests_service
from app.services.audit import AuditActor
from tests.conftest import ADMIN_PASSWORD
from tests.test_delivery import configure_webhook, make_notification

ACTOR = AuditActor.system("test")
OTHER_ADMIN_PASSWORD = "An0ther!Adm1n#Pass"


def _new_session() -> Session:
    return db_session.get_session_factory()()


def _in_threads(*work: Callable[[], Any]) -> list[Any]:
    """Run each callable in its own thread, all at once. Returns each result or
    the exception it raised."""
    results: list[Any] = [None] * len(work)
    start = threading.Barrier(len(work))

    def run(index: int, job: Callable[[], Any]) -> None:
        start.wait()
        try:
            results[index] = job()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test
            results[index] = exc

    threads = [threading.Thread(target=run, args=(i, job)) for i, job in enumerate(work)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    return results


def _slow_password_checks(monkeypatch: pytest.MonkeyPatch, seconds: float = 0.3) -> None:
    real = auth_service.verify_password

    def slow(stored: str, password: str) -> bool:
        time.sleep(seconds)
        return real(stored, password)

    monkeypatch.setattr(auth_service, "verify_password", slow)


def _sign_in(username: str, password: str, ip: str, totp: str | None = None) -> str:
    """One sign-in in its own transaction, committed as the login route does."""
    session = _new_session()
    try:
        auth_service.authenticate(
            session, username=username, password=password, totp_code=totp, ip_address=ip
        )
        session.commit()
        return "ok"
    except auth_service.AuthError as exc:
        session.commit()
        return type(exc).__name__
    finally:
        session.close()


def _attempt_row(db: Session, identifier: str, ip: str) -> LoginAttempt:
    db.expire_all()
    row = db.scalar(
        select(LoginAttempt).where(
            LoginAttempt.identifier == identifier, LoginAttempt.ip_address == ip
        )
    )
    assert row is not None
    return row


# ------------------------------------------------- auth.py:607 sign-in counters


class TestSignInCountersUnderConcurrency:
    def test_a_burst_from_one_address_counts_every_attempt(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each guess is counted, by the address and by the username. Before, the
        guesses made while the first was being checked were all counted as one,
        so a burst got past the per-minute allowance."""
        ip = "203.0.113.7"
        assert _sign_in("admin", "wrong-1", ip) == "InvalidCredentials"
        _slow_password_checks(monkeypatch)

        outcomes = _in_threads(*(lambda: _sign_in("admin", "wrong-2", ip) for _ in range(3)))

        assert outcomes == ["InvalidCredentials"] * 3
        assert _attempt_row(db, auth_service.ANY_ACCOUNT, ip).attempt_count == 4
        source = _attempt_row(db, "admin", ip)
        assert (source.attempt_count, source.failure_count) == (4, 4)

    def test_guesses_from_many_addresses_all_count_against_the_account(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The account-wide counter that stops guessing spread over many
        addresses must not lose the failures that land at the same moment."""
        assert _sign_in("admin", "wrong-0", "198.51.100.1") == "InvalidCredentials"
        _slow_password_checks(monkeypatch)

        outcomes = _in_threads(
            *((lambda ip=f"198.51.100.{n}": _sign_in("admin", "wrong", ip)) for n in range(2, 6))
        )

        assert outcomes == ["InvalidCredentials"] * 4
        assert _attempt_row(db, "admin", auth_service.ACCOUNT_WIDE).failure_count == 5
        db.refresh(admin_user)
        assert admin_user.failed_login_count == 5

    def test_one_authenticator_code_signs_in_once(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Replayed at the same moment from two addresses, a code is accepted
        once: the second sign-in reads the step the first one used."""
        secret, _uri = auth_service.provision_totp(db, user=admin_user)
        admin_user.totp_enabled = True
        db.commit()
        code = pyotp.TOTP(secret).now()
        # The username's counters exist already, as they would for any account
        # that has been signed in to.
        assert _sign_in("admin", "wrong", "192.0.2.9") == "InvalidCredentials"
        _slow_password_checks(monkeypatch)

        outcomes = _in_threads(
            lambda: _sign_in("admin", ADMIN_PASSWORD, "192.0.2.10", code),
            lambda: _sign_in("admin", ADMIN_PASSWORD, "192.0.2.11", code),
        )

        assert outcomes.count("ok") == 1, outcomes
        assert outcomes.count("InvalidCredentials") == 1, outcomes

    def test_the_first_attempt_from_two_requests_at_once_is_not_an_error(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both find no counter row yet; both are counted, neither fails on the
        unique constraint."""
        _slow_password_checks(monkeypatch, seconds=0.1)
        outcomes = _in_threads(
            *(lambda: _sign_in("admin", "wrong", "192.0.2.50") for _ in range(2))
        )
        assert outcomes == ["InvalidCredentials"] * 2
        assert _attempt_row(db, "admin", "192.0.2.50").failure_count == 2


# ------------------------------------------------ auth.py:322 reset-token reuse


def test_a_reset_token_is_redeemed_once_however_the_requests_interleave(
    db: Session, admin_user: UtilityUser
) -> None:
    """The second redemption read the token before the first one spent it: it
    must still be refused, not set a second password."""
    token = auth_service.admin_issue_reset_token(
        db, user=admin_user, actor=AuditActor.system("test")
    )
    db.commit()

    late = _new_session()
    try:
        # The late request's read of the token, from before the other commits.
        seen = late.scalar(select(PasswordResetToken))
        assert seen is not None and seen.used_at is None

        first = _new_session()
        try:
            auth_service.complete_password_reset(first, token=token, new_password="F1rst!Choice#Pw")
            first.commit()
        finally:
            first.close()

        with pytest.raises(auth_service.InvalidResetToken):
            auth_service.complete_password_reset(late, token=token, new_password="L4te!Choice#Pw")
        late.commit()
    finally:
        late.close()

    db.expire_all()
    user = db.get(UtilityUser, admin_user.id)
    assert user is not None
    assert auth_service.verify_password(user.password_hash, "F1rst!Choice#Pw")


# ------------------------------------- accounts.py:81 / :231 the last Admin


def _ctx(session: Session, username: str) -> AuthContext:
    user = session.scalar(select(UtilityUser).where(UtilityUser.username == username))
    assert user is not None
    return AuthContext(user=user, session_row=None, ip_address="127.0.0.1", user_agent=None)  # type: ignore[arg-type]


class TestLastAdminUnderConcurrency:
    @pytest.fixture
    def two_admins(self, db: Session, admin_user: UtilityUser) -> tuple[int, int]:
        other = auth_service.create_user(
            db,
            username="second",
            password=OTHER_ADMIN_PASSWORD,
            role=UtilityRole.ADMIN,
            actor=ACTOR,
        )
        db.commit()
        return admin_user.id, other.id

    @pytest.fixture
    def counts_meet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Hold each request after its count until the other has counted too
        (or for a moment, if the other is made to wait for this one)."""
        real = accounts_routes._count_other_active_admins
        meet = threading.Barrier(2)

        def count(db: Session, *, exclude_id: int) -> int:
            result = real(db, exclude_id=exclude_id)
            with contextlib.suppress(threading.BrokenBarrierError):
                meet.wait(timeout=1.5)
            return result

        monkeypatch.setattr(accounts_routes, "_count_other_active_admins", count)

    def _demote(self, actor: str, target_id: int) -> str:
        session = _new_session()
        try:
            accounts_routes.update_account(
                target_id, UpdateUserRequest(role=UtilityRole.VIEWER), _ctx(session, actor), session
            )
            return "demoted"
        except HTTPException as exc:
            return str(exc.status_code)
        finally:
            session.close()

    def _delete(self, actor: str, target_id: int) -> str:
        session = _new_session()
        try:
            accounts_routes.delete_account(target_id, _ctx(session, actor), session)
            return "deleted"
        except HTTPException as exc:
            return str(exc.status_code)
        finally:
            session.close()

    def _active_admins(self, db: Session) -> int:
        db.expire_all()
        return int(
            db.scalar(
                select(func.count())
                .select_from(UtilityUser)
                .where(UtilityUser.role == UtilityRole.ADMIN, UtilityUser.is_active.is_(True))
            )
            or 0
        )

    @pytest.mark.usefixtures("counts_meet")
    def test_two_admins_demoting_each_other_leave_one(
        self, db: Session, two_admins: tuple[int, int]
    ) -> None:
        first, second = two_admins
        outcomes = _in_threads(
            lambda: self._demote("admin", second), lambda: self._demote("second", first)
        )
        assert sorted(outcomes) in (["400", "demoted"], ["403", "demoted"]), outcomes
        assert self._active_admins(db) == 1

    @pytest.mark.usefixtures("counts_meet")
    def test_two_admins_deleting_each_other_leave_one(
        self, db: Session, two_admins: tuple[int, int]
    ) -> None:
        first, second = two_admins
        outcomes = _in_threads(
            lambda: self._delete("admin", second), lambda: self._delete("second", first)
        )
        assert "deleted" in outcomes and outcomes.count("deleted") == 1, outcomes
        assert self._active_admins(db) == 1


# -------------------------------------------- requests_service.py:60 / :72


def _file(session: Session, entity_id: str, requested: int = 500) -> CreditRequest:
    return requests_service.create_request(
        session,
        data=requests_service.RequestInput(
            entity_type=EntityType.USER, entity_id=entity_id, requested_limit=requested
        ),
        actor=ACTOR,
        is_admin=True,
    )


class TestCreditRequestsUnderConcurrency:
    def test_two_filings_for_one_entity_at_once_leave_one_pending(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = limits_service.resolve_entity_label

        def slow_label(session: Session, **kwargs: Any) -> str | None:
            time.sleep(0.3)
            return real(session, **kwargs)

        monkeypatch.setattr(limits_service, "resolve_entity_label", slow_label)

        def file_one() -> str:
            session = _new_session()
            try:
                _file(session, "user-race")
                session.commit()
                return "filed"
            except requests_service.RequestError:
                return "refused"
            finally:
                session.close()

        outcomes = _in_threads(file_one, file_one)

        assert sorted(outcomes) == ["filed", "refused"]
        pending = db.scalar(
            select(func.count())
            .select_from(CreditRequest)
            .where(
                CreditRequest.entity_id == "user-race",
                CreditRequest.status == RequestStatus.PENDING,
            )
        )
        assert pending == 1

    def test_a_request_approved_meanwhile_cannot_then_be_denied(self, db: Session) -> None:
        """The denial read the request while it was pending; the approval
        committed first. Before, the denial went through: the request said
        denied while its grant stayed applied."""
        request = _file(db, "user-decided")
        db.commit()

        late = _new_session()
        try:
            stale = late.get(CreditRequest, request.id)
            assert stale is not None and stale.status == RequestStatus.PENDING

            first = _new_session()
            try:
                fresh = first.get(CreditRequest, request.id)
                requests_service.approve_request(first, request=fresh, actor=ACTOR)
                first.commit()
            finally:
                first.close()

            with pytest.raises(requests_service.RequestStateError):
                requests_service.deny_request(late, request=stale, actor=ACTOR)
            late.rollback()
        finally:
            late.close()

        db.expire_all()
        decided = db.get(CreditRequest, request.id)
        assert decided is not None and decided.status == RequestStatus.APPROVED
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-decided"))
        assert limit is not None and limit.credit_limit == 500

    def test_a_request_cannot_be_approved_twice(self, db: Session) -> None:
        request = _file(db, "user-twice")
        db.commit()

        late = _new_session()
        try:
            stale = late.get(CreditRequest, request.id)
            first = _new_session()
            try:
                requests_service.approve_request(
                    first, request=first.get(CreditRequest, request.id), actor=ACTOR
                )
                first.commit()
            finally:
                first.close()
            with pytest.raises(requests_service.RequestStateError):
                requests_service.approve_request(
                    late, request=stale, actor=ACTOR, approved_limit=9_999
                )
            late.rollback()
        finally:
            late.close()

        db.expire_all()
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "user-twice"))
        assert limit is not None and limit.credit_limit == 500


# ------------------------------------------------- notifications.py:101 (RBAC)


def test_a_viewer_cannot_mark_the_shared_notifications_read(
    db: Session, viewer_client: TestClient
) -> None:
    notifications.notify(
        db, category="enforcement", severity="critical", title="Restricted", dedupe_key="n-1"
    )
    db.commit()

    response = viewer_client.post("/api/notifications/read", json={})

    assert response.status_code == httpx.codes.FORBIDDEN
    assert notifications.unread_count(db) == 1


def test_an_admin_still_marks_notifications_read(db: Session, admin_client: TestClient) -> None:
    notifications.notify(
        db, category="enforcement", severity="critical", title="Restricted", dedupe_key="n-2"
    )
    db.commit()
    response = admin_client.post("/api/notifications/read", json={})
    assert response.status_code == httpx.codes.OK
    assert response.json()["marked_read"] == 1


# ------------------------------------------- delivery.py:130, settings.py:166


METADATA_SPELLINGS = [
    "http://2852039166/latest/meta-data/",  # decimal
    "http://0xa9fea9fe/latest/meta-data/",  # hex
    "http://0251.0376.0251.0376/latest/meta-data/",  # octal
    "http://169.254.43518/latest/meta-data/",  # short form
    "http://[::ffff:169.254.169.254]/latest/meta-data/",  # IPv4-mapped IPv6
    "http://[::ffff:a9fe:a9fe]/latest/meta-data/",
    "http://[64:ff9b::a9fe:a9fe]/latest/meta-data/",  # NAT64
    "http://[fd00:ec2:0::254]/latest/meta-data/",  # AWS IPv6, spelt out
    "http://metadata.google.internal./computeMetadata/v1/",  # trailing dot
]


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
def resolver(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Names resolve to what the test says; any real connection is recorded."""
    answers: dict[str, str] = {}
    real = socket.getaddrinfo

    def fake(host: str, port: Any, *args: Any, **kwargs: Any) -> Any:
        if host in answers:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], port))]
        return real(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return answers


@pytest.fixture
def connections(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    made: list[tuple[str, int]] = []

    def refuse(address: tuple[str, int], *args: Any, **kwargs: Any) -> socket.socket:
        made.append((str(address[0]), int(address[1])))
        raise ConnectionRefusedError("test: no network")

    monkeypatch.setattr(socket, "create_connection", refuse)
    return made


class TestWebhookAndMailTargets:
    @pytest.mark.parametrize("url", METADATA_SPELLINGS)
    def test_every_spelling_of_the_metadata_address_is_refused(self, url: str) -> None:
        with pytest.raises(delivery.DeliveryError, match="refusing to post"):
            delivery.assert_webhook_target_allowed(url)

    @pytest.mark.parametrize(
        "url", ["https://10.1.2.3/hook", "https://hooks.example.com/x", "http://[fd12::1]/h"]
    )
    def test_ordinary_and_internal_targets_are_still_allowed(self, url: str) -> None:
        delivery.assert_webhook_target_allowed(url)

    @pytest.mark.usefixtures("no_env_proxy")
    def test_a_name_resolving_to_the_metadata_address_is_refused_when_connecting(
        self,
        db: Session,
        resolver: dict[str, str],
        connections: list[tuple[str, int]],
    ) -> None:
        """DNS rebinding: the name passes the check on the URL, then resolves
        to the metadata address when the connection is made."""
        resolver["rebind.example.test"] = "169.254.169.254"
        configure_webhook(db, url="http://rebind.example.test/hook")
        make_notification(db)

        result = delivery.deliver_pending(db)
        db.commit()

        assert result.failed == 1
        assert any("refusing to connect" in error for error in result.errors), result.errors
        assert connections == []

    @pytest.mark.usefixtures("no_env_proxy")
    def test_an_allowed_name_is_connected_to_at_the_address_that_was_checked(
        self, resolver: dict[str, str], connections: list[tuple[str, int]]
    ) -> None:
        resolver["hooks.example.test"] = "10.20.30.40"
        with delivery.webhook_client() as client, pytest.raises(httpx.ConnectError):
            client.post("http://hooks.example.test/hook", content=b"{}")
        assert connections == [("10.20.30.40", 80)]

    def test_the_webhook_client_is_guarded_and_does_not_follow_redirects(self) -> None:
        with delivery.webhook_client() as client:
            assert client.follow_redirects is False
            backend = client._transport._pool._network_backend  # noqa: SLF001
            assert isinstance(backend, httpcore.NetworkBackend)
            with pytest.raises(delivery.TargetRefused):
                backend.connect_tcp("169.254.169.254", 80)

    def test_a_mail_server_resolving_to_the_metadata_address_is_refused(
        self, resolver: dict[str, str], connections: list[tuple[str, int]]
    ) -> None:
        resolver["smtp.rebind.test"] = "169.254.169.254"
        config = delivery.DeliveryConfig(
            min_severity="warning",
            smtp_host="smtp.rebind.test",
            smtp_port=587,
            smtp_username=None,
            smtp_password=None,
            smtp_use_tls=True,
            smtp_from="cxcg@example.com",
            smtp_recipients=("ops@example.com",),
            webhook_url=None,
            webhook_secret=None,
            tenant_name=None,
        )
        with pytest.raises(delivery.DeliveryError, match="refusing to connect"):
            delivery.send_direct_email(
                config=config, to="x@example.com", subject="s", text_body="b"
            )
        assert connections == []


# ---------------------------------------------------------- config.py:52 CORS


class TestCorsOrigins:
    @pytest.mark.parametrize(
        "value",
        ["*", "https://app.example.com,*", "https://*.example.com", "null", "app.example.com"],
    )
    def test_a_wildcard_or_non_origin_is_refused(self, value: str) -> None:
        with pytest.raises(ConfigError, match="CXCG_ALLOWED_ORIGINS"):
            Settings(allowed_origins=value, env="development", cookie_secure=False)

    def test_exact_origins_are_accepted(self) -> None:
        settings = Settings(
            allowed_origins="http://localhost:5173, https://app.example.com:8443/",
            env="development",
            cookie_secure=False,
        )
        assert settings.cors_origins == ["http://localhost:5173", "https://app.example.com:8443"]

    def test_none_by_default(self) -> None:
        assert Settings(env="development", cookie_secure=False).cors_origins == []
