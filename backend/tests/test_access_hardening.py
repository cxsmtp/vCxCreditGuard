"""Sign-in abuse resistance: client addresses, lockouts and throttles."""

from __future__ import annotations

import base64

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.api.deps import client_ip
from app.core.config import get_settings, reset_settings_cache
from app.models import AuditLogEntry, UtilityUser
from app.models.auth import LoginAttempt
from app.services import auth as auth_service
from tests.conftest import ADMIN_PASSWORD, postgres_only


def _request(peer: str, forwarded: str | None = None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded is not None else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers})


@pytest.fixture
def one_trusted_proxy(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("CXCG_TRUSTED_PROXY_HOPS", "1")
    reset_settings_cache()
    yield
    reset_settings_cache()


class TestClientAddress:
    def test_the_header_is_ignored_when_no_proxy_is_trusted(self) -> None:
        assert get_settings().trusted_proxy_hops == 0
        assert client_ip(_request("10.0.0.9", "1.2.3.4")) == "10.0.0.9"

    def test_the_proxys_own_entry_is_used_not_the_clients_claim(
        self, one_trusted_proxy: None
    ) -> None:
        # The client sent "1.2.3.4"; the proxy appended the address it really saw.
        assert client_ip(_request("172.18.0.3", "1.2.3.4, 203.0.113.7")) == "203.0.113.7"

    def test_a_single_overwritten_entry_is_used(self, one_trusted_proxy: None) -> None:
        assert client_ip(_request("172.18.0.3", "203.0.113.7")) == "203.0.113.7"

    def test_a_request_that_bypassed_the_proxy_falls_back_to_the_peer(
        self, one_trusted_proxy: None
    ) -> None:
        assert client_ip(_request("10.0.0.9")) == "10.0.0.9"

    def test_two_hops_reads_two_places_from_the_right(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CXCG_TRUSTED_PROXY_HOPS", "2")
        reset_settings_cache()
        forwarded = "9.9.9.9, 203.0.113.7, 10.1.1.1"
        assert client_ip(_request("172.18.0.3", forwarded)) == "203.0.113.7"

    def test_a_forged_header_cannot_dodge_the_sign_in_throttle(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        """Every attempt claims a new address; all are counted against the real one."""
        statuses = [
            client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "wrong"},
                headers={"X-Forwarded-For": f"198.51.100.{n}"},
            ).status_code
            for n in range(8)
        ]
        assert httpx.codes.LOCKED in statuses

    def test_a_forged_header_does_not_reach_the_audit_log(
        self, client: TestClient, admin_user: UtilityUser, db: Session
    ) -> None:
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
            headers={"X-Forwarded-For": "6.6.6.6"},
        )
        entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "auth.login_failed"))
        assert entry is not None and entry.ip_address != "6.6.6.6"


def _fail(db: Session, *, ip: str, times: int, username: str = "admin") -> None:
    for _ in range(times):
        with pytest.raises(auth_service.AuthError):
            auth_service.authenticate(db, username=username, password="wrong", ip_address=ip)
        db.commit()


class TestLockoutCannotBeUsedAgainstTheOwner:
    def test_failures_from_one_address_lock_that_address_only(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        _fail(db, ip="203.0.113.50", times=get_settings().login_max_attempts)

        # The attacker's address is locked out...
        with pytest.raises(auth_service.AccountLocked):
            auth_service.authenticate(
                db, username="admin", password=ADMIN_PASSWORD, ip_address="203.0.113.50"
            )
        db.rollback()
        # ...but the owner, elsewhere, signs in normally.
        user = auth_service.authenticate(
            db, username="admin", password=ADMIN_PASSWORD, ip_address="198.51.100.4"
        )
        assert user.id == admin_user.id
        db.refresh(admin_user)
        assert admin_user.locked_until is None

    def test_the_account_still_locks_under_a_distributed_attack(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        settings = get_settings()
        per_address = settings.login_max_attempts - 1  # stay under each address's lock
        needed = settings.login_max_attempts * auth_service.ACCOUNT_LOCK_MULTIPLIER
        addresses = -(-needed // per_address)
        for n in range(addresses):
            _fail(db, ip=f"203.0.113.{n}", times=per_address)

        db.refresh(admin_user)
        assert admin_user.locked_until is not None
        with pytest.raises(auth_service.AccountLocked):
            auth_service.authenticate(
                db, username="admin", password=ADMIN_PASSWORD, ip_address="198.51.100.4"
            )

    def test_a_lockout_does_not_reveal_whether_the_account_exists(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        attempts = get_settings().login_max_attempts
        _fail(db, ip="203.0.113.1", times=attempts, username="admin")
        _fail(db, ip="203.0.113.2", times=attempts, username="nobody")
        for ip, username in (("203.0.113.1", "admin"), ("203.0.113.2", "nobody")):
            with pytest.raises(auth_service.AccountLocked):
                auth_service.authenticate(db, username=username, password="x", ip_address=ip)
            db.rollback()

    def test_a_successful_sign_in_clears_the_sources_failures(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        _fail(db, ip="203.0.113.9", times=get_settings().login_max_attempts - 1)
        auth_service.authenticate(
            db, username="admin", password=ADMIN_PASSWORD, ip_address="203.0.113.9"
        )
        db.commit()
        row = db.scalar(
            select(LoginAttempt).where(
                LoginAttempt.identifier == "admin", LoginAttempt.ip_address == "203.0.113.9"
            )
        )
        assert row.failure_count == 0 and row.locked_until is None

    def test_unlocking_an_account_also_unlocks_the_address_that_failed(
        self, admin_client: TestClient, viewer_user: UtilityUser, db: Session
    ) -> None:
        _fail(db, ip="203.0.113.77", times=get_settings().login_max_attempts, username="viewer")
        response = admin_client.post(f"/api/accounts/{viewer_user.id}/unlock")
        assert response.status_code == httpx.codes.OK
        db.expire_all()
        assert db.scalar(select(LoginAttempt).where(LoginAttempt.identifier == "viewer")) is None


class TestThrottles:
    def test_varying_the_username_does_not_reset_the_allowance(self, db: Session) -> None:
        settings = get_settings()
        allowance = settings.login_rate_limit_per_minute * auth_service.ADDRESS_RATE_MULTIPLIER
        outcomes: list[type] = []
        for n in range(allowance + 2):
            try:
                auth_service.authenticate(
                    db, username=f"guess-{n}", password="x", ip_address="203.0.113.200"
                )
            except auth_service.AuthError as exc:
                outcomes.append(type(exc))
            db.commit()
        assert outcomes[0] is auth_service.InvalidCredentials
        assert outcomes[-1] is auth_service.RateLimited

    def test_password_hashing_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(auth_service, "VERIFICATION_WAIT_SECONDS", 0.01)
        held = [
            auth_service._verification_slots.acquire(timeout=1)
            for _ in range(auth_service.MAX_CONCURRENT_VERIFICATIONS)
        ]
        try:
            assert all(held)
            with pytest.raises(auth_service.RateLimited), auth_service._verification_slot():
                pass
        finally:
            for _ in held:
                auth_service._verification_slots.release()
        # And it is usable again once the others finish.
        with auth_service._verification_slot():
            pass


class TestTenantUrlsAreRestricted:
    """Tenant credentials are only ever sent to hosts the deployment trusts."""

    def _save(self, db: Session, **kwargs):
        from app.services import connection as connection_service
        from app.services.audit import AuditActor

        return connection_service.save_connection(db, actor=AuditActor.system("test"), **kwargs)

    def test_a_checkmarx_host_is_accepted(self, db: Session) -> None:
        from tests.conftest import make_api_key

        connection = self._save(db, api_key=make_api_key())
        assert connection.api_base_url == "https://eu.ast.checkmarx.net/api"

    @pytest.mark.parametrize(
        "override",
        [
            "https://attacker.example/api",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost:8443/api",
            "https://eu.ast.checkmarx.net.attacker.example/api",
            "https://notcheckmarx.net/api",
            # Credentials in the authority part (placeholder "user:pw"), split so
            # the literal does not read as a committed authenticated URL.
            "https://" + "user:pw" + "@eu.ast.checkmarx.net/api",
            "https://eu.ast.checkmarx.net/api?next=1",
        ],
    )
    def test_an_api_url_elsewhere_is_refused(self, db: Session, override: str) -> None:
        from app.checkmarx.regions import UntrustedHostError
        from app.services import connection as connection_service
        from tests.conftest import make_api_key

        with pytest.raises(UntrustedHostError):
            self._save(db, api_key=make_api_key(), api_base_url_override=override)
        db.rollback()
        assert connection_service.get_connection(db) is None

    def test_a_key_naming_an_untrusted_identity_server_is_refused(self, db: Session) -> None:
        """The issuer is an unsigned claim: a crafted key must not pick where the
        utility sends its credentials."""
        from app.checkmarx.regions import UntrustedHostError
        from tests.conftest import make_api_key

        crafted = make_api_key(iam_base_url="https://iam.attacker.example")
        with pytest.raises(UntrustedHostError):
            self._save(
                db, api_key=crafted, api_base_url_override="https://eu.ast.checkmarx.net/api"
            )

    def test_plain_http_is_refused_in_production(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.checkmarx.regions import UntrustedHostError, check_tenant_url

        with pytest.raises(UntrustedHostError):
            check_tenant_url("http://eu.ast.checkmarx.net/api", what="platform API URL")

    def test_the_operator_can_allow_a_dedicated_host(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.conftest import make_api_key

        monkeypatch.setenv("CXCG_CX_ALLOWED_HOSTS", "cx.corp.example, other.example")
        reset_settings_cache()
        connection = self._save(
            db, api_key=make_api_key(), api_base_url_override="https://ast.cx.corp.example/api"
        )
        assert connection.api_base_url == "https://ast.cx.corp.example/api"

    def test_a_stored_untrusted_url_is_not_called(self, db: Session) -> None:
        from app.checkmarx.regions import UntrustedHostError
        from app.services import connection as connection_service
        from tests.conftest import make_api_key

        connection = self._save(db, api_key=make_api_key())
        connection.api_base_url = "https://attacker.example/api"  # e.g. edited in the database
        db.commit()
        connection_service.reset_client_cache()
        with pytest.raises(UntrustedHostError):
            connection_service.get_client(db)

    def test_the_api_reports_an_untrusted_host_clearly(self, admin_client: TestClient) -> None:
        from tests.conftest import make_api_key

        response = admin_client.put(
            "/api/connection",
            json={"api_key": make_api_key(), "api_base_url": "https://attacker.example/api"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST, response.text
        assert response.json()["detail"]["code"] == "untrusted_host"
        assert "CXCG_CX_ALLOWED_HOSTS" in response.json()["detail"]["message"]


class TestTracebacksAreRedacted:
    def test_a_secret_quoted_in_an_exception_does_not_reach_the_log(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import logging

        from app.core.logging import configure_logging, register_secret, unregister_secret

        secret = "s3cr3t-webhook-signing-value-123456"
        # A JWT-shaped placeholder (header {"alg":"HS256"}, payload
        # {"sub":"admin","exp":10}, signature "signature-value"), assembled at run
        # time so no token-like literal is committed for secret scanners to flag.
        jwt = ".".join(
            base64.urlsafe_b64encode(part).decode().rstrip("=")
            for part in (b'{"alg":"HS256"}', b'{"sub":"admin","exp":10}', b"signature-value")
        )
        register_secret(secret)
        configure_logging("INFO")
        try:
            try:
                raise RuntimeError(f"POST failed: Authorization: Bearer {jwt} signed with {secret}")
            except RuntimeError:
                logging.getLogger("app.test").exception("Delivery failed")
        finally:
            unregister_secret(secret)
        out = capsys.readouterr().out
        assert "Traceback" in out and "RuntimeError" in out
        assert secret not in out and jwt not in out


class TestMigrationsKeepTheLogHandler:
    def test_logging_is_still_redacted_and_at_info_after_migrating(
        self, tmp_path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Migrations run inside the server process at start-up. They used to
        swap the root log handler for Alembic's own: no redaction, and nothing
        below WARNING, for the rest of the process's life."""
        import logging

        from app.core.logging import configure_logging, register_secret, unregister_secret
        from app.db.migrate import upgrade_to_head

        secret = "s3cr3t-api-key-value-for-logging-9876"
        register_secret(secret)
        configure_logging("INFO")
        try:
            upgrade_to_head(f"sqlite:///{tmp_path / 'migrated.db'}")
            logging.getLogger("app.after_migration").info("Connected with %s", secret)
        finally:
            unregister_secret(secret)
        captured = capsys.readouterr()
        assert "Connected with" in captured.out  # INFO still reaches the log
        assert secret not in captured.out and secret not in captured.err


class TestMasterKeyCheck:
    def test_first_start_records_a_check_value(self, db: Session) -> None:
        from app.models.connection import AppSetting
        from app.services import master_key

        master_key.verify_master_key(db)
        db.commit()
        row = db.get(AppSetting, master_key.CHECK_KEY)
        assert row is not None and row.is_secret and master_key.CHECK_VALUE not in row.value
        # And a later start with the same key passes.
        master_key.verify_master_key(db)

    def _switch_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import base64

        from app.core import crypto

        monkeypatch.setenv("CXCG_MASTER_KEY", base64.b64encode(bytes(range(1, 33))).decode())
        reset_settings_cache()
        crypto.reset_secret_box()

    def test_a_different_key_is_refused(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.core.config import ConfigError
        from app.services import master_key

        master_key.verify_master_key(db)
        db.commit()
        self._switch_key(monkeypatch)
        with pytest.raises(ConfigError, match="master key"):
            master_key.verify_master_key(db)

    def test_an_upgrade_with_the_wrong_key_is_refused_before_vouching_for_it(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A database from before the check existed, started with the wrong key."""
        from app.core.config import ConfigError
        from app.models.connection import AppSetting
        from app.services import connection as connection_service
        from app.services import master_key
        from app.services.audit import AuditActor
        from tests.conftest import make_api_key

        connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        db.commit()
        self._switch_key(monkeypatch)
        with pytest.raises(ConfigError):
            master_key.verify_master_key(db)
        db.rollback()
        assert db.get(AppSetting, master_key.CHECK_KEY) is None

    def test_the_app_refuses_to_start_with_the_wrong_key(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app import main
        from app.core.config import ConfigError
        from app.services import master_key

        master_key.verify_master_key(db)
        db.commit()
        self._switch_key(monkeypatch)
        monkeypatch.setattr(main, "upgrade_to_head", lambda *_a, **_k: None)
        app = main.create_app(get_settings(), run_scheduler=False)
        with pytest.raises(ConfigError), TestClient(app):
            pass


SLACK_STYLE_URL = "https://hooks.chat.example/services/T000/B000/s3cr3tPathToken123456"


class TestWebhookUrlIsASecret:
    def test_it_is_never_returned_stored_in_the_clear_audited_or_backed_up(
        self, admin_client: TestClient, db: Session
    ) -> None:
        from app.models.connection import AppSetting
        from app.services import ops_hardening, settings_store

        saved = admin_client.put("/api/settings", json={"webhook_url": SLACK_STYLE_URL})
        assert saved.status_code == httpx.codes.OK, saved.text
        body = saved.json()
        assert "webhook_url" not in body
        assert body["webhook_url_configured"] is True
        assert body["webhook_host"] == "hooks.chat.example"
        assert "s3cr3tPathToken" not in saved.text

        row = db.get(AppSetting, settings_store.KEY_WEBHOOK_URL)
        assert row.is_secret is True and "s3cr3tPathToken" not in row.value
        # It still works: delivery reads the real value.
        assert settings_store.get_secret(db, settings_store.KEY_WEBHOOK_URL) == SLACK_STYLE_URL

        audit = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "settings.updated"))
        assert "s3cr3tPathToken" not in f"{audit.before}{audit.after}{audit.detail}"
        assert "s3cr3tPathToken" not in str(ops_hardening.export_config_backup(db))
        assert "s3cr3tPathToken" not in admin_client.get("/api/ops/backup").text

    def test_a_viewer_cannot_see_it(self, db: Session, viewer_client: TestClient) -> None:
        from app.services import settings_store

        settings_store.set_secret(db, settings_store.KEY_WEBHOOK_URL, SLACK_STYLE_URL)
        db.commit()
        assert "s3cr3tPathToken" not in viewer_client.get("/api/settings").text

    def test_an_empty_value_clears_it(self, admin_client: TestClient) -> None:
        admin_client.put("/api/settings", json={"webhook_url": SLACK_STYLE_URL})
        cleared = admin_client.put("/api/settings", json={"webhook_url": ""})
        assert cleared.json()["webhook_url_configured"] is False
        assert cleared.json()["webhook_host"] is None

    def test_a_url_stored_in_the_clear_by_an_older_version_is_encrypted_at_start_up(
        self, db: Session
    ) -> None:
        import json

        from app.models.connection import AppSetting
        from app.services import delivery, settings_store

        db.add(
            AppSetting(
                key=settings_store.KEY_WEBHOOK_URL,
                value=json.dumps(SLACK_STYLE_URL),
                is_secret=False,
            )
        )
        db.commit()
        # Usable even before conversion...
        assert delivery.load_config(db).webhook_url == SLACK_STYLE_URL

        assert settings_store.encrypt_legacy_secrets(db) == 1
        db.commit()
        row = db.get(AppSetting, settings_store.KEY_WEBHOOK_URL)
        assert row.is_secret is True and "s3cr3tPathToken" not in row.value
        # ...and after it, and converting twice is harmless.
        assert delivery.load_config(db).webhook_url == SLACK_STYLE_URL
        assert settings_store.encrypt_legacy_secrets(db) == 0


class TestMailServerIsVerified:
    def _config(self, **overrides):
        from app.services.delivery import DeliveryConfig

        values = {
            "min_severity": "warning",
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_username": "cxcg",
            "smtp_password": "mail-password-123",
            "smtp_use_tls": True,
            "smtp_from": "cxcg@example.com",
            "smtp_recipients": ("ops@example.com",),
            "webhook_url": None,
            "webhook_secret": None,
            "tenant_name": "acme",
        }
        values.update(overrides)
        return DeliveryConfig(**values)

    def test_starttls_verifies_the_certificate_and_hostname(self) -> None:
        import ssl

        from app.services import delivery

        seen: dict[str, object] = {}

        class Server:
            def __init__(self, *_args) -> None:
                pass

            def starttls(self, *, context=None) -> None:
                seen["context"] = context

            def login(self, *_args) -> None:
                seen["login"] = True

            def send_message(self, _message) -> None:
                seen["sent"] = True

            def quit(self) -> None:
                pass

        delivery.send_report_email(
            config=self._config(), subject="s", text_body="b", smtp_factory=Server
        )
        context = seen["context"]
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname is True
        assert seen["login"] and seen["sent"]

    def test_an_unverifiable_certificate_stops_the_send_before_the_password(self) -> None:
        import ssl

        from app.services import delivery

        calls: list[str] = []

        class Impostor:
            def __init__(self, *_args) -> None:
                pass

            def starttls(self, *, context=None) -> None:
                raise ssl.SSLCertVerificationError(1, "certificate verify failed: self-signed")

            def login(self, *_args) -> None:
                calls.append("login")

            def send_message(self, _message) -> None:
                calls.append("send")

            def quit(self) -> None:
                pass

        with pytest.raises(delivery.DeliveryError, match="CXCG_SMTP_CA_FILE"):
            delivery.send_report_email(
                config=self._config(), subject="s", text_body="b", smtp_factory=Impostor
            )
        assert calls == []

    def test_the_password_is_never_sent_without_tls(self) -> None:
        from app.services import delivery

        calls: list[str] = []

        class Plain:
            def __init__(self, *_args) -> None:
                pass

            def login(self, *_args) -> None:
                calls.append("login")

            def send_message(self, _message) -> None:
                calls.append("send")

            def quit(self) -> None:
                pass

        with pytest.raises(delivery.DeliveryError, match="without TLS"):
            delivery.send_report_email(
                config=self._config(smtp_use_tls=False),
                subject="s",
                text_body="b",
                smtp_factory=Plain,
            )
        assert calls == []


# ----------------------------------------------------------------------------
# Findings from the independent security review
# ----------------------------------------------------------------------------


class TestUpgradeStartUp:
    """The real start-up order, on a database written by an older version."""

    def _start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app import main

        monkeypatch.setattr(main, "upgrade_to_head", lambda *_a, **_k: None)
        main._startup(get_settings())

    @pytest.mark.parametrize("stored", ['"https://hooks.chat.example/T0/B0/tok"', "null", '""'])
    def test_a_webhook_url_stored_in_the_clear_does_not_stop_the_app_starting(
        self, db: Session, monkeypatch: pytest.MonkeyPatch, stored: str
    ) -> None:
        from app.models.connection import AppSetting
        from app.services import master_key, settings_store

        db.add(AppSetting(key=settings_store.KEY_WEBHOOK_URL, value=stored, is_secret=False))
        db.commit()

        self._start(monkeypatch)  # used to raise "master key is not the one..."

        db.expire_all()
        assert db.get(AppSetting, master_key.CHECK_KEY) is not None
        row = db.get(AppSetting, settings_store.KEY_WEBHOOK_URL)
        assert row.is_secret is True
        expected = "https://hooks.chat.example/T0/B0/tok" if "hooks" in stored else None
        assert settings_store.get_secret(db, settings_store.KEY_WEBHOOK_URL) == expected

    def test_a_connection_on_a_host_that_is_no_longer_allowed_is_reported(
        self, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.models import Notification
        from app.models.enums import ConnectionStatus
        from app.services import connection as connection_service
        from app.services.audit import AuditActor
        from tests.conftest import make_api_key

        connection = connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        connection.api_base_url = "https://ast.dedicated.example/api"  # set before the rule
        db.commit()

        self._start(monkeypatch)

        db.expire_all()
        assert connection_service.get_connection(db).status == ConnectionStatus.FAILED
        alert = db.scalar(select(Notification).where(Notification.title.like("%is blocked")))
        assert alert is not None and "CXCG_CX_ALLOWED_HOSTS" in alert.body

    def test_two_factor_secrets_are_part_of_the_key_check(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import base64

        from app.core import crypto
        from app.core.config import ConfigError
        from app.services import master_key

        auth_service.provision_totp(db, user=admin_user)
        db.commit()
        monkeypatch.setenv("CXCG_MASTER_KEY", base64.b64encode(bytes(range(1, 33))).decode())
        reset_settings_cache()
        crypto.reset_secret_box()
        with pytest.raises(ConfigError):
            master_key.verify_master_key(db)


class TestForwardedHeaderLines:
    def test_a_proxy_that_adds_its_own_header_line_is_still_the_one_believed(
        self, one_trusted_proxy: None
    ) -> None:
        """Some proxies add a second X-Forwarded-For line instead of appending."""
        request = Request(
            {
                "type": "http",
                "client": ("172.18.0.3", 1234),
                "headers": [
                    (b"x-forwarded-for", b"6.6.6.6"),  # sent by the client
                    (b"x-forwarded-for", b"203.0.113.7"),  # added by the proxy
                ],
            }
        )
        assert client_ip(request) == "203.0.113.7"

    def test_a_forged_header_cannot_dodge_the_throttle_behind_a_proxy(
        self, one_trusted_proxy: None, db: Session, admin_user: UtilityUser
    ) -> None:
        outcomes = []
        for n in range(8):
            ip = client_ip(_request("172.18.0.3", f"198.51.100.{n}, 203.0.113.7"))
            try:
                auth_service.authenticate(db, username="admin", password="x", ip_address=ip)
            except auth_service.AuthError as exc:
                outcomes.append(type(exc))
            db.commit()
        assert auth_service.AccountLocked in outcomes


class TestAccountWideLock:
    def _age_account_failures(self, db: Session, username: str = "admin") -> None:
        from datetime import timedelta

        row = db.scalar(
            select(LoginAttempt).where(
                LoginAttempt.identifier == username,
                LoginAttempt.ip_address == auth_service.ACCOUNT_WIDE,
            )
        )
        row.last_attempt_at = row.last_attempt_at - auth_service.ACCOUNT_FAILURE_WINDOW * 2
        for source in db.scalars(
            select(LoginAttempt).where(
                LoginAttempt.identifier == username,
                LoginAttempt.ip_address != auth_service.ACCOUNT_WIDE,
            )
        ):
            source.locked_until = None
            source.window_started_at = source.window_started_at - timedelta(hours=3)
        db.commit()

    def test_one_patient_address_never_locks_the_owner_out(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        """It waits out its own lockout and tries again, for days."""
        settings = get_settings()
        needed = settings.login_max_attempts * auth_service.ACCOUNT_LOCK_MULTIPLIER
        for _ in range(needed // settings.login_max_attempts + 3):
            _fail(db, ip="203.0.113.50", times=settings.login_max_attempts)
            self._age_account_failures(db)

        user = auth_service.authenticate(
            db, username="admin", password=ADMIN_PASSWORD, ip_address="198.51.100.4"
        )
        assert user.id == admin_user.id

    def test_the_owner_at_a_known_address_gets_in_during_a_distributed_attack(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        settings = get_settings()
        auth_service.issue_session(db, user=admin_user, ip_address="198.51.100.4")
        db.commit()
        per_address = settings.login_max_attempts - 1
        needed = settings.login_max_attempts * auth_service.ACCOUNT_LOCK_MULTIPLIER
        for n in range(-(-needed // per_address)):
            _fail(db, ip=f"203.0.113.{n}", times=per_address)

        # A stranger with the right password is still held off...
        with pytest.raises(auth_service.AccountLocked):
            auth_service.authenticate(
                db, username="admin", password=ADMIN_PASSWORD, ip_address="192.0.2.99"
            )
        db.rollback()
        # ...but not the owner where they have signed in before.
        assert auth_service.authenticate(
            db, username="admin", password=ADMIN_PASSWORD, ip_address="198.51.100.4"
        )

    def test_the_account_wide_lock_does_not_reveal_which_usernames_exist(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        settings = get_settings()
        per_address = settings.login_max_attempts - 1
        needed = settings.login_max_attempts * auth_service.ACCOUNT_LOCK_MULTIPLIER
        for username in ("admin", "nobody"):
            for n in range(-(-needed // per_address)):
                _fail(db, ip=f"203.0.113.{n}", times=per_address, username=username)
            with pytest.raises(auth_service.AccountLocked):
                auth_service.authenticate(
                    db, username=username, password="whatever", ip_address="192.0.2.77"
                )
            db.rollback()

    def test_a_disabled_account_is_only_revealed_to_someone_with_the_password(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        admin_user.is_active = False
        db.commit()
        with pytest.raises(auth_service.InvalidCredentials):
            auth_service.authenticate(db, username="admin", password="wrong", ip_address="1.1.1.1")
        db.commit()
        with pytest.raises(auth_service.AccountDisabled):
            auth_service.authenticate(
                db, username="admin", password=ADMIN_PASSWORD, ip_address="1.1.1.1"
            )

    def test_an_ipv6_client_is_throttled_as_its_whole_network(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        assert auth_service.throttle_address("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::/64"
        assert auth_service.throttle_address("203.0.113.7") == "203.0.113.7"
        assert auth_service.throttle_address("testclient") == "testclient"

        outcomes = []
        for n in range(get_settings().login_max_attempts + 1):
            try:
                auth_service.authenticate(
                    db, username="admin", password="x", ip_address=f"2001:db8:1:2::{n + 1:x}"
                )
            except auth_service.AuthError as exc:
                outcomes.append(type(exc))
            db.commit()
        assert outcomes[-1] is auth_service.AccountLocked


class TestRecoveryCodeStorage:
    def test_codes_are_long_and_stored_keyed_not_merely_hashed(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        import hashlib

        codes = auth_service.issue_recovery_codes(db, user=admin_user)
        raw = codes[0].replace("-", "")
        assert len(raw) * 4 >= 80  # bits
        stored = admin_user.totp_recovery_codes
        assert hashlib.sha256(raw.encode()).hexdigest() not in stored
        assert auth_service.use_recovery_code(db, user=admin_user, code=codes[0]) is True
        assert auth_service.use_recovery_code(db, user=admin_user, code=codes[0]) is False


class TestOldBackups:
    def test_a_backup_from_before_the_webhook_was_a_secret_still_restores_it(
        self, db: Session
    ) -> None:
        from app.models.connection import AppSetting
        from app.services import ops_hardening, settings_store
        from app.services.audit import AuditActor

        backup = {
            "backup_version": 1,
            "settings": {settings_store.KEY_WEBHOOK_URL: SLACK_STYLE_URL},
            "limits": [],
            "exemptions": [],
        }
        ops_hardening.restore_config_backup(db, data=backup, actor=AuditActor.system("test"))
        db.commit()
        assert settings_store.get_secret(db, settings_store.KEY_WEBHOOK_URL) == SLACK_STYLE_URL
        assert db.get(AppSetting, settings_store.KEY_WEBHOOK_URL).is_secret is True
        assert "s3cr3tPathToken" not in str(ops_hardening.export_config_backup(db))


class TestImplicitTls:
    def test_port_465_uses_tls_from_the_first_byte(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import smtplib
        import ssl

        from app.services import delivery

        made: dict[str, object] = {}

        class FakeSmtps:
            def __init__(self, host, port, timeout, context) -> None:
                made.update(host=host, port=port, context=context)

        monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSmtps)
        delivery._default_smtp_factory("smtp.example.com", 465, 5.0)
        assert made["port"] == 465
        assert isinstance(made["context"], ssl.SSLContext)
        assert made["context"].verify_mode == ssl.CERT_REQUIRED

    def test_no_starttls_and_credentials_allowed_on_465(self) -> None:
        from app.services import delivery

        calls: list[str] = []

        class Server:
            def __init__(self, *_args) -> None:
                pass

            def starttls(self, *, context=None) -> None:
                calls.append("starttls")

            def login(self, *_args) -> None:
                calls.append("login")

            def send_message(self, _message) -> None:
                calls.append("send")

            def quit(self) -> None:
                pass

        config = TestMailServerIsVerified()._config(smtp_port=465, smtp_use_tls=False)
        delivery.send_report_email(config=config, subject="s", text_body="b", smtp_factory=Server)
        assert calls == ["login", "send"]

    def test_a_missing_ca_file_is_explained(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.services import delivery

        monkeypatch.setenv("CXCG_SMTP_CA_FILE", "/nonexistent/ca.pem")
        reset_settings_cache()
        with pytest.raises(delivery.DeliveryError, match="CXCG_SMTP_CA_FILE"):
            delivery._tls_context()


class TestMalformedUrls:
    @pytest.mark.parametrize("url", ["https://[bad", "https://eu.ast.checkmarx.net:notaport/api"])
    def test_a_malformed_tenant_url_is_refused_not_a_server_error(self, url: str) -> None:
        from app.checkmarx.regions import UntrustedHostError, check_tenant_url

        with pytest.raises(UntrustedHostError):
            check_tenant_url(url, what="platform API URL")

    def test_a_blank_webhook_url_is_not_stored_as_configured(
        self, admin_client: TestClient
    ) -> None:
        body = admin_client.put("/api/settings", json={"webhook_url": "   "}).json()
        assert body["webhook_url_configured"] is False


class TestResetSecrets:
    def test_it_clears_stored_secrets_and_lets_a_new_key_start(
        self, db: Session, admin_user: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import base64

        from app.core import crypto
        from app.models import CreditLimit
        from app.models.connection import AppSetting
        from app.services import connection as connection_service
        from app.services import master_key, settings_store
        from app.services.audit import AuditActor
        from scripts import reset_secrets
        from tests.conftest import make_api_key

        connection_service.save_connection(
            db, api_key=make_api_key(), actor=AuditActor.system("test")
        )
        settings_store.set_secret(db, settings_store.KEY_SMTP_PASSWORD, "mail-password")
        auth_service.provision_totp(db, user=admin_user)
        db.add(CreditLimit(entity_type="user", entity_id="u1", credit_limit=5))
        master_key.verify_master_key(db)
        db.commit()

        # The key is lost; a new one is configured.
        monkeypatch.setenv("CXCG_MASTER_KEY", base64.b64encode(bytes(range(1, 33))).decode())
        reset_settings_cache()
        crypto.reset_secret_box()

        assert reset_secrets.main([]) == 2  # refuses without --yes
        assert reset_secrets.main(["--yes"]) == 0

        db.expire_all()
        assert connection_service.get_connection(db) is None
        assert db.get(AppSetting, settings_store.KEY_SMTP_PASSWORD) is None
        assert admin_user.totp_secret_encrypted is None
        assert db.scalar(select(CreditLimit)) is not None  # everything else is kept
        master_key.verify_master_key(db)  # and the app can start with the new key


class TestBootstrapAdmin:
    def test_the_password_from_the_environment_is_for_the_first_sign_in_only(
        self, client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It sits in an .env file or a start-up log, readable long afterwards."""
        monkeypatch.setenv("CXCG_BOOTSTRAP_ADMIN_USERNAME", "firstadmin")
        monkeypatch.setenv("CXCG_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
        reset_settings_cache()
        user = auth_service.bootstrap_admin_if_needed(db)
        db.commit()
        assert user is not None and user.must_change_password is True

        signed_in = client.post(
            "/api/auth/login", json={"username": "firstadmin", "password": ADMIN_PASSWORD}
        )
        assert signed_in.json()["must_change_password"] is True
        assert client.get("/api/limits").status_code == 403


class TestRecoverAdmin:
    def test_the_only_admin_gets_back_in_with_a_temporary_password(
        self,
        client: TestClient,
        db: Session,
        admin_user: UtilityUser,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from scripts import recover_admin

        auth_service.provision_totp(db, user=admin_user)
        admin_user.totp_enabled = True
        db.commit()
        for _ in range(3):  # leave a lockout counter behind for the account
            client.post(
                "/api/auth/login", json={"username": admin_user.username, "password": "wrong"}
            )
        assert db.scalar(select(LoginAttempt)) is not None

        assert recover_admin.main([]) == 2  # explains itself, changes nothing
        assert recover_admin.main(["nobody"]) == 1
        capsys.readouterr()
        assert recover_admin.main([admin_user.username]) == 0
        line = capsys.readouterr().out.splitlines()[0]
        temporary = line.rsplit(": ", 1)[1]

        db.expire_all()
        assert admin_user.totp_enabled is False
        assert admin_user.must_change_password is True
        assert (
            db.scalar(select(LoginAttempt).where(LoginAttempt.identifier == admin_user.username))
            is None
        )
        assert db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "account.recovered"))

        # The old password no longer works, the temporary one does, without a code.
        assert (
            client.post(
                "/api/auth/login",
                json={"username": admin_user.username, "password": ADMIN_PASSWORD},
            ).status_code
            == 401
        )
        signed_in = client.post(
            "/api/auth/login", json={"username": admin_user.username, "password": temporary}
        )
        assert signed_in.status_code == 200
        assert signed_in.json()["must_change_password"] is True


@postgres_only
class TestRecoveryCodeRace:
    def test_two_simultaneous_sign_ins_cannot_both_spend_one_code(
        self, db: Session, admin_user: UtilityUser
    ) -> None:
        """On PostgreSQL both used to read the code as unused."""
        import threading

        from app.db.session import get_session_factory

        codes = auth_service.issue_recovery_codes(db, user=admin_user)
        db.commit()
        barrier = threading.Barrier(2)
        results: list[bool] = []

        def spend() -> None:
            session = get_session_factory()()
            try:
                user = session.get(UtilityUser, admin_user.id)
                barrier.wait(timeout=10)
                results.append(auth_service.use_recovery_code(session, user=user, code=codes[0]))
                session.commit()
            finally:
                session.close()

        threads = [threading.Thread(target=spend) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        assert sorted(results) == [False, True]


class TestSingleInstance:
    """Two copies against one database would each run a scheduler, and neither
    would see the other's per-target locks."""

    def test_a_second_instance_is_refused(self, db: Session) -> None:
        import subprocess
        import sys

        from app.core.config import ConfigError
        from app.db import instance_guard
        from app.db.session import get_engine

        url = get_settings().database_url
        other = subprocess.Popen(  # noqa: S603 - our own interpreter and a fixed script
            [
                sys.executable,
                "-c",
                "import sys, time\n"
                "from app.db import instance_guard\n"
                "from app.db.session import build_engine\n"
                "instance_guard.acquire(build_engine(sys.argv[1]))\n"
                "print('claimed', flush=True)\n"
                "time.sleep(30)\n",
                url,
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            assert other.stdout.readline().strip() == "claimed"
            with pytest.raises(ConfigError, match="already running"):
                instance_guard.acquire(get_engine())
        finally:
            other.kill()
            other.wait(10)

        # The claim goes with the process that held it: its replacement starts.
        instance_guard.acquire(get_engine())
        instance_guard.release()

    def test_a_filesystem_that_cannot_lock_does_not_stop_the_app(
        self, db: Session, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Only "someone else holds it" means a second instance. A mount that
        cannot lock at all must not look like one, for ever."""
        import fcntl

        from sqlalchemy import create_engine

        from app.db import instance_guard

        def unsupported(*_args: object) -> None:
            raise OSError(95, "Operation not supported")

        monkeypatch.setattr(fcntl, "flock", unsupported)
        engine = create_engine(f"sqlite:///{tmp_path / 'sub' / 'x.db'}")
        assert instance_guard._acquire_sqlite(engine) is None

    def test_starting_the_app_twice_in_one_process_is_allowed(self, db: Session) -> None:
        from app.db import instance_guard
        from app.db.session import get_engine

        instance_guard.acquire(get_engine())
        instance_guard.acquire(get_engine())
        instance_guard.release()
        instance_guard.release()

    @postgres_only
    def test_a_claim_lost_with_its_connection_is_taken_again(self, db: Session) -> None:
        """The advisory lock dies with its connection (a database restart, a
        dropped socket). The scheduler re-checks before each cycle."""
        import subprocess
        import sys
        import time

        from sqlalchemy import text

        from app.db import instance_guard
        from app.db.session import get_engine

        engine = get_engine()

        def drop_the_claim() -> None:
            pid = instance_guard._held.execute(text("SELECT pg_backend_pid()")).scalar()
            instance_guard._held.commit()
            with engine.connect() as other:
                other.execute(text("SELECT pg_terminate_backend(:pid)"), {"pid": pid})
                other.commit()
                for _ in range(100):
                    gone = other.execute(
                        text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"),
                        {"pid": pid},
                    ).scalar()
                    other.commit()
                    if not gone:
                        return
                    time.sleep(0.05)
            raise AssertionError("the claim's connection was not terminated")

        instance_guard.acquire(engine)
        try:
            assert instance_guard.still_held(engine) is True
            drop_the_claim()
            assert instance_guard.still_held(engine) is True  # taken again
            assert instance_guard._held is not None

            # Lost again, and this time another instance gets there first.
            drop_the_claim()
            rival = subprocess.Popen(  # noqa: S603 - our own interpreter and a fixed script
                [
                    sys.executable,
                    "-c",
                    "import sys, time\n"
                    "from app.db import instance_guard\n"
                    "from app.db.session import build_engine\n"
                    "instance_guard.acquire(build_engine(sys.argv[1]))\n"
                    "print('claimed', flush=True)\n"
                    "time.sleep(30)\n",
                    get_settings().database_url,
                ],
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                assert rival.stdout.readline().strip() == "claimed"
                assert instance_guard.still_held(engine) is False
                assert instance_guard.still_held(engine) is False  # and keeps saying so
            finally:
                rival.kill()
                rival.wait(10)
            assert instance_guard.still_held(engine) is True  # the rival is gone
        finally:
            instance_guard.release()
