"""Login, session, CSRF and RBAC behaviour through the HTTP API."""

from __future__ import annotations

import httpx
import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import AuditLogEntry, UtilityUser
from app.models.enums import UtilityRole
from app.services import auth as auth_service
from app.services.audit import AuditActor
from tests.conftest import ADMIN_PASSWORD, login


class TestLogin:
    def test_valid_login_sets_both_cookies(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["username"] == "admin"
        assert body["role"] == "admin"
        assert "cxcg_session" in response.cookies
        assert "cxcg_csrf" in response.cookies

    def test_session_cookie_is_httponly_and_strict(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        cookie_headers = [
            value
            for key, value in response.headers.multi_items()
            if key.lower() == "set-cookie" and value.startswith("cxcg_session=")
        ]
        assert len(cookie_headers) == 1
        header = cookie_headers[0]
        assert "HttpOnly" in header
        assert "SameSite=strict" in header.replace("SameSite=Strict", "SameSite=strict")
        assert "Path=/" in header

    def test_csrf_cookie_is_readable_by_script(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        """The SPA has to read it to echo it back in the header."""
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        header = next(
            value
            for key, value in response.headers.multi_items()
            if key.lower() == "set-cookie" and value.startswith("cxcg_csrf=")
        )
        assert "HttpOnly" not in header

    def test_wrong_password_is_rejected(self, client: TestClient, admin_user: UtilityUser) -> None:
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong-one"}
        )
        assert response.status_code == httpx.codes.UNAUTHORIZED
        assert response.json()["detail"]["code"] == "invalid_credentials"

    def test_unknown_user_gets_the_same_message_as_a_wrong_password(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        unknown = client.post(
            "/api/auth/login", json={"username": "nobody", "password": "wrong-one"}
        )
        wrong = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-one"})
        assert unknown.status_code == wrong.status_code
        assert unknown.json()["detail"]["message"] == wrong.json()["detail"]["message"]

    def test_disabled_account_cannot_log_in(
        self, client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        admin_user.is_active = False
        db.commit()
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert response.status_code == httpx.codes.FORBIDDEN
        assert response.json()["detail"]["code"] == "account_disabled"

    def test_malformed_payload_is_rejected(self, client: TestClient) -> None:
        response = client.post("/api/auth/login", json={"username": "a", "password": ""})
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY

    def test_extra_fields_are_rejected(self, client: TestClient, admin_user: UtilityUser) -> None:
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD, "role": "admin"},
        )
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY


class TestLockoutAndRateLimit:
    def test_account_locks_after_repeated_failures(
        self, client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        settings = get_settings()
        for _ in range(settings.login_max_attempts):
            client.post("/api/auth/login", json={"username": "admin", "password": "wrong-one"})
        response = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert response.status_code == httpx.codes.LOCKED
        assert "Retry-After" in response.headers
        assert response.json()["detail"]["code"] == "account_locked"

    def test_rate_limit_fires_before_the_lockout_when_attempts_are_fast(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        settings = get_settings()
        statuses = [
            client.post(
                "/api/auth/login", json={"username": "admin", "password": "wrong-one"}
            ).status_code
            for _ in range(settings.login_rate_limit_per_minute + 3)
        ]
        assert httpx.codes.TOO_MANY_REQUESTS in statuses

    def test_admin_can_unlock_an_account(
        self, admin_client: TestClient, db: Session, viewer_user: UtilityUser
    ) -> None:
        settings = get_settings()
        viewer_user.failed_login_count = settings.login_max_attempts
        from datetime import timedelta

        from app.db.base import utcnow

        viewer_user.locked_until = utcnow() + timedelta(hours=1)
        db.commit()

        response = admin_client.post(f"/api/accounts/{viewer_user.id}/unlock")
        assert response.status_code == httpx.codes.OK
        db.refresh(viewer_user)
        assert viewer_user.locked_until is None
        assert viewer_user.failed_login_count == 0


class TestSessionLifecycle:
    def test_session_endpoint_requires_a_cookie(self, client: TestClient) -> None:
        assert client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED

    def test_session_endpoint_returns_the_current_user(self, admin_client: TestClient) -> None:
        response = admin_client.get("/api/auth/session")
        assert response.status_code == httpx.codes.OK
        assert response.json()["username"] == "admin"

    def test_logout_revokes_the_session(self, admin_client: TestClient) -> None:
        assert admin_client.post("/api/auth/logout").status_code == httpx.codes.OK
        assert admin_client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED

    def test_a_revoked_session_cookie_stops_working(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        auth_service.revoke_all_sessions(db, user_id=admin_user.id)
        db.commit()
        assert admin_client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED

    def test_a_forged_session_cookie_is_rejected(self, client: TestClient) -> None:
        client.cookies.set("cxcg_session", "forged-token-value")
        assert client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED

    def test_expired_session_is_rejected(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        from datetime import timedelta

        from app.db.base import utcnow
        from app.models import UtilitySession

        row = db.scalars(
            select(UtilitySession).where(UtilitySession.user_id == admin_user.id)
        ).one()
        row.idle_expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
        assert admin_client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED

    def test_deactivating_a_user_kills_their_live_session(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        admin_user.is_active = False
        db.commit()
        assert admin_client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED


class TestCsrf:
    def test_state_change_without_the_header_is_forbidden(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        # Log in without copying the CSRF cookie into the header.
        assert (
            client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        ).status_code == httpx.codes.OK
        response = client.post("/api/auth/logout")
        assert response.status_code == httpx.codes.FORBIDDEN
        assert "X-CSRF-Token" in response.json()["detail"]

    def test_state_change_with_a_wrong_header_is_forbidden(self, admin_client: TestClient) -> None:
        admin_client.headers["X-CSRF-Token"] = "not-the-right-token"
        assert admin_client.post("/api/auth/logout").status_code == httpx.codes.FORBIDDEN

    def test_reads_do_not_require_the_header(
        self, client: TestClient, admin_user: UtilityUser
    ) -> None:
        client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert client.get("/api/auth/session").status_code == httpx.codes.OK


class TestRbac:
    def test_viewer_cannot_create_accounts(self, viewer_client: TestClient) -> None:
        response = viewer_client.post(
            "/api/accounts",
            json={"username": "newbie", "password": "An0ther!Str0ng#1", "role": "viewer"},
        )
        assert response.status_code == httpx.codes.FORBIDDEN
        assert "Admin role" in response.json()["detail"]

    def test_viewer_cannot_change_the_connection(self, viewer_client: TestClient) -> None:
        assert viewer_client.post("/api/connection/test").status_code == httpx.codes.FORBIDDEN

    def test_viewer_can_read_the_connection(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/connection").status_code == httpx.codes.OK

    def test_admin_can_create_a_viewer(self, admin_client: TestClient) -> None:
        response = admin_client.post(
            "/api/accounts",
            json={"username": "newbie", "password": "An0ther!Str0ng#1", "role": "viewer"},
        )
        assert response.status_code == httpx.codes.CREATED
        assert response.json()["role"] == "viewer"

    def test_weak_password_is_rejected_with_reasons(self, admin_client: TestClient) -> None:
        response = admin_client.post(
            "/api/accounts",
            json={"username": "newbie", "password": "password1234", "role": "viewer"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["problems"]

    def test_duplicate_username_is_rejected(
        self, admin_client: TestClient, viewer_user: UtilityUser
    ) -> None:
        response = admin_client.post(
            "/api/accounts",
            json={"username": "viewer", "password": "An0ther!Str0ng#1", "role": "viewer"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST


class TestLastAdminProtection:
    def test_cannot_demote_yourself(
        self, admin_client: TestClient, admin_user: UtilityUser
    ) -> None:
        response = admin_client.patch(f"/api/accounts/{admin_user.id}", json={"role": "viewer"})
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "self_demotion"

    def test_cannot_delete_yourself(
        self, admin_client: TestClient, admin_user: UtilityUser
    ) -> None:
        response = admin_client.delete(f"/api/accounts/{admin_user.id}")
        assert response.json()["detail"]["code"] == "self_delete"

    def test_cannot_demote_the_last_other_admin(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        second = auth_service.create_user(
            db,
            username="admin2",
            password="An0ther!Str0ng#1",
            role=UtilityRole.ADMIN,
            actor=AuditActor.system("test"),
        )
        db.commit()
        # Two admins exist, so demoting the second one is allowed.
        assert (
            admin_client.patch(f"/api/accounts/{second.id}", json={"role": "viewer"}).status_code
            == httpx.codes.OK
        )

    def test_deleting_an_account_revokes_nothing_of_the_actor(
        self, admin_client: TestClient, db: Session, viewer_user: UtilityUser
    ) -> None:
        assert admin_client.delete(f"/api/accounts/{viewer_user.id}").status_code == httpx.codes.OK
        assert admin_client.get("/api/auth/session").status_code == httpx.codes.OK


class TestPasswordChange:
    def test_wrong_current_password_is_rejected(self, admin_client: TestClient) -> None:
        response = admin_client.post(
            "/api/auth/password",
            json={"current_password": "nope-not-it", "new_password": "An0ther!Str0ng#1"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "wrong_password"

    def test_change_succeeds_and_revokes_sessions(
        self, admin_client: TestClient, client: TestClient
    ) -> None:
        response = admin_client.post(
            "/api/auth/password",
            json={"current_password": ADMIN_PASSWORD, "new_password": "An0ther!Str0ng#1"},
        )
        assert response.status_code == httpx.codes.OK
        assert admin_client.get("/api/auth/session").status_code == httpx.codes.UNAUTHORIZED
        assert login(client, "admin", "An0ther!Str0ng#1").status_code == httpx.codes.OK

    def test_weak_new_password_is_rejected(self, admin_client: TestClient) -> None:
        response = admin_client.post(
            "/api/auth/password",
            json={"current_password": ADMIN_PASSWORD, "new_password": "password12345"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "weak_password"


REAUTH = {"current_password": ADMIN_PASSWORD}


def _enable_totp(admin_client: TestClient) -> tuple[str, list[str]]:
    secret = admin_client.post("/api/auth/totp/enroll", json=REAUTH).json()["secret"]
    confirm = admin_client.post("/api/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert confirm.status_code == httpx.codes.OK, confirm.text
    return secret, confirm.json()["recovery_codes"]


class TestTotp:
    def test_enrolment_then_login_requires_a_code(
        self, admin_client: TestClient, client: TestClient
    ) -> None:
        enroll = admin_client.post("/api/auth/totp/enroll", json=REAUTH)
        assert enroll.status_code == httpx.codes.OK
        secret = enroll.json()["secret"]
        assert "otpauth://" in enroll.json()["otpauth_uri"]

        confirm = admin_client.post(
            "/api/auth/totp/confirm", json={"code": pyotp.TOTP(secret).now()}
        )
        assert confirm.status_code == httpx.codes.OK

        admin_client.post("/api/auth/logout")

        without_code = client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert without_code.status_code == httpx.codes.UNAUTHORIZED
        assert without_code.json()["detail"]["code"] == "totp_required"

        with_code = login(client, "admin", ADMIN_PASSWORD, pyotp.TOTP(secret).now())
        assert with_code.status_code == httpx.codes.OK

    def test_wrong_confirmation_code_does_not_enable_totp(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        admin_client.post("/api/auth/totp/enroll", json=REAUTH)
        response = admin_client.post("/api/auth/totp/confirm", json={"code": "000000"})
        assert response.status_code == httpx.codes.BAD_REQUEST
        db.refresh(admin_user)
        assert admin_user.totp_enabled is False

    def test_secret_is_stored_encrypted(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        secret = admin_client.post("/api/auth/totp/enroll", json=REAUTH).json()["secret"]
        db.refresh(admin_user)
        assert admin_user.totp_secret_encrypted is not None
        assert secret not in admin_user.totp_secret_encrypted

    def test_totp_can_be_removed(self, admin_client: TestClient) -> None:
        _enable_totp(admin_client)
        response = admin_client.post("/api/auth/totp/disable", json=REAUTH)
        assert response.status_code == httpx.codes.OK
        assert admin_client.get("/api/auth/session").json()["totp_enabled"] is False

    def test_enrolling_needs_the_password_not_just_a_session(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        """A hijacked or unattended session must not be able to add its own
        authenticator and lock the owner out."""
        missing = admin_client.post("/api/auth/totp/enroll")
        assert missing.status_code == httpx.codes.UNPROCESSABLE_ENTITY
        wrong = admin_client.post("/api/auth/totp/enroll", json={"current_password": "nope"})
        assert wrong.status_code == httpx.codes.BAD_REQUEST
        assert wrong.json()["detail"]["code"] == "wrong_password"
        db.refresh(admin_user)
        assert admin_user.totp_secret_encrypted is None

    def test_disabling_needs_the_password(self, admin_client: TestClient) -> None:
        _enable_totp(admin_client)
        wrong = admin_client.post("/api/auth/totp/disable", json={"current_password": "nope"})
        assert wrong.status_code == httpx.codes.BAD_REQUEST
        assert admin_client.get("/api/auth/session").json()["totp_enabled"] is True

    def test_password_rechecks_are_throttled(self, admin_client: TestClient) -> None:
        statuses = [
            admin_client.post(
                "/api/auth/totp/enroll", json={"current_password": f"guess-{n}"}
            ).status_code
            for n in range(14)
        ]
        assert statuses[0] == httpx.codes.BAD_REQUEST
        assert statuses[-1] == httpx.codes.TOO_MANY_REQUESTS


class TestRecoveryCodes:
    def test_codes_are_issued_once_and_stored_only_as_digests(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        _secret, codes = _enable_totp(admin_client)
        assert len(codes) == 10 and len(set(codes)) == 10
        db.refresh(admin_user)
        stored = admin_user.totp_recovery_codes
        assert len(stored) == 10
        assert not any(code in str(stored) for code in codes)

    def test_a_recovery_code_signs_in_once(
        self, admin_client: TestClient, client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        _secret, codes = _enable_totp(admin_client)
        admin_client.post("/api/auth/logout")

        first = login(client, "admin", ADMIN_PASSWORD, codes[0])
        assert first.status_code == httpx.codes.OK, first.text
        client.post("/api/auth/logout")
        db.refresh(admin_user)
        assert len(admin_user.totp_recovery_codes) == 9
        assert "auth.recovery_code_used" in db.scalars(select(AuditLogEntry.action)).all()

        again = login(client, "admin", ADMIN_PASSWORD, codes[0])
        assert again.status_code == httpx.codes.UNAUTHORIZED
        assert again.json()["detail"]["code"] == "invalid_credentials"

    def test_a_made_up_code_is_refused(self, admin_client: TestClient, client: TestClient) -> None:
        _enable_totp(admin_client)
        admin_client.post("/api/auth/logout")
        response = login(client, "admin", ADMIN_PASSWORD, "aaaa-bbbb-cccc")
        assert response.status_code == httpx.codes.UNAUTHORIZED

    def test_disabling_discards_the_codes(
        self, admin_client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        _enable_totp(admin_client)
        admin_client.post("/api/auth/totp/disable", json=REAUTH)
        db.refresh(admin_user)
        assert admin_user.totp_recovery_codes is None


class TestAdminTotpReset:
    def test_an_admin_can_reset_a_lost_authenticator(
        self,
        admin_client: TestClient,
        db: Session,
        viewer_user: UtilityUser,
    ) -> None:
        from app.services import auth as auth_service
        from app.services.audit import AuditActor

        secret, _uri = auth_service.provision_totp(db, user=viewer_user)
        auth_service.confirm_totp(
            db, user=viewer_user, code=pyotp.TOTP(secret).now(), actor=AuditActor.system("test")
        )
        db.commit()

        response = admin_client.post(f"/api/accounts/{viewer_user.id}/totp/reset")
        assert response.status_code == httpx.codes.OK
        db.refresh(viewer_user)
        assert viewer_user.totp_enabled is False
        assert viewer_user.totp_secret_encrypted is None
        assert viewer_user.totp_recovery_codes is None
        assert "account.totp_reset" in db.scalars(select(AuditLogEntry.action)).all()

    def test_a_viewer_cannot_reset_anyones_authenticator(
        self, viewer_client: TestClient, viewer_user: UtilityUser
    ) -> None:
        response = viewer_client.post(f"/api/accounts/{viewer_user.id}/totp/reset")
        assert response.status_code == httpx.codes.FORBIDDEN


class TestForcedPasswordChange:
    def _temporary_account(self, admin_client: TestClient) -> None:
        created = admin_client.post(
            "/api/accounts",
            json={
                "username": "newbie",
                "password": "Xk7!vQ2#mTz9@Lr4",
                "role": "viewer",
                "must_change_password": True,
            },
        )
        assert created.status_code in (httpx.codes.OK, httpx.codes.CREATED), created.text
        admin_client.post("/api/auth/logout")

    def test_nothing_else_is_reachable_until_the_password_is_changed(
        self, admin_client: TestClient, client: TestClient
    ) -> None:
        self._temporary_account(admin_client)
        signed_in = login(client, "newbie", "Xk7!vQ2#mTz9@Lr4")
        assert signed_in.status_code == httpx.codes.OK
        assert signed_in.json()["must_change_password"] is True

        blocked = client.get("/api/limits")
        assert blocked.status_code == httpx.codes.FORBIDDEN
        assert blocked.json()["detail"]["code"] == "password_change_required"
        # Enough is reachable to see who you are and to fix it.
        assert client.get("/api/me").status_code == httpx.codes.OK
        assert client.get("/api/auth/session").status_code == httpx.codes.OK

        changed = client.post(
            "/api/auth/password",
            json={
                "current_password": "Xk7!vQ2#mTz9@Lr4",
                "new_password": "Wd3$hN8^bYc5-Jf1",
            },
        )
        assert changed.status_code == httpx.codes.OK, changed.text

        assert login(client, "newbie", "Wd3$hN8^bYc5-Jf1").status_code == httpx.codes.OK
        assert client.get("/api/limits").status_code == httpx.codes.OK


class TestAuditTrail:
    def test_successful_login_is_audited(
        self, client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        login(client, "admin", ADMIN_PASSWORD)
        actions = db.scalars(select(AuditLogEntry.action)).all()
        assert "auth.login" in actions

    def test_failed_login_is_audited(
        self, client: TestClient, db: Session, admin_user: UtilityUser
    ) -> None:
        client.post("/api/auth/login", json={"username": "admin", "password": "wrong-one"})
        entry = db.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "auth.login_failed")
        ).one()
        assert entry.target_label == "admin"

    def test_account_changes_record_before_and_after(
        self, admin_client: TestClient, db: Session, viewer_user: UtilityUser
    ) -> None:
        admin_client.patch(f"/api/accounts/{viewer_user.id}", json={"is_active": False})
        entry = db.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "account.updated")
        ).one()
        assert entry.before == {"role": "viewer", "is_active": True, "email": None}
        assert entry.after["is_active"] is False
        assert entry.actor_name == "admin"


class TestSecurityHeaders:
    def test_headers_are_present_on_api_responses(self, client: TestClient) -> None:
        response = client.get("/healthz")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in response.headers["Content-Security-Policy"]
        assert response.headers["Referrer-Policy"] == "no-referrer"

    def test_api_responses_are_not_cacheable(self, admin_client: TestClient) -> None:
        assert admin_client.get("/api/auth/session").headers["Cache-Control"] == "no-store"

    def test_hsts_is_absent_when_tls_is_not_in_use(self, client: TestClient) -> None:
        # The test settings run with cookie_secure=false, standing in for plain HTTP.
        assert "Strict-Transport-Security" not in client.get("/healthz").headers


class TestHealth:
    def test_healthz_is_public_and_terse(self, client: TestClient) -> None:
        response = client.get("/healthz")
        assert response.status_code == httpx.codes.OK
        body = response.json()
        assert body["status"] == "ok"
        assert body["database"] is True
        assert body["checkmarx_connection_configured"] is False
        # scheduler_alive is a terse watchdog flag (ops hardening); it must not leak
        # any internal detail beyond the boolean.
        assert body["scheduler_alive"] in (True, False)
        assert set(body) == {
            "status",
            "version",
            "database",
            "checkmarx_connection_configured",
            "scheduler_alive",
        }
