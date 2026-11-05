"""Self-service and admin-initiated password reset, and diagnostics remediation."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.passwords import PasswordPolicyError
from app.db.base import utcnow
from app.models.auth import PasswordResetToken, UtilityUser
from app.models.enums import UtilityRole
from app.services import auth as auth_service
from app.services import diagnostics as diagnostics_service
from app.services.audit import AuditActor
from tests.conftest import VIEWER_PASSWORD, login

ACTOR = AuditActor.system("test")
NEW_PASSWORD = "N3w!Str0ng#Pass"


@pytest.fixture
def user_with_email(db: Session) -> UtilityUser:
    user = auth_service.create_user(
        db,
        username="dana",
        password="0ld!Str0ng#Pass",
        role=UtilityRole.VIEWER,
        email="dana@demo.example",
        actor=ACTOR,
    )
    db.commit()
    return user


class TestRequestService:
    def test_request_by_username_issues_a_token(
        self, user_with_email: UtilityUser, db: Session
    ) -> None:
        result = auth_service.request_password_reset(db, identifier="dana")
        assert result is not None
        user, token = result
        assert user.id == user_with_email.id
        assert token
        row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.user_id == user.id))
        assert row is not None and row.used_at is None

    def test_request_by_email_is_case_insensitive(
        self, user_with_email: UtilityUser, db: Session
    ) -> None:
        result = auth_service.request_password_reset(db, identifier="DANA@DEMO.EXAMPLE")
        assert result is not None and result[0].id == user_with_email.id

    def test_unknown_or_inactive_account_returns_none(
        self, user_with_email: UtilityUser, db: Session
    ) -> None:
        assert auth_service.request_password_reset(db, identifier="nobody") is None
        user_with_email.is_active = False
        db.flush()
        assert auth_service.request_password_reset(db, identifier="dana") is None

    def test_a_new_request_invalidates_the_previous_token(
        self, user_with_email: UtilityUser, db: Session
    ) -> None:
        _, first = auth_service.request_password_reset(db, identifier="dana")  # type: ignore[misc]
        db.commit()
        auth_service.request_password_reset(db, identifier="dana")  # supersedes the first
        db.commit()
        # Exactly one token remains live; the first no longer redeems.
        live = db.scalar(
            select(func.count())
            .select_from(PasswordResetToken)
            .where(PasswordResetToken.used_at.is_(None))
        )
        assert live == 1
        with pytest.raises(auth_service.InvalidResetToken):
            auth_service.complete_password_reset(db, token=first, new_password=NEW_PASSWORD)


class TestCompleteService:
    def test_redeeming_sets_the_password_and_is_single_use(
        self, user_with_email: UtilityUser, db: Session
    ) -> None:
        _, token = auth_service.request_password_reset(db, identifier="dana")  # type: ignore[misc]
        db.commit()
        user = auth_service.complete_password_reset(db, token=token, new_password=NEW_PASSWORD)
        db.commit()
        assert user.must_change_password is False
        # The token is spent: a second use fails.
        with pytest.raises(auth_service.InvalidResetToken):
            auth_service.complete_password_reset(db, token=token, new_password=NEW_PASSWORD)

    def test_redeeming_clears_the_lockout(self, user_with_email: UtilityUser, db: Session) -> None:
        user_with_email.failed_login_count = 9
        user_with_email.locked_until = utcnow() + timedelta(hours=1)
        db.flush()
        _, token = auth_service.request_password_reset(db, identifier="dana")  # type: ignore[misc]
        db.commit()
        auth_service.complete_password_reset(db, token=token, new_password=NEW_PASSWORD)
        db.commit()
        db.refresh(user_with_email)
        assert user_with_email.failed_login_count == 0
        assert user_with_email.locked_until is None

    def test_expired_token_is_rejected(self, user_with_email: UtilityUser, db: Session) -> None:
        _, token = auth_service.request_password_reset(db, identifier="dana")  # type: ignore[misc]
        row = db.scalar(select(PasswordResetToken))
        row.expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
        with pytest.raises(auth_service.InvalidResetToken):
            auth_service.complete_password_reset(db, token=token, new_password=NEW_PASSWORD)

    def test_weak_password_leaves_the_token_usable(
        self, user_with_email: UtilityUser, db: Session
    ) -> None:
        _, token = auth_service.request_password_reset(db, identifier="dana")  # type: ignore[misc]
        db.commit()
        with pytest.raises(PasswordPolicyError):
            auth_service.complete_password_reset(db, token=token, new_password="short")
        db.rollback()
        # Still redeemable with a strong password.
        user = auth_service.complete_password_reset(db, token=token, new_password=NEW_PASSWORD)
        assert user.id == user_with_email.id


class TestForgotPasswordEndpoint:
    def test_returns_generic_message_for_unknown_and_known(
        self, client: TestClient, user_with_email: UtilityUser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Patch the dispatcher (not the SMTP send) so there is no background-thread
        # race in the assertion: the email is sent off-thread in production.
        dispatched: list[str] = []
        monkeypatch.setattr(
            "app.api.routes.auth._dispatch_reset_email",
            lambda config, *, email, token: dispatched.append(email),
        )
        unknown = client.post("/api/auth/forgot-password", json={"identifier": "ghost"})
        known = client.post("/api/auth/forgot-password", json={"identifier": "dana"})
        assert unknown.status_code == httpx.codes.OK
        assert known.status_code == httpx.codes.OK
        assert unknown.json() == known.json()  # indistinguishable
        # Only the real account with an email triggered a send.
        assert dispatched == ["dana@demo.example"]


class TestResetViaAdminAndEndpoint:
    def test_admin_reset_then_user_resets_and_logs_in(
        self, admin_client: TestClient, viewer_user: UtilityUser
    ) -> None:
        issued = admin_client.post(f"/api/accounts/{viewer_user.id}/reset-password")
        assert issued.status_code == httpx.codes.OK, issued.text
        token = issued.json()["reset_token"]

        done = admin_client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": NEW_PASSWORD}
        )
        assert done.status_code == httpx.codes.OK, done.text

        # The viewer can sign in with the new password and not the old one.
        fresh = admin_client  # same TestClient; login overwrites the session cookie
        assert login(fresh, "viewer", VIEWER_PASSWORD).status_code == httpx.codes.UNAUTHORIZED
        assert login(fresh, "viewer", NEW_PASSWORD).status_code == httpx.codes.OK

    def test_reset_with_a_bad_token_is_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/api/auth/reset-password",
            json={"token": "not-a-real-token-0000", "new_password": NEW_PASSWORD},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "invalid_token"

    def test_admin_reset_requires_admin(
        self, viewer_client: TestClient, admin_user: UtilityUser
    ) -> None:
        response = viewer_client.post(f"/api/accounts/{admin_user.id}/reset-password")
        assert response.status_code == httpx.codes.FORBIDDEN

    def test_admin_reset_rejects_inactive_account(
        self, admin_client: TestClient, viewer_user: UtilityUser, db: Session
    ) -> None:
        db.execute(
            UtilityUser.__table__.update()
            .where(UtilityUser.id == viewer_user.id)
            .values(is_active=False)
        )
        db.commit()
        response = admin_client.post(f"/api/accounts/{viewer_user.id}/reset-password")
        assert response.status_code == httpx.codes.BAD_REQUEST


class TestDiagnosticsRemediation:
    def test_non_ok_checks_carry_remediation_and_ok_checks_do_not(self, db: Session) -> None:
        report = diagnostics_service.run_diagnostics(db)
        for check in report.checks:
            if check.status == diagnostics_service.OK:
                assert check.remediation is None
            else:
                assert check.remediation, f"{check.key} is {check.status} but has no remediation"
        # A fresh database has no connection configured, so that check is actionable.
        connection = next(c for c in report.checks if c.key == "connection")
        assert connection.status == diagnostics_service.FAIL
        assert "Setup" in (connection.remediation or "")

    def test_endpoint_exposes_remediation(self, admin_client: TestClient) -> None:
        body = admin_client.get("/api/ops/diagnostics").json()
        connection = next(c for c in body["checks"] if c["key"] == "connection")
        assert connection["remediation"]
