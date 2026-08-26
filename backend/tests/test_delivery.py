"""Email and webhook delivery of notifications."""

from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
from email.message import EmailMessage

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import Notification
from app.models.enums import Severity
from app.services import delivery, notifications, settings_store

WEBHOOK_URL = "https://hooks.example.com/cxcreditguard"


class FakeSmtp:
    """Records what a real SMTP server would have been asked to do."""

    instances: list[FakeSmtp] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.login_args: tuple[str, str] | None = None
        self.messages: list[EmailMessage] = []
        self.quit_called = False
        FakeSmtp.instances.append(self)

    def starttls(self) -> None:
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.login_args = (username, password)

    def send_message(self, message: EmailMessage) -> None:
        self.messages.append(message)

    def quit(self) -> None:
        self.quit_called = True


@pytest.fixture(autouse=True)
def clean_delivery_state() -> None:
    FakeSmtp.instances = []
    delivery.reset_attempts()


def configure_email(db: Session, **overrides: object) -> None:
    settings_store.set_value(
        db, settings_store.KEY_SMTP_HOST, overrides.get("host", "smtp.example.com")
    )
    settings_store.set_value(db, settings_store.KEY_SMTP_PORT, 587)
    settings_store.set_value(db, settings_store.KEY_SMTP_FROM, "cxcg@example.com")
    settings_store.set_value(
        db, settings_store.KEY_SMTP_RECIPIENTS, overrides.get("recipients", "ops@example.com")
    )
    settings_store.set_value(db, settings_store.KEY_SMTP_USE_TLS, overrides.get("tls", True))
    if overrides.get("username"):
        settings_store.set_value(db, settings_store.KEY_SMTP_USERNAME, overrides["username"])
        settings_store.set_secret(db, settings_store.KEY_SMTP_PASSWORD, str(overrides["password"]))
    db.commit()


def configure_webhook(db: Session, *, secret: str | None = None, url: str = WEBHOOK_URL) -> None:
    settings_store.set_value(db, settings_store.KEY_WEBHOOK_URL, url)
    if secret:
        settings_store.set_secret(db, settings_store.KEY_WEBHOOK_SECRET, secret)
    db.commit()


def make_notification(
    db: Session, *, severity: Severity = Severity.CRITICAL, title: str = "Test"
) -> Notification:
    notification = notifications.notify(
        db,
        category=notifications.CATEGORY_ENFORCEMENT,
        severity=severity,
        title=title,
        body="Something happened that an admin should know about.",
        entity_type="user",
        entity_id="user-1",
        entity_label="Harsh Gokani",
        dedupe_key=f"test-{title}-{severity}",
    )
    db.commit()
    assert notification is not None
    return notification


def mock_webhook(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestSeverityThreshold:
    @pytest.mark.parametrize(
        ("severity", "minimum", "expected"),
        [
            (Severity.INFO, Severity.WARNING, False),
            (Severity.WARNING, Severity.WARNING, True),
            (Severity.ERROR, Severity.WARNING, True),
            (Severity.CRITICAL, Severity.WARNING, True),
            (Severity.WARNING, Severity.CRITICAL, False),
            (Severity.INFO, Severity.INFO, True),
        ],
    )
    def test_threshold_comparison(self, severity: str, minimum: str, expected: bool) -> None:
        assert delivery.meets_threshold(severity, minimum) is expected

    def test_below_threshold_notifications_are_not_delivered(self, db: Session) -> None:
        configure_email(db)
        make_notification(db, severity=Severity.INFO, title="Quiet")
        result = delivery.deliver_pending(db, smtp_factory=FakeSmtp)
        db.commit()
        assert result.considered == 0
        assert FakeSmtp.instances == []


class TestEmail:
    def test_sends_over_starttls_with_credentials(self, db: Session) -> None:
        configure_email(db, username="mailer", password="smtp-secret-value")
        make_notification(db)

        result = delivery.deliver_pending(db, smtp_factory=FakeSmtp)
        db.commit()

        assert result.delivered == 1
        server = FakeSmtp.instances[0]
        assert server.host == "smtp.example.com"
        assert server.started_tls is True
        assert server.login_args == ("mailer", "smtp-secret-value")
        assert server.quit_called is True

    def test_message_content(self, db: Session) -> None:
        configure_email(db)
        notification = make_notification(db, title="User Harsh Gokani restricted")
        delivery.deliver_pending(db, smtp_factory=FakeSmtp)
        db.commit()

        message = FakeSmtp.instances[0].messages[0]
        assert message["Subject"] == "[CxCreditGuard] User Harsh Gokani restricted"
        assert message["To"] == "ops@example.com"
        body = message.get_content()
        assert "Harsh Gokani" in body
        assert "Entity: user Harsh Gokani" in body
        assert str(notification.created_at.year) in body
        assert message["X-CxCreditGuard-Severity"] == "critical"

    def test_multiple_recipients(self, db: Session) -> None:
        configure_email(db, recipients="a@example.com, b@example.com; c@example.com")
        make_notification(db)
        delivery.deliver_pending(db, smtp_factory=FakeSmtp)
        db.commit()
        assert (
            FakeSmtp.instances[0].messages[0]["To"] == "a@example.com, b@example.com, c@example.com"
        )

    def test_starttls_can_be_disabled(self, db: Session) -> None:
        configure_email(db, tls=False)
        make_notification(db)
        delivery.deliver_pending(db, smtp_factory=FakeSmtp)
        db.commit()
        assert FakeSmtp.instances[0].started_tls is False

    def test_connection_failure_is_recorded_not_raised(self, db: Session) -> None:
        configure_email(db)
        notification = make_notification(db)

        def failing(host: str, port: int, timeout: float) -> smtplib.SMTP:
            raise OSError("connection refused")

        result = delivery.deliver_pending(db, smtp_factory=failing)
        db.commit()

        assert result.failed == 1
        assert result.errors
        db.refresh(notification)
        # Still pending, so the next cycle retries it.
        assert notification.delivery is None

    def test_authentication_failure_is_reported_clearly(self, db: Session) -> None:
        configure_email(db, username="mailer", password="wrong-password-value")
        make_notification(db)

        class Rejecting(FakeSmtp):
            def login(self, username: str, password: str) -> None:
                raise smtplib.SMTPAuthenticationError(535, b"nope")

        result = delivery.deliver_pending(db, smtp_factory=Rejecting)
        db.commit()
        assert any("authentication" in error for error in result.errors)

    def test_the_password_never_appears_in_the_recorded_outcome(self, db: Session) -> None:
        configure_email(db, username="mailer", password="smtp-secret-value")
        notification = make_notification(db)

        class Rejecting(FakeSmtp):
            def login(self, username: str, password: str) -> None:
                raise smtplib.SMTPAuthenticationError(535, b"nope")

        delivery.deliver_pending(db, smtp_factory=Rejecting)
        db.commit()
        db.refresh(notification)
        assert "smtp-secret-value" not in repr(notification.delivery)


class TestWebhook:
    def test_posts_a_json_payload(self, db: Session) -> None:
        configure_webhook(db)
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["body"] = json.loads(request.content)
            captured["headers"] = dict(request.headers)
            return httpx.Response(200, json={"ok": True})

        make_notification(db)
        result = delivery.deliver_pending(db, http_client=mock_webhook(handler))
        db.commit()

        assert result.delivered == 1
        assert captured["url"] == WEBHOOK_URL
        body = captured["body"]
        assert body["severity"] == "critical"
        assert body["category"] == "enforcement"
        assert body["entity"]["label"] == "Harsh Gokani"
        assert body["source"]["name"] == "CxCreditGuard"

    def test_signature_covers_the_timestamp_and_body(self, db: Session) -> None:
        """A captured request must not be replayable with a fresh timestamp."""
        configure_webhook(db, secret="webhook-signing-secret")
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = request.content
            captured["signature"] = request.headers[delivery.SIGNATURE_HEADER]
            captured["timestamp"] = request.headers[delivery.TIMESTAMP_HEADER]
            return httpx.Response(204)

        make_notification(db)
        delivery.deliver_pending(db, http_client=mock_webhook(handler))
        db.commit()

        expected = hmac.new(
            b"webhook-signing-secret",
            str(captured["timestamp"]).encode() + b"." + bytes(captured["body"]),  # type: ignore[arg-type]
            hashlib.sha256,
        ).hexdigest()
        assert captured["signature"] == f"sha256={expected}"

    def test_a_different_timestamp_invalidates_the_signature(self) -> None:
        body = b'{"id":1}'
        first = delivery.sign_payload(body, secret="s3cret-value", timestamp="1000")
        second = delivery.sign_payload(body, secret="s3cret-value", timestamp="2000")
        assert first != second

    def test_no_signature_header_without_a_secret(self, db: Session) -> None:
        configure_webhook(db)
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["has_signature"] = delivery.SIGNATURE_HEADER in request.headers
            return httpx.Response(200)

        make_notification(db)
        delivery.deliver_pending(db, http_client=mock_webhook(handler))
        db.commit()
        assert captured["has_signature"] is False

    def test_a_non_2xx_response_is_a_failure(self, db: Session) -> None:
        configure_webhook(db)
        make_notification(db)
        result = delivery.deliver_pending(
            db, http_client=mock_webhook(lambda _r: httpx.Response(503))
        )
        db.commit()
        assert result.failed == 1
        assert any("503" in error for error in result.errors)

    def test_a_transport_error_is_a_failure(self, db: Session) -> None:
        configure_webhook(db)
        make_notification(db)

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out")

        result = delivery.deliver_pending(db, http_client=mock_webhook(handler))
        db.commit()
        assert result.failed == 1


class TestWebhookTargetGuard:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.1.1/hook",
        ],
    )
    def test_metadata_and_link_local_targets_are_refused(self, url: str) -> None:
        with pytest.raises(delivery.DeliveryError, match="refusing to post"):
            delivery.assert_webhook_target_allowed(url)

    def test_an_ordinary_https_target_is_allowed(self) -> None:
        delivery.assert_webhook_target_allowed("https://hooks.slack.com/services/T000/B000/xxx")

    def test_an_internal_hostname_is_still_allowed(self) -> None:
        """Posting to an internal relay is a legitimate deployment, not an attack."""
        delivery.assert_webhook_target_allowed("https://10.1.2.3/hook")

    def test_a_url_without_a_host_is_refused(self) -> None:
        with pytest.raises(delivery.DeliveryError, match="no host"):
            delivery.assert_webhook_target_allowed("https:///nowhere")

    def test_the_guard_runs_during_delivery(self, db: Session) -> None:
        configure_webhook(db, url="http://169.254.169.254/hook")
        make_notification(db)
        result = delivery.deliver_pending(
            db, http_client=mock_webhook(lambda _r: httpx.Response(200))
        )
        db.commit()
        assert result.failed == 1
        assert any("metadata" in error for error in result.errors)


class TestRetryAndGiveUp:
    def test_a_failure_is_retried_on_the_next_cycle(self, db: Session) -> None:
        configure_webhook(db)
        notification = make_notification(db)
        client = mock_webhook(lambda _r: httpx.Response(500))

        delivery.deliver_pending(db, http_client=client)
        db.commit()
        db.refresh(notification)
        assert notification.delivery is None
        assert delivery.attempts_for(notification.id) == 1

        delivery.deliver_pending(db, http_client=client)
        db.commit()
        assert delivery.attempts_for(notification.id) == 2

    def test_it_gives_up_after_the_attempt_cap(self, db: Session) -> None:
        """A dead endpoint must not make the utility resend forever."""
        configure_webhook(db)
        notification = make_notification(db)
        client = mock_webhook(lambda _r: httpx.Response(500))

        for _ in range(delivery.MAX_ATTEMPTS):
            delivery.deliver_pending(db, http_client=client)
            db.commit()

        db.refresh(notification)
        assert notification.delivery is not None
        assert notification.delivery["given_up"] is True
        # No longer selected as pending.
        assert delivery.deliver_pending(db, http_client=client).considered == 0

    def test_a_recovery_before_the_cap_delivers_normally(self, db: Session) -> None:
        configure_webhook(db)
        notification = make_notification(db)

        delivery.deliver_pending(db, http_client=mock_webhook(lambda _r: httpx.Response(500)))
        db.commit()
        delivery.deliver_pending(db, http_client=mock_webhook(lambda _r: httpx.Response(200)))
        db.commit()

        db.refresh(notification)
        assert notification.delivery == {"attempts": 1, "webhook": "sent"}


class TestChannelIndependence:
    def test_email_still_goes_out_when_the_webhook_fails(self, db: Session) -> None:
        configure_email(db)
        configure_webhook(db)
        notification = make_notification(db)

        result = delivery.deliver_pending(
            db,
            smtp_factory=FakeSmtp,
            http_client=mock_webhook(lambda _r: httpx.Response(500)),
        )
        db.commit()

        assert FakeSmtp.instances[0].messages
        assert result.failed == 1
        db.refresh(notification)
        # Still pending overall, because one channel has not delivered.
        assert notification.delivery is None

    def test_with_no_channels_rows_are_marked_skipped_not_rescanned(self, db: Session) -> None:
        notification = make_notification(db)
        result = delivery.deliver_pending(db)
        db.commit()
        assert result.skipped == 1
        db.refresh(notification)
        assert notification.delivery == {"skipped": "no delivery channel configured"}
        assert delivery.deliver_pending(db).considered == 0

    def test_oldest_notifications_are_delivered_first(self, db: Session) -> None:
        configure_email(db)
        for index in range(3):
            make_notification(db, title=f"Event {index}")
        delivery.deliver_pending(db, smtp_factory=FakeSmtp, limit=2)
        db.commit()
        subjects = [server.messages[0]["Subject"] for server in FakeSmtp.instances]
        assert subjects == ["[CxCreditGuard] Event 0", "[CxCreditGuard] Event 1"]


class TestTestNotification:
    def test_it_reports_per_channel_and_stores_nothing(self, db: Session) -> None:
        configure_email(db)
        configure_webhook(db)
        before = len(list(db.scalars(select(Notification))))

        outcome = delivery.send_test_notification(
            db, smtp_factory=FakeSmtp, http_client=mock_webhook(lambda _r: httpx.Response(200))
        )
        db.commit()

        assert outcome == {"email": "sent", "webhook": "sent"}
        assert len(list(db.scalars(select(Notification)))) == before

    def test_it_says_so_when_nothing_is_configured(self, db: Session) -> None:
        assert "No delivery channel" in delivery.send_test_notification(db)["result"]

    def test_the_endpoint_requires_admin(self, viewer_client: TestClient) -> None:
        assert viewer_client.post("/api/settings/test-notification").status_code == 403

    def test_the_endpoint_reports_the_outcome(self, admin_client: TestClient, db: Session) -> None:
        response = admin_client.post("/api/settings/test-notification")
        assert response.status_code == 200
        assert "No delivery channel" in str(response.json()["channels"])
