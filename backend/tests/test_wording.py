"""Text people read: counts with their noun, one-decimal percentages, plain
reasons and errors, and the System health checks for alerts and the database."""

from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy.orm import Session

from app.models.org import CxProject
from app.services import diagnostics, enforcement, error_text, settings_store, wording


@pytest.mark.parametrize(
    ("count", "singular", "plural_form", "shown"),
    [
        (1, "restriction", None, "1 restriction"),
        (0, "restriction", None, "0 restrictions"),
        (2, "minute", None, "2 minutes"),
        (1, "entity", "entities", "1 entity"),
        (3, "entity", "entities", "3 entities"),
        (1250, "user", None, "1,250 users"),
    ],
)
def test_plural(count: int, singular: str, plural_form: str | None, shown: str) -> None:
    assert wording.plural(count, singular, plural_form) == shown


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        (Decimal("4.94"), "4.9%"),
        (Decimal("4.95"), "5.0%"),
        (5, "5.0%"),
        (100, "100.0%"),
        (64.2, "64.2%"),
        (Decimal("-0.04"), "0.0%"),
    ],
)
def test_percent_has_one_decimal(value: object, shown: str) -> None:
    assert wording.percent(value) == shown


def test_a_lift_reason_reads_as_words() -> None:
    assert enforcement.reason_text("credit_increased") == (
        "the limit was raised or usage is within budget again"
    )
    assert enforcement.reason_text("period_rollover") == "a new budget period started"
    assert enforcement.reason_text("some_new_code") == "some new code"


def test_an_unexpected_error_labels_its_type() -> None:
    shown = error_text.public_error(AttributeError("secret detail"))
    assert shown == "An unexpected error occurred; see the server log (error type: AttributeError)."
    assert "secret detail" not in shown


def _check(db: Session, key: str) -> diagnostics.Check | None:
    return next((c for c in diagnostics.run_diagnostics(db).checks if c.key == key), None)


def test_no_notification_channel_warns(db: Session) -> None:
    check = _check(db, "notifications")
    assert check is not None and check.status == diagnostics.WARN
    assert "only shown in the Notification Center" in check.detail
    assert check.remediation and "Settings → Notifications" in check.remediation


def test_partial_email_is_named(db: Session) -> None:
    settings_store.set_value(db, settings_store.KEY_SMTP_HOST, "smtp.example.com")
    db.commit()
    check = _check(db, "notifications")
    assert check is not None and check.status == diagnostics.WARN
    assert "only partly set up" in check.detail


def test_email_counts_as_a_channel(db: Session) -> None:
    settings_store.set_value(db, settings_store.KEY_SMTP_HOST, "smtp.example.com")
    settings_store.set_value(db, settings_store.KEY_SMTP_FROM, "guard@example.com")
    settings_store.set_value(db, settings_store.KEY_SMTP_RECIPIENTS, "a@example.com")
    db.commit()
    check = _check(db, "notifications")
    assert check is not None and check.status == diagnostics.OK
    assert check.detail == "Alerts are sent by email to 1 recipient."


def test_sqlite_past_its_advised_size_suggests_postgresql(db: Session) -> None:
    assert _check(db, "database") is None
    db.add_all(
        CxProject(id=f"p-{n}", name=f"project-{n}")
        for n in range(diagnostics.SQLITE_MAX_PROJECTS + 1)
    )
    db.commit()
    check = _check(db, "database")
    if db.get_bind().dialect.name != "sqlite":
        assert check is None  # already on PostgreSQL: nothing to advise
        return
    assert check is not None and check.status == diagnostics.WARN
    assert "501 projects" in check.detail and "PostgreSQL" in check.detail
