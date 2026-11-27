"""Credits in text people read: exactly one decimal, thousands separators."""

from __future__ import annotations

from decimal import Decimal

import pytest

from app.services import credits_text, diagnostics, recount, usage_mix


@pytest.mark.parametrize(
    ("value", "shown"),
    [
        (Decimal("12.0000"), "12.0"),
        (Decimal("1365.5"), "1,365.5"),
        (Decimal("0.5"), "0.5"),
        (Decimal("0"), "0.0"),
        (12, "12.0"),
        (1234567, "1,234,567.0"),
        (2.5, "2.5"),
        (0.15, "0.2"),  # as written, not as the float's binary value
        ("7.25", "7.3"),  # halves round up, as the browser's formatCredits does
        (Decimal("0.04"), "0.0"),
        (Decimal("-0.04"), "0.0"),  # never "-0.0"
        (Decimal("-3.25"), "-3.3"),
        (Decimal("1E+3"), "1,000.0"),
    ],
)
def test_one_decimal_everywhere(value: object, shown: str) -> None:
    assert credits_text.credits(value) == shown


def test_something_that_is_no_number_is_shown_as_it_is() -> None:
    assert credits_text.credits("n/a") == "n/a"


def test_the_older_helpers_delegate() -> None:
    assert usage_mix.format_credits(Decimal("4")) == "4.0"
    assert usage_mix.format_credits(Decimal("0.25")) == "0.3"
    assert diagnostics._credits(Decimal("1365.5000")) == "1,365.5"
    assert diagnostics._credits(None) == "unknown"
    assert diagnostics._credits("12.5") == "12.5"
    assert recount._credits(Decimal("12.0000")) == "12.0"
    assert recount._credits(None) == "unknown"
