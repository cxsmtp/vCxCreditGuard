"""Counts and percentages in text people read.

``plural`` writes a count with its noun ("1 restriction", "2 restrictions",
"1,250 users") instead of "restriction(s)". ``percent`` writes a percentage
with exactly one decimal ("4.9%", "100.0%"), matching ``formatPercent`` in the
frontend, so the same figure reads the same everywhere.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

_TENTH = Decimal("0.1")


def noun(count: int, singular: str, plural_form: str | None = None) -> str:
    """The noun alone, singular for exactly one: "restriction" or "restrictions"."""
    return singular if count == 1 else (plural_form or f"{singular}s")


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    """The count with thousands separators and its noun: "1 entity", "3 entities"."""
    return f"{count:,} {noun(count, singular, plural_form)}"


def percent(value: object) -> str:
    """One decimal, halves rounded up (as the browser does): "4.9%", "64.2%"."""
    try:
        amount = Decimal(value if isinstance(value, Decimal) else str(value))
        rounded = amount.quantize(_TENTH, rounding=ROUND_HALF_UP) + 0
    except (InvalidOperation, ValueError):
        return f"{value}%"
    return f"{rounded:,.1f}%"
