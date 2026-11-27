"""How a credit amount reads in text people see.

Notifications, emails, audit details, diagnostics, reports and self-test or
recount messages all show credits the same way: exactly one decimal, with
thousands separators ("12.0", "1,365.5", "0.5"), matching ``formatCredits``
in the frontend. API values, stored values and machine-readable export
columns keep their full precision; only sentences use this.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

_TENTH = Decimal("0.1")


def credits(value: object) -> str:
    """One decimal, thousands separators, halves rounded up (as the browser does)."""
    try:
        # str() first so a float reads as written (0.15, not 0.1499...).
        amount = Decimal(value if isinstance(value, Decimal) else str(value))
        # + 0 turns a rounded "-0.0" into "0.0".
        rounded = amount.quantize(_TENTH, rounding=ROUND_HALF_UP) + 0
    except (InvalidOperation, ValueError):
        return str(value)
    return f"{rounded:,.1f}"
