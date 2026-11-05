"""Reading the tenant's AI credit balance from GET /api/credits/info.

This is the pool side of the ledger: how many AI credits the tenant was granted,
how many it has spent and how many remain. It is distinct from
``/credits/consumption`` (this module's sibling, :mod:`app.checkmarx.usage`),
which reports *who* spent credits; here we only want the tenant-wide totals.

The exact field names the endpoint uses are not contractually fixed across
tenants, so parsing is deliberately forgiving: several spellings are accepted,
a missing third value is derived from the other two, and anything that cannot be
read lands as ``None`` rather than ``0``. An unknown balance is not a zero
balance - the same rule the rest of the utility follows.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from app.checkmarx.client import CheckmarxClient

logger = logging.getLogger(__name__)

CREDITS_INFO_PATH = "/credits/info"

# Candidate key spellings, most specific first. Nested under a "credits" or
# "data" envelope is also tried.
_TOTAL_KEYS = ("totalCredits", "total", "granted", "grantedCredits", "limit", "quota")
_USED_KEYS = ("usedCredits", "used", "consumed", "consumedCredits", "spent")
_AVAILABLE_KEYS = (
    "availableCredits",
    "available",
    "remaining",
    "remainingCredits",
    "balance",
)


@dataclass(frozen=True, slots=True)
class CreditBalance:
    """The tenant's credit pool as reported. Any field may be unknown (``None``)."""

    total: Decimal | None
    used: Decimal | None
    available: Decimal | None
    raw: dict[str, Any]

    def has_values(self) -> bool:
        return any(v is not None for v in (self.total, self.used, self.available))


def _coerce(value: Any) -> Decimal | None:
    """A credit figure as a Decimal, or None when it is absent or unparseable.

    Never raises and never invents a zero: a value we cannot read is unknown.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed >= 0 else None


def _first(payload: dict[str, Any], keys: tuple[str, ...]) -> Decimal | None:
    for key in keys:
        if key in payload:
            coerced = _coerce(payload[key])
            if coerced is not None:
                return coerced
    return None


def parse_credit_balance(payload: Any) -> CreditBalance | None:
    """Parse a ``/credits/info`` body. Returns None when it is not an object."""
    if not isinstance(payload, dict):
        logger.warning("Credit balance response was %s, expected an object", type(payload).__name__)
        return None

    # Unwrap a common envelope if the figures are not at the top level.
    source = payload
    for envelope in ("credits", "data", "result"):
        inner = payload.get(envelope)
        if isinstance(inner, dict) and any(
            k in inner for k in (*_TOTAL_KEYS, *_USED_KEYS, *_AVAILABLE_KEYS)
        ):
            source = inner
            break

    total = _first(source, _TOTAL_KEYS)
    used = _first(source, _USED_KEYS)
    available = _first(source, _AVAILABLE_KEYS)

    # Fill in the third figure from the other two when it is missing, but never
    # fabricate two unknowns into one.
    if available is None and total is not None and used is not None:
        available = total - used if total >= used else Decimal("0")
    elif used is None and total is not None and available is not None:
        used = total - available if total >= available else Decimal("0")

    return CreditBalance(total=total, used=used, available=available, raw=payload)


def fetch_credit_balance(client: CheckmarxClient) -> CreditBalance | None:
    """Read the tenant credit pool. Returns None when the call or parse fails.

    A None result must leave the last known good balance standing; the caller
    does not write a snapshot for it.
    """
    try:
        payload = client.get_json(CREDITS_INFO_PATH, base="api")
    except Exception as exc:  # noqa: BLE001 - an unreachable pool is unknown, not fatal
        logger.info("Could not read the tenant credit balance: %s", exc)
        return None
    return parse_credit_balance(payload)
