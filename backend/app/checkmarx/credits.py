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

    # Prefer figures at the top level; only unwrap a common envelope when the
    # top level carries none of the keys we recognise.
    source = payload
    _known = (*_TOTAL_KEYS, *_USED_KEYS, *_AVAILABLE_KEYS)
    if not any(key in payload for key in _known):
        for envelope in ("credits", "data", "result"):
            inner = payload.get(envelope)
            if isinstance(inner, dict) and any(k in inner for k in _known):
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


# ------------------------------------------------------------- action rates

# What each billed action costs, per action. Under the same /api base as every
# other platform call: GET /api/v1/credits/action-rates. Observed shape:
#   {"count": 3, "rates": [{"action_type": "fusion_scan_-_opus_5.5",
#    "credits_per_action": "2", "display_name": "Fusion Scan - Opus 5.5",
#    "is_active": true, ...}, ...]}
# A rate is NOT always the credits one transaction costs. On a live tenant
# (2026-11) it was for triage (1) and remediation (3); for Fusion and DAST
# correlation the consumption feed reports far more per transaction (Opus 5.5:
# rate 2, about 108.9 credits per transaction; DAST correlation: rate 14, about
# 156.8). So nothing multiplies a rate by a count unchecked: the price used is
# the rate only when the feed agrees with it within 10% (or has no figure), and
# otherwise the feed's own credits / transactions (usage_mix.price_table).
ACTION_RATES_PATH = "/v1/credits/action-rates"


@dataclass(frozen=True, slots=True)
class ActionRate:
    action_type: str
    display_name: str | None
    credits_per_action: Decimal
    is_active: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "display_name": self.display_name,
            # A string, so the stored JSON keeps the exact decimal.
            "credits_per_action": str(self.credits_per_action),
            "is_active": self.is_active,
        }


def parse_action_rates(payload: Any) -> list[ActionRate] | None:
    """The rates in an action-rates body, or None when it is not readable.

    A rate whose price cannot be read is left out rather than read as 0: a
    price of nothing would make every Fusion scan look free.
    """
    if isinstance(payload, dict):
        entries = payload.get("rates")
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = None
    if not isinstance(entries, list):
        logger.info("The action-rates response carries no list of rates")
        return None
    rates: list[ActionRate] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        action_type = entry.get("action_type") or entry.get("actionType")
        price = _coerce(entry.get("credits_per_action", entry.get("creditsPerAction")))
        if not isinstance(action_type, str) or not action_type.strip() or price is None:
            continue
        display = entry.get("display_name") or entry.get("displayName")
        active = entry.get("is_active", entry.get("isActive", True))
        rates.append(
            ActionRate(
                action_type=action_type.strip()[:128],
                display_name=display.strip()[:128] if isinstance(display, str) else None,
                credits_per_action=price,
                is_active=active is not False,
            )
        )
    return rates


def fetch_action_rates(client: CheckmarxClient) -> list[ActionRate] | None:
    """Read the price of each action. Raises CheckmarxError when the call fails;
    returns None when it answers with something that is not a list of rates."""
    return parse_action_rates(client.get_json(ACTION_RATES_PATH, base="api"))
