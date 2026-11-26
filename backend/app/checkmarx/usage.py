"""Reading and parsing GET /api/credits/consumption.

Everything that knows the shape of that response lives in this one module, so a
change to the payload is a single file edit. Callers get ``ParsedUsagePage``
objects and never touch the JSON.

Observed response shape (viewBy=user), from a live tenant (2026-11):

    {
      "items": [
        {
          "name": "Jane Example",
          "email": "jane@example.com",
          "userEmail": "jane@example.com",
          "creditsUsed": "1",
          "percentOfTotal": 0.1,
          "actionsPerformed": {
            "actions": [{"actionType": "triage", "transactionCount": 1}],
            "total": 1
          }
        }
      ],
      "totalItems": 44, "totalPages": 3, "currentPage": 1
    }

Every dimension uses the same row shape. ``project`` and ``application`` rows
carry only ``name`` (no id; a project row's name can be an ``org/repo`` that is
no synced project), and ``action`` rows name the action as Checkmarx displays
it, with the type and its transactions nested like any other row:

    {"name": "Fusion Scan - Opus 5.5", "creditsUsed": "31024", "percentOfTotal": 78.56,
     "actionsPerformed": {"actions": [{"actionType": "fusion_scan_-_opus_5.5",
                                       "transactionCount": 285}], "total": 285}}

A flat action row (``actionType``/``transactionCount`` at the top level) is
still read, for older payloads.

Robustness choices, each because of something visible in the real data:

* ``email`` and ``userEmail`` are both optional, and several rows carry an email
  address in ``name`` instead. Identity resolution therefore works from a
  normalised key rather than trusting any single field.
* ``creditsUsed`` is not the same as ``actionsPerformed.total``: a remediation can
  cost 3 credits for 1 transaction, and a Fusion scan far more than its listed
  rate. Credits are the budget currency, transactions are only reported for
  context.
* ``creditsUsed`` arrives as a string (``"31024"``, ``"252.5"``); integers and
  floats are accepted too. See :func:`parse_credits`.
* No row carries an id. Matching is by name; the id fields read below
  (``reported_id``) are for payloads that may carry one in future.
* Unknown ``actionType`` values are kept under their raw name rather than dropped,
  so a newly billed action type still counts against budgets.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any

from app.checkmarx.client import CheckmarxClient
from app.models.enums import ActionType, UsageView

logger = logging.getLogger(__name__)

CONSUMPTION_PATH = "/credits/consumption"
DEFAULT_PAGE_SIZE = 100
# The lookback window passed as ``period``. It must be at least as wide as the
# widest budget period in use, because per-period figures are derived by diffing
# against a baseline taken from this same window.
DEFAULT_PERIOD = "last_year"
# Confirmed against a live tenant: anything else answers
# 400 {"error":"invalid period query parameter: \"...\""}. The endpoint does not
# enumerate them itself, so this list is empirical.
SUPPORTED_PERIODS: tuple[str, ...] = (
    "last_month",
    "last_30_days",
    "last_90_days",
    "last_180_days",
    "last_year",
)

# Roughly how far back each window reaches, in days. Used to warn when the window
# is narrower than a budget period, which would silently undercount: consumption
# that happened inside the period but outside the window is invisible.
PERIOD_DAYS: dict[str, int] = {
    "last_month": 31,
    "last_30_days": 30,
    "last_90_days": 90,
    "last_180_days": 180,
    "last_year": 365,
}
MAX_PAGES = 500

# An unrecognised viewBy does NOT fail. The endpoint answers 200 and silently
# returns the user dimension instead, so a successful response is not evidence that
# the dimension asked for exists. This sentinel is used to fetch the fallback
# response deliberately, so a real dimension can be told apart from the fallback by
# comparing them. Chosen to be something no tenant would implement.
FALLBACK_PROBE_VIEW = "__cxcg_unsupported_probe__"

# Maps the raw actionType strings onto our enum. Anything absent from this table
# is preserved verbatim instead of being collapsed into "unknown", so the GUI can
# show what actually spent the credits.
_ACTION_ALIASES: dict[str, str] = {
    "triage": ActionType.TRIAGE,
    "ai_triage": ActionType.TRIAGE,
    "aitriage": ActionType.TRIAGE,
    "auto_triage": ActionType.AUTO_TRIAGE,
    "autotriage": ActionType.AUTO_TRIAGE,
    "remediation": ActionType.REMEDIATION,
    "ai_remediation": ActionType.REMEDIATION,
    "airemediation": ActionType.REMEDIATION,
    "dast_correlation": ActionType.DAST_CORRELATION,
    "dastcorrelation": ActionType.DAST_CORRELATION,
    "fusion": ActionType.FUSION,
    "fusion_scan": ActionType.FUSION,
    "fusionscan": ActionType.FUSION,
}


def action_key(raw: str) -> str:
    """A raw action type (or a rate's display name) as one comparable key.

    ``fusion_scan_-_opus_5.5`` and ``Fusion Scan - Opus 5.5`` both become
    ``fusion_scan___opus_5.5``, which is how a consumption row's action type is
    matched to its price in ``GET /api/v1/credits/action-rates``.
    """
    return raw.strip().lower().replace("-", "_").replace(" ", "_")


def normalise_action_type(raw: str | None) -> str:
    """The action type a raw ``actionType`` belongs to.

    Fusion is billed per model, so the feed names it with the model in it
    (``fusion_scan_-_opus_5.5``, the action-rates endpoint's ``action_type``).
    Every such variant is Fusion here; the model stays in the raw row
    (``UsageRecord.raw``) and in the action dimension's subject, and
    :func:`fusion_model` reads it back where a price needs it.
    """
    if not raw:
        return ActionType.UNKNOWN
    key = action_key(raw)
    if _is_fusion_scan(key):
        return ActionType.FUSION
    return _ACTION_ALIASES.get(key, _ACTION_ALIASES.get(key.replace("_", ""), key))


def _is_fusion_scan(key: str) -> bool:
    """A Fusion scan, with or without its model: ``fusion``, ``fusion_scan``,
    ``fusionscan`` and ``fusion_scan_<model>``. Any other type that merely starts
    with "fusion" is not assumed to be one and stays visible as it is."""
    if key in ("fusion", "fusion_scan", "fusionscan"):
        return True
    return key.startswith(("fusion_scan_", "fusionscan_"))


def fusion_model(raw: str | None) -> str | None:
    """The model in a Fusion action type, for people to read, or None.

    ``fusion_scan_-_opus_5.5`` gives ``Opus 5.5``; a plain ``fusion`` gives None.
    """
    if not raw or normalise_action_type(raw) != ActionType.FUSION:
        return None
    key = action_key(raw)
    for prefix in ("fusion_scan", "fusionscan", "fusion"):
        if key.startswith(prefix):
            key = key[len(prefix) :]
            break
    words = [word for word in key.split("_") if word]
    if not words:
        return None
    return " ".join(word[:1].upper() + word[1:] for word in words)


def parse_credits(value: Any) -> Decimal:
    """A reported credit figure as a Decimal, without ever raising.

    Accepts what the feed sends: a numeric string (``"31024"``, ``" 252.5 "``,
    ``"1e3"``), an int or a float. A row we cannot parse must not abort the whole
    poll, and it must not be invented as a non zero cost either, so it lands as
    zero and is logged. That covers booleans, NaN and infinities, and localised
    strings (``"1,234.5"``, ``"1.234,5"``), whose meaning is ambiguous and is not
    guessed.
    """
    if value is None:
        return Decimal("0")
    if isinstance(value, bool):
        logger.warning("Could not parse a creditsUsed value of type bool")
        return Decimal("0")
    try:
        if isinstance(value, int):
            parsed = Decimal(value)
        elif isinstance(value, float):
            parsed = Decimal(repr(value))
        elif isinstance(value, str):
            parsed = Decimal(value.strip())
        else:
            raise TypeError(type(value).__name__)
    except (InvalidOperation, ValueError, TypeError):
        logger.warning("Could not parse a creditsUsed value of type %s", type(value).__name__)
        return Decimal("0")
    if not parsed.is_finite():
        logger.warning("Ignored a creditsUsed value that is not a finite number")
        return Decimal("0")
    return parsed


def _first_string(item: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def looks_like_email(value: str | None) -> bool:
    if not value:
        return False
    candidate = value.strip()
    return "@" in candidate and " " not in candidate and candidate.count("@") == 1


@dataclass(frozen=True, slots=True)
class ParsedUsageItem:
    """One entity's consumption as reported, normalised but not yet resolved."""

    subject_key: str
    subject_name: str | None
    subject_email: str | None
    credits_used: Decimal
    percent_of_total: float | None
    transactions: int | None
    actions: dict[str, int]
    # The reported identifier when the API supplies one, as it does for the
    # application and project dimensions.
    reported_id: str | None
    raw: dict[str, Any]


@dataclass(slots=True)
class ParsedUsagePage:
    items: list[ParsedUsageItem] = field(default_factory=list)
    total_items: int | None = None
    total_pages: int | None = None
    current_page: int | None = None
    raw: dict[str, Any] | None = None


def parse_usage_item(item: dict[str, Any]) -> ParsedUsageItem | None:
    """Normalise one row of ``items``. Returns None for a row with no identity."""
    name = _first_string(item, "name", "displayName", "userName", "username")
    email = _first_string(item, "userEmail", "email", "userPrincipalName")
    # No row seen on a live tenant carries an id; matching is by name. Read in
    # case a future payload adds one (an id then wins over the name).
    reported_id = _first_string(item, "id", "userId", "applicationId", "projectId")

    # Several rows carry the address in ``name`` and no email field at all.
    if email is None and looks_like_email(name):
        email = name

    subject_key = (email or name or reported_id or "").strip().lower()
    if not subject_key:
        logger.warning("Skipping a consumption row with no name, email or id")
        return None

    actions: dict[str, int] = {}
    transactions: int | None = None
    performed = item.get("actionsPerformed")
    if isinstance(performed, dict):
        raw_total = performed.get("total")
        if isinstance(raw_total, int):
            transactions = raw_total
        raw_actions = performed.get("actions")
        if isinstance(raw_actions, list):
            for entry in raw_actions:
                if not isinstance(entry, dict):
                    continue
                action = normalise_action_type(entry.get("actionType"))
                count = entry.get("transactionCount")
                actions[action] = actions.get(action, 0) + (count if isinstance(count, int) else 0)
    # An older, flat action row: the type in the row itself rather than nested.
    # A live tenant nests it under actionsPerformed like every other dimension.
    elif looks_like_action_row(item):
        actions[normalise_action_type(_first_string(item, "actionType", "action", "name"))] = (
            item.get("transactionCount") if isinstance(item.get("transactionCount"), int) else 0
        )

    percent = item.get("percentOfTotal")
    return ParsedUsageItem(
        subject_key=subject_key,
        subject_name=name,
        subject_email=email,
        credits_used=parse_credits(item.get("creditsUsed", item.get("credits"))),
        percent_of_total=float(percent) if isinstance(percent, int | float) else None,
        transactions=transactions,
        actions=actions,
        reported_id=reported_id,
        raw=item,
    )


def looks_like_action_row(item: dict[str, Any]) -> bool:
    return "actionType" in item or "transactionCount" in item


def parse_usage_page(payload: Any) -> ParsedUsagePage:
    """Parse one response body into items plus pagination metadata."""
    page = ParsedUsagePage()
    if isinstance(payload, list):
        # Defensive: an envelope-less variant would still be usable.
        page.items = [
            parsed
            for entry in payload
            if isinstance(entry, dict) and (parsed := parse_usage_item(entry)) is not None
        ]
        return page
    if not isinstance(payload, dict):
        logger.warning("Consumption response was %s, expected an object", type(payload).__name__)
        return page

    page.raw = payload
    items = payload.get("items")
    if isinstance(items, list):
        page.items = [
            parsed
            for entry in items
            if isinstance(entry, dict) and (parsed := parse_usage_item(entry)) is not None
        ]
    for attribute, key in (
        ("total_items", "totalItems"),
        ("total_pages", "totalPages"),
        ("current_page", "currentPage"),
    ):
        value = payload.get(key)
        if isinstance(value, int):
            setattr(page, attribute, value)
    return page


def fingerprint_page(page: ParsedUsagePage) -> frozenset[str]:
    """Identity of a response, for comparing one dimension against another.

    Only the subject keys are used. Credit figures would work too, but two
    dimensions can legitimately report the same total (a single project and a single
    user can each account for everything), while the *set of subjects* differs
    whenever the dimensions are genuinely different.
    """
    return frozenset(item.subject_key for item in page.items)


def fetch_fallback_fingerprint(
    client: CheckmarxClient, *, period: str = DEFAULT_PERIOD, page_size: int = DEFAULT_PAGE_SIZE
) -> frozenset[str] | None:
    """What the endpoint returns for a viewBy it does not recognise.

    Returns None if the probe itself fails, in which case the caller should not draw
    any conclusion about dimension support.
    """
    try:
        payload = client.get_json(
            CONSUMPTION_PATH,
            params={
                "viewBy": FALLBACK_PROBE_VIEW,
                "period": period,
                "page": 1,
                "size": page_size,
            },
        )
    except Exception as exc:  # noqa: BLE001 - a failed probe is inconclusive, not fatal
        logger.info("Fallback probe did not return a comparable response: %s", exc)
        return None
    return fingerprint_page(parse_usage_page(payload))


def fetch_usage(
    client: CheckmarxClient,
    *,
    view_by: UsageView | str,
    period: str = DEFAULT_PERIOD,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> Iterator[ParsedUsagePage]:
    """Yield every page of consumption for one dimension.

    Pagination here is 1 based with ``page`` and ``size``, and driven by
    ``totalPages``, which is what the endpoint actually returns. It does not use
    the generic offset/limit paginator on the client for that reason.
    """
    page_number = 1
    while page_number <= MAX_PAGES:
        payload = client.get_json(
            CONSUMPTION_PATH,
            params={
                "viewBy": str(view_by),
                "period": period,
                "page": page_number,
                "size": page_size,
                "sort_by": "creditsUsed",
                "sort_order": "desc",
            },
        )
        page = parse_usage_page(payload)
        yield page

        if not page.items:
            return
        if page.total_pages is not None and page_number >= page.total_pages:
            return
        if page.total_pages is None and len(page.items) < page_size:
            return
        page_number += 1

    logger.warning("Consumption pagination for %s stopped at %d pages", view_by, MAX_PAGES)
