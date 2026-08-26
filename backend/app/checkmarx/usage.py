"""Reading and parsing GET /api/credits/consumption.

Everything that knows the shape of that response lives in this one module, so a
change to the payload is a single file edit. Callers get ``ParsedUsagePage``
objects and never touch the JSON.

Observed response shape (viewBy=user):

    {
      "items": [
        {
          "name": "Aslesha Nargolkar",
          "email": "aslesha.nargolkar@checkmarx.com",
          "userEmail": "aslesha.nargolkar@checkmarx.com",
          "creditsUsed": 1,
          "percentOfTotal": 0.1,
          "actionsPerformed": {
            "actions": [{"actionType": "triage", "transactionCount": 1}],
            "total": 1
          }
        }
      ],
      "totalItems": 44, "totalPages": 3, "currentPage": 1
    }

Robustness choices, each because of something visible in the real data:

* ``email`` and ``userEmail`` are both optional, and several rows carry an email
  address in ``name`` instead. Identity resolution therefore works from a
  normalised key rather than trusting any single field.
* ``creditsUsed`` is not the same as ``actionsPerformed.total``: a remediation can
  cost 3 credits for 1 transaction. Credits are the budget currency, transactions
  are only reported for context.
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


def normalise_action_type(raw: str | None) -> str:
    if not raw:
        return ActionType.UNKNOWN
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    return _ACTION_ALIASES.get(key, _ACTION_ALIASES.get(key.replace("_", ""), key))


def _to_decimal(value: Any) -> Decimal:
    """Coerce a reported credit figure without ever raising.

    A row we cannot parse must not abort the whole poll, and it must not be
    invented as a non zero cost either, so it lands as zero and is logged.
    """
    if value is None:
        return Decimal("0")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        logger.warning("Could not parse a creditsUsed value of type %s", type(value).__name__)
        return Decimal("0")


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
    # The action dimension reports the type in the row itself rather than nested.
    elif looks_like_action_row(item):
        actions[normalise_action_type(_first_string(item, "actionType", "action", "name"))] = (
            item.get("transactionCount") if isinstance(item.get("transactionCount"), int) else 0
        )

    percent = item.get("percentOfTotal")
    return ParsedUsageItem(
        subject_key=subject_key,
        subject_name=name,
        subject_email=email,
        credits_used=_to_decimal(item.get("creditsUsed", item.get("credits"))),
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
