"""Reading and parsing GET /api/credits/activity, the per-action credit log.

Everything that knows the shape of that response lives here, as
``usage.py`` does for the consumption summary. Observed on a live tenant
(2026-11), one row per billed action:

    {"items": [{"date": "2026-11-25T10:21:28Z", "action": "Fusion Scan - Opus 5.5",
                "creditsUsed": "144.5", "user": "jdoe", "userEmail": "",
                "projects": ["payments/api"], "projectIds": ["<uuid>"],
                "applications": [], "applicationIds": [], "scanner": "sast",
                "risks": ["..."], "environments": [], "environmentIds": [],
                "scans": ["..."], "scanIds": ["<uuid>"]}],
     "totalItems": 1939, "totalPages": 20, "currentPage": 1}

What the real data showed, and what follows from it:

* The rows carry ids (``projectIds``, ``applicationIds``) and a date, so a
  row is attributed by id and counted in the period it happened in.
* There is no row id, and two real events can be identical in every field,
  the timestamp included (59 of 1,939 rows were). Identical rows are never
  merged: a row's identity is only ever used to count how many times it was
  seen (see ``app/services/activity_source.py``).
* ``creditsUsed`` is a string; ``userEmail`` is often an empty string.
* ``sort_by=date&sort_order=asc`` is requested, so new rows append at the end
  and rows ageing out leave from the front (see the fetch rules in
  ``activity_source``). The parser checks the order instead of trusting it.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from app.checkmarx.client import CheckmarxClient
from app.checkmarx.errors import CheckmarxResponseError
from app.checkmarx.usage import parse_credits

logger = logging.getLogger(__name__)

ACTIVITY_PATH = "/credits/activity"
# The window asked for. Only the tail of the log is read in a normal cycle, so
# a short window keeps positions (and a full reconciliation sweep) small.
ACTIVITY_PERIOD = "last_30_days"
ACTIVITY_PERIOD_DAYS = 30
ACTIVITY_PAGE_SIZE = 500


class ActivityMalformedError(CheckmarxResponseError):
    """The activity log answered 200 with something that is not the log."""


@dataclass(frozen=True, slots=True)
class ActivityEvent:
    """One billed action, as reported. Never merged with an identical one."""

    date: datetime
    action: str
    credits: Decimal
    user: str
    user_email: str
    project_ids: tuple[str, ...]
    application_ids: tuple[str, ...]
    scan_ids: tuple[str, ...]
    scanner: str
    # Position in the page it was read from (0 based), for the read cursor.
    index: int = 0
    project_name: str | None = None

    @property
    def project_id(self) -> str | None:
        return self.project_ids[0] if self.project_ids else None

    @property
    def application_id(self) -> str | None:
        return self.application_ids[0] if self.application_ids else None

    @property
    def subject_key(self) -> str:
        """The key a person or account is known by in Settings → Attribution,
        the same one the consumption summary uses: the email when there is
        one, the reported name otherwise."""
        return (self.user_email or self.user).strip().lower()[:320]

    @property
    def key(self) -> str:
        """The fields that cannot change once the action happened: rows with
        the same key are counted as a multiset (how many there are is all
        that can be known)."""
        return event_key(self)

    @property
    def variant(self) -> tuple[str, str, tuple[str, ...]]:
        """The fields Checkmarx may fill in or change later for the same
        action (who, by name and email, and the application): not part of
        the key, so a row re-rendered with them is not a new event."""
        return (self.user, self.user_email.lower(), self.application_ids)


def _canonical_credits(value: Decimal) -> str:
    text = format(value.normalize(), "f") if value else "0"
    return text


def event_key(event: ActivityEvent) -> str:
    """The identity of a row: its date, action, credits, project ids, scan
    ids and scanner, which describe the action itself and are assumed never
    to change for a past action. ``user``, ``userEmail`` and
    ``applicationIds`` are left out: they may be filled in or changed later
    (an email added to the account, the project added to an application),
    and a row must not become a new event when they do."""
    fields = [
        event.date.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        event.action,
        _canonical_credits(event.credits),
        list(event.project_ids),
        list(event.scan_ids),
        event.scanner,
    ]
    encoded = json.dumps(fields, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode()).hexdigest()


def parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(entry).strip() for entry in value if isinstance(entry, str) and entry.strip())


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def parse_event(item: Any, index: int = 0) -> ActivityEvent | None:
    """One row of ``items``; None for a row that cannot be dated (it cannot be
    put in a period, nor told apart from others)."""
    if not isinstance(item, dict):
        return None
    date = parse_date(item.get("date"))
    if date is None:
        return None
    names = item.get("projects")
    return ActivityEvent(
        date=date,
        action=_text(item.get("action")),
        credits=parse_credits(item.get("creditsUsed")),
        user=_text(item.get("user")),
        user_email=_text(item.get("userEmail")),
        project_ids=_ids(item.get("projectIds")),
        application_ids=_ids(item.get("applicationIds")),
        scan_ids=_ids(item.get("scanIds")),
        scanner=_text(item.get("scanner")),
        index=index,
        project_name=(
            names[0] if isinstance(names, list) and names and isinstance(names[0], str) else None
        ),
    )


@dataclass(slots=True)
class ActivityPage:
    number: int
    events: list[ActivityEvent] = field(default_factory=list)
    # Rows in ``items``, parsed or not.
    rows: int = 0
    # Rows that could not be parsed (no date): never counted.
    bad_rows: int = 0
    total_items: int | None = None
    total_pages: int | None = None
    credits: Decimal = Decimal("0")


def parse_page(payload: Any, number: int) -> ActivityPage:
    """A response body; ActivityMalformedError when it is not the log."""
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ActivityMalformedError(
            "The credit activity log answered with something other than a list of items."
        )
    page = ActivityPage(number=number)
    items = payload["items"]
    page.rows = len(items)
    for index, item in enumerate(items):
        event = parse_event(item, index)
        if event is None:
            page.bad_rows += 1
            continue
        page.events.append(event)
        page.credits += event.credits
    for attribute, key in (("total_items", "totalItems"), ("total_pages", "totalPages")):
        value = payload.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            setattr(page, attribute, value)
    if page.bad_rows:
        logger.warning(
            "%d credit activity row(s) on page %d had no usable date", page.bad_rows, number
        )
    return page


def fetch_page(
    client: CheckmarxClient,
    number: int,
    *,
    size: int = ACTIVITY_PAGE_SIZE,
    period: str = ACTIVITY_PERIOD,
) -> ActivityPage:
    payload = client.get_json(
        ACTIVITY_PATH,
        params={
            "period": period,
            "page": number,
            "size": size,
            "sort_by": "date",
            "sort_order": "asc",
        },
    )
    return parse_page(payload, number)
