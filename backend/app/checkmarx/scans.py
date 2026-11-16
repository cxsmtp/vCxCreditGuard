"""Reading a project's scans: ``GET /api/scans/``.

Used only by auto-triage attribution, to find who started the scans whose
completion triggered an auto triage. Everything that knows the shape of the
scans payload lives here.

Observed response shape (also what ``POST /api/scans/byFilters`` returns):

    {
      "totalCount": 7265, "filteredTotalCount": 2,
      "scans": [
        {"id": "...", "status": "Completed", "branch": "main",
         "createdAt": "2026-11-06T19:00:27.916583Z",
         "updatedAt": "2026-11-06T19:13:46.982628Z",
         "projectId": "...", "initiator": "someone@example.com",
         "sourceOrigin": "PR Webhook", "sourceType": "github", ...}
      ]
    }

``initiator`` is an email for a person, but an integration (a PR webhook, a
scheduler) reports its own name there. Scans are returned newest first.

Listing is deliberately bounded: a project can have thousands of scans, and one
busy project must never make a governance cycle unbounded. A listing that hits
its page cap says so (``truncated``) instead of pretending it saw everything.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.checkmarx.client import CheckmarxClient

logger = logging.getLogger(__name__)

SCANS_PATH = "/scans/"
# Statuses whose results auto triage runs on. "Partial" is a scan where an
# engine failed but others produced results, which are still triaged.
COMPLETED_STATUSES: frozenset[str] = frozenset({"completed", "partial"})
DEFAULT_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class ScanSummary:
    id: str
    status: str
    branch: str | None
    created_at: datetime | None
    # When the scan finished. The listing has no explicit field for it; for a
    # finished scan ``updatedAt`` is its last change, which is the completion.
    completed_at: datetime | None
    initiator: str | None
    source_origin: str | None

    @property
    def completed(self) -> bool:
        return self.status.strip().lower() in COMPLETED_STATUSES


@dataclass
class ScanPage:
    scans: list[ScanSummary]
    total: int | None


@dataclass
class ScanListing:
    scans: list[ScanSummary]
    # True when the page cap was reached before the listing reached ``since``.
    truncated: bool
    requests: int


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Python before 3.11 accepted at most six fractional digits; Checkmarx
    # sometimes sends more. Trim rather than fail.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = ""
        rest = ""
        for index, char in enumerate(tail):
            if char.isdigit():
                digits += char
            else:
                rest = tail[index:]
                break
        text = f"{head}.{digits[:6] or '0'}{rest}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def format_time(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_scan(item: Any) -> ScanSummary | None:
    if not isinstance(item, dict):
        return None
    scan_id = item.get("id")
    if not isinstance(scan_id, str) or not scan_id:
        return None
    status = item.get("status") if isinstance(item.get("status"), str) else ""
    created = parse_time(item.get("createdAt"))
    updated = parse_time(item.get("updatedAt"))
    initiator = item.get("initiator")
    branch = item.get("branch")
    origin = item.get("sourceOrigin")
    return ScanSummary(
        id=scan_id,
        status=status,
        branch=branch if isinstance(branch, str) and branch else None,
        created_at=created,
        completed_at=updated or created,
        initiator=initiator.strip() if isinstance(initiator, str) and initiator.strip() else None,
        source_origin=origin if isinstance(origin, str) and origin else None,
    )


def parse_scan_page(payload: Any) -> ScanPage:
    if isinstance(payload, list):
        items = payload
        total = None
    elif isinstance(payload, dict):
        items = payload.get("scans") if isinstance(payload.get("scans"), list) else []
        total = None
        for key in ("filteredTotalCount", "totalCount"):
            if isinstance(payload.get(key), int):
                total = payload[key]
                break
    else:
        return ScanPage(scans=[], total=None)
    return ScanPage(
        scans=[scan for item in items if (scan := parse_scan(item)) is not None], total=total
    )


def has_wildcard(branch: str) -> bool:
    return any(char in branch for char in "*?[")


def branch_matches(branch: str | None, patterns: list[str] | None) -> bool:
    """Whether a scan on ``branch`` is one auto triage runs on.

    No patterns means every branch. A pattern with a wildcard is matched as a
    glob, anything else exactly.
    """
    if not patterns:
        return True
    if branch is None:
        return False
    return any(
        fnmatch.fnmatchcase(branch, pattern) if has_wildcard(pattern) else branch == pattern
        for pattern in patterns
    )


def list_project_scans(
    client: CheckmarxClient,
    *,
    project_id: str,
    branch: str | None = None,
    since: datetime | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_pages: int = 5,
) -> ScanListing:
    """The project's scans, newest first, back to ``since`` (by creation time).

    ``since`` is sent as ``from-date`` and also enforced here, because paging
    stops as soon as a page reaches scans created before it: the listing is
    newest first, so nothing after that point can be newer. At most
    ``max_pages`` requests are made; reaching that cap with more to read sets
    ``truncated``.
    """
    scans: list[ScanSummary] = []
    seen: set[str] = set()
    requests = 0
    offset = 0
    while requests < max_pages:
        params: dict[str, Any] = {"project-id": project_id, "limit": page_size, "offset": offset}
        if branch:
            params["branch"] = branch
        if since is not None:
            params["from-date"] = format_time(since)
        payload = client.get_json(SCANS_PATH, params=params)
        requests += 1
        page = parse_scan_page(payload)
        reached_since = False
        for scan in page.scans:
            if scan.id in seen:
                continue
            seen.add(scan.id)
            if since is not None and scan.created_at is not None and scan.created_at < since:
                reached_since = True
                continue
            scans.append(scan)
        offset += len(page.scans)
        if (
            reached_since
            or len(page.scans) < page_size
            or (page.total is not None and offset >= page.total)
        ):
            return ScanListing(scans=scans, truncated=False, requests=requests)
    logger.info("Scan listing for project %s stopped at the %d page cap", project_id, max_pages)
    return ScanListing(scans=scans, truncated=True, requests=requests)
