"""Third review of realfix: the card's "Show more" asked for limit=200, 400,
600, ... and the API refuses anything above 500. The card now asks for the
next page by offset, a page at a time."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_show_more_pages_by_offset(admin_client: TestClient) -> None:
    for offset in (0, 200, 400, 600):
        r = admin_client.get(
            "/api/usage/unmatched-entities", params={"limit": 200, "offset": offset}
        )
        assert r.status_code == 200, (offset, r.status_code)
    # A page is never more than 500 rows.
    r = admin_client.get("/api/usage/unmatched-entities", params={"limit": 600})
    assert r.status_code == 422
