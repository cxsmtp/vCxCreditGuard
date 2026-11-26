"""Sixth review of realfix: the feed is paged and sorted by creditsUsed. When
the ranking shifts between two page requests, one name is served on both
pages. The ingest sums a subject's rows across pages, so that name reads at
double its total for one reading. The ledger banks the spike as an increase
(and ignores the fall back as a roll-down): the name's whole history lands in
the period counter, for good."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

import httpx
import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def _drifted_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    """viewBy=project, size 2: page 1 holds ranks 1-2; by the time page 2 is
    asked for, rank 2 has been overtaken by rank 3, so page 2 serves the old
    rank 2 again (and the old rank 3 is on neither page)."""
    real = FakeTenant._consumption_response

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "project":
            return real(self, params)
        rows = sorted(
            self.consumption["project"], key=lambda r: float(r["creditsUsed"]), reverse=True
        )
        page = int(params.get("page", ["1"])[0])
        window = rows[0:2] if page == 1 else [rows[1]]
        return httpx.Response(
            200,
            json={"items": window, "totalItems": len(rows), "totalPages": 2, "currentPage": page},
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)


def test_a_row_served_on_two_pages_banks_history(
    db: Session,
    connected,
    monkeypatch: pytest.MonkeyPatch,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/api", credits=5000)
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="platform/tools", credits=900)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    web = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    assert _state(db, web).credits_used == 0
    # One reading with the ranking drifting between page requests.
    _drifted_pages(monkeypatch)
    cycle.run_cycle(trigger="manual")
    monkeypatch.undo()
    connected(tenant)
    # Then normal readings; nobody spent anything at all.
    cycle.run_cycle(trigger="manual")
    cycle.run_cycle(trigger="manual")
    used = _state(db, web).credits_used
    assert used == 0, used
