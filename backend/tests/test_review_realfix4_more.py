"""Fourth review of realfix: the edge cases around it, with their own tests.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import CheckmarxClient, Listing
from app.models import UsageAnchor
from app.models.enums import EntityType
from app.models.org import CxGroup, CxProject
from app.services import cycle, ingestion, org_sync, settings_store
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _state

# ------------------------------------------------------------------ listings


class _Pages:
    def __init__(self, pages):  # type: ignore[no-untyped-def]
        self.pages = pages

    def get_json(self, path, *, base, params):  # type: ignore[no-untyped-def]
        return self.pages(params["offset"], params["limit"])


def test_a_listing_whose_order_shifts_is_not_complete_by_count_alone() -> None:
    # Five rows; between the first and the second page one row moves ahead,
    # so the second page repeats a row and the moved one is never returned.
    first = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
    second = [{"id": "c"}, {"id": "e"}]

    def pages(offset, _limit):  # type: ignore[no-untyped-def]
        return {"totalCount": 5, "items": first if offset == 0 else (second if offset == 3 else [])}

    listing = Listing()
    rows = list(CheckmarxClient.paginate(_Pages(pages), "/x", page_size=3, listing=listing))  # type: ignore[arg-type]
    assert len(rows) == 5 and listing.read == 4 and not listing.complete


def _short_projects(monkeypatch: pytest.MonkeyPatch, total: int) -> None:
    """Every listing reports ``total`` but returns only what the key sees."""
    real = FakeTenant._paged

    def paged(self, rows, key, params):  # type: ignore[no-untyped-def]
        response = real(self, rows, key, params)
        if key == "projects":
            body = response.json()
            body["totalCount"] = total
            return httpx.Response(200, json=body)
        return response

    monkeypatch.setattr(FakeTenant, "_paged", paged)


def test_a_consistently_short_listing_is_accepted_after_three(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = live_tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    tenant.projects = [p for p in tenant.projects if p["id"] != "proj-tools"]
    _short_projects(monkeypatch, total=len(tenant.projects) + 5)
    warnings = []
    for _ in range(3):
        result = org_sync.sync_org_model(db, tenant.client())
        db.commit()
        warnings.append(result.warnings)
        if _ < 2:
            assert not db.get(CxProject, "proj-tools").is_deleted
    assert db.get(CxProject, "proj-tools").is_deleted
    assert any("taken as everything this API key can see" in w for w in warnings[2])
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert not any("project listing" in w for w in result.warnings), result.warnings


def test_many_groups_missing_at_once_wait_for_the_next_sync(db: Session) -> None:
    tenant = live_tenant()
    for index in range(4):
        tenant.add_group(group_id=f"grp-extra-{index}", name=f"Extra {index}")
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    kept = [g for g in tenant.groups if not g["id"].startswith("grp-extra")]
    tenant.groups[:] = kept
    result = org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert not db.get(CxGroup, "grp-extra-0").is_deleted
    assert any("missing from the IAM listing at once" in w for w in result.warnings)
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert db.get(CxGroup, "grp-extra-0").is_deleted


# ------------------------------------------------------------- attribution


def test_an_old_unmatched_name_does_not_take_over_a_vanishing_one(
    db: Session,
    connected,  # noqa: F811
) -> None:
    """The entity's old name leaves the feed while a name that has been
    unmatched all along starts to match it: not a rename taking over."""
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    settings_store.set_value(db, org_sync.SHORT_LISTINGS_KEY, {})
    db.commit()
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-api")
    cycle.run_cycle(trigger="manual")
    # Push the name's first unmatched reading far into the past.
    from datetime import timedelta

    from app.models import UsageNameState

    state = db.scalar(select(UsageNameState).where(UsageNameState.subject_key == NAME))
    state.first_unmatched_at = state.first_unmatched_at - timedelta(days=3)
    db.commit()
    for p in tenant.projects:
        if p["id"] == "proj-api":
            p["name"] = NAME
    tenant.consumption["project"] = [
        r for r in tenant.consumption["project"] if r["name"] != "payments/api"
    ]
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, project)
    assert state.credits_used < 100, (state.credits_used, state.baseline_credits)


def test_a_returning_name_whose_total_rolled_down_re_anchors_lower(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    connected(tenant)
    settings_store.set_value(db, ingestion.HOLD_READINGS_KEY, 1)
    db.commit()
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    web = next(p for p in tenant.projects if p["id"] == "proj-web")
    tenant.projects.remove(web)
    cycle.run_cycle(trigger="manual", force_org_sync=True)  # deleted
    cycle.run_cycle(trigger="manual", force_org_sync=True)  # confirmed
    cycle.run_cycle(trigger="manual")
    # Meanwhile most of its history left the lookback window.
    tenant.set_entity_credits(view="project", name="payments/web", credits=600)
    tenant.projects.append(web)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    db.expire_all()
    anchor = db.scalar(select(UsageAnchor).where(UsageAnchor.subject_key == "payments/web"))
    assert anchor.reason == ingestion.ANCHOR_RETURNED and anchor.offset_credits == 600
    assert _state(db, project).credits_used == 0
    tenant.set_entity_credits(view="project", name="payments/web", credits=625)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 25


def test_a_carried_name_is_left_out_of_the_lists_by_name(
    db: Session,
    connected,  # noqa: F811
) -> None:
    from app.models.enums import UsageView
    from app.services import dashboard

    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=104)
    # Large enough that losing one name is no collapse the feed is doubted for.
    tenant.set_entity_credits(view="project", name="payments/api", credits=1000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    tenant.consumption["project"] = [
        r for r in tenant.consumption["project"] if r["name"] != "payments/web"
    ]
    cycle.run_cycle(trigger="manual")
    names = {r.subject_key for r in dashboard.latest_snapshot_records(db, UsageView.PROJECT)}
    assert "payments/web" not in names
    # ...while budgets still count it until the hold ends.
    assert ingestion.latest_totals(db, UsageView.PROJECT)["proj-web"] == Decimal("104")


# ------------------------------------------------------------------ paging


def test_keyset_pages_neither_skip_nor_repeat_when_a_cycle_re_ranks(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    for index in range(6):
        tenant.set_entity_credits(view="project", name=f"gone/repo-{index}", credits=100 - index)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    first = admin_client.get("/api/usage/unmatched-entities", params={"limit": 3}).json()
    # A cycle re-ranks: the last of the first page would now come first.
    tenant.set_entity_credits(view="project", name="gone/repo-5", credits=500)
    tenant.set_entity_credits(view="project", name="gone/repo-0", credits=1)
    cycle.run_cycle(trigger="manual")
    rest = admin_client.get(
        "/api/usage/unmatched-entities",
        params={"limit": 50, "after": first[-1]["cursor"], "readings": first[0]["readings"]},
    ).json()
    keys = [row["subject_key"] for row in first + rest]
    assert len(keys) == len(set(keys))
    assert {f"gone/repo-{index}" for index in range(6)} <= set(keys)
