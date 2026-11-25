"""Eighth review of realfix (round seven). Synthetic data only.

1. A doubted fall believed because it outlasted its bound (3 doubted
   readings or 2 hours) re-bases the name lower; when the glitch ends and the
   feed reports the true total again, the recovery is counted as new usage.
2. A user row with a display name only is never taken for a repeat, so page
   drift on the credits-sorted feed (the row served on two pages) doubles it
   in a reading the completeness checks believe; the spike is counted, the
   fall back is believed, and every drift counts the row's whole total again.
"""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit
from tests.test_usage_ledger_round7 import _doubted, _Run, _tenant


def test_a_glitch_outlasting_the_doubt_bound_is_not_counted_on_recovery(
    db: Session, connected, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    assert run.used(web) == 0
    # A persistently short listing reports payments/web far too low, in
    # doubted readings, for longer than the bound (3 readings).
    _doubted(monkeypatch, "payments/web", 400)
    for _ in range(4):
        run.step()
    monkeypatch.undo()
    connected(tenant)
    monkeypatch.setattr(
        __import__("app.services.ingestion", fromlist=["utcnow"]), "utcnow", lambda: run.clock[0]
    )
    # The glitch ends: the true total (unchanged, 1000) is reported again.
    run.step()
    run.step()
    # Nobody used anything: the budget must still read 0.
    assert run.used(web) == 0


def _drifted_user_pages(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    """viewBy=user, two pages sorted by creditsUsed desc. Page 1 ends with
    ``name``; between the two page requests the row just below it overtakes
    it, so page 2 starts with ``name`` again and the overtaking row is on
    neither page. Row count equals totalItems and no row carries an id or
    email, so nothing looks wrong."""
    real = FakeTenant._consumption_response

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "user":
            return real(self, params)
        rows = sorted(self.consumption["user"], key=lambda r: float(r["creditsUsed"]), reverse=True)
        at = next(i for i, r in enumerate(rows) if r["name"] == name)
        page = int(params.get("page", ["1"])[0])
        items = rows[: at + 1] if page == 1 else [rows[at]] + rows[at + 2 :]
        return httpx.Response(
            200,
            json={"items": items, "totalItems": len(rows), "totalPages": 2, "currentPage": page},
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)


def test_page_drift_on_a_display_name_only_row_is_not_counted(
    db: Session, connected, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = live_tenant()
    # Bob Baker's row carries a display name only (matched by full name).
    tenant.set_user_credits(name="Bob Baker", credits=500, actions={"triage": 500})
    tenant.set_user_credits(name="Dana Drift", credits=400, actions={"triage": 400})
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    bob = _limit(db, EntityType.USER, "user-bob")
    run.step()
    assert run.used(bob) == 0
    for _ in range(3):
        # One reading drifts between its two page requests...
        _drifted_user_pages(monkeypatch, "Bob Baker")
        run.step()
        monkeypatch.undo()
        connected(tenant)
        monkeypatch.setattr(
            __import__("app.services.ingestion", fromlist=["utcnow"]),
            "utcnow",
            lambda: run.clock[0],
        )
        # ...then a clean one. Nobody used anything at all.
        run.step()
    assert run.used(bob) == 0


def test_usage_masked_by_a_roll_down_is_not_counted_as_new_after_forgetting(
    db: Session, connected, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``last_rise_at`` is when the total last *rose*. Usage spent in an
    interval where older usage rolled out faster is never seen as a rise, so
    the name is forgotten while that usage is still in the lookback window;
    a one-reading absence then brings it back in full, into a later period."""
    from app.services import settings_store

    settings_store.set_value(db, settings_store.KEY_USAGE_PERIOD, "last_30_days")
    db.commit()
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 12, 1, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1100)
    run.step()  # Dec 1: a rise of 100, counted (last rise)
    # Dec 5: 1000 of old usage rolls out while 100 new is spent: a believed
    # fall to 200 (the 100 new is the documented, accepted under-count).
    tenant.set_entity_credits(view="project", name="payments/web", credits=200)
    run.step(hours=24 * 4)
    # Dec 31: the Dec 1 rise rolls out; only the Dec 5 usage is left.
    tenant.set_entity_credits(view="project", name="payments/web", credits=100)
    run.step(hours=24 * 26)
    rows = tenant.consumption["project"]
    # Jan 1 00:30: one reading without the row (e.g. it slipped between pages).
    tenant.consumption["project"] = [r for r in rows if r["name"] != "payments/web"]
    run.clock[0] = datetime(2028, 1, 1, 0, 0, tzinfo=UTC)
    run.step()
    tenant.consumption["project"] = rows
    run.step()
    run.step()
    # Nothing was used in January: the 100 is December's usage.
    assert run.used(web) == 0


def test_usage_between_the_application_and_project_reads_counts_once_when_an_app_row_appears(
    db: Session, connected, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Views are read application, then project. In the ingest where an
    application's own row first appears, its budget is still fed by its
    projects (``own_figures`` was taken before), up to the project read;
    from the next ingest on its own row feeds it from the application read
    of the ingest before. Usage between the two reads counts twice."""
    tenant = _tenant()
    tenant.consumption["application"] = []
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    app = _limit(db, EntityType.APPLICATION, "app-payments")
    run.step()
    run.step()
    assert run.used(app) == 0
    real = FakeTenant._consumption_response
    armed = [True]

    def response(self, params):  # type: ignore[no-untyped-def]
        served = real(self, params)
        if armed[0] and params.get("viewBy", [""])[0] == "application":
            armed[0] = False
            # 50 credits are spent on payments/web right after this read.
            self.set_entity_credits(view="project", name="payments/web", credits=1050)
            self.set_entity_credits(view="application", name="Payments", credits=21050)
        return served

    # The application's own row appears (it reports both projects' usage).
    tenant.set_entity_credits(view="application", name="Payments", credits=21000)
    monkeypatch.setattr(FakeTenant, "_consumption_response", response)
    run.step()
    run.step()
    run.step()
    assert run.used(app) == 50
