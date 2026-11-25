"""Third review of realfix: the rest of the fixes, with their own tests.

Listings that come back short never soft-delete; a name whose entity was
really deleted is kept on it until the deletion is confirmed and re-uses its
history when the entity comes back; a corrected automatic match keeps the
budget's own usage; the automation rule knows common build identities.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.client import Listing
from app.models import UnresolvedSubject, UsageRecord
from app.models.enums import EntityType
from app.models.org import CxApplication, CxProject
from app.services import cycle, ingestion, org_sync
from app.services.subject_matching import is_integration_identity
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _limit, _map, _state

# ---------------------------------------------------------------- listings


def _truncated(monkeypatch: pytest.MonkeyPatch, key: str, keep: int) -> None:
    """The listing reports every row in its total but stops after ``keep``."""
    real = FakeTenant._paged

    def paged(self, rows, list_key, params):  # type: ignore[no-untyped-def]
        if list_key == key:
            offset = int(params.get("offset", ["0"])[0])
            shown = rows[offset:keep] if offset < keep else []
            return httpx.Response(200, json={"totalCount": len(rows), list_key: shown})
        return real(self, rows, list_key, params)

    monkeypatch.setattr(FakeTenant, "_paged", paged)


class TestShortListingsDeleteNothing:
    def test_projects(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        tenant = live_tenant()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        _truncated(monkeypatch, "projects", 1)
        result = org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert not [p.id for p in db.scalars(select(CxProject)) if p.is_deleted]
        assert any("project listing was incomplete" in w for w in result.warnings)

    def test_applications(self, db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
        tenant = live_tenant()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert len(tenant.applications) >= 1
        _truncated(monkeypatch, "applications", 0)
        result = org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert not [a.id for a in db.scalars(select(CxApplication)) if a.is_deleted]
        assert any("application listing was incomplete" in w for w in result.warnings)

    def test_a_complete_listing_still_deletes(self, db: Session) -> None:
        tenant = live_tenant()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        tenant.projects = [p for p in tenant.projects if p["id"] != "proj-web"]
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert db.get(CxProject, "proj-web").is_deleted


class TestPaginate:
    class _Client:
        def __init__(self, pages):  # type: ignore[no-untyped-def]
            self.pages = pages
            self.asked: list[int] = []

        def get_json(self, path, *, base, params):  # type: ignore[no-untyped-def]
            self.asked.append(params["offset"])
            return self.pages(params["offset"], params["limit"])

    def _read(self, pages, page_size=3):  # type: ignore[no-untyped-def]
        from app.checkmarx.client import CheckmarxClient

        fake = self._Client(pages)
        listing = Listing()
        rows = list(
            CheckmarxClient.paginate(fake, "/x", page_size=page_size, listing=listing)  # type: ignore[arg-type]
        )
        return rows, listing, fake.asked

    def test_a_server_page_cap_is_read_to_the_total(self) -> None:
        rows = [{"id": str(i)} for i in range(7)]
        got, listing, _ = self._read(
            lambda offset, _limit: {"totalCount": 7, "items": rows[offset : offset + 2]}
        )
        assert [r["id"] for r in got] == [str(i) for i in range(7)] and listing.complete

    def test_an_empty_page_before_the_total_is_incomplete(self) -> None:
        rows = [{"id": str(i)} for i in range(7)]
        got, listing, _ = self._read(
            lambda offset, _limit: {"totalCount": 7, "items": rows[offset : min(offset + 3, 3)]}
        )
        assert len(got) == 3 and not listing.complete

    def test_without_a_total_a_short_page_is_followed_once(self) -> None:
        rows = [{"id": str(i)} for i in range(5)]
        got, listing, asked = self._read(lambda offset, _limit: rows[offset : offset + 2])
        assert len(got) == 5 and listing.complete and asked == [0, 2, 4, 5]

    def test_a_repeated_page_is_incomplete(self) -> None:
        got, listing, _ = self._read(lambda _offset, _limit: [{"id": "a"}, {"id": "b"}])
        assert len(got) == 2 and not listing.complete


# ------------------------------------------------------- a deleted entity


def _drop(tenant, project_id: str):  # type: ignore[no-untyped-def]
    kept = [p for p in tenant.projects if p["id"] != project_id]
    dropped = [p for p in tenant.projects if p["id"] == project_id]
    tenant.projects = kept
    return dropped


def test_a_project_deleted_for_one_sync_keeps_its_usage(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(view="project", name="payments/web", credits=104)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100

    # A complete listing without the project: deleted, not yet confirmed.
    dropped = _drop(tenant, "proj-web")
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    db.expire_all()
    assert db.get(CxProject, "proj-web").is_deleted
    row = db.scalar(
        select(UsageRecord)
        .where(UsageRecord.subject_key == "payments/web")
        .order_by(UsageRecord.id.desc())
    )
    # Its name counts nowhere meanwhile, and what was counted stays counted.
    assert row.entity_id is None
    assert _state(db, group).credits_used == 100

    # Back at the next sync: nothing was lost, nothing counted twice.
    tenant.projects.extend(dropped)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100
    assert _state(db, group).credits_used == 100


def test_a_confirmed_deletion_and_a_return_bring_no_history(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    _map(admin_client, "proj-tools")
    tools = _limit(db, EntityType.PROJECT, "proj-tools")
    cycle.run_cycle(trigger="manual")

    dropped = _drop(tenant, "proj-tools")
    cycle.run_cycle(trigger="manual", force_org_sync=True)  # deleted
    cycle.run_cycle(trigger="manual", force_org_sync=True)  # confirmed
    db.expire_all()
    assert "proj-tools" not in ingestion.latest_totals(db, "project")

    tenant.projects.extend(dropped)
    tenant.set_entity_credits(view="project", name=NAME, credits=900)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    # Only the 30 reported since it came back (usage ledger): nothing of its
    # history, or of the mapped name's, comes back as usage.
    assert _state(db, tools).credits_used == 30


# ------------------------------------------- correcting an automatic match


def test_correcting_an_automatic_match_moves_only_what_comes_after(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    from datetime import timedelta

    from app.db.base import utcnow
    from app.services import evaluation

    tenant = live_tenant()
    tenant.add_user(
        user_id="user-dave",
        username="dave.dawson@example.com",
        email="dave.dawson@example.com",
        first_name="Dave",
        last_name="Dawson",
    )
    tenant.set_user_credits(name="cx-dave-dawson", credits=40)  # auto-matched to Dave
    tenant.set_user_credits(name="Dave Dawson", email="dave.dawson@example.com", credits=10)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    dave = _limit(db, EntityType.USER, "user-dave")
    cycle.run_cycle(trigger="manual")
    # Next month: the period's baseline holds the handle's 40 and Dave's 10.
    now = utcnow()
    next_month = (now.replace(day=1) + timedelta(days=32)).replace(day=2)
    evaluation.evaluate_all(db, now=next_month)
    db.commit()
    tenant.set_user_credits(name="Dave Dawson", email="dave.dawson@example.com", credits=15)
    tenant.set_user_credits(name="cx-dave-dawson", credits=43)
    ingestion.ingest_usage(db, connection_client(db))
    db.commit()
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=1))
    db.commit()
    assert _latest(db, dave).credits_used == 8

    # The handle was someone else all along.
    subject = db.scalar(
        select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "cx-dave-dawson")
    )
    r = admin_client.post(f"/api/usage/unresolved/{subject.id}/map", json={"user_id": "user-bob"})
    assert r.status_code == 200, r.text
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=2))
    db.commit()
    # Restated for the usage ledger (fifth review): what a period counted stays
    # counted; the correction moves the handle's usage from now on.
    assert _latest(db, dave).credits_used == 8
    bob = _limit(db, EntityType.USER, "user-bob")
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=3))
    db.commit()
    tenant.set_user_credits(name="cx-dave-dawson", credits=50)
    ingestion.ingest_usage(db, connection_client(db))
    db.commit()
    evaluation.evaluate_all(db, now=next_month + timedelta(hours=4))
    db.commit()
    assert _latest(db, dave).credits_used == 8
    assert _latest(db, bob).credits_used == 7


def connection_client(db):  # type: ignore[no-untyped-def]
    from app.services import connection as connection_service

    return connection_service.get_client(db)


def _latest(db, limit):  # type: ignore[no-untyped-def]
    from app.models import LimitPeriodState

    db.expire_all()
    return db.scalar(
        select(LimitPeriodState)
        .where(LimitPeriodState.limit_id == limit.id)
        .order_by(LimitPeriodState.period_start.desc())
        .limit(1)
    )


# -------------------------------------------------------------- automation


@pytest.mark.parametrize(
    "name",
    [
        "GitHub-Actions",
        "sonar-scanner",
        "buildserver01",
        "build-agent",
        "gitlab-runner",
        "deploy-svc",
        "dependabot",
        "renovate",
        "snyk-bot",
    ],
)
def test_build_identities_are_automation(name: str) -> None:
    assert is_integration_identity(name, None)


@pytest.mark.parametrize(
    "name",
    [
        "Runner",
        "Builder",
        "Bob_Builder",
        "Mary-Runner",
        "Sonia",
        "Jenkins",
        "jsmith2",
        "Paul.Scanner",
        "Mary-Build",
        "lee.sonar",
        "Build-Agent",
    ],
)
def test_names_like_build_words_stay_people(name: str) -> None:
    assert not is_integration_identity(name, None)
