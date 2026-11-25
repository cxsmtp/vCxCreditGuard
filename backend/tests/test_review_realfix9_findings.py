"""Ninth review of realfix (round eight). Synthetic data only (example.com).

1. A collapse ceiling is lost when its name misses one reading of the same
   collapse: the "missing" bookkeeping turns the ceiling into an ordinary
   remembered total, and the name's return at its collapsed total is believed
   (the collapse is the latest believed reading by then). When the feed
   recovers, the glitch is counted.
2. Two people who share a display name, split across a page boundary, are
   now read as one repeated row (the higher kept). When a later reading
   serves them on one page they are added up again, and the smaller one's
   usage, all of it from before the tool watched the name, is counted.
"""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import UsageMissingName
from app.models.enums import EntityType
from app.services import ledger
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit
from tests.test_usage_ledger_round7 import _Run, _tenant


def _collapse(tenant) -> list[dict]:  # type: ignore[no-untyped-def]
    saved = [dict(row) for row in tenant.consumption["project"]]
    for row in tenant.consumption["project"]:
        row["creditsUsed"] = str(int(float(row["creditsUsed"]) // 10))
    return saved


def test_a_collapse_ceiling_survives_the_name_missing_one_reading_of_the_collapse(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    saved = _collapse(tenant)
    for _ in range(4):
        run.step(hours=1)
    held = db.scalar(select(UsageMissingName).where(UsageMissingName.subject_key == "payments/web"))
    assert held is not None and held.kind == ledger.COLLAPSE
    collapsed = tenant.consumption["project"]
    # Still the same collapse: one reading misses payments/web, the next has
    # it back at its collapsed total (100).
    tenant.consumption["project"] = [r for r in collapsed if r["name"] != "payments/web"]
    run.step(hours=1)
    tenant.consumption["project"] = collapsed
    run.step(hours=1)
    # The feed recovers. Nobody used anything.
    tenant.consumption["project"] = saved
    run.step()
    run.step()
    assert run.used(web) == 0


def test_a_name_missing_from_a_persisting_collapse_keeps_its_ceiling(
    db: Session, connected, monkeypatch
) -> None:
    """A name that fell to nothing in the collapse fell too."""
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    saved = _collapse(tenant)
    collapsed = tenant.consumption["project"]
    tenant.consumption["project"] = [r for r in collapsed if r["name"] != "payments/web"]
    for _ in range(4):
        run.step(hours=1)
    # Still collapsed; payments/web is listed again at its collapsed total.
    tenant.consumption["project"] = collapsed
    run.step(hours=1)
    tenant.consumption["project"] = saved
    run.step()
    run.step()
    assert run.used(web) == 0


def _user(name: str, credits: int, email: str | None = None) -> dict:
    row = {
        "name": name,
        "creditsUsed": str(credits),
        "percentOfTotal": 0.1,
        "actionsPerformed": {
            "actions": [{"actionType": "triage", "transactionCount": credits}],
            "total": credits,
        },
    }
    if email:
        row["email"] = row["userEmail"] = email
    return row


def test_two_people_sharing_a_display_name_rejoining_one_page_count_nothing(
    db: Session, connected, monkeypatch
) -> None:
    tenant = live_tenant()
    xavier = _user("Xavier Example", 100, "xavier@example.com")
    bob_big, bob_small = _user("Bob Baker", 50), _user("Bob Baker", 10)
    yolanda = _user("Yolanda Example", 5, "yolanda@example.com")
    # Two pages of two: the two Bob Bakers (two people) straddle the boundary.
    tenant.page_size_override = 2
    tenant.consumption["user"] = [xavier, bob_big, bob_small, yolanda]
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    bob = _limit(db, EntityType.USER, "user-bob")
    run.step()
    run.step()
    assert run.used(bob) == 0
    # A new person enters at the top of the (credits-sorted) ranking: every
    # row moves down one place and both Bob Bakers are now on page 2.
    # Neither of them used anything.
    walter = _user("Walter Example", 200, "walter@example.com")
    tenant.consumption["user"] = [walter, xavier, bob_big, bob_small, yolanda]
    run.step()
    run.step()
    assert run.used(bob) == 0


def _short_project_listing(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The project listing says it has one row more than it serves."""
    import httpx

    from tests.fake_tenant import FakeTenant

    real = FakeTenant._consumption_response

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "project":
            return real(self, params)
        rows = self.consumption["project"]
        return httpx.Response(
            200,
            json={"items": rows, "totalItems": len(rows) + 1, "totalPages": 1, "currentPage": 1},
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)


def test_a_collapse_accepted_in_a_short_listing_keeps_its_ceiling(
    db: Session, connected, monkeypatch
) -> None:
    """The reading that accepts the collapse is also one row short: its falls
    are held as doubted dips, not collapse ceilings, so the next complete
    reading of the same collapse 'confirms' them."""
    from app.services import ingestion

    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    saved = _collapse(tenant)
    for _ in range(2):
        run.step(hours=1)  # held
    # The third collapsed reading, two hours on, accepts the collapse; it is
    # also one row short.
    _short_project_listing(monkeypatch)
    run.step(hours=1)
    db.expire_all()
    held = db.scalar(select(UsageMissingName).where(UsageMissingName.subject_key == "payments/web"))
    assert held is not None and held.kind in (ledger.DIP, ledger.COLLAPSE)
    monkeypatch.undo()
    connected(tenant)
    monkeypatch.setattr(ingestion, "utcnow", lambda: run.clock[0])
    # The same collapse, now in a complete listing.
    run.step(hours=1)
    tenant.consumption["project"] = saved
    run.step()
    run.step()
    assert run.used(web) == 0


def test_a_held_fall_is_not_confirmed_by_the_reading_that_accepts_a_collapse(
    db: Session, connected, monkeypatch
) -> None:
    """payments/web's fall is held as doubted; then the whole feed collapses
    and the collapse is accepted because it persisted. That reading is the
    collapse, not a confirmation of the fall."""
    from app.services import ingestion
    from tests.test_usage_ledger_round7 import _doubted

    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    _doubted(monkeypatch, "payments/web", 400)
    run.step()
    monkeypatch.undo()
    connected(tenant)
    monkeypatch.setattr(ingestion, "utcnow", lambda: run.clock[0])
    db.expire_all()
    held = db.scalar(select(UsageMissingName).where(UsageMissingName.subject_key == "payments/web"))
    assert held is not None and held.kind == ledger.DIP
    saved = _collapse(tenant)
    for _ in range(3):
        run.step(hours=1)  # held, held, accepted
    run.step(hours=1)
    tenant.consumption["project"] = saved
    run.step()
    run.step()
    assert run.used(web) == 0


def test_an_application_row_mapped_to_its_application_does_not_count_the_read_overlap_twice(
    db: Session, connected, monkeypatch, admin_client
) -> None:
    """The eighth review's B4 (usage between the application and project reads
    of one ingest counted twice when an application's own row starts feeding
    its budget), reached by mapping an unmatched application row instead of
    the row appearing: the mapped row is not new to the feed, so it is not
    'fresh', and its first increase covers the interval its projects fed."""
    from tests.fake_tenant import FakeTenant
    from tests.test_review_realfix7_properties import _api

    tenant = _tenant()
    # The application's own row is reported under a name the sync does not
    # know (it matches nothing): its budget is fed by its projects.
    tenant.consumption["application"] = []
    tenant.set_entity_credits(view="application", name="Payments (legacy)", credits=21000)
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
            self.set_entity_credits(view="application", name="Payments (legacy)", credits=21050)
        return served

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)
    run.step()
    monkeypatch.setattr(FakeTenant, "_consumption_response", real)
    # The admin maps the application row to its application.
    mapped = _api(
        admin_client,
        "/api/usage/unmatched-entities/map",
        {"view": "application", "subject_key": "Payments (legacy)", "entity_id": "app-payments"},
    )
    assert mapped.status_code == 200, mapped.text
    db.expire_all()
    run.step()
    run.step()
    assert run.used(app) == 50


def test_an_application_renamed_in_the_feed_before_the_sync_counts_once(
    db: Session, connected, monkeypatch
) -> None:
    """The feed reports the application's own row under its new name first
    (unmatched for a cycle, so its projects feed its budget); the sync then
    learns the rename. The row is not new to the feed by then, so it is not
    'fresh': in that ingest it feeds the budget, and so do its projects
    (own_figures was taken from the reading where it matched nothing)."""
    tenant = _tenant()
    tenant.consumption["application"] = []
    tenant.set_entity_credits(view="application", name="Payments", credits=21000)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    app = _limit(db, EntityType.APPLICATION, "app-payments")
    run.step()
    run.step()
    assert run.used(app) == 0
    # The feed renames first.
    tenant.consumption["application"] = []
    tenant.set_entity_credits(view="application", name="Payments EU", credits=21000)
    run.step()
    run.step()
    run.step()
    # The sync catches up a few cycles later; 50 credits are spent on payments/web meanwhile.
    next(a for a in tenant.applications if a["id"] == "app-payments")["name"] = "Payments EU"
    tenant.set_entity_credits(view="project", name="payments/web", credits=1050)
    tenant.set_entity_credits(view="application", name="Payments EU", credits=21050)
    run.step()
    run.step()
    assert run.used(app) == 50
