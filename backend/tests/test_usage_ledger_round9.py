"""The usage ledger after the ninth review of realfix: a group's own row
keeps its collapse ceiling through a missing reading; "last_month" (a
calendar month) is remembered as long as it can hold usage; a project back
after its group's own row left does not count again what the row counted;
and an increase and a claim counting towards one new counter in one reading.
Synthetic data only."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType, PeriodType
from app.services import limits_service, settings_store
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _limit
from tests.test_usage_ledger_round7 import _Run, _tenant


def test_a_group_row_keeps_its_collapse_ceiling_through_a_missing_reading(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    tenant.consumption["group"] = []
    tenant.set_entity_credits(view="group", name="AA-Platform", credits=50000)
    tenant.set_entity_credits(view="group", name="Payments", credits=21000)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    group = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.GROUP,
            entity_id="grp-payments",
            credit_limit=100000,
            period_type=PeriodType.MONTHLY,
            enforce=False,
            include_member_usage=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    for _ in range(3):
        run.step()
    saved = [dict(row) for row in tenant.consumption["group"]]
    # The group view collapses for hours, and is accepted; one reading of the
    # collapse misses Payments, the next has it back, still collapsed.
    for row in tenant.consumption["group"]:
        row["creditsUsed"] = str(int(float(row["creditsUsed"])) // 10)
    collapsed = tenant.consumption["group"]
    for _ in range(4):
        run.step(hours=1)
    tenant.consumption["group"] = [r for r in collapsed if r["name"] != "Payments"]
    run.step(hours=1)
    tenant.consumption["group"] = collapsed
    run.step(hours=1)
    run.step(hours=1)
    # The feed recovers; nothing was used.
    tenant.consumption["group"] = saved
    for _ in range(3):
        run.step()
    assert run.used(group) == 0


def test_last_month_is_remembered_as_long_as_a_calendar_month_can_hold_usage(
    db: Session, connected, monkeypatch
) -> None:
    """Usage on the 1st of a month is in "last_month" until the end of the
    next: a name absent 40 days after its last rise may still be reporting it."""
    settings_store.set_value(db, settings_store.KEY_USAGE_PERIOD, "last_month")
    db.commit()
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 3, 1, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1100)
    run.step()  # Mar 1: the last rise
    rows = tenant.consumption["project"]
    tenant.consumption["project"] = [r for r in rows if r["name"] != "payments/web"]
    run.clock[0] = datetime(2027, 4, 10, 6, tzinfo=UTC)  # 40 days on
    run.step(hours=0)
    tenant.consumption["project"] = rows
    run.step()
    run.step()
    assert run.used(web, "2027-04") == 0


def _group_budget(db: Session):  # type: ignore[no-untyped-def]
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.GROUP,
            entity_id="grp-payments",
            credit_limit=100000,
            period_type=PeriodType.MONTHLY,
            enforce=False,
            include_member_usage=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    return limit


@pytest.mark.parametrize("later", [False, True], ids=["together", "a-reading-later"])
def test_a_project_back_after_its_group_row_left_does_not_count_the_spend_again(
    db: Session, connected, monkeypatch, later: bool
) -> None:
    """The group's own row counts a spend made while one of its projects is
    missing from the project view; then the group's row leaves and the
    project comes back: its increase spans the spend, and the group budget,
    fed by its projects again, must not count it a second time."""
    tenant = _tenant()
    tenant.consumption["group"] = []
    tenant.set_entity_credits(view="group", name="AA-Platform", credits=50000)
    tenant.set_entity_credits(view="group", name="Payments", credits=21000)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    group = _group_budget(db)
    for _ in range(3):
        run.step()
    rows = tenant.consumption["project"]
    web = next(r for r in rows if r["name"] == "payments/web")
    tenant.consumption["project"] = [r for r in rows if r["name"] != "payments/web"]
    run.step()
    # 500 spent on payments/web while it is missing; the group's row has it.
    tenant.set_entity_credits(view="group", name="Payments", credits=21500)
    run.step()
    assert run.used(group) == 500
    # The group's row leaves its view; payments/web is back, with the 500.
    tenant.consumption["group"] = [
        r for r in tenant.consumption["group"] if r["name"] != "Payments"
    ]
    if later:
        # The project comes back a reading after the group's row left.
        run.step()
    tenant.consumption["project"] = [*tenant.consumption["project"], dict(web, creditsUsed="1500")]
    run.step()
    run.step()
    assert run.used(group) == 500


def test_a_group_row_renamed_in_the_feed_before_the_sync_counts_once(
    db: Session, connected, monkeypatch
) -> None:
    """The group's own row is reported under a new name first (matching
    nothing, so its projects feed the budget); when the sync learns the
    rename, the row is not new to the feed, and must not feed the budget in
    the ingest where its projects still did."""
    tenant = _tenant()
    tenant.consumption["group"] = []
    tenant.set_entity_credits(view="group", name="AA-Platform", credits=50000)
    tenant.set_entity_credits(view="group", name="Payments", credits=21000)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    group = _group_budget(db)
    for _ in range(3):
        run.step()
    tenant.consumption["group"] = [
        r for r in tenant.consumption["group"] if r["name"] != "Payments"
    ]
    tenant.set_entity_credits(view="group", name="Payments EU", credits=21000)
    for _ in range(3):
        run.step()
    # The sync learns the rename as 50 credits are spent on payments/web.
    next(g for g in tenant.groups if g["id"] == "grp-payments")["name"] = "Payments EU"
    tenant.set_entity_credits(view="project", name="payments/web", credits=1050)
    tenant.set_entity_credits(view="group", name="Payments EU", credits=21050)
    run.step()
    run.step()
    run.step()
    assert run.used(group) == 50


def test_a_project_renamed_under_a_collapse_ceiling_starts_from_it(
    db: Session, connected, monkeypatch
) -> None:
    """A name held under a collapse ceiling and missing is a rename partner:
    the new name of the same project starts from the ceiling."""
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    saved = [dict(row) for row in tenant.consumption["project"]]
    for row in tenant.consumption["project"]:
        row["creditsUsed"] = str(int(float(row["creditsUsed"])) // 10)
    for _ in range(4):
        run.step(hours=1)
    # Renamed (feed and sync) while the collapse lasts ...
    for project in tenant.projects:
        if project["id"] == "proj-web":
            project["name"] = "payments/web2"
    for row in tenant.consumption["project"]:
        if row["name"] == "payments/web":
            row["name"] = "payments/web2"
    run.step(hours=1)
    # ... and the feed recovers under the new name: nothing was used.
    for row in saved:
        if row["name"] == "payments/web":
            row["name"] = "payments/web2"
    tenant.consumption["project"] = saved
    run.step()
    run.step()
    assert run.used(web) == 0


def test_an_increase_and_a_claim_open_one_counter_together(
    db: Session, connected, monkeypatch
) -> None:
    """A project created and used before the sync brought it, in a group
    whose budget has counted nothing yet this month: in the reading after the
    sync, its new increase and its claimed earlier usage both feed the
    group's counter, which the first creates and the second must find."""
    tenant = _tenant()
    tenant.add_group(group_id="grp-new", name="New team")
    tenant.set_entity_credits(view="project", name="example-org/new", credits=100)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime.now(UTC) - timedelta(hours=1))
    run.step(hours=0)
    group = _limit(db, EntityType.GROUP, "grp-new")
    # Created on the test's clock, before the usage it is to count.
    group.created_at = run.clock[0]
    db.commit()
    run.step(hours=0.1)
    tenant.set_entity_credits(view="project", name="example-org/new", credits=130)
    run.step(hours=0.1)  # 30 observed while it matched nothing
    tenant.add_project(project_id="proj-new", name="example-org/new", group_ids=["grp-new"])
    tenant.set_entity_credits(view="project", name="example-org/new", credits=150)
    run.clock[0] = datetime.now(UTC) + timedelta(minutes=1)
    run.step(hours=0)  # 20 more, and the 30 claimed
    assert run.used(group) == 50
