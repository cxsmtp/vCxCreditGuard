"""The usage ledger after the seventh review of realfix: believed falls and
the rise after them, people who share a display name, doubted falls surfaced
and bounded, claims and budgets created later, a period-type switch between
month and quarter, closed periods never lowered, and counters of periods that
never had a state. Synthetic data only."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import BudgetUsage, LimitPeriodState, UsageMissingName, UsageRecord
from app.models.enums import EntityType, LimitStatus, PeriodType, UsageView
from app.services import connection as connection_service
from app.services import (
    diagnostics,
    evaluation,
    ingestion,
    ledger,
    limits_service,
    org_sync,
    retention,
)
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _limit


class _Run:
    """Org sync, reading and evaluation on a clock the test moves."""

    def __init__(self, db: Session, monkeypatch, start: datetime) -> None:  # type: ignore[no-untyped-def]
        self.db = db
        self.clock = [start]
        monkeypatch.setattr(ingestion, "utcnow", lambda: self.clock[0])
        self.client = connection_service.get_client(db)

    def step(self, hours: float = 0.5, *, evaluate: bool = True):  # type: ignore[no-untyped-def]
        self.clock[0] += timedelta(hours=hours)
        org_sync.sync_org_model(self.db, self.client)
        self.db.commit()
        result = ingestion.ingest_usage(self.db, self.client)
        self.db.commit()
        if evaluate:
            evaluation.evaluate_all(self.db, now=self.clock[0])
            self.db.commit()
        return result

    def used(self, limit, key: str | None = None) -> Decimal:  # type: ignore[no-untyped-def]
        self.db.expire_all()
        query = select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id)
        if key is not None:
            query = query.where(LimitPeriodState.period_key == key)
        state = self.db.scalars(query.order_by(LimitPeriodState.period_start.desc())).first()
        return state.credits_used


def _tenant() -> FakeTenant:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="payments/api", credits=20000)
    return tenant


def _doubted(monkeypatch: pytest.MonkeyPatch, name: str, credits: int | list[int]) -> None:
    """Every project reading doubted (one row short), ``name`` reported at
    ``credits`` (a one-item list can be changed between readings)."""
    real = FakeTenant._consumption_response
    value = credits if isinstance(credits, list) else [credits]

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "project":
            return real(self, params)
        rows = [
            dict(row, creditsUsed=str(value[0])) if row["name"] == name else row
            for row in self.consumption["project"]
        ]
        return httpx.Response(
            200,
            json={"items": rows, "totalItems": len(rows) + 1, "totalPages": 1, "currentPage": 1},
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)


def test_a_believed_fall_to_a_small_total_and_the_rise_after_it(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1010)
    run.step()
    # Almost all of its usage rolls out of the window: a complete reading.
    tenant.set_entity_credits(view="project", name="payments/web", credits=4)
    run.step()
    for credits in (24, 64):
        tenant.set_entity_credits(view="project", name="payments/web", credits=credits)
        run.step()
    assert run.used(web) == 70


def test_two_people_who_share_a_display_name_are_added_up_not_repeated(
    db: Session, connected
) -> None:
    """User rows with no id and no email cannot be told apart by name: they
    are two rows, added up, and no reason to doubt the reading."""
    tenant = live_tenant()
    tenant.consumption["user"].append({"name": "Sam Lee", "creditsUsed": "5"})
    tenant.consumption["user"].append({"name": "Sam Lee", "creditsUsed": "7"})
    connected(tenant)
    fetched = ingestion._fetch_dimension(
        tenant.client(), view=UsageView.USER, period_param="last_year", page_size=100
    )
    assert fetched.merged["sam lee"].credits_used == 12
    assert (fetched.repeated, fetched.suspect) == (0, False)


def test_the_same_project_row_served_twice_is_read_once_and_doubted(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    real = FakeTenant._consumption_response

    def response(self, params):  # type: ignore[no-untyped-def]
        if params.get("viewBy", [""])[0] != "project":
            return real(self, params)
        rows = list(self.consumption["project"])
        twice = next(r for r in rows if r["name"] == "payments/web")
        return httpx.Response(
            200,
            json={
                "items": [*rows, twice],
                "totalItems": len(rows),
                "totalPages": 1,
                "currentPage": 1,
            },
        )

    monkeypatch.setattr(FakeTenant, "_consumption_response", response)
    fetched = ingestion._fetch_dimension(
        tenant.client(), view=UsageView.PROJECT, period_param="last_year", page_size=100
    )
    assert fetched.merged["payments/web"].credits_used == 1000
    assert (fetched.repeated, fetched.suspect) == (1, True)


class TestDoubtedFallsAreSurfacedAndBounded:
    def test_a_held_fall_is_reported_by_the_reading_and_the_health_check(
        self, db: Session, connected, monkeypatch
    ) -> None:
        tenant = _tenant()
        connected(tenant)
        run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
        run.step()
        run.step()
        with pytest.MonkeyPatch.context() as mp:
            _doubted(mp, "payments/web", 100)
            result = run.step()
        assert any("payments/web" in w for w in result.warnings), result.warnings
        assert result.dimensions["project"].doubted_falls == ["payments/web"]
        check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "doubted_falls")
        assert check.status == diagnostics.WARN and "payments/web" in check.detail
        # A complete reading clears it.
        run.step()
        assert all(c.key != "doubted_falls" for c in diagnostics.run_diagnostics(db).checks)

    def test_a_fall_doubted_reading_after_reading_is_believed_in_the_end(
        self, db: Session, connected, monkeypatch
    ) -> None:
        """Restated in the eighth review: a fall doubted for longer than the
        bound stops being reported, but the total before it stays a ceiling
        (an outlasting glitch must not be counted when it ends). In readings
        that stay doubted, the name's usage counts again only above that
        ceiling: 400 -> 450 counts nothing (a documented under-count)."""
        tenant = _tenant()
        connected(tenant)
        run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
        run.step()
        web = _limit(db, EntityType.PROJECT, "proj-web")
        run.step()
        # Every reading doubted from now on; the fall is real.
        reported = [400]
        _doubted(monkeypatch, "payments/web", reported)
        for _ in range(ledger.DIP_MAX_DOUBTS):
            run.step(hours=0.25)
        held = db.scalar(select(UsageMissingName))
        assert (held.kind, held.last_total) == (ledger.CEILING, 1000)
        # Still under the ceiling: nothing counts.
        reported[0] = 450
        run.step()
        assert run.used(web) == 0
        # Above it, only what is above it.
        reported[0] = 1030
        run.step()
        assert run.used(web) == 30

    def test_a_doubt_older_than_its_bound_is_believed(
        self, db: Session, connected, monkeypatch
    ) -> None:
        """Restated in the eighth review: past its bound a doubted fall is no
        longer reported, and its total stays a ceiling until a believed
        reading confirms the lower total."""
        tenant = _tenant()
        connected(tenant)
        run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
        run.step()
        run.step()
        _doubted(monkeypatch, "payments/web", 400)
        run.step()
        assert db.scalar(select(UsageMissingName)) is not None
        run.step(hours=ledger.DIP_MAX_AGE.total_seconds() / 3600 + 0.5)
        assert db.scalar(select(UsageMissingName)).kind == ledger.CEILING
        assert all(c.key != "doubted_falls" for c in diagnostics.run_diagnostics(db).checks)
        # A believed reading at the lower total confirms it.
        monkeypatch.undo()
        connected(tenant)
        monkeypatch.setattr(ingestion, "utcnow", lambda: run.clock[0])
        tenant.set_entity_credits(view="project", name="payments/web", credits=400)
        run.step()
        assert db.scalar(select(UsageMissingName)) is None


def test_a_claim_does_not_feed_a_budget_created_after_the_usage(
    db: Session, connected, monkeypatch
) -> None:
    """A project created and used before the sync brought it keeps that usage,
    but a budget made for it afterwards does not count what happened before
    the budget existed."""
    tenant = _tenant()
    tenant.set_entity_credits(view="project", name="example-org/new", credits=100)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime.now(UTC) - timedelta(hours=1))
    run.step(hours=0)
    run.step(hours=0.1)
    tenant.set_entity_credits(view="project", name="example-org/new", credits=130)
    run.step(hours=0.1)  # 30 observed while it matched nothing
    tenant.add_project(project_id="proj-new", name="example-org/new", group_ids=[])
    # The budget exists before the sync brings the project, after the usage.
    new = _limit(db, EntityType.PROJECT, "proj-new")
    run.clock[0] = datetime.now(UTC) + timedelta(minutes=1)
    run.step(hours=0)
    assert run.used(new) == 0


def test_monthly_to_quarterly_mid_quarter_keeps_the_earlier_months(
    db: Session, connected, monkeypatch
) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 20, 6, tzinfo=UTC))
    run.step()
    web = _limit(db, EntityType.PROJECT, "proj-web")
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1010)
    run.step()  # 10 in January
    run.step(hours=24 * 14)  # February
    tenant.set_entity_credits(view="project", name="payments/web", credits=1015)
    run.step()  # 5 in February
    limits_service.update_limit(
        db, limit=web, changes={"period_type": PeriodType.QUARTERLY}, actor=ACTOR
    )
    db.commit()
    run.step()
    assert run.used(web, "2027-Q1") == 15
    limits_service.update_limit(
        db, limit=web, changes={"period_type": PeriodType.MONTHLY}, actor=ACTOR
    )
    db.commit()
    run.step()
    assert run.used(web, "2027-02") == 5


def test_a_closed_restricted_period_is_never_lowered(db: Session) -> None:
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            credit_limit=100,
            period_type=PeriodType.MONTHLY,
            enforce=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    january = datetime(2027, 1, 1, tzinfo=UTC)
    db.add(
        LimitPeriodState(
            limit_id=limit.id,
            period_key="2027-01",
            period_start=january,
            period_end=datetime(2027, 2, 1, tzinfo=UTC),
            credits_used=Decimal("150"),
            baseline_credits=Decimal("0"),
            reported_total=Decimal("150"),
            baseline_at=january,
            usage_available=True,
            status=LimitStatus.RESTRICTED,
            last_evaluated_at=datetime(2027, 1, 31, tzinfo=UTC),
        )
    )
    # A late increase for January, observed after its last evaluation.
    db.add(
        BudgetUsage(
            limit_id=limit.id,
            period_key="2027-01",
            credits=Decimal("50"),
            actions={},
            updated_at=datetime(2027, 1, 31, 23, tzinfo=UTC),
        )
    )
    db.commit()
    evaluation.evaluate_all(db, now=datetime(2027, 2, 2, tzinfo=UTC))
    db.commit()
    db.expire_all()
    state = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2027-01"
        )
    )
    assert state.credits_used == 150


def test_counters_of_periods_that_never_had_a_state_are_pruned(db: Session) -> None:
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            credit_limit=100,
            period_type=PeriodType.MONTHLY,
            enforce=False,
        ),
        actor=ACTOR,
    )
    for key in ("2020-01", "2020-Q1", utcnow().strftime("%Y-%m")):
        db.add(
            BudgetUsage(
                limit_id=limit.id, period_key=key, credits=Decimal("1"), updated_at=utcnow()
            )
        )
    db.commit()
    retention._prune_counters(db, utcnow() - timedelta(days=90))
    db.commit()
    keys = {row.period_key for row in db.scalars(select(BudgetUsage))}
    assert keys == {utcnow().strftime("%Y-%m")}


def test_a_rise_is_remembered_on_the_reading(db: Session, connected, monkeypatch) -> None:
    tenant = _tenant()
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1001)
    run.step()
    risen = run.clock[0]
    run.step()
    db.expire_all()
    latest = ingestion.latest_live_snapshot(db, "project")
    record = db.scalar(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == latest.id, UsageRecord.subject_key == "payments/web"
        )
    )
    assert record.last_rise_at == risen


def test_a_closed_period_counted_from_totals_is_not_raised_to_its_counter_later(
    db: Session, connected, monkeypatch
) -> None:
    """A group budget counting existing usage: a project leaves the group, so
    the period's figure (current totals of current members) falls below what
    the ledger saw. Turning the switch off in a later period leaves the closed
    period as it was counted."""
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1000)
    tenant.set_entity_credits(view="project", name="platform/tools", credits=20000)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 20, 6, tzinfo=UTC))
    run.step()
    group = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.GROUP,
            entity_id="grp-payments",
            credit_limit=100000,
            period_type=PeriodType.MONTHLY,
            enforce=False,
            count_existing_usage=True,
        ),
        actor=ACTOR,
    )
    db.commit()
    run.step()
    tenant.set_entity_credits(view="project", name="payments/web", credits=1010)
    run.step()
    for project in tenant.projects:
        if project["id"] == "proj-web":
            project["groups"] = []
    run.step()
    january = run.used(group, "2027-01")
    assert january < 10  # payments/api's 8 only, now that web left
    run.step(hours=24 * 14)
    limits_service.update_limit(
        db, limit=group, changes={"count_existing_usage": False}, actor=ACTOR
    )
    db.commit()
    run.step()
    assert run.used(group, "2027-01") == january
