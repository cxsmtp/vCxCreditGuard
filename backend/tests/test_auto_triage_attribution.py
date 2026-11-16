"""Charging auto-triage credits to the person who started the scan.

Every identity, id and figure here is synthetic. The payload shapes (scan
listing, auto-triage configuration with branches while switched off, a webhook
integration as initiator) follow what a real tenant returns.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx import scans as scans_api
from app.checkmarx.iam import AI_ROLE_NAMES
from app.db.base import utcnow
from app.models import (
    AuditLogEntry,
    AutoTriageCharge,
    AutoTriageProjectState,
    CreditLimit,
    LimitPeriodState,
    Notification,
    UnresolvedSubject,
    UsageRecord,
)
from app.models.enums import EntityType, PeriodType, RunStatus, UsageView
from app.services import (
    auto_triage_attribution,
    cycle,
    diagnostics,
    evaluation,
    ingestion,
    limits_service,
    preview_service,
    retention,
    settings_store,
)
from app.services import connection as connection_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key, sqlite_only
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
HARSH = "harsh.gokani@checkmarx.com"
AKASH = "akash.singh@checkmarx.com"
SEAN = "sean.casey@checkmarx.com"
BOT = "ci-webhook-runner"


# ------------------------------------------------------------------- fixtures


@pytest.fixture
def tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    # The tenant files automation spend under a synthetic user. It must stay
    # out of every user figure whatever the setting.
    fake.set_user_credits(name="Auto-triage", credits=10, actions={"auto_triage": 10})
    fake.set_entity_credits(
        view="project",
        name="payments/api",
        credits=10,
        entity_id="proj-api",
        actions={"auto_triage": 10},
    )
    # The owner's case: auto triage was switched off after it ran, but the
    # configuration still names the branch it ran on.
    fake.set_auto_triage_config("proj-api", enabled=False, branches=["main"])
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = fake.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    return fake


def turn_on(db: Session) -> None:
    settings_store.set_value(db, settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR, True)
    db.commit()


def run(*, force: bool = False) -> cycle.CycleResult:
    result = cycle.run_cycle(trigger="manual", force_org_sync=force)
    assert result.status in {RunStatus.SUCCESS, RunStatus.PARTIAL}, result.errors
    return result


def set_project(
    tenant: FakeTenant, project_id: str, name: str, credits: int, *, other: int = 0
) -> None:
    actions = {"auto_triage": credits - other}
    if other:
        actions["triage"] = other
    tenant.set_entity_credits(
        view="project", name=name, credits=credits, entity_id=project_id, actions=actions
    )


def scan(
    tenant: FakeTenant,
    scan_id: str,
    initiator: str | None,
    *,
    ago: timedelta = timedelta(0),
    branch: str = "main",
    project_id: str = "proj-api",
    **extra,
) -> None:
    tenant.add_scan(
        project_id=project_id,
        scan_id=scan_id,
        initiator=initiator,
        completed_at=utcnow() - ago,
        branch=branch,
        **extra,
    )


def model(db: Session) -> auto_triage_attribution.AttributionModel:
    db.expire_all()
    return auto_triage_attribution.build_model(db)


def charges(db: Session) -> list[AutoTriageCharge]:
    db.expire_all()
    return list(db.scalars(select(AutoTriageCharge).order_by(AutoTriageCharge.id)))


def user_limit(
    db: Session,
    user_id: str,
    credit_limit: int,
    *,
    period: str = PeriodType.LIFETIME,
    enforce: bool = False,
    count_existing: bool = False,
) -> CreditLimit:
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.USER,
            entity_id=user_id,
            credit_limit=credit_limit,
            period_type=period,
            enforce=enforce,
            count_existing_usage=count_existing,
        ),
        actor=ACTOR,
    )
    db.commit()
    return limit


def period_state(db: Session, limit: CreditLimit) -> LimitPeriodState:
    db.expire_all()
    state = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
    assert state is not None
    return state


def parts(db: Session, user_id: str) -> dict[tuple[str, str], Decimal]:
    out: dict[tuple[str, str], Decimal] = {}
    for part in model(db).parts_for(user_id):
        key = (part.project_id, part.basis)
        out[key] = out.get(key, Decimal("0")) + part.credits
    return out


def observing_for(db: Session, project_id: str, how_long: timedelta) -> None:
    """Pretend observation of the project began ``how_long`` ago."""
    state = db.get(AutoTriageProjectState, project_id)
    assert state is not None
    state.observing_since = state.observing_since - how_long
    db.commit()


def total_charged(m: auto_triage_attribution.AttributionModel, project_id: str) -> Decimal:
    return sum(
        (
            part.credits
            for user_parts in m.parts_by_user.values()
            for part in user_parts
            if part.project_id == project_id
        ),
        Decimal("0"),
    )


# ------------------------------------------------------------- setting is off


class TestOff:
    def test_off_changes_nothing_anywhere(
        self, db: Session, tenant: FakeTenant, admin_client: TestClient
    ) -> None:
        scan(tenant, "scan-h1", HARSH, ago=timedelta(days=3))
        run(force=True)
        harsh = user_limit(db, "user-harsh", 100)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h2", HARSH)
        result = run()

        assert "auto_triage_attribution" not in result.steps
        assert not [path for _method, path in tenant.requests if "/api/scans" in path]
        assert db.scalar(select(func.count()).select_from(AutoTriageCharge)) == 0
        assert db.scalar(select(func.count()).select_from(AutoTriageProjectState)) == 0
        state = period_state(db, harsh)
        # Harsh's own reported 3 credits, nothing else.
        assert state.credits_used == Decimal("3") and state.attributed_credits is None
        assert model(db).enabled is False

        limits = admin_client.get("/api/limits").json()
        row = next(item for item in limits if item["entity_id"] == "user-harsh")
        assert row["current_period"]["credits_used"] in ("3", "3.0000", 3)
        assert row["current_period"]["auto_triage_attributed"] is None
        dry = admin_client.get("/api/preview/dry-run").json()
        assert all(item["auto_triage_attributed"] is None for item in dry["rows"])
        overview = admin_client.get("/api/usage/auto-triage-attribution").json()
        assert overview["enabled"] is False and overview["users"] == []
        settings = admin_client.get("/api/settings").json()
        assert settings["charge_auto_triage_to_scan_initiator"] is False
        checks = {check.key for check in diagnostics.run_diagnostics(db).checks}
        assert "auto_triage_attribution" not in checks
        # The synthetic automation user is never offered for mapping.
        assert (
            db.scalar(
                select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "auto-triage")
            )
            is None
        )

    def test_the_pseudo_user_stays_excluded_when_on(self, db: Session, tenant: FakeTenant) -> None:
        turn_on(db)
        scan(tenant, "scan-h1", HARSH, ago=timedelta(days=3))
        run(force=True)
        assert (
            db.scalar(
                select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "auto-triage")
            )
            is None
        )
        assert "auto-triage" not in model(db).initiators


# ------------------------------------------------------------------- observed


class TestObserved:
    def test_an_increase_is_charged_to_whoever_ran_the_scan_on_the_branch(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH)
        # Same interval, wrong branch: auto triage does not run on it.
        scan(tenant, "scan-s1", SEAN, branch="feature/login")
        result = run()

        assert result.steps["auto_triage_attribution"]["observed_charges"] == 1
        [charge] = charges(db)
        assert charge.basis == "observed" and charge.initiator == HARSH
        assert charge.credits == Decimal("4") and charge.scan_ids == ["scan-h1"]
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("4")}
        assert parts(db, "user-sean") == {}
        # The listing asked for the configured branch.
        assert any(query.get("branch") == ["main"] for query in tenant.scan_queries)
        # The project keeps every credit it reports; the rest stays on it only.
        project = model(db).projects["proj-api"]
        assert project.auto_triage_credits == Decimal("14")
        assert project.observed == Decimal("4") and project.unattributed == Decimal("10")

    def test_two_scans_by_two_people_split_the_increase_equally(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 16)
        scan(tenant, "scan-h1", HARSH)
        scan(tenant, "scan-a1", AKASH)
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("3")}
        assert parts(db, "user-akash") == {("proj-api", "observed"): Decimal("3")}

    def test_no_scan_in_the_window_widens_to_the_latest_one_before_it(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        # Observing for a while already: the scan completed after observation
        # began, in an interval whose auto triage had not shown up yet.
        observing_for(db, "proj-api", timedelta(hours=6))
        scan(tenant, "scan-a0", AKASH, ago=timedelta(hours=5))
        set_project(tenant, "proj-api", "payments/api", 12)
        run()
        [*_, charge] = charges(db)
        assert charge.initiator == AKASH and charge.basis == "observed"
        assert charge.detail and "latest one before" in charge.detail

    def test_with_no_scan_at_all_the_increase_stays_on_the_project(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 12)
        run()
        [charge] = charges(db)
        assert charge.basis == "unattributed" and charge.initiator is None
        m = model(db)
        assert m.parts_by_user == {}
        assert m.projects["proj-api"].unattributed == Decimal("12")

    def test_a_project_appearing_later_is_observed_not_estimated(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        # No consumption at all yet: the project is not in the feed.
        tenant.consumption["project"] = [
            row for row in tenant.consumption["project"] if row.get("id") != "proj-tools"
        ]
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-tools", "platform/tools", 5)
        scan(tenant, "scan-k1", AKASH, project_id="proj-tools")
        run()
        assert parts(db, "user-akash") == {("proj-tools", "observed"): Decimal("5")}

    def test_a_project_coming_back_with_consumption_it_had_is_estimated(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        # platform/tools reports credits from the start, without the per action
        # breakdown (no reading). When the breakdown appears, its auto triage is
        # history, not something that just happened.
        scan(tenant, "scan-k0", AKASH, ago=timedelta(days=3), project_id="proj-tools")
        turn_on(db)
        run(force=True)
        assert db.get(AutoTriageProjectState, "proj-tools") is None
        set_project(tenant, "proj-tools", "platform/tools", 5)
        run()
        assert [c for c in charges(db) if c.project_id == "proj-tools"] == []
        assert parts(db, "user-akash") == {("proj-tools", "estimated"): Decimal("5")}


# ------------------------------------------------------------------ estimated


class TestEstimated:
    def test_history_is_attributed_even_though_auto_triage_is_switched_off_now(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        for number in range(3):
            scan(tenant, f"scan-h{number}", HARSH, ago=timedelta(days=4 + number))
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=9))
        # Not an auto-triage branch: never counted.
        for number in range(5):
            scan(tenant, f"scan-k{number}", AKASH, ago=timedelta(days=2), branch="develop")
        set_project(tenant, "proj-api", "payments/api", 8)
        turn_on(db)
        run(force=True)

        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("6")}
        assert parts(db, "user-sean") == {("proj-api", "estimated"): Decimal("2")}
        assert parts(db, "user-akash") == {}
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.history_status == "done"
        assert state.branches == ["main"]

    def test_observed_and_estimated_together_never_exceed_the_project(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=5))
        set_project(tenant, "proj-api", "payments/api", 8)
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 12)
        scan(tenant, "scan-a1", AKASH)
        run()

        assert parts(db, "user-akash") == {("proj-api", "observed"): Decimal("4")}
        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("4")}
        assert parts(db, "user-sean") == {("proj-api", "estimated"): Decimal("4")}
        assert total_charged(model(db), "proj-api") == Decimal("12")

    def test_charges_above_what_is_reported_now_are_scaled_down(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 16)
        scan(tenant, "scan-h1", HARSH)
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("6")}
        # Older usage ages out of the window: the project now reports less than
        # was charged inside it (not so much less that the read is held back).
        set_project(tenant, "proj-api", "payments/api", 5)
        run()
        m = model(db)
        assert m.projects["proj-api"].scale < 1
        assert total_charged(m, "proj-api") <= Decimal("5")
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("5")}

    def test_mixed_actions_take_only_the_auto_triage_share(self, db: Session) -> None:
        record = UsageRecord(credits_used=Decimal("10"), actions={"auto_triage": 3, "triage": 1})
        # Priced at the tenant's credits per auto-triage transaction.
        assert auto_triage_attribution.auto_triage_share(record, Decimal("2")) == Decimal("6")
        # Without a price, by transaction mix.
        assert auto_triage_attribution.auto_triage_share(record, None) == Decimal("7.5")
        only = UsageRecord(credits_used=Decimal("5"), actions={"auto_triage": 9})
        assert auto_triage_attribution.auto_triage_share(only, Decimal("100")) == Decimal("5")
        none = UsageRecord(credits_used=Decimal("5"), actions={"triage": 9})
        assert auto_triage_attribution.auto_triage_share(none, None) == Decimal("0")


# ---------------------------------------------------------------- unresolved


class TestUnresolvedInitiator:
    def test_a_bot_initiator_is_raised_and_counts_once_mapped(
        self, db: Session, tenant: FakeTenant, admin_client: TestClient
    ) -> None:
        turn_on(db)
        run(force=True)
        sean_limit = user_limit(db, "user-sean", 1000)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-b1", BOT, source_origin="PR Webhook")
        run()

        subjects = admin_client.get("/api/usage/unresolved").json()
        row = next(item for item in subjects if item["subject_key"] == BOT)
        assert row["source"] == "scan_initiator" and row["counts_towards_user_id"] is None
        m = model(db)
        assert m.parts_by_user == {}
        assert m.projects["proj-api"].unresolved == Decimal("4")
        assert period_state(db, sean_limit).credits_used == Decimal("5")
        assert admin_client.get("/api/dashboard").json()["tiles"]["unresolved_scan_initiators"] == 1
        assert db.scalar(
            select(Notification).where(Notification.title.like("Auto-triage credits could not%"))
        )

        response = admin_client.post(
            f"/api/usage/unresolved/{row['id']}/map", json={"user_id": "user-sean"}
        )
        assert response.status_code == 200, response.text
        assert parts(db, "user-sean") == {("proj-api", "observed"): Decimal("4")}
        overview = admin_client.get(
            "/api/usage/auto-triage-attribution", params={"user_id": "user-sean"}
        ).json()
        assert overview["users"][0]["total"] in ("4", "4.0000")
        assert overview["recent_charges"][0]["initiator"] == BOT

        run()
        # Lifetime: counts everything attributed, on top of Sean's own 5.
        state = period_state(db, sean_limit)
        assert state.attributed_credits == Decimal("4")
        assert state.credits_used == Decimal("9")


# ------------------------------------------------------------------ failures


class TestFailuresAndCaps:
    def test_scans_unreadable_the_cycle_continues_and_catches_up(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        first = run(force=True)
        assert first.steps["auto_triage_attribution"]["warnings"] == []
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH)
        tenant.fail_paths["/api/scans"] = 503
        failed = run()

        stats = failed.steps["auto_triage_attribution"]
        assert stats["warnings"] and "could not be read" in stats["warnings"][0]
        assert "evaluate" in failed.steps
        assert charges(db) == []
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_credits == Decimal("10")
        assert state.last_error
        assert db.scalar(
            select(Notification).where(
                Notification.title.like("Auto-triage credits could not all%")
            )
        )

        del tenant.fail_paths["/api/scans"]
        run()
        [charge] = charges(db)
        assert charge.initiator == HARSH and charge.credits == Decimal("4")

    def test_an_outage_stops_the_step_instead_of_waiting_on_every_project(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        set_project(tenant, "proj-web", "payments/web", 4)
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        set_project(tenant, "proj-web", "payments/web", 6)
        tenant.fail_paths["/api/scans"] = 503
        before = len(tenant.requests)
        result = run()

        stats = result.steps["auto_triage_attribution"]
        assert stats["deferred"] == 1
        scan_calls = [path for _m, path in tenant.requests[before:] if "/api/scans" in path]
        # One listing, with its retries; the second project is not attempted.
        from app.core.config import get_settings

        assert len(scan_calls) == get_settings().cx_max_retries + 1
        assert charges(db) == []

    def test_per_cycle_cap_defers_to_the_next_cycle_and_estimates_meanwhile(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=3), project_id="proj-web")
        set_project(tenant, "proj-web", "payments/web", 4)
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        set_project(tenant, "proj-web", "payments/web", 6)
        scan(tenant, "scan-h1", HARSH)
        scan(tenant, "scan-a1", AKASH, project_id="proj-web")
        monkeypatch.setattr(auto_triage_attribution, "MAX_PROJECTS_PER_CYCLE", 1)
        capped = run()

        stats = capped.steps["auto_triage_attribution"]
        assert stats["deferred"] == 1 and stats["warnings"]
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("4")}
        # Not traced yet, so the whole of proj-web is estimated from history.
        assert parts(db, "user-sean") == {("proj-web", "estimated"): Decimal("6")}
        assert parts(db, "user-akash") == {}

        monkeypatch.setattr(auto_triage_attribution, "MAX_PROJECTS_PER_CYCLE", 50)
        run()
        assert parts(db, "user-akash") == {("proj-web", "observed"): Decimal("2")}
        assert parts(db, "user-sean") == {("proj-web", "estimated"): Decimal("4")}

    def test_per_project_cap_falls_back_to_the_estimate(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=3))
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 13)
        for number in range(3):
            scan(tenant, f"scan-h{number}", HARSH)
        monkeypatch.setattr(auto_triage_attribution, "MAX_PAGES_PER_LISTING", 1)
        monkeypatch.setattr(auto_triage_attribution, "SCAN_PAGE_SIZE", 2)
        result = run()

        assert result.steps["auto_triage_attribution"]["capped"] == 1
        assert charges(db) == []
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_credits == Decimal("13")
        assert parts(db, "user-sean") == {("proj-api", "estimated"): Decimal("13")}


# ------------------------------------------------------- windows and periods


class TestWindowAndPeriod:
    def test_a_monthly_budget_counts_only_what_is_observed_after_its_baseline(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=4))
        set_project(tenant, "proj-api", "payments/api", 8)
        run(force=True)
        monthly = user_limit(db, "user-harsh", 100, period=PeriodType.MONTHLY)
        lifetime = user_limit(db, "user-sean", 100)
        existing = user_limit(db, "user-akash", 100, period=PeriodType.MONTHLY, count_existing=True)
        scan(tenant, "scan-a0", AKASH, ago=timedelta(days=4))
        turn_on(db)
        run()

        # 8 credits of history: harsh, sean and akash 8/3 each (rounded down).
        share = Decimal("2.6666")
        harsh = period_state(db, monthly)
        assert harsh.attributed_credits == 0
        assert harsh.credits_used == 0  # own 3 credits were in the baseline too
        assert period_state(db, lifetime).attributed_credits == share
        assert period_state(db, lifetime).credits_used == Decimal("5") + share
        assert period_state(db, existing).attributed_credits == share

        set_project(tenant, "proj-api", "payments/api", 12)
        scan(tenant, "scan-h1", HARSH)
        run()
        harsh = period_state(db, monthly)
        assert harsh.attributed_credits == Decimal("4")
        assert harsh.credits_used == Decimal("4")

    def test_charges_older_than_the_window_drop_out(self, db: Session, tenant: FakeTenant) -> None:
        turn_on(db)
        run(force=True)
        old = utcnow() - timedelta(days=400)
        db.add(
            AutoTriageCharge(
                project_id="proj-api",
                basis="observed",
                initiator=HARSH,
                initiator_key=HARSH,
                scan_ids=["scan-old"],
                scan_count=1,
                credits=Decimal("5"),
                window_start=old - timedelta(minutes=15),
                window_end=old,
                created_at=old,
            )
        )
        db.commit()
        assert parts(db, "user-harsh") == {}

    def test_retention_prunes_only_charges_outside_the_window(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        for days in (400, 60):
            moment = utcnow() - timedelta(days=days)
            db.add(
                AutoTriageCharge(
                    project_id="proj-api",
                    basis="observed",
                    initiator=HARSH,
                    initiator_key=HARSH,
                    scan_count=1,
                    credits=Decimal("1"),
                    window_start=moment,
                    window_end=moment,
                    created_at=moment,
                )
            )
        db.commit()
        result = retention.prune(db, retention_days=30)
        db.commit()
        assert result.auto_triage_charges == 1
        # Still inside the year-long lookback, so still part of a figure.
        assert [c.window_end.date() for c in charges(db)] == [
            (utcnow() - timedelta(days=60)).date()
        ]
        settings_store.set_value(db, settings_store.KEY_USAGE_PERIOD, "last_30_days")
        db.commit()
        assert retention.prune(db, retention_days=30).auto_triage_charges == 1
        db.commit()
        assert charges(db) == []

    def test_a_group_with_member_usage_counts_members_but_not_its_own_projects_twice(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        set_project(tenant, "proj-tools", "platform/tools", 4)
        scan(tenant, "scan-h1", HARSH)
        scan(tenant, "scan-k1", AKASH, project_id="proj-tools")
        group = limits_service.create_limit(
            db,
            data=limits_service.LimitInput(
                entity_type=EntityType.GROUP,
                entity_id="grp-platform",
                credit_limit=1000,
                period_type=PeriodType.LIFETIME,
                include_member_usage=True,
            ),
            actor=ACTOR,
        )
        db.commit()
        run()
        state = period_state(db, group)
        # Harsh's 4 from payments/api counts; Akash's 4 from platform/tools is
        # already in the group's own project figure.
        assert state.attributed_credits == Decimal("4")


# ------------------------------------------------------------ enforcement


class TestEnforcement:
    def test_turning_it_on_breaches_and_enforces_a_user_limit(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        run(force=True)
        limit = user_limit(db, "user-harsh", 5, enforce=True)
        run()
        assert period_state(db, limit).status == "ok"
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

        dry_before = preview_service.dry_run(db)
        assert next(r for r in dry_before.rows if r.limit_id == limit.id).would_enforce is False

        turn_on(db)
        run()
        state = period_state(db, limit)
        assert state.attributed_credits == Decimal("10")
        assert state.credits_used == Decimal("13")
        assert state.status == "restricted"
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    def test_the_simulation_shows_it_before_any_cycle_applies_it(
        self, db: Session, tenant: FakeTenant, admin_client: TestClient
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        turn_on(db)
        run(force=True)
        limit = user_limit(db, "user-harsh", 5, enforce=True)
        dry = admin_client.get("/api/preview/dry-run").json()
        row = next(item for item in dry["rows"] if item["limit_id"] == limit.id)
        assert Decimal(row["auto_triage_attributed"]) == Decimal("10")
        assert Decimal(row["credits_used"]) == Decimal("13")
        assert row["would_enforce"] is True

        run()
        detail = admin_client.get(f"/api/limits/{limit.id}").json()["current_period"]
        attributed = detail["auto_triage_attributed"]
        assert Decimal(attributed["counted"]) == Decimal("10")
        assert attributed["counts_existing_usage"] is True
        assert attributed["parts"][0]["project_id"] == "proj-api"
        assert attributed["parts"][0]["basis"] == "estimated"

    def test_turning_it_on_for_many_people_trips_the_safety_ceiling(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=4))
        scan(tenant, "scan-a0", AKASH, ago=timedelta(days=4))
        set_project(tenant, "proj-api", "payments/api", 30)
        run(force=True)
        for user_id in ("user-harsh", "user-sean", "user-akash"):
            user_limit(db, user_id, 6, enforce=True)
        settings_store.set_value(db, settings_store.KEY_MAX_NEW_ENFORCEMENTS, 2)
        db.commit()
        run()
        assert settings_store.enforcement_guard(db).paused is False

        turn_on(db)
        result = run()

        guard = settings_store.enforcement_guard(db)
        assert guard.paused and "safety ceiling of 2" in (guard.pause_reason or "")
        assert result.steps["evaluate"]["enforced"] == 0
        for user_id in ("user-harsh", "user-sean", "user-akash"):
            assert all(role in tenant.role_mappings[user_id] for role in AI_ROLE_NAMES)


# ------------------------------------------------------------ settings and api


class TestSettingsAndApi:
    def test_the_setting_is_audited_with_before_and_after(
        self, db: Session, admin_client: TestClient
    ) -> None:
        response = admin_client.put(
            "/api/settings", json={"charge_auto_triage_to_scan_initiator": True}
        )
        assert response.status_code == 200, response.text
        assert response.json()["charge_auto_triage_to_scan_initiator"] is True
        entry = db.scalar(
            select(AuditLogEntry)
            .where(AuditLogEntry.action == "settings.updated")
            .order_by(AuditLogEntry.id.desc())
        )
        assert entry is not None
        assert entry.before == {"charge_auto_triage_to_scan_initiator": False}
        assert entry.after == {"charge_auto_triage_to_scan_initiator": True}
        # Turning it on starts a new observation epoch; off and on again
        # starts another, and both changes are audited.
        first = settings_store.auto_triage_observation_epoch(db)
        assert first
        for value in (False, True):
            response = admin_client.put(
                "/api/settings", json={"charge_auto_triage_to_scan_initiator": value}
            )
            assert response.status_code == 200, response.text
        db.expire_all()
        assert settings_store.auto_triage_observation_epoch(db) not in (None, first)
        audited = list(
            db.scalars(
                select(AuditLogEntry)
                .where(AuditLogEntry.action == "settings.updated")
                .order_by(AuditLogEntry.id)
            )
        )
        assert [entry.after for entry in audited[-2:]] == [
            {"charge_auto_triage_to_scan_initiator": False},
            {"charge_auto_triage_to_scan_initiator": True},
        ]

    def test_a_viewer_cannot_turn_it_on(self, viewer_client: TestClient) -> None:
        response = viewer_client.put(
            "/api/settings", json={"charge_auto_triage_to_scan_initiator": True}
        )
        assert response.status_code == 403

    def test_a_configuration_backup_does_not_carry_it(
        self, db: Session, admin_client: TestClient
    ) -> None:
        turn_on(db)
        backup = admin_client.get("/api/ops/backup").json()
        assert settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR not in backup["settings"]

    def test_diagnostics_explain_it_when_on(self, db: Session, tenant: FakeTenant) -> None:
        turn_on(db)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-b1", BOT, ago=timedelta(days=2))
        run(force=True)
        check = next(
            item
            for item in diagnostics.run_diagnostics(db).checks
            if item.key == "auto_triage_attribution"
        )
        assert check.status == "warn" and BOT in check.detail
        assert check.remediation

    def test_demo_mode_never_charges_anyone(self, db: Session) -> None:
        turn_on(db)
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
        db.commit()
        assert settings_store.auto_triage_to_initiator(db) is False
        assert model(db).enabled is False
        # Leaving demo mode makes it effective again: observation restarts.
        before = settings_store.auto_triage_observation_epoch(db)
        settings_store.set_value(db, settings_store.KEY_DEMO_MODE, False)
        db.commit()
        assert settings_store.auto_triage_observation_epoch(db) not in (None, before)


# ------------------------------------------------------------ crash safety


@sqlite_only
def test_no_write_lock_is_held_while_scans_are_read(db: Session, tenant: FakeTenant) -> None:
    import sqlite3

    from app.core.config import get_settings

    path = get_settings().database_url.removeprefix("sqlite:///")
    held: list[str] = []

    def probe(request) -> None:  # type: ignore[no-untyped-def]
        connection = sqlite3.connect(path, timeout=0)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ROLLBACK")
        except sqlite3.OperationalError:
            held.append(request.url.path)
        finally:
            connection.close()

    scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
    turn_on(db)
    tenant.on_request = probe
    run(force=True)
    set_project(tenant, "proj-api", "payments/api", 14)
    scan(tenant, "scan-b1", BOT)
    run()
    assert any("/api/scans" in path for _m, path in tenant.requests)
    assert held == []


def test_scan_times_with_long_fractions_parse() -> None:
    parsed = scans_api.parse_time("2026-11-06T19:13:46.9827631Z")
    assert parsed is not None and parsed.microsecond == 982763
    assert scans_api.branch_matches("release/1.2", ["release/*"])
    assert not scans_api.branch_matches("main", ["release/*"])
    assert scans_api.branch_matches("anything", None)


def test_ingestion_is_untouched_by_the_setting(db: Session) -> None:
    """The user figure Checkmarx reports never includes the attributed part."""
    tenant = populated_tenant()
    tenant.set_user_credits(name="Auto-triage", credits=10, actions={"auto_triage": 10})
    settings_store.set_value(db, settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR, True)
    db.commit()
    client = tenant.client()
    from app.services import org_sync

    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    totals = ingestion.latest_totals(db, UsageView.USER)
    assert totals.get("user-harsh") == Decimal("3")
    index = evaluation.UsageIndex(db)
    assert index.user_total("user-harsh") == (Decimal("3"), True)


# ---------------------------------------------------------- review regressions


def set_price(tenant: FakeTenant, credits: int, transactions: int = 100) -> None:
    """The tenant-wide credits per auto-triage transaction (action dimension)."""
    rows = [row for row in tenant.consumption["action"] if row["actionType"] != "auto_triage"]
    rows.append(
        {
            "name": "auto_triage",
            "actionType": "auto_triage",
            "transactionCount": transactions,
            "creditsUsed": credits,
        }
    )
    tenant.consumption["action"] = rows


def set_state(db: Session, project_id: str, **values) -> None:  # type: ignore[no-untyped-def]
    state = db.get(AutoTriageProjectState, project_id)
    assert state is not None
    for key, value in values.items():
        setattr(state, key, value)
    db.commit()


def drop_project_row(tenant: FakeTenant, project_id: str) -> None:
    tenant.consumption["project"] = [
        row for row in tenant.consumption["project"] if row.get("id") != project_id
    ]


def map_initiator(admin_client: TestClient, initiator: str, user_id: str) -> None:
    row = next(
        item
        for item in admin_client.get("/api/usage/unresolved").json()
        if item["subject_key"] == initiator
    )
    response = admin_client.post(
        f"/api/usage/unresolved/{row['id']}/map", json={"user_id": user_id}
    )
    assert response.status_code == 200, response.text


class TestObservationRestarts:
    def test_turning_it_off_and_on_again_does_not_charge_the_gap_as_observed(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        monthly = user_limit(db, "user-harsh", 50, period=PeriodType.MONTHLY)
        run()
        assert period_state(db, monthly).attributed_credits == 0
        settings_store.set_value(db, settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR, False)
        db.commit()
        # Weeks of auto triage while it was off.
        set_state(db, "proj-api", last_collected_at=utcnow() - timedelta(days=60))
        scan(tenant, "scan-old", HARSH, ago=timedelta(days=40))
        set_project(tenant, "proj-api", "payments/api", 100)
        run()
        turn_on(db)
        result = run()

        assert [c for c in charges(db) if c.basis == "observed"] == []
        # The gap is history: estimated, so a monthly budget does not count it.
        assert period_state(db, monthly).attributed_credits == 0
        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("100")}
        assert result.steps["auto_triage_attribution"]["restarted"] >= 1
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_transactions == 100
        assert state.observation_epoch == settings_store.auto_triage_observation_epoch(db)

        # From here on it is observed again.
        set_project(tenant, "proj-api", "payments/api", 104)
        scan(tenant, "scan-h1", HARSH)
        run()
        assert period_state(db, monthly).attributed_credits == Decimal("4")

    def test_a_state_from_before_the_upgrade_restarts_instead_of_charging(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        # What the migration leaves on an existing row: no transaction cursor,
        # no epoch, and an old credit cursor.
        set_state(
            db,
            "proj-api",
            last_transactions=None,
            observation_epoch=None,
            last_credits=Decimal("1"),
            last_collected_at=utcnow() - timedelta(days=30),
        )
        scan(tenant, "scan-h1", HARSH)
        set_project(tenant, "proj-api", "payments/api", 14)
        run()
        assert charges(db) == []
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_transactions == 14

    def test_a_new_project_is_not_observed_from_a_stale_cursor(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        drop_project_row(tenant, "proj-tools")
        turn_on(db)
        run(force=True)
        settings_store.set_value(db, settings_store.KEY_AUTO_TRIAGE_TO_INITIATOR, False)
        db.commit()
        set_state(db, "proj-api", last_collected_at=utcnow() - timedelta(days=60))
        # proj-tools appears while the other cursors are from the earlier
        # enablement: its consumption may be from any time in the gap.
        scan(tenant, "scan-k0", AKASH, ago=timedelta(days=20), project_id="proj-tools")
        set_project(tenant, "proj-tools", "platform/tools", 5)
        turn_on(db)
        run()
        assert [c for c in charges(db) if c.project_id == "proj-tools"] == []
        assert parts(db, "user-akash") == {("proj-tools", "estimated"): Decimal("5")}

    def test_changing_the_lookback_window_restarts_observation(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH)
        run()
        assert len(charges(db)) == 1
        settings_store.set_value(db, settings_store.KEY_USAGE_PERIOD, "last_90_days")
        db.commit()
        # A different window reports a different count: not new auto triage.
        set_project(tenant, "proj-api", "payments/api", 20)
        run()
        assert len(charges(db)) == 1
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.period_param == "last_90_days"
        assert state.last_transactions == 20
        set_project(tenant, "proj-api", "payments/api", 23)
        scan(tenant, "scan-h2", HARSH)
        run()
        assert [c.credits for c in charges(db)] == [Decimal("4"), Decimal("3")]


class TestCursorFollowsTransactions:
    def test_a_reading_without_the_breakdown_or_a_missing_row_is_no_reading(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        turn_on(db)
        run(force=True)
        monthly = user_limit(db, "user-harsh", 50, period=PeriodType.MONTHLY)
        run()
        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("10")}
        # Same credits, no per-action breakdown for the row.
        tenant.set_entity_credits(
            view="project", name="payments/api", credits=10, entity_id="proj-api"
        )
        result = run()
        # The row missing altogether.
        drop_project_row(tenant, "proj-api")
        run()
        set_project(tenant, "proj-api", "payments/api", 10)
        run()
        assert charges(db) == []
        assert period_state(db, monthly).attributed_credits == 0
        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("10")}
        assert result.steps["auto_triage_attribution"]["no_reading"] == 1
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_transactions == 10

    def test_a_price_change_is_not_new_auto_triage(self, db: Session, tenant: FakeTenant) -> None:
        tenant.set_entity_credits(
            view="project",
            name="payments/api",
            credits=200,
            entity_id="proj-api",
            actions={"auto_triage": 100, "triage": 50},
        )
        set_price(tenant, 100)
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        turn_on(db)
        run(force=True)
        monthly = user_limit(db, "user-harsh", 1000, period=PeriodType.MONTHLY)
        run()
        for credits in (110, 100, 110, 100, 110):
            set_price(tenant, credits)
            run()
        assert charges(db) == []
        assert period_state(db, monthly).attributed_credits == 0

    def test_new_transactions_are_priced_at_the_current_unit(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.set_entity_credits(
            view="project",
            name="payments/api",
            credits=200,
            entity_id="proj-api",
            actions={"auto_triage": 100, "triage": 50},
        )
        set_price(tenant, 100)
        turn_on(db)
        run(force=True)
        set_price(tenant, 110)
        tenant.set_entity_credits(
            view="project",
            name="payments/api",
            credits=210,
            entity_id="proj-api",
            actions={"auto_triage": 110, "triage": 50},
        )
        scan(tenant, "scan-h1", HARSH)
        run()
        [charge] = charges(db)
        # 10 new transactions at 1.10 credits each.
        assert charge.initiator == HARSH and charge.credits == Decimal("11")

    def test_transactions_ageing_out_move_the_cursor_down_without_charging(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 6)
        run()
        assert charges(db) == []
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_transactions == 6
        set_project(tenant, "proj-api", "payments/api", 9)
        scan(tenant, "scan-h1", HARSH)
        run()
        [charge] = charges(db)
        assert charge.credits == Decimal("3")

    def test_the_price_never_takes_other_actions_credits(self) -> None:
        # 10 credits for 3 auto-triage and 1 triage transactions. The tenant
        # average (3 per auto triage) would make 9 of the 10 auto triage, but
        # the mix leaves only 7.5 for it: the rest is the person's own triage.
        record = UsageRecord(credits_used=Decimal("10"), actions={"auto_triage": 3, "triage": 1})
        assert auto_triage_attribution.auto_triage_share(record, Decimal("3")) == Decimal("7.5")
        assert auto_triage_attribution.auto_triage_share(record, Decimal("100")) == Decimal("7.5")
        # A cheaper tenant price still applies.
        assert auto_triage_attribution.auto_triage_share(record, Decimal("1")) == Decimal("3")


class TestWhichScansCount:
    def test_scans_without_an_initiator_keep_their_share_on_the_project(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 20)
        scan(tenant, "scan-h1", HARSH)
        for number in range(9):
            scan(tenant, f"scan-n{number}", None, source_origin="scheduler")
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("1")}
        unattributed = [c for c in charges(db) if c.basis == "unattributed"]
        assert [c.scan_count for c in unattributed] == [9]
        assert unattributed[0].credits == Decimal("9")

    def test_history_counts_scans_without_an_initiator_too(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4))
        for number in range(9):
            scan(tenant, f"scan-n{number}", None, ago=timedelta(days=3))
        turn_on(db)
        run(force=True)
        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("1")}
        assert model(db).projects["proj-api"].unattributed == Decimal("9")

    def test_only_completed_and_partial_scans_count(self, db: Session, tenant: FakeTenant) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH, status="Partial")
        scan(tenant, "scan-s1", SEAN, status="Failed")
        scan(tenant, "scan-a1", AKASH, status="Canceled")
        scan(tenant, "scan-b1", BOT, status="Running")
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("4")}
        assert parts(db, "user-sean") == {} and parts(db, "user-akash") == {}

    def test_history_ignores_scans_that_did_not_complete(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        scan(tenant, "scan-h0", HARSH, ago=timedelta(days=4), status="Partial")
        scan(tenant, "scan-s0", SEAN, ago=timedelta(days=4), status="Failed")
        turn_on(db)
        run(force=True)
        assert parts(db, "user-harsh") == {("proj-api", "estimated"): Decimal("10")}
        assert parts(db, "user-sean") == {}

    def test_a_scan_just_before_the_previous_reading_shares_the_increase(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        # Completed ten minutes before the reading that was just dealt with:
        # its auto triage can land in the next reading (the lag).
        scan(tenant, "scan-h1", HARSH, ago=timedelta(minutes=10))
        scan(tenant, "scan-a1", AKASH)
        set_project(tenant, "proj-api", "payments/api", 14)
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("2")}
        assert parts(db, "user-akash") == {("proj-api", "observed"): Decimal("2")}
        assert all(charge.detail is None for charge in charges(db))

    def test_history_outside_the_window_is_not_estimated_against(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_state(
            db,
            "proj-api",
            history=[
                [HARSH, (utcnow() - timedelta(days=400)).date().isoformat(), 5],
                [SEAN, (utcnow() - timedelta(days=3)).date().isoformat(), 1],
            ],
            history_status="done",
        )
        assert parts(db, "user-sean") == {("proj-api", "estimated"): Decimal("10")}
        assert parts(db, "user-harsh") == {}


class TestWidenFallbackBounds:
    def test_it_does_not_reach_before_observation_began(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        # Before observation: that scan belongs to the estimate, not to a rise.
        scan(tenant, "scan-a0", AKASH, ago=timedelta(days=5))
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 12)
        run()
        [charge] = charges(db)
        assert charge.basis == "unattributed" and charge.initiator is None
        assert parts(db, "user-akash") == {("proj-api", "estimated"): Decimal("10")}

    def test_it_does_not_reach_outside_the_lookback_window(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        observing_for(db, "proj-api", timedelta(days=500))
        scan(tenant, "scan-a0", AKASH, ago=timedelta(days=380))
        set_project(tenant, "proj-api", "payments/api", 12)
        run()
        [charge] = charges(db)
        assert charge.basis == "unattributed"

    def test_it_does_not_reach_before_the_previous_charged_interval(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        observing_for(db, "proj-api", timedelta(days=3))
        # Completed before the last charged interval: its own auto triage was
        # dealt with then.
        scan(tenant, "scan-a0", AKASH, ago=timedelta(hours=30))
        moment = utcnow() - timedelta(hours=20)
        db.add(
            AutoTriageCharge(
                project_id="proj-api",
                basis="unattributed",
                scan_ids=[],
                scan_count=0,
                credits=Decimal("0"),
                window_start=moment,
                window_end=moment + timedelta(minutes=45),
                created_at=moment,
            )
        )
        db.commit()
        set_project(tenant, "proj-api", "payments/api", 12)
        run()
        assert charges(db)[-1].basis == "unattributed"
        assert parts(db, "user-akash") == {}


class TestOneProjectFailing:
    def test_an_unexpected_error_in_one_project_lets_the_others_proceed(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        set_project(tenant, "proj-web", "payments/web", 4)
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        set_project(tenant, "proj-web", "payments/web", 6)
        scan(tenant, "scan-h1", HARSH)
        scan(tenant, "scan-a1", AKASH, project_id="proj-web")
        real = scans_api.list_project_scans

        def broken(client, *, project_id, **kwargs):  # type: ignore[no-untyped-def]
            if project_id == "proj-api":
                raise ValueError("value too long for type character varying(320)")
            return real(client, project_id=project_id, **kwargs)

        monkeypatch.setattr(scans_api, "list_project_scans", broken)
        result = run()

        stats = result.steps["auto_triage_attribution"]
        assert any("proj-api" in warning for warning in stats["warnings"])
        assert "evaluate" in result.steps
        assert parts(db, "user-akash") == {("proj-web", "observed"): Decimal("2")}
        state = db.get(AutoTriageProjectState, "proj-api")
        assert state is not None and state.last_transactions == 10
        assert state.last_error and "ValueError" in state.last_error

        monkeypatch.setattr(scans_api, "list_project_scans", real)
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("4")}

    def test_an_overlong_initiator_is_cut_to_the_column_width(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-b1", "integration-" + "x" * 400)
        run()
        [charge] = charges(db)
        assert charge.basis == "observed"
        assert charge.initiator is not None and len(charge.initiator) <= 320
        assert charge.initiator_key is not None and len(charge.initiator_key) <= 320

    def test_branches_that_are_not_a_list_mean_all_branches(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        tenant.auto_triage["proj-api"]["config"]["branches"] = "main"
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH, branch="develop")
        run()
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("4")}


class TestBusyProjects:
    def test_scans_long_before_the_interval_do_not_trip_the_cap(
        self, db: Session, tenant: FakeTenant, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        turn_on(db)
        run(force=True)
        # Busy hours well before the interval: those scans finished long ago.
        for number in range(6):
            scan(tenant, f"scan-k{number}", AKASH, ago=timedelta(hours=6 + number))
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH)
        monkeypatch.setattr(auto_triage_attribution, "MAX_PAGES_PER_LISTING", 1)
        monkeypatch.setattr(auto_triage_attribution, "SCAN_PAGE_SIZE", 2)
        result = run()
        assert result.steps["auto_triage_attribution"]["capped"] == 0
        assert parts(db, "user-harsh") == {("proj-api", "observed"): Decimal("4")}


class TestPeriodBaseline:
    def test_an_observed_charge_before_the_baseline_does_not_count_once_mapped(
        self, db: Session, tenant: FakeTenant, admin_client: TestClient
    ) -> None:
        turn_on(db)
        run(force=True)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-b1", BOT)
        run()
        # The monthly budget opens after that charge was observed.
        monthly = user_limit(db, "user-sean", 1000, period=PeriodType.MONTHLY)
        run()
        map_initiator(admin_client, BOT, "user-sean")
        run()
        assert parts(db, "user-sean") == {("proj-api", "observed"): Decimal("4")}
        assert period_state(db, monthly).attributed_credits == 0

    def test_a_new_period_does_not_count_charges_from_the_last_one(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        turn_on(db)
        run(force=True)
        monthly = user_limit(db, "user-harsh", 1000, period=PeriodType.MONTHLY)
        run()
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-h1", HARSH)
        run()
        assert period_state(db, monthly).attributed_credits == Decimal("4")
        # A new month opens: its baseline is taken after that charge.
        state = period_state(db, monthly)
        state.baseline_at = utcnow()
        db.commit()
        run()
        assert period_state(db, monthly).attributed_credits == 0

    def test_the_limit_detail_figures_agree_between_cycles(
        self, db: Session, tenant: FakeTenant, admin_client: TestClient
    ) -> None:
        turn_on(db)
        run(force=True)
        limit = user_limit(db, "user-sean", 1000)
        set_project(tenant, "proj-api", "payments/api", 14)
        scan(tenant, "scan-b1", BOT)
        run()
        map_initiator(admin_client, BOT, "user-sean")
        # Mapped, but no cycle has evaluated it yet.
        detail = admin_client.get(f"/api/limits/{limit.id}").json()["current_period"]
        attributed = detail["auto_triage_attributed"]
        counted = Decimal(attributed["counted"])
        assert counted == Decimal("4")
        assert counted + Decimal(attributed["not_counted"]) == Decimal(attributed["window_total"])
        assert sum(Decimal(part["counted"]) for part in attributed["parts"]) == counted
        assert Decimal(attributed["evaluated_counted"]) == 0
