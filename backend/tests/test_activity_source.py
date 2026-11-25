"""The credit activity log as the usage source (app/services/activity_source.py).

Synthetic data only: example.com addresses and made-up ids.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.checkmarx import activity as activity_api
from app.models import UnresolvedSubject
from app.models.activity import ActivityEventCount, ActivitySourceState, subject_entity_id
from app.models.enums import EntityType, UsageView
from app.services import (
    activity_source,
    auto_triage_attribution,
    diagnostics,
    enforcement,
    ingestion,
    settings_store,
)
from tests.activity_world import (
    APP_OTHER,
    APP_PAY,
    G_PAY,
    P_API,
    P_TOOLS,
    P_WEB,
    PROJECT_NAMES,
    U_ALICE,
    U_BOB,
    U_CARA,
    budget,
    counter,
    install_clock,
    iso,
    new_tenant,
    seed_org,
    use_source,
)

START = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)


@pytest.fixture
def env(db: Session, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    clock = install_clock(monkeypatch, START)
    seed_org(db)
    tenant = new_tenant()
    return SimpleNamespace(db=db, clock=clock, tenant=tenant, client=tenant.client())


def run(env: SimpleNamespace) -> activity_source.ActivityResult:
    result = activity_source.ingest_activity(env.db, env.client)
    env.db.commit()
    return result


def tick(env: SimpleNamespace, minutes: int = 15) -> datetime:
    env.clock.value = env.clock.value + timedelta(minutes=minutes)
    return env.clock.value


def at(minutes: float) -> str:
    return iso(START + timedelta(minutes=minutes))


def state(env: SimpleNamespace) -> ActivitySourceState:
    env.db.expire_all()
    found = env.db.get(ActivitySourceState, 1)
    assert found is not None
    return found


def seeded(env: SimpleNamespace) -> None:
    """The first fetch: records, counts nothing."""
    result = run(env)
    assert result.seeded and result.events_counted == 0
    assert result.source_active


# ------------------------------------------------------------------- parser


class TestParser:
    ROW = {
        "date": "2026-11-25T10:21:28Z",
        "action": "Fusion Scan - Opus 5.5",
        "creditsUsed": "144.5",
        "user": "cx-jane-doe",
        "userEmail": "",
        "projects": ["payments/api"],
        "projectIds": [P_API],
        "applications": [],
        "applicationIds": [],
        "scanner": "sast",
        "risks": ["r"],
        "environments": [],
        "environmentIds": [],
        "scans": ["s"],
        "scanIds": ["5ca00000-0000-4000-8000-000000000001"],
    }

    def test_a_row_is_read_with_its_ids_date_and_string_credits(self) -> None:
        event = activity_api.parse_event(dict(self.ROW))
        assert event is not None
        assert event.date == datetime(2026, 11, 25, 10, 21, 28, tzinfo=UTC)
        assert event.credits == Decimal("144.5")
        assert event.project_id == P_API and event.application_id is None
        assert event.user_email == "" and event.subject_key == "cx-jane-doe"
        assert event.scan_ids == ("5ca00000-0000-4000-8000-000000000001",)

    def test_the_email_is_the_subject_when_there_is_one(self) -> None:
        event = activity_api.parse_event(
            {**self.ROW, "user": "Jane Doe", "userEmail": "Jane@Example.com"}
        )
        assert event is not None and event.subject_key == "jane@example.com"

    def test_identical_rows_share_a_key_and_any_field_changes_it(self) -> None:
        first = activity_api.parse_event(dict(self.ROW))
        second = activity_api.parse_event(dict(self.ROW), index=7)
        assert first is not None and second is not None
        assert first.key == second.key
        for name, value in (
            ("date", "2026-11-25T10:21:29Z"),
            ("action", "Triage"),
            ("creditsUsed", "144"),
            ("user", "someone"),
            ("userEmail", "x@example.com"),
            ("projectIds", [P_WEB]),
            ("applicationIds", [APP_PAY]),
            ("scanIds", ["5ca00000-0000-4000-8000-000000000002"]),
            ("scanner", "sca"),
        ):
            other = activity_api.parse_event({**self.ROW, name: value})
            assert other is not None and other.key != first.key, name

    def test_credits_written_differently_are_the_same_figure(self) -> None:
        one = activity_api.parse_event({**self.ROW, "creditsUsed": "144.50"})
        two = activity_api.parse_event({**self.ROW, "creditsUsed": "144.5"})
        assert one is not None and two is not None and one.key == two.key

    def test_a_row_without_a_date_is_left_out_and_counted_as_bad(self) -> None:
        page = activity_api.parse_page(
            {"items": [dict(self.ROW), {**self.ROW, "date": None}], "totalItems": 2}, 1
        )
        assert len(page.events) == 1 and page.bad_rows == 1 and page.rows == 2
        assert page.total_items == 2

    @pytest.mark.parametrize("payload", [[], {"items": None}, "x", {"rows": []}])
    def test_an_answer_that_is_not_the_log_is_malformed(self, payload: object) -> None:
        with pytest.raises(activity_api.ActivityMalformedError):
            activity_api.parse_page(payload, 1)


# ---------------------------------------------------------------- counting


class TestCounting:
    def test_identical_rows_are_distinct_events(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
        seeded(env)
        tick(env)
        for _ in range(3):
            env.tenant.add_activity(date=at(5), credits="1", project_id=P_API, user="Auto-triage")
        result = run(env)
        assert result.events_counted == 3
        assert counter(env.db, limit) == Decimal(3)
        # Read again: nothing new.
        tick(env)
        assert run(env).events_counted == 0
        assert counter(env.db, limit) == Decimal(3)
        # One more identical row: one more event.
        env.tenant.add_activity(date=at(5), credits="1", project_id=P_API, user="Auto-triage")
        tick(env)
        assert run(env).events_counted == 1
        assert counter(env.db, limit) == Decimal(4)

    def test_the_first_fetch_counts_nothing_and_old_rows_never_count(
        self, env: SimpleNamespace
    ) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=9))
        env.tenant.add_activity(date=at(-60), credits="50", project_id=P_API, user="jdoe")
        seeded(env)
        assert counter(env.db, limit) == 0
        # A row dated before the switch that the first read did not hold (it
        # arrived late) is never counted either.
        env.tenant.add_activity(date=at(-30), credits="7", project_id=P_API, user="jdoe")
        tick(env)
        env.tenant.add_activity(date=at(10), credits="2", project_id=P_API, user="jdoe")
        result = run(env)
        assert result.events_counted == 1
        assert counter(env.db, limit) == Decimal(2)

    def test_an_event_counts_in_the_period_of_its_own_date(
        self, env: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env.clock.value = datetime(2026, 11, 30, 23, 0, tzinfo=UTC)
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        quarterly = budget(env.db, EntityType.PROJECT, P_WEB, created_at=START)
        seeded(env)
        env.tenant.add_activity(
            date="2026-11-30T23:59:59Z", credits="3", project_id=P_API, user="jdoe"
        )
        env.tenant.add_activity(
            date="2026-12-01T00:00:00Z", credits="5", project_id=P_API, user="jdoe"
        )
        env.clock.value = datetime(2026, 12, 1, 0, 30, tzinfo=UTC)
        run(env)
        env.clock.value = datetime(2026, 12, 31, 23, 30, tzinfo=UTC)
        run(env)
        env.tenant.add_activity(
            date="2026-12-31T23:59:59Z", credits="1", project_id=P_WEB, user="jdoe"
        )
        env.tenant.add_activity(
            date="2027-01-01T00:00:00Z", credits="2", project_id=P_WEB, user="jdoe"
        )
        env.clock.value = datetime(2027, 1, 1, 0, 30, tzinfo=UTC)
        run(env)
        assert counter(env.db, limit, "2026-11") == Decimal(3)
        assert counter(env.db, limit, "2026-12") == Decimal(5)
        assert counter(env.db, limit, "2026-Q4") == Decimal(8)
        assert counter(env.db, quarterly, "2026-Q4") == Decimal(1)
        assert counter(env.db, quarterly, "2027-Q1") == Decimal(2)

    def test_an_event_before_a_budget_was_created_does_not_count_towards_it(
        self, env: SimpleNamespace
    ) -> None:
        seeded(env)
        env.tenant.add_activity(date=at(5), credits="4", project_id=P_API, user="jdoe")
        tick(env, 30)
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START + timedelta(minutes=20))
        env.tenant.add_activity(date=at(25), credits="6", project_id=P_API, user="jdoe")
        run(env)
        assert counter(env.db, limit) == Decimal(6)

    def test_application_by_id_and_by_project_counts_once(self, env: SimpleNamespace) -> None:
        pay = budget(env.db, EntityType.APPLICATION, APP_PAY, created_at=START)
        other = budget(env.db, EntityType.APPLICATION, APP_OTHER, created_at=START)
        seeded(env)
        # P_API belongs to APP_PAY by the sync; the row also names it.
        env.tenant.add_activity(
            date=at(1), credits="2", project_id=P_API, application_id=APP_PAY, user="jdoe"
        )
        # The row names an application the project is not synced into.
        env.tenant.add_activity(
            date=at(2), credits="3", project_id=P_TOOLS, application_id=APP_OTHER, user="jdoe"
        )
        # No application id: the project's application by the sync.
        env.tenant.add_activity(date=at(3), credits="5", project_id=P_API, user="jdoe")
        tick(env)
        run(env)
        assert counter(env.db, pay) == Decimal(7)
        assert counter(env.db, other) == Decimal(3)

    def test_group_budgets_count_each_event_once(self, env: SimpleNamespace) -> None:
        plain = budget(env.db, EntityType.GROUP, G_PAY, created_at=START)
        seeded(env)
        # Alice is a member and P_API is the group's project: one event.
        env.tenant.add_activity(
            date=at(1), credits="4", project_id=P_API, user="Alice", email="alice@example.com"
        )
        # Alice on a project outside the group: not the plain group's.
        env.tenant.add_activity(
            date=at(2), credits="1", project_id=P_TOOLS, user="Alice", email="alice@example.com"
        )
        tick(env)
        run(env)
        assert counter(env.db, plain) == Decimal(4)

    def test_a_group_budget_with_member_usage_counts_an_event_once(
        self, env: SimpleNamespace
    ) -> None:
        members = budget(
            env.db, EntityType.GROUP, G_PAY, created_at=START, include_member_usage=True
        )
        seeded(env)
        env.tenant.add_activity(
            date=at(1), credits="4", project_id=P_API, user="Alice", email="alice@example.com"
        )
        env.tenant.add_activity(
            date=at(2), credits="1", project_id=P_TOOLS, user="Alice", email="alice@example.com"
        )
        tick(env)
        run(env)
        assert counter(env.db, members) == Decimal(5)


# --------------------------------------------------------------- the person


class TestPeople:
    def test_email_then_username_then_unmatched(self, env: SimpleNamespace) -> None:
        alice = budget(env.db, EntityType.USER, U_ALICE, created_at=START)
        bob = budget(env.db, EntityType.USER, U_BOB, created_at=START)
        cara = budget(env.db, EntityType.USER, U_CARA, created_at=START)
        seeded(env)
        env.tenant.add_activity(
            date=at(1), credits="2", project_id=P_API, user="Alice E", email="alice@example.com"
        )
        env.tenant.add_activity(date=at(2), credits="3", project_id=P_API, user="jdoe")
        env.tenant.add_activity(date=at(3), credits="5", project_id=P_API, user="Unknown Person")
        tick(env)
        result = run(env)
        assert counter(env.db, alice) == Decimal(2)
        assert counter(env.db, bob) == Decimal(3)
        assert counter(env.db, cara) == 0
        assert result.user_outcomes == {"user": 2, "unmatched": 1}
        row = env.db.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "unknown person")
        )
        assert row is not None and not row.is_bot and row.mapped_user_id is None

        # An admin maps the name to Cara: what it does from then on is hers.
        row.mapped_user_id = U_CARA
        env.db.commit()
        env.tenant.add_activity(date=at(20), credits="7", project_id=P_API, user="Unknown Person")
        tick(env)
        run(env)
        assert counter(env.db, cara) == Decimal(7)

    def test_never_two_user_budgets_for_one_event(self, env: SimpleNamespace) -> None:
        alice = budget(env.db, EntityType.USER, U_ALICE, created_at=START)
        cara = budget(env.db, EntityType.USER, U_CARA, created_at=START)
        seeded(env)
        # The email says Alice; the name is Cara's username.
        env.tenant.add_activity(
            date=at(1), credits="2", project_id=P_API, user="cara", email="alice@example.com"
        )
        tick(env)
        run(env)
        assert counter(env.db, alice) == Decimal(2)
        assert counter(env.db, cara) == 0


class TestIntegrationAccounts:
    def test_a_project_budget_keeps_a_bot_off_every_user_budget(self, env: SimpleNamespace) -> None:
        project = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
        own = budget(env.db, EntityType.USER, subject_entity_id("tracix[bot]"), created_at=START)
        seeded(env)
        env.tenant.add_activity(date=at(1), credits="9", project_id=P_API, user="tracix[bot]")
        tick(env)
        result = run(env)
        assert counter(env.db, project) == Decimal(9)
        assert counter(env.db, own) == 0
        assert result.user_outcomes == {"project_budget": 9 // 9}

    def test_without_a_project_budget_a_bot_is_its_own_subject(self, env: SimpleNamespace) -> None:
        own = budget(env.db, EntityType.USER, subject_entity_id("tracix[bot]"), created_at=START)
        seeded(env)
        env.tenant.add_activity(date=at(1), credits="9", project_id=P_WEB, user="tracix[bot]")
        tick(env)
        result = run(env)
        assert counter(env.db, own) == Decimal(9)
        assert result.user_outcomes == {"subject": 1}
        row = env.db.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "tracix[bot]")
        )
        assert row is not None and row.is_bot

    def test_a_listed_integration_mapped_to_a_person_counts_for_them(
        self, env: SimpleNamespace
    ) -> None:
        settings_store.set_value(
            env.db, settings_store.KEY_INTEGRATION_ACCOUNTS, ["ExampleSheriff"]
        )
        env.db.commit()
        cara = budget(env.db, EntityType.USER, U_CARA, created_at=START)
        seeded(env)
        env.tenant.add_activity(date=at(1), credits="5", project_id=P_WEB, user="ExampleSheriff")
        tick(env)
        run(env)
        row = env.db.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "examplesheriff")
        )
        assert row is not None and row.is_bot
        assert counter(env.db, cara) == 0
        row.mapped_user_id = U_CARA
        env.db.commit()
        env.tenant.add_activity(date=at(30), credits="4", project_id=P_WEB, user="ExampleSheriff")
        tick(env, 30)
        run(env)
        assert counter(env.db, cara) == Decimal(4)

    def test_a_project_budget_created_mid_period_applies_forward(
        self, env: SimpleNamespace
    ) -> None:
        own = budget(
            env.db, EntityType.USER, subject_entity_id("dependabot[bot]"), created_at=START
        )
        seeded(env)
        env.tenant.add_activity(date=at(5), credits="3", project_id=P_TOOLS, user="dependabot[bot]")
        tick(env, 30)
        project = budget(
            env.db, EntityType.PROJECT, P_TOOLS, created_at=START + timedelta(minutes=20)
        )
        env.tenant.add_activity(
            date=at(25), credits="4", project_id=P_TOOLS, user="dependabot[bot]"
        )
        run(env)
        # Before the project budget: the account's own budget. After: the project's.
        assert counter(env.db, own) == Decimal(3)
        assert counter(env.db, project) == Decimal(4)

    def test_auto_triage_goes_to_the_initiator_not_a_subject(self, env: SimpleNamespace) -> None:
        project = budget(env.db, EntityType.PROJECT, P_WEB, created_at=START)
        seeded(env)
        env.tenant.add_activity(date=at(1), credits="1", project_id=P_API, user="Auto-triage")
        env.tenant.add_activity(
            date=at(1), credits="2", project_id=P_API, user="Auto-remediation", action="Remediation"
        )
        env.tenant.add_activity(date=at(2), credits="1", project_id=P_WEB, user="Auto-triage")
        tick(env)
        result = run(env)
        assert result.user_outcomes == {"initiator": 2, "project_budget": 1}
        assert counter(env.db, project) == Decimal(1)
        # Not raised as a person, and no subject budget is fed.
        assert (
            env.db.scalar(
                select(func.count())
                .select_from(UnresolvedSubject)
                .where(UnresolvedSubject.subject_key.in_(["auto-triage", "auto-remediation"]))
            )
            == 0
        )

    def test_initiator_charges_follow_the_project_budget_rule(self, env: SimpleNamespace) -> None:
        """Auto-triage charged to the scan initiator (auto_triage_attribution)
        skips a project that had an active project budget while the log was
        the source; outside that, nothing changes."""
        assert activity_source.initiator_skip(env.db) is None
        budget(env.db, EntityType.PROJECT, P_API, created_at=START + timedelta(minutes=30))
        seeded(env)
        skip = activity_source.initiator_skip(env.db)
        assert skip is not None

        def part(project: str, minutes: int) -> auto_triage_attribution.AttributedPart:
            return auto_triage_attribution.AttributedPart(
                user_id=U_ALICE,
                project_id=project,
                basis=auto_triage_attribution.BASIS_OBSERVED,
                credits=Decimal(2),
                initiator="alice@example.com",
                observed_at=START + timedelta(minutes=minutes),
            )

        assert skip(part(P_API, 40))
        assert not skip(part(P_API, 10))  # before the project budget
        assert not skip(part(P_WEB, 40))  # no project budget
        assert not skip(part(P_API, -10))  # before the log was the source
        model = auto_triage_attribution.AttributionModel(
            enabled=True,
            available=True,
            parts_by_user={U_ALICE: [part(P_API, 40), part(P_WEB, 40)]},
        )
        usage = auto_triage_attribution.attributed_usage(
            model, user_ids=[U_ALICE], counts_existing=True, since=None, skip=skip
        )
        assert usage.counted == Decimal(2)

    def test_a_subject_budget_restricts_nobody_and_is_offered_in_the_picker(
        self, env: SimpleNamespace, admin_client
    ) -> None:
        seeded(env)
        env.tenant.add_activity(date=at(1), credits="1", project_id=P_WEB, user="tracix[bot]")
        tick(env)
        run(env)
        entity_id = subject_entity_id("tracix[bot]")
        assert (
            enforcement.plan_targets(env.db, entity_type=EntityType.USER, entity_id=entity_id) == []
        )
        found = admin_client.get(
            "/api/org/entities",
            params={"entity_type": "user", "q": "tracix", "include_subjects": "true"},
        )
        assert found.status_code == 200, found.text
        assert [entity["entity_id"] for entity in found.json()] == [entity_id]
        # Never offered where a person is wanted (mapping a name).
        people = admin_client.get(
            "/api/org/entities", params={"entity_type": "user", "q": "tracix"}
        )
        assert people.json() == []
        made = budget(env.db, EntityType.USER, entity_id)
        assert made.entity_label == "tracix[bot] (integration account)"


# --------------------------------------------------------- paging and drift


def _old_rows(env: SimpleNamespace, count: int) -> None:
    for index in range(count):
        env.tenant.add_activity(
            date=at(-600 + index), credits="1", project_id=P_TOOLS, user=f"old{index}"
        )


class TestDrift:
    @pytest.fixture(autouse=True)
    def small_pages(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(activity_api, "ACTIVITY_PAGE_SIZE", 3)

    def test_rows_ageing_out_while_reading_only_skip(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        _old_rows(env, 4)
        seeded(env)
        truth = Decimal(0)
        for index in range(9):
            env.tenant.add_activity(date=at(1 + index), credits="1", project_id=P_API, user="jdoe")
            truth += 1

        def age_out(page: int) -> None:
            if page > 1 and env.tenant.activity:
                env.tenant.activity.pop(0)

        env.tenant.activity_hook = age_out
        tick(env, 30)
        run(env)
        assert counter(env.db, limit) <= truth
        env.tenant.activity_hook = None
        tick(env)
        run(env)
        assert counter(env.db, limit) == truth

    def test_a_row_inserted_while_reading_is_never_read_twice(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        seeded(env)
        for index in range(8):
            env.tenant.add_activity(date=at(1 + index), credits="1", project_id=P_API, user="jdoe")
        inserted = {"done": False}

        def insert(page: int) -> None:
            # Between the first and second page: a row dated earlier than
            # what was read shifts every later row one place on.
            if page == 2 and not inserted["done"]:
                inserted["done"] = True
                env.tenant.activity.insert(
                    0,
                    {
                        **env.tenant.activity[0],
                        "date": at(0.5),
                        "user": "late",
                        "creditsUsed": "1",
                    },
                )

        env.tenant.activity_hook = insert
        tick(env, 30)
        result = run(env)
        assert counter(env.db, limit) <= Decimal(9)
        assert "uncertain_dates" in result.issues or "total_changed" in result.issues
        env.tenant.activity_hook = None
        for _ in range(3):
            tick(env)
            run(env)
            assert counter(env.db, limit) <= Decimal(9)
        assert counter(env.db, limit) == Decimal(9)

    def test_rows_of_one_date_across_a_boundary_wait_and_count_once(
        self, env: SimpleNamespace
    ) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        seeded(env)
        for minutes, user in ((1, "a"), (1, "b"), (2, "c"), (2, "d"), (3, "e")):
            env.tenant.add_activity(date=at(minutes), credits="1", project_id=P_API, user=user)
        env.tenant.activity_tie_shuffle = random.Random(7)
        tick(env, 30)
        first = run(env)
        # Page size 3: the rows of minute 2 meet at the boundary.
        assert "uncertain_dates" in first.issues
        assert counter(env.db, limit) <= Decimal(5)
        for _ in range(4):
            tick(env)
            run(env)
            assert counter(env.db, limit) <= Decimal(5)
        assert counter(env.db, limit) == Decimal(5)

    def test_an_order_that_goes_back_counts_nothing(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        seeded(env)
        for index in range(6):
            env.tenant.add_activity(date=at(1 + index), credits="1", project_id=P_API, user="jdoe")

        def shift(page: int) -> None:
            # Three earlier rows at once: page 2 starts before page 1 ended.
            if page == 2:
                for offset in range(3):
                    env.tenant.activity.append(
                        {
                            **env.tenant.activity[0],
                            "date": at(0.1 + offset / 10),
                            "user": f"x{offset}",
                        }
                    )
                env.tenant.activity_hook = None

        env.tenant.activity_hook = shift
        tick(env, 30)
        result = run(env)
        assert "order_went_back" in result.issues
        assert result.events_counted == 0
        tick(env)
        run(env)
        assert counter(env.db, limit) == Decimal(9)

    def test_a_log_not_sorted_as_asked_is_malformed(self, env: SimpleNamespace) -> None:
        for index in range(4):
            env.tenant.add_activity(date=at(-10 + index), credits="1", project_id=P_API, user="a")
        env.tenant.activity_ignore_sort = True
        result = run(env)
        assert not result.source_active and result.error

    def test_the_page_cap_reads_what_it_can_and_catches_up(self, env: SimpleNamespace) -> None:
        settings_store.set_value(env.db, settings_store.KEY_ACTIVITY_MAX_PAGES, 3)
        env.db.commit()
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        seeded(env)
        st = state(env)
        st.last_sweep_at = START  # no sweep in this test
        env.db.commit()
        for index in range(14):
            env.tenant.add_activity(
                date=at(1 + index // 2), credits="1", project_id=P_API, user=f"u{index % 2}"
            )
        tick(env, 30)
        first = run(env)
        assert first.partial and first.warnings
        assert counter(env.db, limit) < Decimal(14)
        for _ in range(8):
            tick(env)
            run(env)
            assert counter(env.db, limit) <= Decimal(14)
        assert counter(env.db, limit) == Decimal(14)

    def test_an_incomplete_fetch_never_over_counts(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        seeded(env)
        for index in range(7):
            env.tenant.add_activity(date=at(1 + index), credits="1", project_id=P_API, user="jdoe")

        def grow(page: int) -> None:
            if page == 2:
                env.tenant.add_activity(date=at(9), credits="1", project_id=P_API, user="jdoe")

        env.tenant.activity_hook = grow
        tick(env, 30)
        result = run(env)
        assert "total_changed" in result.issues and not result.complete
        assert counter(env.db, limit) <= Decimal(8)
        env.tenant.activity_hook = None
        tick(env)
        run(env)
        assert counter(env.db, limit) == Decimal(8)


# --------------------------------------------------------------- the store


class TestStore:
    def test_keys_older_than_the_window_are_pruned_and_never_count(
        self, env: SimpleNamespace
    ) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=60))
        seeded(env)
        env.tenant.add_activity(date=at(1), credits="1", project_id=P_API, user="jdoe")
        tick(env)
        run(env)
        assert env.db.scalar(select(func.count()).select_from(ActivityEventCount)) == 1
        # 32 days later the row has left the window and its key is pruned.
        env.tenant.activity = []
        tick(env, 32 * 24 * 60)
        run(env)
        assert env.db.scalar(select(func.count()).select_from(ActivityEventCount)) == 0
        # Served again (a log that kept it): older than the window, never counted.
        env.tenant.add_activity(date=at(1), credits="1", project_id=P_API, user="jdoe")
        tick(env)
        run(env)
        assert counter(env.db, limit) == Decimal(1)


# ------------------------------------------------------ switching sources


def _summary_rows(env: SimpleNamespace, totals: dict[str, int]) -> None:
    for project_id, total in totals.items():
        env.tenant.set_entity_credits(view="project", name=PROJECT_NAMES[project_id], credits=total)


def _ingest(env: SimpleNamespace):  # type: ignore[no-untyped-def]
    result = ingestion.ingest_usage(env.db, env.client, views=(UsageView.PROJECT,))
    env.db.commit()
    return result


class TestSwitching:
    def test_summary_only_is_the_old_behaviour(self, env: SimpleNamespace) -> None:
        use_source(env.db, settings_store.USAGE_SOURCE_SUMMARY)
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
        _summary_rows(env, {P_API: 10})
        _ingest(env)
        tick(env)
        _summary_rows(env, {P_API: 14})
        env.tenant.add_activity(date=at(10), credits="4", project_id=P_API, user="jdoe")
        _ingest(env)
        assert counter(env.db, limit) == Decimal(4)
        assert env.tenant.activity_requests == []

    def test_switch_over_and_fallback_never_count_twice(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
        truth = Decimal(0)

        def spend(minutes_from_now: float, credits: int) -> None:
            nonlocal truth
            when = env.clock.value + timedelta(minutes=minutes_from_now)
            env.tenant.add_activity(
                date=iso(when), credits=str(credits), project_id=P_API, user="jdoe"
            )
            total = sum(
                int(row["creditsUsed"])
                for row in env.tenant.activity
                if row["projectIds"] == [P_API]
            )
            _summary_rows(env, {P_API: total})
            truth += credits

        # 1. The summary feed is the source (the log answers 404).
        saved, env.tenant.activity = env.tenant.activity, None
        _summary_rows(env, {P_API: 0})
        _ingest(env)
        env.tenant.activity = saved
        env.tenant.activity_status = 404
        for _ in range(2):
            tick(env)
            spend(-5, 3)
            _ingest(env)
        assert counter(env.db, limit) == Decimal(6)
        # 2. The log answers (asked again after the re-probe delay): it seeds,
        # the summary stops feeding.
        env.tenant.activity_status = None
        tick(env, 6 * 60 + 15)
        spend(-5, 2)  # between the summary's last reading and the seed: lost
        result = _ingest(env)
        assert result.activity is not None and result.activity.seeded
        assert counter(env.db, limit) == Decimal(6)
        tick(env)
        spend(-5, 5)
        _ingest(env)
        assert counter(env.db, limit) == Decimal(11)
        # 3. The log is gone (404): the summary takes over, its first reading
        # counts nothing.
        env.tenant.activity_status = 404
        tick(env)
        spend(-5, 7)
        result = _ingest(env)
        assert result.activity is not None and not result.activity.source_active
        assert counter(env.db, limit) == Decimal(11)
        tick(env)
        spend(-5, 1)
        _ingest(env)
        assert counter(env.db, limit) == Decimal(12)
        assert counter(env.db, limit) <= truth
        # 4. Back again after the re-probe delay: seeds, counts nothing twice.
        env.tenant.activity_status = None
        tick(env, 7 * 60)
        spend(-5, 4)
        result = _ingest(env)
        assert result.activity is not None and result.activity.seeded
        assert counter(env.db, limit) == Decimal(12)
        tick(env)
        spend(-5, 6)
        _ingest(env)
        assert counter(env.db, limit) == Decimal(18)
        assert counter(env.db, limit) <= truth

    def test_a_short_outage_keeps_the_log_and_counts_it_later(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START)
        seeded(env)
        env.tenant.activity_status = 503
        env.tenant.add_activity(date=at(5), credits="3", project_id=P_API, user="jdoe")
        tick(env)
        result = run(env)
        assert result.source_active and result.read_failed and result.warnings
        assert counter(env.db, limit) == 0
        env.tenant.activity_status = None
        tick(env)
        run(env)
        assert counter(env.db, limit) == Decimal(3)

    def test_a_long_outage_falls_back(self, env: SimpleNamespace) -> None:
        seeded(env)
        env.tenant.activity_status = 503
        for _ in range(5):
            tick(env)
            result = run(env)
        assert not result.source_active
        assert state(env).status == activity_source.FALLBACK

    def test_turning_the_setting_off_hands_back_to_the_summary(self, env: SimpleNamespace) -> None:
        limit = budget(env.db, EntityType.PROJECT, P_API, created_at=START - timedelta(days=1))
        _summary_rows(env, {P_API: 10})
        _ingest(env)
        assert activity_source.source_active(env.db)
        tick(env)
        _summary_rows(env, {P_API: 12})
        _ingest(env)
        use_source(env.db, settings_store.USAGE_SOURCE_SUMMARY)
        tick(env)
        _summary_rows(env, {P_API: 15})
        _ingest(env)
        # The first summary reading after the log counts nothing.
        assert counter(env.db, limit) == 0
        tick(env)
        _summary_rows(env, {P_API: 16})
        _ingest(env)
        assert counter(env.db, limit) == Decimal(1)
        assert state(env).status == activity_source.OFF


# ---------------------------------------------------------- reconciliation


class TestReconciliation:
    def test_the_daily_sweep_compares_the_log_with_the_summary(self, env: SimpleNamespace) -> None:
        env.tenant.add_activity(date=at(-30), credits="10", project_id=P_API, user="jdoe")
        env.tenant.consumption["action"] = [{"name": "Triage", "creditsUsed": "10"}]
        ingestion._record_dimension(env.db, UsageView.ACTION, supported=True, error=None)
        env.db.commit()
        seeded(env)
        tick(env)
        result = run(env)
        assert result.sweep
        assert state(env).reconciliation["status"] == "match"
        check = next(
            c for c in diagnostics.run_diagnostics(env.db).checks if c.key == "activity_source"
        )
        assert check.status == diagnostics.OK and "adds up" in check.detail

        env.tenant.consumption["action"] = [{"name": "Triage", "creditsUsed": "25"}]
        tick(env, 25 * 60)
        run(env)
        assert state(env).reconciliation["status"] == "mismatch"
        check = next(
            c for c in diagnostics.run_diagnostics(env.db).checks if c.key == "activity_source"
        )
        assert check.status == diagnostics.WARN and "25" in check.detail
