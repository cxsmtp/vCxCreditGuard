"""Limit evaluation: baselines, warnings, breaches, precedence and rollover."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.models import CreditLimit, EnforcementAction, Exemption, LimitPeriodState, Notification
from app.models.enums import EntityType, LimitStatus, PeriodType
from app.services import evaluation, ingestion, org_sync
from app.services.audit import AuditActor
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
SEPTEMBER = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


def prepare(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    return tenant, client


def add_limit(
    db: Session,
    *,
    entity_type: EntityType,
    entity_id: str,
    credit_limit: int,
    enforce: bool = False,
    warning_threshold_pct: int = 80,
    period_type: str = PeriodType.MONTHLY,
    include_member_usage: bool = False,
    hold_until_released: bool = False,
    label: str | None = None,
) -> CreditLimit:
    limit = CreditLimit(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=label or entity_id,
        credit_limit=credit_limit,
        period_type=period_type,
        enforce=enforce,
        warning_threshold_pct=warning_threshold_pct,
        include_member_usage=include_member_usage,
        hold_until_released=hold_until_released,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    return limit


def state_of(db: Session, limit: CreditLimit, period_key: str = "2026-08") -> LimitPeriodState:
    state = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == period_key
        )
    )
    assert state is not None
    return state


class TestBaselines:
    def test_the_first_evaluation_baselines_and_reports_zero_usage(self, db: Session) -> None:
        """The API reports a year of history. A brand new monthly budget must not
        start out already exhausted by consumption that predates it."""
        tenant, client = prepare(db)
        limit = add_limit(db, entity_type=EntityType.USER, entity_id="user-sean", credit_limit=10)

        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.reported_total == Decimal("5")
        assert state.baseline_credits == Decimal("5")
        assert state.credits_used == Decimal("0")
        assert state.status == LimitStatus.OK

    def test_usage_is_the_increase_over_the_baseline(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(db, entity_type=EntityType.USER, entity_id="user-sean", credit_limit=10)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        tenant.set_user_credits(name="Sean Casey", credits=9, actions={"triage": 9})
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.credits_used == Decimal("4")

    def test_a_shrinking_lookback_window_re_baselines_instead_of_going_negative(
        self, db: Session
    ) -> None:
        tenant, client = prepare(db)
        limit = add_limit(db, entity_type=EntityType.USER, entity_id="user-sean", credit_limit=10)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        # Old consumption drops out of the sliding window.
        tenant.set_user_credits(name="Sean Casey", credits=2, actions={"triage": 2})
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.credits_used == Decimal("0")
        assert state.baseline_credits == Decimal("2")

    def test_a_lifetime_limit_counts_everything_reported(self, db: Session) -> None:
        """Lifetime means all credits ever. Discounting history here would make a
        lifetime budget silently mean "since the limit was created", and a limit of
        10 against 5 already spent would read as 0 used."""
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-sean",
            credit_limit=10,
            period_type=PeriodType.LIFETIME,
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        state = state_of(db, limit, "lifetime")
        assert state.baseline_credits == Decimal("0")
        assert state.credits_used == Decimal("5")


class TestThresholds:
    def test_warning_fires_at_the_threshold(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-sean",
            credit_limit=10,
            warning_threshold_pct=80,
            label="Sean Casey",
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        tenant.set_user_credits(name="Sean Casey", credits=13, actions={"triage": 13})
        ingestion.ingest_usage(db, client)
        db.commit()
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert result.warned == 1
        state = state_of(db, limit)
        assert state.status == LimitStatus.WARNED
        assert state.warned_at is not None
        notification = db.scalar(select(Notification).where(Notification.category == "warning"))
        assert notification is not None
        assert "80%" in (notification.body or "")

    def test_no_warning_below_the_threshold(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(db, entity_type=EntityType.USER, entity_id="user-sean", credit_limit=10)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=12, actions={"triage": 12})
        ingestion.ingest_usage(db, client)
        db.commit()
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert result.warned == 0
        assert state_of(db, limit).status == LimitStatus.OK

    def test_the_warning_notification_is_raised_once_per_period(self, db: Session) -> None:
        """A two minute scheduler would otherwise send this 720 times a day."""
        tenant, client = prepare(db)
        add_limit(db, entity_type=EntityType.USER, entity_id="user-sean", credit_limit=10)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=14, actions={"triage": 14})
        ingestion.ingest_usage(db, client)
        db.commit()

        for _ in range(5):
            evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
            db.commit()

        warnings = list(db.scalars(select(Notification).where(Notification.category == "warning")))
        assert len(warnings) == 1

    def test_a_custom_threshold_is_respected(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-sean",
            credit_limit=10,
            warning_threshold_pct=50,
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=10, actions={"triage": 10})
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert state_of(db, limit).status == LimitStatus.WARNED


class TestMonitorOnly:
    def test_monitor_only_notifies_and_changes_nothing(self, db: Session) -> None:
        tenant, client = prepare(db)
        add_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", credit_limit=5, enforce=False
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=20)
        ingestion.ingest_usage(db, client)
        db.commit()
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert result.breached == 1
        assert result.monitor_only == 1
        assert result.enforced == 0
        # Zero side effects in the tenant.
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert db.scalar(select(EnforcementAction)) is None

        notification = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit%"))
        )
        assert notification is not None
        assert "monitor only" in (notification.body or "")

    def test_new_limits_default_to_monitor_only(self, db: Session) -> None:
        limit = CreditLimit(
            entity_type=EntityType.USER, entity_id="u1", credit_limit=1, period_type="monthly"
        )
        db.add(limit)
        db.commit()
        assert limit.enforce is False


class TestEnforcement:
    def test_a_breached_enforcing_limit_restricts_the_user(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            credit_limit=5,
            enforce=True,
            label="Harsh Gokani",
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=20)
        ingestion.ingest_usage(db, client)
        db.commit()
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert result.enforced == 1
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert state_of(db, limit).status == LimitStatus.RESTRICTED

    def test_a_breached_project_limit_disables_project_ai(self, db: Session) -> None:
        tenant, client = prepare(db)
        add_limit(
            db,
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            credit_limit=1,
            enforce=True,
            label="payments/web",
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_entity_credits(
            view="project", name="payments/web", credits=99, entity_id="proj-web"
        )
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is False

    def test_an_application_breach_restricts_all_its_projects(self, db: Session) -> None:
        tenant, client = prepare(db)
        add_limit(
            db,
            entity_type=EntityType.APPLICATION,
            entity_id="app-payments",
            credit_limit=1,
            enforce=True,
            label="Payments",
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_entity_credits(
            view="application", name="Payments", credits=500, entity_id="app-payments"
        )
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert tenant.auto_triage["proj-api"]["enabled"] is False
        assert tenant.auto_triage["proj-web"]["enabled"] is False
        assert tenant.auto_triage["proj-tools"]["enabled"] is True

    def test_evaluation_without_a_client_cannot_enforce(self, db: Session) -> None:
        tenant, client = prepare(db)
        add_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", credit_limit=1, enforce=True
        )
        result = evaluation.evaluate_all(db, client=None, now=AUGUST, actor=ACTOR)
        db.commit()
        assert result.enforced == 0
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    def test_an_exempt_entity_is_flagged_but_not_restricted(self, db: Session) -> None:
        tenant, client = prepare(db)
        db.add(Exemption(entity_type=EntityType.USER, entity_id="user-harsh", reason="lead"))
        add_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", credit_limit=1, enforce=True
        )
        db.commit()
        # Baseline first, then spend past the limit.
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()

        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert result.enforced == 0
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        notification = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit%"))
        )
        assert notification is not None
        assert "exemption list" in (notification.body or "")


class TestPrecedence:
    def test_any_single_breached_limit_restricts_the_user(self, db: Session) -> None:
        """A user under a generous user budget is still stopped by a tight group
        budget: the most restrictive limit is the one that bites."""
        tenant, client = prepare(db)
        add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-akash",
            credit_limit=1_000_000,
            enforce=True,
        )
        add_limit(
            db,
            entity_type=EntityType.GROUP,
            entity_id="grp-payments",
            credit_limit=1,
            enforce=True,
            label="Payments",
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        tenant.set_entity_credits(
            view="project", name="payments/api", credits=999, entity_id="proj-api"
        )
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        # The group breach restricted its projects even though the user budget is fine.
        assert tenant.auto_triage["proj-api"]["enabled"] is False

    def test_two_limits_on_the_same_project_each_produce_their_own_record(
        self, db: Session
    ) -> None:
        tenant, client = prepare(db)
        add_limit(
            db, entity_type=EntityType.PROJECT, entity_id="proj-api", credit_limit=1, enforce=True
        )
        add_limit(
            db,
            entity_type=EntityType.APPLICATION,
            entity_id="app-payments",
            credit_limit=1,
            enforce=True,
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_entity_credits(
            view="project", name="payments/api", credits=999, entity_id="proj-api"
        )
        tenant.set_entity_credits(
            view="application", name="Payments", credits=999, entity_id="app-payments"
        )
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        limit_ids = {
            action.limit_id
            for action in db.scalars(select(EnforcementAction))
            if action.target_id == "proj-api"
        }
        assert len(limit_ids) == 2

    def test_group_usage_sums_its_projects(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db, entity_type=EntityType.GROUP, entity_id="grp-payments", credit_limit=100
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        state = state_of(db, limit)
        # proj-api 8 + proj-web 4
        assert state.reported_total == Decimal("12")

    def test_group_usage_can_include_member_users(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.GROUP,
            entity_id="grp-payments",
            credit_limit=100,
            include_member_usage=True,
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        # 12 from projects, plus Sean 5 and Akash 0.
        assert state_of(db, limit).reported_total == Decimal("17")

    def test_application_usage_falls_back_to_summing_projects(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.consumption["application"] = []
        tenant_obj, client = prepare(db, tenant)
        limit = add_limit(
            db, entity_type=EntityType.APPLICATION, entity_id="app-payments", credit_limit=100
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert state_of(db, limit).reported_total == Decimal("12")


class TestUnavailableUsage:
    def test_a_project_limit_is_not_enforced_when_the_dimension_is_unsupported(
        self, db: Session
    ) -> None:
        """Unknown must never be treated as zero, and it must never be treated as
        a breach either."""
        tenant = populated_tenant()
        tenant.unsupported_views.add("project")
        tenant_obj, client = prepare(db, tenant)
        limit = add_limit(
            db, entity_type=EntityType.PROJECT, entity_id="proj-web", credit_limit=1, enforce=True
        )

        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert result.unavailable == 1
        assert result.enforced == 0
        state = state_of(db, limit)
        assert state.usage_available is False
        assert state.status == LimitStatus.OK
        assert tenant_obj.auto_triage["proj-web"]["enabled"] is True

    def test_the_reason_is_reported_to_the_admin(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.unsupported_views.add("project")
        tenant_obj, client = prepare(db, tenant)
        add_limit(db, entity_type=EntityType.PROJECT, entity_id="proj-web", credit_limit=1)
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        note = result.evaluations[0].note
        assert note is not None
        assert "does not report consumption" in note


class TestRollover:
    def test_a_new_period_resets_the_counter(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(db, entity_type=EntityType.USER, entity_id="user-sean", credit_limit=10)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=14, actions={"triage": 14})
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert state_of(db, limit, "2026-08").credits_used == Decimal("9")

        evaluation.evaluate_all(db, client=client, now=SEPTEMBER, actor=ACTOR)
        db.commit()
        september = state_of(db, limit, "2026-09")
        assert september.credits_used == Decimal("0")
        assert september.baseline_credits == Decimal("14")

    def test_rollover_restores_access_automatically(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", credit_limit=1, enforce=True
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

        result = evaluation.evaluate_all(db, client=client, now=SEPTEMBER, actor=ACTOR)
        db.commit()

        assert result.restored == 1
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert state_of(db, limit, "2026-08").status == LimitStatus.RESTORED

    def test_hold_until_released_survives_the_rollover(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            credit_limit=1,
            enforce=True,
            hold_until_released=True,
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        result = evaluation.evaluate_all(db, client=client, now=SEPTEMBER, actor=ACTOR)
        db.commit()
        assert result.restored == 0
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert state_of(db, limit, "2026-08").status == LimitStatus.RESTRICTED


class TestLimitChanges:
    def test_switching_to_monitor_only_lifts_the_restriction(self, db: Session) -> None:
        from app.services import limits_service

        tenant, client = prepare(db)
        limit = add_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", credit_limit=1, enforce=True
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

        limits_service.update_limit(
            db, limit=limit, changes={"enforce": False}, actor=ACTOR, client=client
        )
        db.commit()
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    def test_deleting_a_limit_lifts_its_restrictions(self, db: Session) -> None:
        from app.services import limits_service

        tenant, client = prepare(db)
        limit = add_limit(
            db, entity_type=EntityType.PROJECT, entity_id="proj-web", credit_limit=1, enforce=True
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        tenant.set_entity_credits(
            view="project", name="payments/web", credits=99, entity_id="proj-web"
        )
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert tenant.auto_triage["proj-web"]["enabled"] is False

        restored = limits_service.delete_limit(db, limit=limit, actor=ACTOR, client=client)
        db.commit()
        assert restored == 1
        assert tenant.auto_triage["proj-web"]["enabled"] is True

    def test_an_inactive_limit_is_not_evaluated(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db, entity_type=EntityType.USER, entity_id="user-harsh", credit_limit=1, enforce=True
        )
        limit.is_active = False
        db.commit()
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert result.evaluated == 0


class TestMisconfiguration:
    def test_a_custom_period_without_a_start_is_reported_not_enforced(self, db: Session) -> None:
        tenant, client = prepare(db)
        add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            credit_limit=1,
            enforce=True,
            period_type=PeriodType.CUSTOM,
        )
        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert result.errors
        assert result.enforced == 0
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert db.scalar(select(Notification).where(Notification.title.like("%misconfigured%")))

    def test_a_closed_custom_period_is_not_enforced(self, db: Session) -> None:
        tenant, client = prepare(db)
        limit = add_limit(
            db,
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            credit_limit=1,
            enforce=True,
            period_type=PeriodType.CUSTOM,
        )
        limit.custom_period_start = datetime(2026, 1, 1, tzinfo=UTC)
        limit.custom_period_end = datetime(2026, 2, 1, tzinfo=UTC)
        db.commit()

        result = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        assert result.enforced == 0
        assert result.evaluations[0].note is not None
        assert "not currently open" in result.evaluations[0].note


@pytest.mark.parametrize("threshold", [1, 50, 99, 100])
def test_thresholds_are_accepted_across_the_range(db: Session, threshold: int) -> None:
    tenant, client = prepare(db)
    limit = add_limit(
        db,
        entity_type=EntityType.USER,
        entity_id="user-sean",
        credit_limit=100,
        warning_threshold_pct=threshold,
    )
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert state_of(db, limit).status == LimitStatus.OK
