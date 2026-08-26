"""Regressions for the usage measurement bugs found against a live tenant.

All three came from one report: a project showing 13 credits in Checkmarx and 0 in
CxCreditGuard.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import usage as usage_api
from app.models.enums import EntityType, LimitStatus, PeriodType, UsageView
from app.models.limits import CreditLimit, LimitPeriodState
from app.models.usage import DimensionState, UnresolvedSubject, UsageSnapshot
from app.services import connection as connection_service
from app.services import evaluation, ingestion, org_sync
from app.services.audit import AuditActor
from app.services.periods import current_window
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant

ACTOR = AuditActor.system("test")
NOW = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)

# The exact payload the tenant returned for viewBy=project. Note: no id field, and
# the project is identified by name alone.
REAL_PROJECT_ROW = {
    "name": "singakash/CxHybrid",
    "creditsUsed": 13,
    "percentOfTotal": 100,
    "actionsPerformed": {
        "actions": [
            {"actionType": "remediation", "transactionCount": 1},
            {"actionType": "triage", "transactionCount": 10},
        ],
        "total": 11,
    },
}


def tenant_like_production() -> FakeTenant:
    """A tenant shaped like the one in the bug report."""
    tenant = FakeTenant()
    tenant.add_project(project_id="proj-hybrid", name="singakash/CxHybrid")
    tenant.add_user(
        user_id="user-akash",
        username="akash.singh@checkmarx.com",
        email="akash.singh@checkmarx.com",
        first_name="Akash",
        last_name="Singh",
    )
    tenant.consumption["project"] = [dict(REAL_PROJECT_ROW)]
    # The user view reports Auto Triage as a synthetic person.
    tenant.consumption["user"] = [
        {
            "name": "Akash Singh",
            "email": "akash.singh@checkmarx.com",
            "userEmail": "akash.singh@checkmarx.com",
            "creditsUsed": 3,
            "percentOfTotal": 23.08,
            "actionsPerformed": {
                "actions": [{"actionType": "remediation", "transactionCount": 1}],
                "total": 1,
            },
        },
        {
            "name": "Auto-triage",
            "creditsUsed": 10,
            "percentOfTotal": 76.92,
            "actionsPerformed": {
                "actions": [{"actionType": "triage", "transactionCount": 10}],
                "total": 10,
            },
        },
    ]
    # The action dimension names each type in title case, with the lowercase
    # actionType nested underneath.
    tenant.consumption["action"] = [
        {
            "name": "Remediation",
            "creditsUsed": 3,
            "percentOfTotal": 23.08,
            "actionsPerformed": {
                "actions": [{"actionType": "remediation", "transactionCount": 1}],
                "total": 1,
            },
        },
        {
            "name": "Triage",
            "creditsUsed": 10,
            "percentOfTotal": 76.92,
            "actionsPerformed": {
                "actions": [{"actionType": "triage", "transactionCount": 10}],
                "total": 10,
            },
        },
    ]
    # Real dimensions, idle on this tenant.
    tenant.consumption["application"] = []
    tenant.consumption["group"] = []
    return tenant


def prepared(db: Session, tenant: FakeTenant):
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    return client


def add_limit(
    db: Session, *, period_type: str, budget: int, count_existing: bool = False
) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.PROJECT,
        entity_id="proj-hybrid",
        entity_label="singakash/CxHybrid",
        credit_limit=budget,
        period_type=period_type,
        enforce=False,
        count_existing_usage=count_existing,
        created_at=NOW,
        custom_period_start=datetime(2026, 8, 1, tzinfo=UTC)
        if period_type == PeriodType.CUSTOM
        else None,
    )
    db.add(limit)
    db.commit()
    return limit


def state_of(db: Session, limit: CreditLimit) -> LimitPeriodState:
    window = current_window(limit, NOW)
    state = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == window.key
        )
    )
    assert state is not None
    return state


class TestProjectsAreMatchedByNameAlone:
    """The response carries no id, so name matching is the only thing that works."""

    def test_credits_are_attributed_to_the_project(self, db: Session) -> None:
        client = prepared(db, tenant_like_production())
        totals = ingestion.latest_totals(db, UsageView.PROJECT)
        assert totals == {"proj-hybrid": Decimal("13")}
        assert client is not None

    def test_the_action_breakdown_survives(self, db: Session) -> None:
        prepared(db, tenant_like_production())
        from app.models.usage import UsageRecord

        record = db.scalar(select(UsageRecord).where(UsageRecord.entity_id == "proj-hybrid"))
        assert record is not None
        assert record.actions == {"triage": 10, "remediation": 1}
        # 13 credits for 11 transactions: credits are the budget currency.
        assert record.credits_used == Decimal("13")
        assert record.transactions == 11


class TestLifetimeAndCustomPeriodsCountEverything:
    """The reported bug. A lifetime budget that discounts history is meaningless."""

    def test_a_lifetime_limit_counts_all_reported_credits(self, db: Session) -> None:
        client = prepared(db, tenant_like_production())
        limit = add_limit(db, period_type=PeriodType.LIFETIME, budget=10)

        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.baseline_credits == Decimal("0")
        assert state.credits_used == Decimal("13")
        # 13 against a budget of 10 is a breach, and must not read as within budget.
        assert state.status == LimitStatus.BREACHED

    def test_a_custom_period_counts_all_reported_credits(self, db: Session) -> None:
        client = prepared(db, tenant_like_production())
        limit = add_limit(db, period_type=PeriodType.CUSTOM, budget=50)

        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.baseline_credits == Decimal("0")
        assert state.credits_used == Decimal("13")

    def test_a_monthly_limit_still_discounts_history_by_default(self, db: Session) -> None:
        """The protective behaviour has to stay: a year of history must not exhaust a
        fresh monthly budget on day one."""
        client = prepared(db, tenant_like_production())
        limit = add_limit(db, period_type=PeriodType.MONTHLY, budget=10)

        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.baseline_credits == Decimal("13")
        assert state.credits_used == Decimal("0")
        assert state.status == LimitStatus.OK

    def test_a_monthly_limit_can_opt_into_counting_history(self, db: Session) -> None:
        client = prepared(db, tenant_like_production())
        limit = add_limit(db, period_type=PeriodType.MONTHLY, budget=10, count_existing=True)

        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()

        state = state_of(db, limit)
        assert state.baseline_credits == Decimal("0")
        assert state.credits_used == Decimal("13")
        assert state.status == LimitStatus.BREACHED

    def test_new_consumption_still_accrues_after_a_baseline(self, db: Session) -> None:
        tenant = tenant_like_production()
        client = prepared(db, tenant)
        limit = add_limit(db, period_type=PeriodType.MONTHLY, budget=10)
        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()

        tenant.consumption["project"][0]["creditsUsed"] = 20
        ingestion.ingest_usage(db, client)
        db.commit()
        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()

        assert state_of(db, limit).credits_used == Decimal("7")

    def test_an_unavailable_dimension_never_baselines(self, db: Session) -> None:
        tenant = tenant_like_production()
        tenant.unsupported_views.add("project")
        client = prepared(db, tenant)
        limit = add_limit(db, period_type=PeriodType.LIFETIME, budget=10)

        evaluation.evaluate_all(db, client=client, now=NOW, actor=ACTOR)
        db.commit()
        state = state_of(db, limit)
        assert state.usage_available is False
        assert state.baseline_credits == Decimal("0")
        assert state.credits_used == Decimal("0")


class TestSilentViewByFallback:
    """An unrecognised viewBy answers 200 with the user view, so a successful
    response is not evidence that the dimension exists."""

    def test_the_fallback_is_detected_and_the_dimension_disabled(self, db: Session) -> None:
        tenant = tenant_like_production()
        # Model the real behaviour: any unknown viewBy returns the user rows.
        tenant.consumption["project"] = list(tenant.consumption["user"])
        tenant.fallback_view = "user"

        client = tenant.client()
        org_sync.sync_org_model(db, client)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        assert result.dimensions["project"].supported is False
        assert db.get(DimensionState, "project").supported is False
        assert any("returned the user view instead" in w for w in result.warnings)
        # And nothing was filed as project usage.
        assert ingestion.latest_totals(db, UsageView.PROJECT) == {}
        assert db.scalar(select(UsageSnapshot).where(UsageSnapshot.view_by == "project")) is None

    def test_a_genuine_dimension_is_not_mistaken_for_a_fallback(self, db: Session) -> None:
        tenant = tenant_like_production()
        tenant.fallback_view = "user"
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        assert result.dimensions["project"].supported is True
        assert ingestion.latest_totals(db, UsageView.PROJECT) == {"proj-hybrid": Decimal("13")}

    def test_a_failed_probe_does_not_disable_a_dimension(self, db: Session) -> None:
        """An inconclusive probe must not be read as evidence of absence."""
        tenant = tenant_like_production()
        tenant.fallback_view = "user"
        tenant.probe_fails = True

        client = tenant.client()
        org_sync.sync_org_model(db, client)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        assert result.dimensions["project"].supported is True
        assert ingestion.latest_totals(db, UsageView.PROJECT) == {"proj-hybrid": Decimal("13")}

    def test_an_idle_real_dimension_is_not_mistaken_for_a_fallback(self, db: Session) -> None:
        """A dimension with no data returns an empty list, which proves nothing
        either way. It must not be disabled on that basis."""
        tenant = tenant_like_production()
        tenant.fallback_view = "user"
        tenant.consumption["application"] = []
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert result.dimensions["application"].supported is True

    def test_the_probe_runs_once_not_per_dimension(self, db: Session) -> None:
        tenant = tenant_like_production()
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        tenant.requests.clear()
        ingestion.ingest_usage(db, client)
        db.commit()
        probes = [path for method, path in tenant.requests if path.endswith("/credits/consumption")]
        # One probe plus one request per dimension, not one probe per dimension.
        assert len(probes) >= 4
        assert tenant.probe_calls == 1


class TestAutoTriageIsNotAPerson:
    """Auto Triage is reported in the user dimension under a synthetic name."""

    def test_it_is_not_offered_as_an_unmatched_user(self, db: Session) -> None:
        prepared(db, tenant_like_production())
        unresolved = list(db.scalars(select(UnresolvedSubject)))
        assert [row.subject_key for row in unresolved] == []

    def test_it_is_counted_as_automated(self, db: Session) -> None:
        tenant = tenant_like_production()
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert result.dimensions["user"].automated == 1
        assert result.dimensions["user"].unresolved == 0

    def test_it_is_not_attributed_to_any_user_limit(self, db: Session) -> None:
        prepared(db, tenant_like_production())
        totals = ingestion.latest_totals(db, UsageView.USER)
        # Only the real person's 3 credits, not the 10 from automation.
        assert totals == {"user-akash": Decimal("3")}

    def test_the_credits_still_count_at_project_level(self, db: Session) -> None:
        """The brief says Auto Triage belongs to the project, and it does."""
        prepared(db, tenant_like_production())
        assert ingestion.latest_totals(db, UsageView.PROJECT)["proj-hybrid"] == Decimal("13")

    @pytest.mark.parametrize(
        "name", ["Auto-triage", "auto triage", "AUTOTRIAGE", "auto_triage", "System"]
    )
    def test_spelling_variants_are_recognised(self, name: str) -> None:
        assert ingestion.is_synthetic_subject(name) is True

    def test_a_real_person_is_not_treated_as_automation(self) -> None:
        assert ingestion.is_synthetic_subject("Akash Singh") is False
        assert ingestion.is_synthetic_subject("autonomy.team@example.com") is False


class TestLookbackWindowValidation:
    """Only five windows are accepted; anything else is a 400 that would break
    ingestion until somebody noticed."""

    def test_the_supported_set_is_what_the_tenant_accepts(self) -> None:
        assert usage_api.SUPPORTED_PERIODS == (
            "last_month",
            "last_30_days",
            "last_90_days",
            "last_180_days",
            "last_year",
        )

    def test_a_bad_window_is_rejected_at_the_settings_api(self, admin_client: TestClient) -> None:
        response = admin_client.put("/api/settings", json={"usage_period_param": "this_month"})
        assert response.status_code == httpx.codes.BAD_REQUEST
        assert response.json()["detail"]["code"] == "invalid_period"
        assert "last_year" in response.json()["detail"]["message"]

    @pytest.mark.parametrize("window", usage_api.SUPPORTED_PERIODS)
    def test_every_supported_window_is_accepted(
        self, admin_client: TestClient, window: str
    ) -> None:
        response = admin_client.put("/api/settings", json={"usage_period_param": window})
        assert response.status_code == httpx.codes.OK
        assert response.json()["usage_period_param"] == window

    def test_the_settings_response_advertises_them(self, admin_client: TestClient) -> None:
        body = admin_client.get("/api/settings").json()
        assert body["allowed_usage_periods"] == list(usage_api.SUPPORTED_PERIODS)


class TestApiSurface:
    def test_the_new_option_round_trips_through_the_api(
        self, admin_client: TestClient, db: Session
    ) -> None:
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        tenant = tenant_like_production()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()

        created = admin_client.post(
            "/api/limits",
            json={
                "entity_type": "project",
                "entity_id": "proj-hybrid",
                "credit_limit": 20,
                "count_existing_usage": True,
            },
        )
        assert created.status_code == httpx.codes.CREATED
        assert created.json()["count_existing_usage"] is True

        updated = admin_client.patch(
            f"/api/limits/{created.json()['id']}", json={"count_existing_usage": False}
        )
        assert updated.json()["count_existing_usage"] is False

    def test_it_defaults_to_false(self, admin_client: TestClient, db: Session) -> None:
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        tenant = tenant_like_production()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        created = admin_client.post(
            "/api/limits",
            json={"entity_type": "project", "entity_id": "proj-hybrid", "credit_limit": 20},
        )
        assert created.json()["count_existing_usage"] is False
