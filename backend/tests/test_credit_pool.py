"""Tenant credit pool: parsing /credits/info, storing it, and the dashboard view."""

from __future__ import annotations

from decimal import Decimal

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.checkmarx import credits as credits_api
from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType
from app.models.limits import CreditLimit
from app.models.usage import CreditBalanceSnapshot
from app.services import dashboard as dashboard_service
from tests.fake_tenant import FakeTenant, populated_tenant


class TestParse:
    def test_reads_the_standard_shape(self) -> None:
        bal = credits_api.parse_credit_balance(
            {"totalCredits": 1000, "usedCredits": 150, "availableCredits": 850}
        )
        assert bal is not None
        assert (bal.total, bal.used, bal.available) == (
            Decimal("1000"),
            Decimal("150"),
            Decimal("850"),
        )

    def test_derives_the_missing_third_figure(self) -> None:
        bal = credits_api.parse_credit_balance({"total": 1000, "used": 300})
        assert bal is not None
        assert bal.available == Decimal("700")

    def test_unknown_figures_stay_none_never_zero(self) -> None:
        bal = credits_api.parse_credit_balance({"somethingElse": 5})
        assert bal is not None
        assert (bal.total, bal.used, bal.available) == (None, None, None)
        assert bal.has_values() is False

    def test_a_non_object_body_is_none(self) -> None:
        assert credits_api.parse_credit_balance([1, 2, 3]) is None
        assert credits_api.parse_credit_balance("nope") is None

    def test_an_envelope_is_unwrapped(self) -> None:
        bal = credits_api.parse_credit_balance({"data": {"total": 500, "remaining": 200}})
        assert bal is not None
        assert bal.total == Decimal("500")
        assert bal.available == Decimal("200")


class TestFetch:
    def test_reads_the_tenant_balance(self, db: Session) -> None:
        tenant = FakeTenant()
        bal = credits_api.fetch_credit_balance(tenant.client())
        assert bal is not None
        assert bal.total == Decimal("1000")

    def test_a_missing_endpoint_is_none_not_zero(self, db: Session) -> None:
        tenant = FakeTenant()
        tenant.credit_info = None  # endpoint 404s
        assert credits_api.fetch_credit_balance(tenant.client()) is None


ACTOR = None


class TestDashboardPool:
    def _seed_balance(self, db: Session, **figures: int) -> None:
        db.add(
            CreditBalanceSnapshot(
                collected_at=utcnow(),
                total_credits=Decimal(str(figures.get("total", 1000))),
                used_credits=Decimal(str(figures.get("used", 150))),
                available_credits=Decimal(str(figures.get("available", 850))),
                raw={},
            )
        )
        db.commit()

    def _add_limit(self, db: Session, entity_id: str, amount: int, active: bool = True) -> None:
        db.add(
            CreditLimit(
                entity_type=EntityType.USER,
                entity_id=entity_id,
                credit_limit=amount,
                period_type=PeriodType.MONTHLY,
                is_active=active,
            )
        )
        db.commit()

    def test_reports_balance_and_assigned(self, db: Session) -> None:
        self._seed_balance(db, total=1000, used=150, available=850)
        self._add_limit(db, "user-a", 200)
        self._add_limit(db, "user-b", 300)
        pool = dashboard_service.credit_pool(db)
        assert pool.total == Decimal("1000")
        assert pool.available == Decimal("850")
        assert pool.assigned == Decimal("500")
        assert pool.over_allocation is None

    def test_flags_over_allocation(self, db: Session) -> None:
        self._seed_balance(db, total=100)
        self._add_limit(db, "user-a", 400)
        pool = dashboard_service.credit_pool(db)
        assert pool.over_allocation == Decimal("300")

    def test_inactive_limits_are_not_assigned(self, db: Session) -> None:
        self._seed_balance(db)
        self._add_limit(db, "user-a", 200, active=False)
        assert dashboard_service.credit_pool(db).assigned == Decimal("0")

    def test_unknown_balance_is_null_not_zero(self, db: Session) -> None:
        # No snapshot has ever been written.
        pool = dashboard_service.credit_pool(db)
        assert pool.total is None
        assert pool.used is None
        assert pool.available is None
        assert pool.assigned == Decimal("0")

    def test_dashboard_endpoint_exposes_pool(self, admin_client: TestClient, db: Session) -> None:
        self._seed_balance(db, total=1000, used=150, available=850)
        body = admin_client.get("/api/dashboard").json()
        assert body["credit_pool"]["total"] == "1000.0000"
        assert body["credit_pool"]["available"] == "850.0000"


def test_cycle_fixture_tenant_serves_credit_info() -> None:
    # The shared populated tenant answers /credits/info so a cycle can store it.
    tenant = populated_tenant()
    bal = credits_api.fetch_credit_balance(tenant.client())
    assert bal is not None and bal.total == Decimal("1000")
