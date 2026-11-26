"""A small synthetic tenant and a controlled clock for the activity source
tests (app/services/activity_source.py). Synthetic data only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

import app.db.base as base_module
from app.models import (
    BudgetUsage,
    CreditLimit,
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.enums import PeriodType
from app.services import limits_service, settings_store
from app.services.audit import AuditActor
from tests.fake_tenant import FakeTenant

ACTOR = AuditActor.system("test")

P_API = "0b6f1d2e-0000-4000-8000-000000000001"
P_WEB = "0b6f1d2e-0000-4000-8000-000000000002"
P_TOOLS = "0b6f1d2e-0000-4000-8000-000000000003"
APP_PAY = "a0000000-0000-4000-8000-0000000000a1"
APP_OTHER = "a0000000-0000-4000-8000-0000000000a2"
G_PAY = "90000000-0000-4000-8000-0000000000c1"
U_ALICE = "e0000000-0000-4000-8000-000000000001"
U_BOB = "e0000000-0000-4000-8000-000000000002"
U_CARA = "e0000000-0000-4000-8000-000000000003"

PROJECT_NAMES = {P_API: "payments/api", P_WEB: "payments/web", P_TOOLS: "platform/tools"}


class Clock(datetime):
    """``app.db.base.utcnow`` (every timestamp the app takes) reads this."""

    value: datetime = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)

    @classmethod
    def now(cls, tz=None):  # type: ignore[no-untyped-def, override]
        return cls.value


def install_clock(monkeypatch, start: datetime) -> type[Clock]:  # type: ignore[no-untyped-def]
    Clock.value = start
    monkeypatch.setattr(base_module, "datetime", Clock)
    return Clock


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def seed_org(db: Session) -> None:
    """Three projects, one group and one application, three people."""
    now = base_module.utcnow() - timedelta(days=60)
    for project_id, name in PROJECT_NAMES.items():
        db.add(CxProject(id=project_id, name=name, created_at=now, updated_at=now))
    db.add(CxGroup(id=G_PAY, name="payments", created_at=now, updated_at=now))
    db.add(CxApplication(id=APP_PAY, name="Payments", created_at=now, updated_at=now))
    db.add(CxApplication(id=APP_OTHER, name="Other", created_at=now, updated_at=now))
    db.add(CxProjectGroup(project_id=P_API, group_id=G_PAY))
    db.add(CxProjectGroup(project_id=P_WEB, group_id=G_PAY))
    db.add(CxApplicationProject(application_id=APP_PAY, project_id=P_API))
    db.add(
        CxUser(
            id=U_ALICE,
            username="alice.example",
            email="alice@example.com",
            first_name="Alice",
            last_name="Example",
            created_at=now,
            updated_at=now,
        )
    )
    db.add(
        CxUser(
            id=U_BOB,
            username="jdoe",
            email=None,
            first_name="Bob",
            last_name="Sample",
            created_at=now,
            updated_at=now,
        )
    )
    db.add(
        CxUser(
            id=U_CARA,
            username="cara",
            email="cara@example.com",
            first_name="Cara",
            last_name="Demo",
            created_at=now,
            updated_at=now,
        )
    )
    db.flush()
    db.add(CxGroupMembership(group_id=G_PAY, user_id=U_ALICE))
    db.commit()


def budget(
    db: Session,
    entity_type: str,
    entity_id: str,
    *,
    created_at: datetime | None = None,
    include_member_usage: bool = False,
    period_type: str = PeriodType.MONTHLY,
) -> CreditLimit:
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=entity_type,
            entity_id=entity_id,
            credit_limit=100_000,
            period_type=period_type,
            enforce=False,
            include_member_usage=include_member_usage,
        ),
        actor=ACTOR,
    )
    if created_at is not None:
        limit.created_at = created_at
    db.commit()
    return limit


def counter(db: Session, limit: CreditLimit, key: str | None = None) -> Decimal:
    """A budget's counter for one period key, or summed over its months."""
    db.expire_all()
    rows = db.scalars(select(BudgetUsage).where(BudgetUsage.limit_id == limit.id)).all()
    if key is not None:
        return sum((Decimal(row.credits) for row in rows if row.period_key == key), Decimal(0))
    return sum((Decimal(row.credits) for row in rows if "-Q" not in row.period_key), Decimal(0))


def use_source(db: Session, source: str) -> None:
    settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, source)
    db.commit()


def new_tenant() -> FakeTenant:
    tenant = FakeTenant()
    tenant.activity = []
    return tenant
