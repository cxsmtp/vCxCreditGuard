"""Fifth review of realfix (guard): 2,000 projects whose usage is reported under
repo names that are all mapped (the real tenant's 87%), 20 group budgets over
all of them, with the usage ledger."""

from __future__ import annotations

import time
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import BudgetUsage, EntityMapping
from app.models.enums import EntityType, PeriodType, UsageView
from app.models.limits import CreditLimit
from app.services import cycle, ingestion
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401

N = 2000


def test_scale_all_mapped(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    groups = [f"g-{k}" for k in range(20)]
    for gid in groups:
        tenant.add_group(group_id=gid, name=gid)
    for i in range(N):
        tenant.add_project(project_id=f"p-{i}", name=f"Proj {i}", group_ids=groups)
        tenant.set_entity_credits(view="project", name=f"org/repo-{i}", credits=1000 + i)
    for i in range(300):
        tenant.set_user_credits(name=f"person{i}@example.com", credits=i + 1)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    start = time.perf_counter()
    ingestion.attribution_lock(db)
    for i in range(N):
        db.add(
            EntityMapping(
                view_by="project",
                subject_key=f"org/repo-{i}",
                entity_id=f"p-{i}",
                mapped_at=utcnow(),
            )
        )
        db.flush()
        ingestion.move_subject(
            db,
            view=UsageView.PROJECT,
            subject_key=f"org/repo-{i}",
            entity_type=EntityType.PROJECT,
            entity_id=f"p-{i}",
            follows=lambda r: True,
        )
    db.commit()
    mapping = time.perf_counter() - start
    for gid in groups:
        db.add(
            CreditLimit(
                entity_type=EntityType.GROUP,
                entity_id=gid,
                credit_limit=10**7,
                period_type=PeriodType.MONTHLY,
                enforce=False,
            )
        )
    for i in range(N):
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id=f"p-{i}",
                credit_limit=10**6,
                period_type=PeriodType.MONTHLY,
                enforce=False,
            )
        )
    db.commit()
    timings = []
    for step in range(3):
        for i in range(0, N, 7):
            tenant.set_entity_credits(
                view="project", name=f"org/repo-{i}", credits=1000 + i + step + 1
            )
        start = time.perf_counter()
        cycle.run_cycle(trigger="manual")
        timings.append(time.perf_counter() - start)
    counters = list(db.scalars(select(BudgetUsage)))
    print(
        "RR5-SCALE mapping",
        round(mapping, 1),
        "cycles",
        [round(t, 1) for t in timings],
        "counters",
        len(counters),
    )
    assert max(timings) < 120, timings
    # Every group budget counted each increase once (steps 1..3 of every 7th repo).
    groups_counted = {
        row.credits for row in counters if row.limit_id <= len(groups) and row.period_key
    }
    assert groups_counted == {Decimal(3 * len(range(0, N, 7)))}, groups_counted
