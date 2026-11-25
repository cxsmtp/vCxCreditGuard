"""Fourth review of realfix (guard): baseline_names at 2,000 projects and limits."""

from __future__ import annotations

import json
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import LimitPeriodState
from app.models.enums import EntityType, PeriodType
from app.models.limits import CreditLimit
from app.services import cycle, evaluation
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401

N = 2000


def test_scale(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    groups = [f"g-{k}" for k in range(20)]
    for gid in groups:
        tenant.add_group(group_id=gid, name=gid)
    for i in range(N):
        tenant.add_project(project_id=f"p-{i}", name=f"org/repo-{i}", group_ids=groups)
        tenant.set_entity_credits(view="project", name=f"org/repo-{i}", credits=i + 1)
    for i in range(300):
        tenant.set_user_credits(name=f"person{i}@example.com", credits=i + 1)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
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
    db.commit()
    start = time.perf_counter()
    evaluation.evaluate_all(db)
    db.commit()
    first = time.perf_counter() - start
    start = time.perf_counter()
    evaluation.evaluate_all(db)
    db.commit()
    second = time.perf_counter() - start
    sizes = [len(json.dumps(s.baseline_names or {})) for s in db.scalars(select(LimitPeriodState))]
    # Real name matches never move, so a budget over thousands of projects
    # stores next to nothing; and the cost stays the evaluation's own.
    assert len(sizes) == N + len(groups)
    assert max(sizes) < 200 and sum(sizes) < 50 * len(sizes), (max(sizes), sum(sizes))
    assert first < 120 and second < 120, (first, second)
