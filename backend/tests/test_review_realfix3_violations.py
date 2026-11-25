"""Third review of realfix (restated for the usage ledger): thinning old readings must not hide
once thinning removes it the name's real rise after a restriction is skipped.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import EnforcementAction, PolicyViolation, UnresolvedSubject
from app.models.enums import EntityType, PeriodType
from app.models.usage import UsageSnapshot
from app.services import cycle, ingestion, limits_service, retention
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401


def _contractor(tenant, credits: int, remediation: int) -> None:  # type: ignore[no-untyped-def]
    tenant.set_user_credits(
        name="Former Contractor", credits=credits, actions={"remediation": remediation}
    )
    rows = tenant.consumption["user"]
    rows.insert(0, rows.pop())


def test_rise_of_a_mapped_name_after_thinning_is_still_reported(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.USER,
            entity_id="user-alice",
            credit_limit=2,
            period_type=PeriodType.LIFETIME,
            enforce=True,
        ),
        actor=ACTOR,
    )
    db.commit()
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    assert db.scalar(select(EnforcementAction)).status == "applied"
    _contractor(tenant, 500, 40)
    cycle.run_cycle(trigger="manual")
    subject = db.scalar(
        select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "former contractor")
    )
    r = admin_client.post(f"/api/usage/unresolved/{subject.id}/map", json={"user_id": "user-alice"})
    assert r.status_code == 200, r.text
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    mapped_reading = ingestion.latest_live_snapshot(db, "user")

    # Five days pass (everything so far is older than the 3 days kept whole).
    back = timedelta(days=5)
    for model, columns in (
        (UsageSnapshot, ("collected_at",)),
        (EnforcementAction, ("applied_at", "created_at")),
    ):
        for row in db.scalars(select(model)):
            for column in columns:
                if getattr(row, column) is not None:
                    setattr(row, column, getattr(row, column) - back)
    db.commit()
    keep, _ = retention.pinned_snapshots(db, utcnow())
    pinned = mapped_reading.id in keep
    retention.prune(db, retention_days=365, actor=ACTOR)
    db.commit()
    db.expire_all()
    gone = db.get(UsageSnapshot, mapped_reading.id) is None

    # Remediation the mapped name runs now is usage after the restriction.
    _contractor(tenant, 520, 43)
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    found = [v for v in db.scalars(select(PolicyViolation)) if v.kind == "usage_after_restriction"]
    assert len(found) == 1, (pinned, gone, [(v.kind, v.evidence) for v in found])
