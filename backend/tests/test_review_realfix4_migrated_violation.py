"""Review 4: a project mapping made before the upgrade but after a
restriction on that project. The migration anchors it at offset 0, dated at
mapped_at, with no reference_actions; violations then read the name's whole
history as usage after the restriction.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import EnforcementAction, EntityMapping, PolicyViolation, UsageAnchor, UsageRecord
from app.models.enums import EntityType, PeriodType
from app.services import cycle, ingestion, limits_service
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401

NAME = "old-org/payments-api"


def test_pre_upgrade_mapping_after_a_restriction_is_no_violation(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=300, actions={"auto_triage": 30})
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-api",
            credit_limit=1,
            period_type=PeriodType.LIFETIME,
            enforce=True,
        ),
        actor=ACTOR,
    )
    db.commit()
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    kinds = [(a.kind, a.status) for a in db.scalars(select(EnforcementAction))]
    assert ("disable_auto_triage", "applied") in kinds, kinds

    # Before the upgrade, an admin mapped the name (the old code re-pointed the
    # latest reading's row); the upgrade then anchors it at 0, at mapped_at.
    mapped_at = utcnow()
    latest = ingestion.latest_live_snapshot(db, "project")
    db.add(
        EntityMapping(
            view_by="project", subject_key=NAME, entity_id="proj-api", mapped_at=mapped_at
        )
    )
    row = db.scalar(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == latest.id, UsageRecord.subject_key == NAME
        )
    )
    row.entity_id, row.entity_type = "proj-api", EntityType.PROJECT
    db.add(
        UsageAnchor(
            view_by="project",
            subject_key=NAME,
            entity_id="proj-api",
            offset_credits=0,
            snapshot_id=latest.id,
            anchored_at=mapped_at,
            reason="mapping",
        )
    )
    db.commit()
    cycle.run_cycle(trigger="manual")  # nothing new reported
    db.expire_all()
    found = [v for v in db.scalars(select(PolicyViolation)) if v.kind == "usage_after_restriction"]
    assert not found, [v.evidence for v in found]
