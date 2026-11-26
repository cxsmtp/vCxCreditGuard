"""Third review of realfix (restated for the usage ledger): an overridden
mapping from before the upgrade must not read the name's whole history as
usage after the project's restriction.

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import EnforcementAction, EntityMapping, PolicyViolation
from app.models.enums import EntityType, PeriodType
from app.services import cycle, limits_service
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401


def test_overridden_mapping_seeded_by_the_migration_is_no_violation(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(
        view="project", name="payments/api", credits=8, actions={"auto_triage": 8}
    )
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
    cycle.run_cycle(trigger="manual")

    # The upgrade: an old mapping of the name (to another project) that the
    # real name match has always overridden. Under the usage ledger (fifth
    # review) only increases observed after the restriction count, and there
    # are none.
    db.add(
        EntityMapping(
            view_by="project", subject_key="payments/api", entity_id="proj-web", mapped_at=utcnow()
        )
    )
    db.commit()
    cycle.run_cycle(trigger="manual")  # nothing new reported
    db.expire_all()
    found = [v for v in db.scalars(select(PolicyViolation)) if v.kind == "usage_after_restriction"]
    assert not found, [(v.evidence) for v in found]
