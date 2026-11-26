"""Fifth review of realfix: a restricted user's consumption key changes (email changed in IAM,
the feed reporting the new key first). The renamed key takes over in full, with
no anchor; violations compare it with the pinned reading, where it is absent,
so its whole history reads as usage after the restriction."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import EnforcementAction, PolicyViolation
from app.models.enums import EntityType, PeriodType
from app.services import cycle, limits_service
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401


def test_renamed_key_of_a_restricted_user_is_not_a_violation(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_user_credits(name="Bob Baker", credits=4000, actions={"triage": 4000})
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

    # Feed first: Alice's usage now reported under her new address, same totals.
    rows = tenant.consumption["user"]
    tenant.consumption["user"] = [r for r in rows if r.get("email") != "alice.archer@example.com"]
    tenant.set_user_credits(
        name="Alice Archer", email="alice.smith@example.com", credits=3, actions={"remediation": 1}
    )
    cycle.run_cycle(trigger="manual")
    # Then the sync learns the new address.
    for user in tenant.users:
        if user["id"] == "user-alice":
            user["email"] = "alice.smith@example.com"
            user["username"] = "alice.smith@example.com"
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    found = [
        (v.kind, v.evidence)
        for v in db.scalars(select(PolicyViolation))
        if v.kind == "usage_after_restriction"
    ]
    assert found == [], found
