"""Sixth review of realfix: a group whose own row first appears in the group
view in the same cycle as its project's increase. The project view is read
before the group view, so it feeds the group budget (no own figure in the
previous group reading), and the group view's new row counts in full too."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType, PeriodType
from app.services import cycle, limits_service
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import ACTOR, _state


def test_group_first_own_row_counts_twice(db: Session, connected) -> None:  # noqa: F811
    tenant = live_tenant()
    tenant.consumption["group"] = []  # a real, idle group dimension
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limit = limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.GROUP,
            entity_id="grp-platform",
            credit_limit=100,
            period_type=PeriodType.MONTHLY,
            enforce=False,
            include_member_usage=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    cycle.run_cycle(trigger="manual")
    assert _state(db, limit).credits_used == 0
    # platform/tools (the group's only project) goes from 2 to 50 credits,
    # and the group dimension reports the group's 50 for the first time.
    tenant.set_entity_credits(view="project", name="platform/tools", credits=50)
    tenant.set_entity_credits(view="group", name="AA-Platform", credits=50)
    cycle.run_cycle(trigger="manual")
    used = _state(db, limit).credits_used
    # platform/tools went 2 -> 50: 48 new credits. Never more than that.
    assert used <= 48, (used, _dump(db))


def _dump(db):  # type: ignore[no-untyped-def]
    from sqlalchemy import select

    from app.models import UsageDelta

    return [
        (d.view_by, d.subject_key, d.entity_id, d.credits)
        for d in db.scalars(select(UsageDelta).order_by(UsageDelta.id))
    ]
