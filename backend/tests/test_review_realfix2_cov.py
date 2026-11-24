"""Second review of realfix (guards): coverage parents by path, single flight."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
from app.services import coverage, org_sync
from tests.fake_tenant import FakeTenant


def _tenant() -> FakeTenant:
    tenant = FakeTenant()
    tenant.add_group(
        group_id="g-eng", name="Engineering", path="/Engineering", roles=list(DEFAULT_AI_ROLE_NAMES)
    )
    tenant.add_group(group_id="g-team", name="Team A", path="/Engineering/Team A", roles=[])
    tenant.add_user(
        user_id="dev",
        username="dev@example.com",
        roles=list(DEFAULT_AI_ROLE_NAMES),
        groups=["Team A"],
    )
    tenant.join_group("dev", "g-team")
    return tenant


def test_parent_group_by_path_keeps_access(db: Session) -> None:
    tenant = _tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    report = coverage.compute(db, tenant.client())
    assert report.restrictable == 0 and report.unknown == 0, report.as_dict()


def test_single_flight_returns_cached_and_never_blocks(db: Session) -> None:
    tenant = _tenant()
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    assert coverage._computing.acquire(blocking=False)
    try:
        got = coverage.current(db, tenant.client(), refresh=True)
    finally:
        coverage._computing.release()
    assert got is None  # nothing cached yet: the page gets nothing, not a wait
    got = coverage.current(db, tenant.client(), refresh=True)
    assert got is not None
