"""Third review of realfix: Auto Triage attribution reads every row of a project in full, so
a name mapped to the project brings its whole Auto Triage history in as an
"increase" that is charged to whoever scanned (forward-only does not apply).

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from decimal import Decimal

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.enums import PeriodType
from tests.fake_tenant import FakeTenant
from tests.test_auto_triage_attribution import (  # noqa: F401
    ALICE,
    charges,
    parts,
    period_state,
    run,
    scan,
    tenant,
    turn_on,
    user_limit,
)


def test_mapping_a_name_charges_no_history_to_the_scanner(
    db: Session,
    tenant: FakeTenant,  # noqa: F811
    admin_client: TestClient,
) -> None:
    turn_on(db)
    tenant.set_entity_credits(
        view="project",
        name="old-name/payments-api",
        credits=300,
        actions={"auto_triage": 300},
    )
    run(force=True)
    limit = user_limit(db, "user-alice", 1000, period=PeriodType.MONTHLY)
    run()
    assert period_state(db, limit).credits_used == 0
    scan(tenant, "scan-h1", ALICE)  # Alice scans; nothing new is reported
    r = admin_client.post(
        "/api/usage/unmatched-entities/map",
        json={"view": "project", "subject_key": "old-name/payments-api", "entity_id": "proj-api"},
    )
    assert r.status_code == 200, r.text
    run()
    # The mapped name reported nothing new, so nobody may be charged for it.
    assert parts(db, "user-alice") == {}, (
        [(c.credits, c.basis) for c in charges(db)],
        period_state(db, limit).credits_used,
    )
    assert period_state(db, limit).credits_used == Decimal("0")
