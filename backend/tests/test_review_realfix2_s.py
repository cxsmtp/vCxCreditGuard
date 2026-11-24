"""Second review of realfix (guards): Auto Triage undo, PR severities shapes."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.checkmarx import platform
from app.models import EnforcementAction
from app.models.enums import EnforcementKind, EnforcementStatus
from app.services import enforcement
from app.services.audit import AuditActor
from tests.test_real_tenant_shapes import PERIOD, action_of, project_limit, setup_tenant

ACTOR = AuditActor.system("test")


def test_undo_after_side_effects_outcome_unknown(db: Session) -> None:
    tenant, client = setup_tenant(db)

    def flip(request) -> None:  # type: ignore[no-untyped-def]
        if request.method == "PUT" and "/ai-agents-coordinator/" in str(request.url):
            tenant.allow_ai_usage["proj-api"] = False

    tenant.on_request = flip
    tenant.auto_triage["proj-api"] = {"enabled": True, "config": {"branches": ["main"]}}
    limit = project_limit(db, actions=["auto_triage"])
    enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()
    action = action_of(db, EnforcementKind.DISABLE_AUTO_TRIAGE)
    assert action.status == EnforcementStatus.APPLIED
    assert action.undo_snapshot[enforcement.OUTCOME_UNKNOWN] is True
    tenant.on_request = None
    # A second cycle (verification / re-assert) must not lose enabled_before.
    tenant.auto_triage["proj-api"]["enabled"] = True
    enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()
    db.expire_all()
    action = action_of(db, EnforcementKind.DISABLE_AUTO_TRIAGE)
    assert action.undo_snapshot.get("enabled_before") is True, action.undo_snapshot
    assert tenant.auto_triage["proj-api"]["enabled"] is False
    puts_before = len(tenant.auto_triage_puts)
    assert enforcement.restore_action(db, client, action=action, actor=ACTOR)
    db.commit()
    assert tenant.auto_triage["proj-api"]["enabled"] is True
    body = tenant.auto_triage_puts[-1][1]
    assert len(tenant.auto_triage_puts) == puts_before + 1
    assert set(body) == {"configurations"}, body
    db.expire_all()
    assert db.get(EnforcementAction, action.id).status == EnforcementStatus.REVERSED


def test_pr_null_value_and_not_editable(db: Session) -> None:
    import pytest

    with pytest.raises(platform.PrSeveritiesShapeError):
        platform.parse_pr_severities({"value": None, "isEditable": True})
    ro = platform.parse_pr_severities({"value": ["CRITICAL"], "isEditable": False})
    assert ro.editable is False
    rw = platform.parse_pr_severities({"value": ["CRITICAL"]})
    assert rw.editable is True
    # A bare list has no isEditable: editable.
    assert platform.parse_pr_severities(["HIGH"]).editable is True


def test_pr_not_editable_means_no_write_on_apply(db: Session) -> None:
    tenant, client = setup_tenant(db)
    tenant.repo_severities_shape = "wrapped"
    tenant.repo_severities_editable = False
    limit = project_limit(db, actions=["pr_remediation"])
    writes_before = list(getattr(tenant, "requests", []))
    enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()
    puts = [
        r
        for r in tenant.requests[len(writes_before) :]
        if r[0] in ("PUT", "PATCH", "POST") and "repos-manager" in r[1]
    ]
    assert not puts, puts
