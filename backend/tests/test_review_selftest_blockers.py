"""Adversarial review of the enforcement self-test (synthetic data, fake tenant)."""

from __future__ import annotations

import contextlib
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.enums import EnforcementStatus, EntityType, LimitStatus
from app.services import audit_chain, enforcement, evaluation
from app.services import enforcement_selftest as selftest
from app.services.audit import AuditActor
from app.services.periods import current_window
from tests.fake_tenant import populated_tenant
from tests.test_enforcement_selftest import AI, run, run_actions, setup_tenant

ACTOR = AuditActor.system("review")


def _origin(tenant, project_id: str) -> tuple[str, bool]:
    entry = tenant.fusion_setting(project_id)
    return entry["originLevel"], entry["isPersisted"]


# (a) The self-test leaves an inherited Fusion setting pinned on the project.


def test_inherited_fusion_on_is_left_inherited(db: Session) -> None:
    tenant, client = setup_tenant(db)
    tenant.set_fusion_setting("proj-web", value="true", origin="Tenant")
    before = _origin(tenant, "proj-web")

    row = run(db, client, project="proj-web", actions=["fusion"])

    # Expected: the project still follows the tenant (exact undo), or the
    # self-test refuses / fails loudly. Observed: pinned at project level,
    # reported only as a warning.
    assert _origin(tenant, "proj-web") == before, (row.status, _origin(tenant, "proj-web"))


def test_inherited_fusion_off_is_not_pinned_by_the_lock(db: Session) -> None:
    """Fusion inherited OFF: nothing to turn off, but the (default-on) lock
    makes the restriction write, and the restore pins 'false' on the project,
    so a later tenant-wide change no longer reaches it."""
    tenant, client = setup_tenant(db)
    tenant.set_fusion_setting("proj-web", value="false", origin="Tenant")
    before = _origin(tenant, "proj-web")

    row = run(db, client, project="proj-web", actions=["fusion"])

    assert _origin(tenant, "proj-web") == before, (row.status, _origin(tenant, "proj-web"))


# (b) Restore on the self-test's own alert lifts a REAL restriction.


def test_restore_on_a_held_selftest_action_keeps_a_real_restriction(db: Session) -> None:
    tenant, client = setup_tenant(db)
    tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
    row = run(db, client, user="user-alice")
    assert row.status == "restore_failed"
    [held] = run_actions(db, row)
    assert enforcement.may_be_in_force(held)

    # A real budget on Alice breaches meanwhile and restricts her.
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-alice",
        entity_label="Alice",
        credit_limit=10,
        period_type="monthly",
        enforce=True,
    )
    db.add(limit)
    db.commit()
    window = current_window(limit, utcnow())
    db.add(
        LimitPeriodState(
            limit_id=limit.id,
            period_key=window.key,
            period_start=window.start,
            period_end=window.end,
            credits_used=Decimal(50),
            usage_available=True,
            status=LimitStatus.BREACHED,
        )
    )
    db.commit()
    enforcement.apply_enforcement(db, client, limit=limit, period_key=window.key, actor=ACTOR)
    db.commit()
    real = db.scalar(select(EnforcementAction).where(EnforcementAction.limit_id == limit.id))
    assert real.status == EnforcementStatus.APPLIED

    # The admin follows the self-test alert ("Restore here does it now"):
    # the Notification Center route calls restore_action(reason=ADMIN_REASON).
    tenant.fail_requests.clear()
    held = db.get(EnforcementAction, held.id)
    enforcement.restore_action(
        db, client, action=held, actor=ACTOR, reason=enforcement.ADMIN_REASON
    )
    db.commit()
    db.expire_all()
    real = db.get(EnforcementAction, real.id)

    # Expected: undoing the self-test leaves the real budget's restriction alone.
    # Observed: the real restriction is lifted as an admin restore, so the
    # breached budget does not restrict Alice again for the rest of the period.
    assert real.status == EnforcementStatus.APPLIED, (real.status, real.reversal_reason)
    assert not AI & set(tenant.role_mappings["user-alice"])


# Control: the cycle's own sweep handles the same overlap correctly.


def test_sweep_of_a_held_selftest_action_keeps_a_real_restriction(db: Session) -> None:
    tenant = populated_tenant()
    tenant, client = setup_tenant(db, tenant)
    tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
    row = run(db, client, user="user-alice")
    [held] = run_actions(db, row)
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-alice",
        entity_label="Alice",
        credit_limit=10,
        period_type="monthly",
        enforce=True,
    )
    db.add(limit)
    db.commit()
    window = current_window(limit, utcnow())
    enforcement.apply_enforcement(db, client, limit=limit, period_key=window.key, actor=ACTOR)
    db.commit()
    tenant.fail_requests.clear()
    result = evaluation.EvaluationResult() if hasattr(evaluation, "EvaluationResult") else None
    evaluation._lift_unjustified_restrictions(db, client, actor=ACTOR, result=result)
    db.commit()
    db.expire_all()
    assert db.get(EnforcementAction, held.id).status == EnforcementStatus.REVERSED
    real = db.scalar(select(EnforcementAction).where(EnforcementAction.limit_id == limit.id))
    assert real.status == EnforcementStatus.APPLIED
    assert not AI & set(tenant.role_mappings["user-alice"])
    assert audit_chain.verify_chain(db).ok


# Audit chain after a refusal, a failure and a pass.


def test_audit_chain_verifies_after_refusal_failure_and_pass(db: Session) -> None:
    tenant, client = setup_tenant(db)
    with contextlib.suppress(selftest.SelfTestRefused):
        run(db, client, user="user-alice", confirm={"user": "Alice Archer"}, project="nope")
    tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
    run(db, client, user="user-alice")
    tenant.fail_requests.clear()
    run(db, client, user="user-bob")
    run(db, client, project="proj-api")
    assert audit_chain.verify_chain(db).ok


# Should-fix probe: long names overflow String(512) columns on PostgreSQL.


def test_long_names_do_not_break_the_run(db: Session) -> None:
    from app.models.org import CxProject

    tenant, client = setup_tenant(db)
    project = db.get(CxProject, "proj-api")
    project.name = "p" * 505
    db.commit()
    row = run(db, client, user="user-alice", project="proj-api", actions=["auto_triage"])
    assert row.status in ("passed", "warning"), (row.status, row.summary)
    assert tenant.auto_triage["proj-api"]["enabled"] is True


# TOCTOU: a real budget breaches between the first check and the target lock.


def test_breach_between_check_and_lock_is_caught_under_the_lock(db: Session, monkeypatch) -> None:
    from tests.test_enforcement_selftest import writes

    tenant, client = setup_tenant(db)
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-alice",
        entity_label="Alice",
        credit_limit=10,
        period_type="monthly",
        enforce=True,
    )
    db.add(limit)
    db.commit()
    real_check = selftest._check_confirmation

    def breach_then_confirm(targets, confirm):
        real_check(targets, confirm)
        window = current_window(limit, utcnow())
        db.add(
            LimitPeriodState(
                limit_id=limit.id,
                period_key=window.key,
                period_start=window.start,
                period_end=window.end,
                credits_used=Decimal(50),
                usage_available=True,
                status=LimitStatus.BREACHED,
            )
        )
        db.flush()

    monkeypatch.setattr(selftest, "_check_confirmation", breach_then_confirm)
    since = len(tenant.requests)
    row = run(db, client, user="user-alice")
    assert row.status == "failed"
    assert not writes(tenant, since)
    assert run_actions(db, row) == []
    assert audit_chain.verify_chain(db).ok


# Shared root cause: real enforcement + restore pins an inherited Fusion too.


@pytest.mark.xfail(
    strict=True,
    reason=(
        "README unknown #6: restore pins an inherited Fusion value; fix pending the "
        "tenant's reset-to-inherited API"
    ),
)
def test_real_enforcement_restore_also_pins_inherited_fusion(db: Session) -> None:
    tenant, client = setup_tenant(db)
    tenant.set_fusion_setting("proj-web", value="true", origin="Tenant")
    before = _origin(tenant, "proj-web")
    limit = CreditLimit(
        entity_type=EntityType.PROJECT,
        entity_id="proj-web",
        entity_label="web",
        credit_limit=10,
        period_type="monthly",
        enforce=True,
        project_actions=["fusion"],
    )
    db.add(limit)
    db.commit()
    enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-11", actor=ACTOR)
    db.commit()
    enforcement.restore_for_limit(
        db, client, limit_id=limit.id, actor=ACTOR, reason=enforcement.ADMIN_REASON
    )
    db.commit()
    assert _origin(tenant, "proj-web") == before


# Should-fix probe: a held DEMO self-test action restored from the Notification
# Center is sent to the LIVE tenant client (demo ids, so it 404s there).


def test_demo_hold_restore_goes_to_the_live_tenant(admin_client, db: Session, monkeypatch) -> None:
    import httpx

    from app.services import connection as connection_service
    from app.services import demo_service, demo_tenant, settings_store

    live, _ = setup_tenant(db)
    monkeypatch.setattr(connection_service, "get_client", lambda _s: live.client())
    demo_tenant.tenant().reset()
    demo_service.seed(db)
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
    db.commit()
    real_iam = demo_tenant.DemoTenant._iam

    def failing_posts(self, method, path, body):
        if method == "POST" and "role-mappings" in path:
            return httpx.Response(500, json={"message": "down"})
        return real_iam(self, method, path, body)

    monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", failing_posts)
    row = run(db, demo_tenant.client(), user="demo-user-ada", demo=True)
    assert row.status == "restore_failed"
    [held] = run_actions(db, row)
    since = len(live.requests)
    admin_client.post(f"/api/notifications/enforcements/{held.id}/restore")
    demo_tenant.tenant().reset()
    live_calls = [p for _m, p in live.requests[since:] if "demo-user" in p]
    assert not live_calls, live_calls
