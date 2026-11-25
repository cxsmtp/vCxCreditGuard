"""Re-review probes for 0c03021 (synthetic data, fake tenant)."""

from __future__ import annotations

from decimal import Decimal

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.enums import EnforcementStatus, EntityType, LimitStatus
from app.services import audit_chain, demo_service, demo_tenant, enforcement, settings_store
from app.services import connection as connection_service
from app.services.audit import AuditActor
from app.services.periods import current_window
from tests.conftest import make_api_key
from tests.test_enforcement_selftest import AI, run, run_actions, setup_tenant

ACTOR = AuditActor.system("review2")


def _breached_user_limit(db: Session, user_id: str) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id=user_id,
        entity_label=user_id,
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
    return limit


def _held_with_real_sibling(db: Session):
    tenant, client = setup_tenant(db)
    tenant.fail_requests[("POST", "/role-mappings/clients/")] = 400
    row = run(db, client, user="user-alice")
    assert row.status == "restore_failed"
    [held] = run_actions(db, row)
    limit = _breached_user_limit(db, "user-alice")
    window = current_window(limit, utcnow())
    enforcement.apply_enforcement(db, client, limit=limit, period_key=window.key, actor=ACTOR)
    db.commit()
    real = db.scalar(select(EnforcementAction).where(EnforcementAction.limit_id == limit.id))
    assert real.status == EnforcementStatus.APPLIED
    tenant.fail_requests.clear()
    return tenant, client, held, real


def test_admin_restore_of_the_real_action_still_releases_everything(db: Session) -> None:
    """The enforcement.py edit must not change a real admin Restore."""
    tenant, client, held, real = _held_with_real_sibling(db)
    enforcement.restore_action(
        db,
        client,
        action=db.get(EnforcementAction, real.id),
        actor=ACTOR,
        reason=enforcement.ADMIN_REASON,
    )
    db.commit()
    db.expire_all()
    assert db.get(EnforcementAction, real.id).status == EnforcementStatus.REVERSED
    assert db.get(EnforcementAction, real.id).reversal_reason == enforcement.ADMIN_REASON
    assert db.get(EnforcementAction, held.id).status == EnforcementStatus.REVERSED
    assert set(tenant.role_mappings["user-alice"]) >= AI
    assert audit_chain.verify_chain(db).ok


def test_route_restore_of_a_selftest_hold_with_a_real_sibling(
    admin_client, db: Session, monkeypatch
) -> None:
    tenant, _client, held, real = _held_with_real_sibling(db)
    monkeypatch.setattr(connection_service, "get_client", lambda _s: tenant.client())
    response = admin_client.post(f"/api/notifications/enforcements/{held.id}/restore")
    assert response.status_code == 200, response.text
    db.expire_all()
    assert db.get(EnforcementAction, real.id).status == EnforcementStatus.APPLIED
    assert not AI & set(tenant.role_mappings["user-alice"])
    # Should-fix probe: the admin is told access was restored, which it was not.
    body = response.json()
    assert "restored" not in body["message"].lower() or body["restored"] is False, body


def test_full_live_cycle_never_sends_a_demo_hold_to_the_live_tenant(
    db: Session, monkeypatch
) -> None:
    from app.services import cycle

    live, _ = setup_tenant(db)
    connection_service.save_connection(db, api_key=make_api_key(), actor=ACTOR)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _s: live.client())
    demo_tenant.tenant().reset()
    demo_service.seed(db)
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
    db.commit()
    real_iam = demo_tenant.DemoTenant._iam

    def failing_posts(self, method, path, body):  # type: ignore[no-untyped-def]
        if method == "POST" and "role-mappings" in path:
            return httpx.Response(500, json={"message": "down"})
        return real_iam(self, method, path, body)

    monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", failing_posts)
    row = run(db, demo_tenant.client(), user="demo-user-ada", demo=True)
    assert row.status == "restore_failed"
    [held] = run_actions(db, row)
    monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", real_iam)

    # Live mode, the demo hold still there (demo flag off without clearing).
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, False)
    from sqlalchemy import delete as sa_delete

    db.execute(sa_delete(CreditLimit).where(CreditLimit.entity_id.like("demo-%")))
    db.commit()
    since = len(live.requests)
    cycle.run_cycle(trigger="manual")
    # Seeded demo entities left in the DB in live mode draw some GETs from the
    # ordinary live cycle (same with no hold: see the control); no write may.
    leaked = [(m, p) for m, p in live.requests[since:] if "demo-" in p and m != "GET"]
    assert not leaked, leaked
    db.expire_all()
    assert not enforcement.may_be_in_force(db.get(EnforcementAction, held.id))
    assert "create-fusion-scan" in demo_tenant.tenant().state["users"]["demo-user-ada"]
    demo_tenant.tenant().reset()


def test_control_same_without_the_hold(db: Session, monkeypatch) -> None:
    from app.services import cycle

    live, _ = setup_tenant(db)
    connection_service.save_connection(db, api_key=make_api_key(), actor=ACTOR)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _s: live.client())
    demo_tenant.tenant().reset()
    demo_service.seed(db)
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, True)
    db.commit()
    real_iam = demo_tenant.DemoTenant._iam

    def failing_posts(self, method, path, body):  # type: ignore[no-untyped-def]
        if method == "POST" and "role-mappings" in path:
            return httpx.Response(500, json={"message": "down"})
        return real_iam(self, method, path, body)

    monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", failing_posts)
    row = run(db, demo_tenant.client(), user="demo-user-ada", demo=True)
    assert row.status == "restore_failed"
    [held] = run_actions(db, row)
    monkeypatch.setattr(demo_tenant.DemoTenant, "_iam", real_iam)

    # Live mode, the demo hold still there (demo flag off without clearing).
    settings_store.set_value(db, settings_store.KEY_DEMO_MODE, False)
    from sqlalchemy import delete as sa_delete

    db.execute(sa_delete(CreditLimit).where(CreditLimit.entity_id.like("demo-%")))
    db.commit()
    db.execute(sa_delete(EnforcementAction).where(EnforcementAction.id == held.id))
    db.commit()
    since = len(live.requests)
    cycle.run_cycle(trigger="manual")
    # Seeded demo entities left in the DB in live mode draw some GETs from the
    # ordinary live cycle (same with no hold: see the control); no write may.
    leaked = [(m, p) for m, p in live.requests[since:] if "demo-" in p and m != "GET"]
    assert not leaked, leaked
    demo_tenant.tenant().reset()


def test_auto_triage_inherited_scope_is_not_written(db: Session) -> None:
    """Should-fix probe: an AI-agent configuration read with a non-project scope
    is restricted anyway; a pin is only detected afterwards."""
    tenant, client = setup_tenant(db)
    original = tenant._auto_triage_response
    state = {"pinned": False}

    def scoped(request: httpx.Request, path: str):  # type: ignore[no-untyped-def]
        response = original(request, path)
        if request.method == "PUT":
            state["pinned"] = True
            return response
        payload = response.json()
        payload["scope"] = "project" if state["pinned"] else "tenant"
        return httpx.Response(200, json=payload)

    tenant._auto_triage_response = scoped  # type: ignore[method-assign]
    row = run(db, client, project="proj-web", actions=["auto_triage"])
    assert not state["pinned"], (row.status, row.summary)
