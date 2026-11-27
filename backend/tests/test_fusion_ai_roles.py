"""The Fusion and LLM roles as the default AI roles, and roles back on more credits.

* The default list is create-fusion-scan, manage-fusion, update-llm-scan-mode
  and manage-llm-configuration; a list an admin chose is kept, and a stored
  copy of the old (Risk Management) default moves to the new one.
* ``ai-triage-assist`` is refused on save and never removed by any path.
* A restricted user given more credits - a raised budget, or an approved credit
  request - gets back exactly the roles the restriction removed, under the
  list it recorded (also when the setting changed meanwhile, and for one
  recorded before the list was a setting), and it is audited.

Synthetic tenant data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.checkmarx import iam
from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES, LEGACY_AI_ROLE_NAMES
from app.db.migrate import alembic_config
from app.models import AuditLogEntry, CreditLimit, EnforcementAction, LimitPeriodState
from app.models.enums import EnforcementStatus, EntityType, LimitStatus, PeriodType
from app.services import (
    enforcement,
    evaluation,
    ingestion,
    limits_service,
    org_sync,
    requests_service,
    settings_store,
)
from app.services.audit import AuditActor
from tests.conftest import TEST_DATABASE_URL, USING_SQLITE
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
FUSION_ROLES = (
    "create-fusion-scan",
    "manage-fusion",
    "update-llm-scan-mode",
    "manage-llm-configuration",
)


@pytest.fixture(autouse=True)
def _readings_in_august(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingestion, "utcnow", lambda: datetime(2026, 8, 11, 11, 0, tzinfo=UTC))


def restricted_alice(db: Session, *, ai_roles: list[str] | None = None):
    """Alice over a 5-credit user budget and restricted, with the AI role
    list the restriction is made under (the default unless given)."""
    tenant = populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    if ai_roles is not None:
        settings_store.set_value(db, settings_store.KEY_AI_ROLES, ai_roles)
    db.commit()
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-alice",
        entity_label="Alice Archer",
        credit_limit=5,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    before = sorted(tenant.role_mappings["user-alice"])
    tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=20)
    ingestion.ingest_usage(db, client)
    db.commit()
    assert evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR).enforced == 1
    db.commit()
    return tenant, client, limit, before


def alice_action(db: Session) -> EnforcementAction:
    db.expire_all()
    return db.scalars(
        select(EnforcementAction).where(EnforcementAction.target_id == "user-alice")
    ).one()


def assert_lifted(db: Session, tenant: FakeTenant, limit: CreditLimit, before: list[str]) -> None:
    mapped = tenant.role_mappings["user-alice"]
    assert sorted(mapped) == before  # exactly what she had
    assert len(mapped) == len(set(mapped))  # nothing twice
    action = alice_action(db)
    assert action.status == EnforcementStatus.REVERSED
    assert action.reversal_reason == "credit_increased"
    state = db.scalars(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id)).one()
    assert state.status == LimitStatus.RESTORED
    audited = db.scalars(
        select(AuditLogEntry).where(
            AuditLogEntry.action == "enforcement.reversed",
            AuditLogEntry.target_id == "user-alice",
        )
    ).all()
    assert len(audited) == 1
    assert "the limit was raised or usage is within budget again" in (audited[0].detail or "")


def raise_budget(db: Session, client, limit: CreditLimit, credits: int = 50) -> None:
    limits_service.update_limit(
        db, limit=limit, changes={"credit_limit": credits}, actor=ACTOR, client=client
    )
    db.commit()


# ------------------------------------------------------------- the default


def test_the_default_is_the_fusion_and_llm_roles(db: Session) -> None:
    assert DEFAULT_AI_ROLE_NAMES == FUSION_ROLES
    assert settings_store.ai_role_names(db) == FUSION_ROLES
    # Composites that would over-restrict are not on it, nor the AI Triage system role.
    assert not {"scan-fusion", "fusion-manager", "ai-triage-assist"} & set(FUSION_ROLES)
    # manage-fusion and manage-llm-configuration match manage-* but are not admin roles.
    assert not any(settings_store.admin_like_role(name) for name in FUSION_ROLES)
    assert settings_store.admin_like_role("manage-users")
    assert all(iam.ROLE_DESCRIPTIONS.get(name) for name in FUSION_ROLES)


def test_a_restriction_removes_the_fusion_roles_only(db: Session) -> None:
    tenant, _client, _limit, before = restricted_alice(db)
    action = alice_action(db)
    assert action.undo_snapshot["ai_roles"] == list(FUSION_ROLES)
    assert {r["name"] for r in action.undo_snapshot["removed_roles"]} == set(FUSION_ROLES)
    left = set(tenant.role_mappings["user-alice"])
    assert left == set(before) - set(FUSION_ROLES)
    assert set(LEGACY_AI_ROLE_NAMES) <= left  # the Risk Management pages stay


def test_a_list_an_admin_chose_is_kept(db: Session) -> None:
    settings_store.set_value(db, settings_store.KEY_AI_ROLES, ["view-risk-management-tab"])
    db.commit()
    assert settings_store.ai_role_names(db) == ("view-risk-management-tab",)


# ------------------------------------------------------ ai-triage-assist


def test_ai_triage_assist_is_refused_on_save(admin_client: TestClient) -> None:
    refused = admin_client.put(
        "/api/settings", json={"ai_roles": ["create-fusion-scan", "ai-triage-assist"]}
    )
    assert refused.status_code == 400, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == "forbidden_ai_roles"
    assert "breaks Auto Triage" in detail["message"]
    assert detail["roles"] == ["ai-triage-assist"]
    assert admin_client.get("/api/settings").json()["ai_roles"] == list(FUSION_ROLES)


def test_ai_triage_assist_is_never_removed_whatever_is_stored(db: Session) -> None:
    # Stored some other way (an old backup, a script): left out of the list...
    settings_store.set_value(
        db, settings_store.KEY_AI_ROLES, ["ai-triage-assist", "create-fusion-scan"]
    )
    db.commit()
    assert settings_store.ai_role_names(db) == ("create-fusion-scan",)
    settings_store.set_value(db, settings_store.KEY_AI_ROLES, ["AI-Triage-Assist"])
    db.commit()
    assert settings_store.ai_role_names(db) == FUSION_ROLES
    # ...out of a recorded restriction...
    assert enforcement.snapshot_ai_roles({"ai_roles": ["ai-triage-assist", "x"]}) == {"x"}
    # ...and never sent to the tenant, whoever asks.
    tenant = FakeTenant()
    tenant.add_client_role("ai-triage-assist")
    tenant.add_user(
        user_id="bot", username="bot@example.com", roles=["ai-triage-assist", "manage-fusion"]
    )
    client = tenant.client()
    iam.remove_user_client_roles(
        client,
        user_id="bot",
        client_uuid="any",
        roles=[iam.RoleRef(id="role-ai-triage-assist", name="ai-triage-assist")],
    )
    assert not [m for m, path in tenant.requests if m == "DELETE"]
    assert "ai-triage-assist" in tenant.role_mappings["bot"]


def test_a_restriction_leaves_ai_triage_assist_alone(db: Session) -> None:
    tenant = populated_tenant()
    tenant.add_client_role("ai-triage-assist")
    tenant.role_mappings["user-alice"].append("ai-triage-assist")
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    settings_store.set_value(
        db, settings_store.KEY_AI_ROLES, ["create-fusion-scan", "ai-triage-assist"]
    )
    db.add(
        CreditLimit(
            entity_type=EntityType.USER,
            entity_id="user-alice",
            entity_label="Alice Archer",
            credit_limit=1,
            period_type=PeriodType.MONTHLY,
            enforce=True,
        )
    )
    db.commit()
    limit = db.scalars(select(CreditLimit)).one()
    enforcement.apply_enforcement(db, client, limit=limit, period_key="2026-08", actor=ACTOR)
    db.commit()
    action = alice_action(db)
    assert [r["name"] for r in action.undo_snapshot["removed_roles"]] == ["create-fusion-scan"]
    assert "ai-triage-assist" in tenant.role_mappings["user-alice"]


# ------------------------------------------- roles back on more credits


def test_raising_the_budget_gives_the_fusion_roles_back(db: Session) -> None:
    tenant, client, limit, before = restricted_alice(db)
    assert not set(FUSION_ROLES) & set(tenant.role_mappings["user-alice"])
    raise_budget(db, client, limit)
    assert_lifted(db, tenant, limit, before)


def test_approving_a_credit_request_gives_the_roles_back(db: Session) -> None:
    tenant, client, limit, before = restricted_alice(db)
    request = requests_service.create_request(
        db,
        data=requests_service.RequestInput(
            entity_type=EntityType.USER, entity_id="user-alice", requested_limit=40
        ),
        actor=ACTOR,
    )
    db.commit()
    requests_service.approve_request(db, request=request, actor=ACTOR, client=client)
    db.commit()
    assert_lifted(db, tenant, limit, before)


def test_a_raise_still_short_of_usage_gives_nothing_back(db: Session) -> None:
    tenant, client, limit, _before = restricted_alice(db)
    raise_budget(db, client, limit, credits=10)  # usage is 20
    assert alice_action(db).status == EnforcementStatus.APPLIED
    assert not set(FUSION_ROLES) & set(tenant.role_mappings["user-alice"])


def test_the_roles_recorded_come_back_after_the_setting_changed(db: Session) -> None:
    """Restricted under the old (Risk Management) list; the setting is the new
    default by the time more credits arrive: the old roles come back, and the
    Fusion roles - never taken - are left alone."""
    tenant, client, limit, before = restricted_alice(db, ai_roles=list(LEGACY_AI_ROLE_NAMES))
    action = alice_action(db)
    assert action.undo_snapshot["ai_roles"] == list(LEGACY_AI_ROLE_NAMES)
    assert not set(LEGACY_AI_ROLE_NAMES) & set(tenant.role_mappings["user-alice"])
    assert set(FUSION_ROLES) <= set(tenant.role_mappings["user-alice"])

    settings_store.set_value(db, settings_store.KEY_AI_ROLES, list(FUSION_ROLES))
    db.commit()
    # A cycle meanwhile neither hands the old roles back nor takes the new ones.
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert not set(LEGACY_AI_ROLE_NAMES) & set(tenant.role_mappings["user-alice"])
    assert set(FUSION_ROLES) <= set(tenant.role_mappings["user-alice"])

    raise_budget(db, client, limit)
    assert_lifted(db, tenant, limit, before)


def test_a_restriction_recorded_before_the_list_was_a_setting(db: Session) -> None:
    """No ``ai_roles`` on the snapshot means the Risk Management default of the
    time, never today's: the cycle's "return what a restriction should not have
    taken" pass must not hand those roles back while it is in force."""
    tenant, client, limit, before = restricted_alice(db, ai_roles=list(LEGACY_AI_ROLE_NAMES))
    action = alice_action(db)
    snapshot = dict(action.undo_snapshot)
    del snapshot["ai_roles"]
    action.undo_snapshot = snapshot
    settings_store.set_value(db, settings_store.KEY_AI_ROLES, list(FUSION_ROLES))
    db.commit()

    returned = enforcement.return_roles_outside_the_restriction(db, client, actor=ACTOR)
    db.commit()
    assert returned == 0
    assert not set(LEGACY_AI_ROLE_NAMES) & set(tenant.role_mappings["user-alice"])
    assert alice_action(db).status == EnforcementStatus.APPLIED
    assert enforcement.snapshot_ai_roles(snapshot) == set(LEGACY_AI_ROLE_NAMES)

    raise_budget(db, client, limit)
    assert_lifted(db, tenant, limit, before)


def test_a_role_an_admin_mapped_back_by_hand_is_not_doubled(db: Session) -> None:
    tenant, client, limit, before = restricted_alice(db)
    tenant.role_mappings["user-alice"].append("create-fusion-scan")  # by hand, in Checkmarx One
    raise_budget(db, client, limit)
    assert alice_action(db).error is None
    assert_lifted(db, tenant, limit, before)


def test_the_next_cycle_finishes_it_when_checkmarx_was_unreachable(db: Session) -> None:
    tenant, client, limit, before = restricted_alice(db)
    tenant.fail_requests[("POST", "/role-mappings/clients/")] = 503
    raise_budget(db, client, limit)
    assert alice_action(db).status == EnforcementStatus.APPLIED
    del tenant.fail_requests[("POST", "/role-mappings/clients/")]
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    mapped = tenant.role_mappings["user-alice"]
    assert sorted(mapped) == before
    assert alice_action(db).status == EnforcementStatus.REVERSED


# ------------------------------------------------- existing installs


def _migration_url(tmp_path: Path) -> str:
    if USING_SQLITE:
        return f"sqlite:///{(tmp_path / 'ai-roles.db').as_posix()}"
    engine = create_engine(TEST_DATABASE_URL)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    return TEST_DATABASE_URL


def _stored(engine, value: list[str] | None) -> None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM app_setting WHERE key = 'enforcement.ai_roles'"))
        if value is not None:
            connection.execute(
                text(
                    "INSERT INTO app_setting (key, value, is_secret, created_at, updated_at) "
                    "VALUES ('enforcement.ai_roles', :value, false, :now, :now)"
                ),
                {"value": json.dumps(value), "now": datetime(2026, 11, 1, tzinfo=UTC)},
            )


def _read(engine) -> list[str] | None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        value = connection.execute(
            text("SELECT value FROM app_setting WHERE key = 'enforcement.ai_roles'")
        ).scalar()
    return None if value is None else json.loads(value)


@pytest.mark.parametrize(
    ("stored", "after"),
    [
        (list(LEGACY_AI_ROLE_NAMES), list(FUSION_ROLES)),  # the old default, stored
        (None, None),  # never stored: the code's default applies
        (["view-risk-management-tab", "view-risk-management"], None),  # a choice: kept
        (["view-risk-management"], None),
        ([*LEGACY_AI_ROLE_NAMES, "create-fusion-scan"], None),
    ],
)
def test_the_migration_moves_only_the_old_default(
    tmp_path: Path, stored: list[str] | None, after: list[str] | None
) -> None:
    url = _migration_url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, "b3e8d1f6a9c4")
    engine = create_engine(url)
    _stored(engine, stored)
    command.upgrade(config, "c9f2a6e1d4b7")
    assert _read(engine) == (after if after is not None else stored)
    command.downgrade(config, "b3e8d1f6a9c4")
    assert _read(engine) == stored
    command.upgrade(config, "head")
    assert _read(engine) == (after if after is not None else stored)
    engine.dispose()
