"""Tests for automatic access restoration when credit limit is increased for an entity."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.models import CreditLimit, EnforcementAction, LimitPeriodState
from app.models.enums import EnforcementStatus, EntityType, LimitStatus, PeriodType
from app.services import evaluation, ingestion, limits_service, org_sync
from app.services.audit import AuditActor
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)


def prepare(db: Session, tenant: FakeTenant | None = None):
    tenant = tenant or populated_tenant()
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    return tenant, client


def add_limit(
    db: Session,
    *,
    entity_type: EntityType,
    entity_id: str,
    credit_limit: int,
    enforce: bool = True,
    period_type: str = PeriodType.MONTHLY,
    label: str | None = None,
) -> CreditLimit:
    limit = CreditLimit(
        entity_type=entity_type,
        entity_id=entity_id,
        entity_label=label or entity_id,
        credit_limit=credit_limit,
        period_type=period_type,
        enforce=enforce,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    return limit


def test_user_credit_increase_restores_roles(db: Session) -> None:
    """When a restricted user's credit limit is increased, the next run restores their AI roles."""
    tenant, client = prepare(db)
    limit = add_limit(
        db,
        entity_type=EntityType.USER,
        entity_id="user-harsh",
        credit_limit=5,
        enforce=True,
        label="Harsh Gokani",
    )
    # Establish baseline (0 used)
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()

    # User consumes 20 credits (breaches 5 limit)
    tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=20)
    ingestion.ingest_usage(db, client)
    db.commit()

    # 1. First run: breach limit and restrict access
    result1 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert result1.enforced == 1

    state1 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state1.status == LimitStatus.RESTRICTED
    assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    # 2. Increase credit limit for user to 50 (usage 20 < 50)
    limit.credit_limit = 50
    db.commit()

    # 3. Next run: evaluate_all should detect usage < limit and restore roles
    result2 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert result2.restored == 1

    state2 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state2.status == LimitStatus.RESTORED
    assert state2.restored_at is not None

    # Roles restored back on user
    assert any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    actions = list(
        db.scalars(
            select(EnforcementAction).where(
                EnforcementAction.limit_id == limit.id, EnforcementAction.period_key == "2026-08"
            )
        )
    )
    assert len(actions) > 0
    for act in actions:
        assert act.status == EnforcementStatus.REVERSED
        assert act.reversal_reason == "credit_increased"


def test_project_credit_increase_restores_access(db: Session) -> None:
    """When a restricted project's credit limit is increased, the next run
    restores project configuration."""
    tenant, client = prepare(db)
    limit = add_limit(
        db,
        entity_type=EntityType.PROJECT,
        entity_id="proj-web",
        credit_limit=5,
        enforce=True,
        label="payments/web",
    )
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()

    # Project consumes 99 credits
    tenant.set_entity_credits(view="project", name="payments/web", credits=99, entity_id="proj-web")
    ingestion.ingest_usage(db, client)
    db.commit()

    # 1. Breach and restrict
    res1 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert res1.enforced > 0
    assert tenant.auto_triage["proj-web"]["enabled"] is False

    state1 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state1.status == LimitStatus.RESTRICTED

    # 2. Increase credit limit to 200
    limit.credit_limit = 200
    db.commit()

    # 3. Next run
    res2 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert res2.restored > 0

    state2 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state2.status == LimitStatus.RESTORED
    assert tenant.auto_triage["proj-web"]["enabled"] is True


def test_application_credit_increase_restores_child_projects(db: Session) -> None:
    """When an application limit breaches and is later given more credit, child
    projects are restored."""
    tenant, client = prepare(db)
    limit = add_limit(
        db,
        entity_type=EntityType.APPLICATION,
        entity_id="app-payments",
        credit_limit=10,
        enforce=True,
        label="Payments",
    )
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()

    tenant.set_entity_credits(
        view="application", name="Payments", credits=500, entity_id="app-payments"
    )
    ingestion.ingest_usage(db, client)
    db.commit()

    res1 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert res1.enforced > 0

    state1 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state1.status == LimitStatus.RESTRICTED

    # Increase credit limit to 1000
    limit.credit_limit = 1000
    db.commit()

    res2 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert res2.restored > 0

    state2 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state2.status == LimitStatus.RESTORED


def test_group_credit_increase_restores_child_projects(db: Session) -> None:
    """When a group limit breaches and credit limit is increased, child projects are restored."""
    tenant, client = prepare(db)
    limit = add_limit(
        db,
        entity_type=EntityType.GROUP,
        entity_id="grp-payments",
        credit_limit=10,
        enforce=True,
        label="Payments",
    )
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()

    # Project in group consumes credits
    tenant.set_entity_credits(
        view="project", name="payments/web", credits=200, entity_id="proj-web"
    )
    ingestion.ingest_usage(db, client)
    db.commit()

    res1 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert res1.enforced > 0

    # Increase credit limit to 1000
    limit.credit_limit = 1000
    db.commit()

    res2 = evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert res2.restored > 0

    # Every half of a group restriction is restored together. A regression that
    # re-enabled only the SCM (PR) triage side would silently leave Auto Triage off.
    assert tenant.auto_triage["proj-api"]["enabled"] is True
    assert tenant.auto_triage["proj-web"]["enabled"] is True
    assert tenant.repo_severities["repo-1"] == ["CRITICAL", "HIGH"]

    state2 = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state2.status == LimitStatus.RESTORED


def test_update_limit_service_restores_immediately_on_credit_increase(db: Session) -> None:
    """Updating credit limit via limits_service restores access immediately when
    client is supplied."""
    tenant, client = prepare(db)
    limit = add_limit(
        db,
        entity_type=EntityType.USER,
        entity_id="user-harsh",
        credit_limit=5,
        enforce=True,
        label="Harsh Gokani",
    )
    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()

    tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=20)
    ingestion.ingest_usage(db, client)
    db.commit()

    evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
    db.commit()
    assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)

    # Update limit using limits_service
    limits_service.update_limit(
        db, limit=limit, changes={"credit_limit": 500}, actor=ACTOR, client=client
    )

    # Verify restored immediately
    assert any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
    state = db.scalar(
        select(LimitPeriodState).where(
            LimitPeriodState.limit_id == limit.id, LimitPeriodState.period_key == "2026-08"
        )
    )
    assert state.status == LimitStatus.RESTORED
