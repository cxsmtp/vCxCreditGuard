"""Findings of the independent review of realfix, as tests (synthetic data only)."""

from __future__ import annotations

from decimal import Decimal

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Notification
from app.models.enums import EntityType, PeriodType
from app.models.limits import LimitPeriodState
from app.services import cycle, limits_service
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401


def test_mapping_mid_period_does_not_count_lookback_history_as_this_period(
    db: Session,
    connected,  # noqa: F811
    admin_client: TestClient,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name="example-org/payments-api", credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-api",
            credit_limit=100,
            period_type=PeriodType.MONTHLY,
            enforce=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    cycle.run_cycle(trigger="manual")  # the period's baseline (8 credits)
    response = admin_client.post(
        "/api/usage/unmatched-entities/map",
        json={
            "view": "project",
            "subject_key": "example-org/payments-api",
            "entity_id": "proj-api",
        },
    )
    assert response.status_code == httpx.codes.OK, response.text
    # Nothing new was spent: the 870 credits were already in the lookback window.
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    state = db.scalar(select(LimitPeriodState))
    assert state is not None
    breach = db.scalar(
        select(Notification).where(Notification.title.like("%reached its credit limit"))
    )
    assert breach is None, (state.credits_used, state.baseline_credits, breach.body)


def test_a_person_with_a_one_word_or_cjk_name_and_no_email_is_not_automation() -> None:
    from app.services import subject_matching

    for name in ("张伟", "Priya", "José"):
        outcome = subject_matching.classify(
            subject_key=name.lower(), name=name, email=None, profiles=(), integrations=True
        )
        # A person who matches nobody must stay an unmatched *person* (alerted,
        # mappable), not be filed silently as automation.
        assert not outcome.is_bot, name


def test_coverage_does_not_claim_budgets_will_not_bite_when_it_could_not_read(
    db: Session,
) -> None:
    from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
    from app.services import coverage, org_sync
    from tests.fake_tenant import FakeTenant

    tenant = FakeTenant()
    for index in range(5):
        tenant.add_user(
            user_id=f"u{index}",
            username=f"u{index}@example.com",
            email=f"u{index}@example.com",
            roles=list(DEFAULT_AI_ROLE_NAMES),  # direct mappings only: fully restrictable
        )
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    report = coverage.compute(db, None)  # not connected / demo / IAM unreadable
    assert report.unknown == 5
    # Nothing is known to be unreachable, so no "will not bite" verdict.
    assert report.warning() is None, report.warning()


def test_without_a_feed_figure_fusion_is_not_priced_at_the_listed_rate(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.consumption["action"] = []  # no action dimension figure (zero transactions)
    connected(tenant)
    tenant.set_entity_credits(
        view="project",
        name="payments/web",
        credits=4,
        entity_id="proj-web",
        actions={"fusion_scan_-_opus_5.5": 2},
    )
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.PROJECT,
            entity_id="proj-web",
            credit_limit=100,
            period_type=PeriodType.MONTHLY,
            enforce=False,
        ),
        actor=ACTOR,
    )
    db.commit()
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(
        view="project",
        name="payments/web",
        credits=222,
        entity_id="proj-web",
        actions={"fusion_scan_-_opus_5.5": 4},
    )
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    breach = db.scalar(
        select(Notification).where(Notification.title.like("%reached its credit limit"))
    )
    assert breach is not None
    # The listed rate is known not to be a Fusion price; 2 scans = 4 credits is wrong.
    assert "= 4 credits" not in breach.body, breach.body


def test_weighted_share_is_not_described_as_most_of_the_actions() -> None:
    from app.models.enums import EnforcementKind
    from app.services import usage_mix

    mix = usage_mix.UsageMix(
        credits_used=Decimal("209"),
        attributed=Decimal("0"),
        transactions={"fusion": 1, "triage": 100},
        credits_by_action=None,
        unit_prices={"fusion": Decimal("109"), "triage": Decimal("1")},
    )
    text = usage_mix.does_not_stop(EnforcementKind.REMOVE_USER_ROLES, mix)
    # 1 of 101 actions was Fusion: "most of the actions" is false.
    assert "Most of the actions behind them were Fusion scans" not in text, text


def test_coverage_counts_an_ai_role_granted_by_a_parent_group(db: Session) -> None:
    from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
    from app.services import coverage, org_sync
    from tests.fake_tenant import FakeTenant

    ai = list(DEFAULT_AI_ROLE_NAMES)
    tenant = FakeTenant()
    tenant.add_group(group_id="g-parent", name="Engineering", roles=ai)
    tenant.add_group(group_id="g-child", name="Team A", path="/Engineering/Team A", roles=[])
    tenant.add_user(
        user_id="dev",
        username="dev@example.com",
        email="dev@example.com",
        roles=ai,
        groups=["Team A"],
    )
    tenant.join_group("dev", "g-child")
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    report = coverage.compute(db, tenant.client())
    # Keycloak subgroups inherit their parent's role mappings (and role_sources,
    # which enforcement uses, reads parents): removing dev's direct mapping
    # leaves the AI roles in place, so dev is not restrictable.
    assert report.restrictable == 0, report.as_dict()


def test_coverage_with_a_rejected_key_makes_a_handful_of_token_calls(db: Session) -> None:
    from app.services import coverage, org_sync
    from tests.test_enforcement_coverage import shaped_tenant

    tenant = shaped_tenant()
    for index in range(40):
        tenant.add_group(group_id=f"g{index}", name=f"G{index}", roles=[])
        tenant.add_user(
            user_id=f"x{index}",
            username=f"x{index}@example.com",
            roles=["view-risk-management", f"other-{index}"],
            groups=[f"G{index}"],
        )
        tenant.join_group(f"x{index}", f"g{index}")
    org_sync.sync_org_model(db, tenant.client())
    db.commit()
    tenant.requests.clear()
    tenant.fail_paths["/protocol/openid-connect/token"] = 401  # a synthetic / revoked key
    coverage.compute(db, tenant.client())
    token_calls = [p for _m, p in tenant.requests if p.endswith("/openid-connect/token")]
    assert len(token_calls) <= 3, len(token_calls)


def test_settings_role_list_page_loads_with_a_rejected_key_do_not_retry_each_time(
    db: Session, monkeypatch, admin_client: TestClient
) -> None:
    from app.services import connection as connection_service
    from app.services import role_sources
    from tests.conftest import make_api_key
    from tests.fake_tenant import FakeTenant

    tenant = FakeTenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = tenant.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    monkeypatch.setattr(role_sources, "_listing_cache", None)
    tenant.fail_paths["/protocol/openid-connect/token"] = 401
    for _ in range(5):  # five opens of Settings -> Enforcement
        assert admin_client.get("/api/settings/client-roles").status_code == 200
    token_calls = [p for _m, p in tenant.requests if p.endswith("/openid-connect/token")]
    assert len(token_calls) <= 1, len(token_calls)


def test_auto_triage_put_does_not_send_server_owned_or_inherited_tenant_fields() -> None:
    from app.checkmarx import platform

    live_get = {
        "scope": "project",
        "projectId": "p-1",
        "allowAiUsage": True,  # scan.config.ai.allowAiUsage, inherited from the Tenant level
        "configurations": [
            {
                "feature": "auto_triage",
                "enabled": True,
                "config": {"branches": ["main"]},
                "allowOverride": {"projects": True},
            },
            {
                "feature": "auto_remediation",
                "enabled": False,
                "config": {"branches": ["main"]},
                "allowOverride": {"projects": True},
            },
        ],
    }
    body = platform.auto_triage_put_body(live_get, enabled=False, config=None)
    # Echoing allowAiUsage could pin the tenant's AI kill switch on the project;
    # scope/projectId are named by the path.
    assert set(body) == {"configurations"}, sorted(body)
