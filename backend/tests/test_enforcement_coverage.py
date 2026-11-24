"""Enforcement coverage: whether a user restriction can actually bite.

Synthetic tenant shaped like the live one (2026-11): a protected composite role
(``ast-admin``) holding every default AI role and held by most users, another
composite (``ast-risk-manager``), a group granting an AI role, and dedicated AI
roles on the tenant.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
from app.services import connection as connection_service
from app.services import coverage, diagnostics, key_permissions, org_sync, settings_store
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant

ACTOR = AuditActor.system("test")
AI = list(DEFAULT_AI_ROLE_NAMES)


def shaped_tenant() -> FakeTenant:
    tenant = FakeTenant()
    tenant.add_client_role("ast-admin", contains=[*AI, "view-projects"])
    tenant.add_client_role("ast-risk-manager", contains=AI)
    for name in ("ai-triage-assist", "scan-fusion", "fusion-manager"):
        tenant.add_client_role(name, contains=[])
    tenant.add_group(group_id="g-ai", name="AI Users", roles=["view-risk-management"])
    # Roles as /users/v2 reports them: everything held, composites expanded.
    for index in range(7):
        tenant.add_user(
            user_id=f"admin-{index}",
            username=f"admin{index}@example.com",
            email=f"admin{index}@example.com",
            roles=["ast-admin", *AI, "view-projects"],
        )
    tenant.add_user(user_id="risk", username="risk@example.com", roles=["ast-risk-manager", *AI])
    tenant.add_user(
        user_id="grouped",
        username="grouped@example.com",
        roles=["view-risk-management"],
        groups=["AI Users"],
    )
    tenant.join_group("grouped", "g-ai")
    tenant.add_user(user_id="direct", username="direct@example.com", roles=list(AI))
    tenant.add_user(user_id="none", username="none@example.com", roles=["view-projects"])
    return tenant


@pytest.fixture
def connected(db: Session, monkeypatch: pytest.MonkeyPatch):
    tenant = shaped_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = tenant.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    monkeypatch.setattr(connection_service, "optional_client", lambda _session: client)
    org_sync.sync_org_model(db, client)
    db.commit()
    key_permissions.discard_pending_denials()
    yield tenant
    key_permissions.discard_pending_denials()


def test_who_a_user_restriction_can_reach(db: Session, connected: FakeTenant) -> None:
    report = coverage.compute(db, connected.client())
    assert report.ai_holders == 10
    assert report.protected == 7
    assert report.via_composite == 8
    assert report.via_group == 1
    assert report.via_composite_or_group == 9
    assert report.restrictable == 1
    assert report.unknown == 0
    assert report.composites["ast-admin"] == sorted(AI)
    assert report.composite_holders["ast-admin"] == 7
    assert report.groups_granting == ["AI Users"]
    assert report.dedicated_roles == ["ai-triage-assist", "fusion-manager", "scan-fusion"]
    assert report.low
    warning = report.warning()
    assert warning is not None
    assert "will not bite" in warning and "only 1 of the 10" in warning
    assert "ai-triage-assist" in warning and "never changes the list" in warning


def test_it_only_reads_and_never_changes_the_role_list(db: Session, connected: FakeTenant) -> None:
    before = list(settings_store.ai_role_names(db))
    coverage.current(db, connected.client(), refresh=True)
    assert list(settings_store.ai_role_names(db)) == before
    assert all(method == "GET" or "token" in path for method, path in connected.requests)


def test_admins_see_it_and_it_is_cached(
    db: Session, connected: FakeTenant, admin_client: TestClient
) -> None:
    first = admin_client.get("/api/preview/coverage")
    assert first.status_code == httpx.codes.OK, first.text
    body = first.json()
    assert body["restrictable"] == 1 and body["low"] is True
    assert body["warning"].startswith("User budgets will not bite")
    reads = len(connected.requests)
    again = admin_client.get("/api/preview/coverage").json()
    assert again["computed_at"] == body["computed_at"]
    assert len(connected.requests) == reads  # served from the cache
    refreshed = admin_client.get("/api/preview/coverage?refresh=true").json()
    assert refreshed["computed_at"] >= body["computed_at"]


def test_viewers_do_not(viewer_client: TestClient) -> None:
    assert viewer_client.get("/api/preview/coverage").status_code == httpx.codes.FORBIDDEN


def test_diagnostics_shows_a_low_coverage(db: Session, connected: FakeTenant) -> None:
    coverage.current(db, connected.client(), refresh=True)
    check = {c.key: c for c in diagnostics.run_diagnostics(db).checks}["enforcement_coverage"]
    assert check.status == diagnostics.WARN
    assert "will not bite" in check.detail


def test_without_a_tenant_only_protection_is_counted(db: Session, connected: FakeTenant) -> None:
    report = coverage.compute(db, None)
    assert report.available is False
    assert report.protected == 7
    assert report.restrictable == 0 and report.unknown == 3
    assert report.notes
