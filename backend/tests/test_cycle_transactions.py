"""The cycle never holds a database write lock while it talks to Checkmarx.

A governance cycle spends most of its time waiting on a remote API. If it does
that with an open write transaction, every other writer queues behind it: on
PostgreSQL a sign-in (which appends to the hash-chained audit log) waits for the
whole cycle. These tests observe the database at the exact moment of each
Checkmarx request and fail if a write lock is held.
"""

from __future__ import annotations

import sqlite3

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.checkmarx.iam import AI_ROLE_NAMES
from app.core.config import get_settings
from app.db.session import session_scope
from app.models import CreditLimit, EnforcementAction
from app.models.enums import EnforcementStatus, EntityType, PeriodType, RunStatus
from app.services import connection as connection_service
from app.services import cycle, limits_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key, sqlite_only
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")


def _watch_for_write_locks(tenant: FakeTenant) -> list[tuple[str, str]]:
    """Record every Checkmarx request made while a write transaction is open.

    SQLite allows one writer at a time, so a second connection that cannot start
    a write transaction proves somebody else is holding one.
    """
    path = get_settings().database_url.removeprefix("sqlite:///")
    held: list[tuple[str, str]] = []

    def probe(request: httpx.Request) -> None:
        connection = sqlite3.connect(path, timeout=0)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ROLLBACK")
        except sqlite3.OperationalError:
            held.append((request.method, request.url.path))
        finally:
            connection.close()

    tenant.on_request = probe
    return held


@pytest.fixture
def tenant(db: Session, monkeypatch: pytest.MonkeyPatch) -> FakeTenant:
    fake = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR)
    db.commit()
    client = fake.client()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
    return fake


def _enforced_user_limit(db: Session, *, credit_limit: int) -> None:
    limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.USER,
            entity_id="user-harsh",
            credit_limit=credit_limit,
            period_type=PeriodType.MONTHLY,
            enforce=True,
        ),
        actor=ACTOR,
    )
    db.commit()


@sqlite_only
class TestNoWriteLockAcrossNetworkCalls:
    def test_the_probe_itself_notices_a_held_write_lock(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        """Control: without this, the tests below could pass by seeing nothing."""
        held = _watch_for_write_locks(tenant)
        client = tenant.client()
        client.get_json("/projects")
        assert held == []

        _enforced_user_limit(db, credit_limit=5)
        db.execute(update(CreditLimit).values(credit_limit=6))  # open write, not committed
        client.get_json("/projects")
        db.rollback()
        assert held == [("GET", "/api/projects")]

    def test_a_plain_cycle_holds_no_write_lock_while_calling_checkmarx(
        self, tenant: FakeTenant
    ) -> None:
        held = _watch_for_write_locks(tenant)
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert result.status == RunStatus.SUCCESS, result.errors
        assert tenant.requests, "the cycle should have called the tenant"
        assert held == []

    def test_enforcing_and_restoring_hold_no_write_lock_while_calling_checkmarx(
        self, db: Session, tenant: FakeTenant
    ) -> None:
        # Baseline cycle, then usage jumps past an enforced limit.
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status == RunStatus.SUCCESS
        _enforced_user_limit(db, credit_limit=1)
        cycle.run_cycle(trigger="manual")
        tenant.set_user_credits(name="Harsh Gokani", email="harsh.gokani@checkmarx.com", credits=50)

        held = _watch_for_write_locks(tenant)
        cycle.run_cycle(trigger="manual")
        assert not any(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert held == []

        # Raising the limit restores access, also without a lock across the call.
        with session_scope() as session:
            action = session.scalar(
                select(EnforcementAction).where(
                    EnforcementAction.status == EnforcementStatus.APPLIED
                )
            )
            assert action is not None
            limit = session.get(CreditLimit, action.limit_id)
            limits_service.update_limit(
                session,
                limit=limit,
                changes={"credit_limit": 100000},
                actor=ACTOR,
                client=tenant.client(),
            )
        assert all(role in tenant.role_mappings["user-harsh"] for role in AI_ROLE_NAMES)
        assert held == []
