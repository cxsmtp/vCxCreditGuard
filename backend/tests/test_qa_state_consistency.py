"""State and consistency findings of the v0.1.1 QA report.

* #2: no path calls a user protected who is then restricted; the cycle, the
  fast check, the Simulation and the self-test agree; a restriction after a
  "protected" notice says why the protection ended.
* #5: "entities restricted" counts restrictions in force, the same everywhere.
* #8: the breach notice and the Budgets page say what happened.
* #9: every application and every lift of a restriction is notified, quoting
  the limit in force then.
* #10: Readiness in System health is OK only when every item is green.
* #11: a cycle that reads data moves the connection's "last success".
* #12: the last full cycle and the last success come from the same runs.
* #13: a short listing names the row it could not read.
* #23: budgets already over are not "projected to breach".
* #24: repeated group names are reported once, as a warning.
* #25: Restore access only on notices about a restriction in force.

Synthetic tenant data only (example.com).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import platform
from app.checkmarx.client import CheckmarxClient, Listing
from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
from app.db.base import utcnow
from app.models import (
    AuditLogEntry,
    CreditLimit,
    EnforcementAction,
    LimitPeriodState,
    Notification,
    SchedulerRun,
)
from app.models.connection import CxConnection
from app.models.enums import EnforcementStatus, EntityType, LimitStatus, PeriodType, RunStatus
from app.services import connection as connection_service
from app.services import (
    credits_text,
    cycle,
    dashboard,
    diagnostics,
    enforcement,
    enforcement_selftest,
    evaluation,
    ingestion,
    notifications,
    org_sync,
    preview_service,
    recount,
    reporting_service,
    settings_store,
)
from app.services.audit import AuditActor
from app.services.periods import current_window
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
PERIOD = "2026-08"
AI = list(DEFAULT_AI_ROLE_NAMES)
ALICE = "user-alice"


@pytest.fixture(autouse=True)
def _readings_in_august(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingestion, "utcnow", lambda: datetime(2026, 8, 11, 11, 0, tzinfo=UTC))
    preview_service._role_cache.clear()


def with_ast_admin(tenant: FakeTenant, user_id: str = ALICE) -> FakeTenant:
    """ast-admin as on a live tenant: a composite role holding the AI roles."""
    tenant.add_client_role("ast-admin", contains=AI)
    tenant.role_mappings[user_id] = [*tenant.role_mappings[user_id], "ast-admin"]
    for user in tenant.users:
        if user["id"] == user_id:
            user["roles"] = [*tenant.role_mappings[user_id]]
    return tenant


def synced(db: Session, tenant: FakeTenant):  # type: ignore[no-untyped-def]
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    return tenant, client


def budget(db: Session, entity_id: str = ALICE, credit_limit: int = 20) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id=entity_id,
        entity_label="Alice Archer",
        credit_limit=credit_limit,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    return limit


def over_budget(db: Session, tenant: FakeTenant, client) -> CreditLimit:  # type: ignore[no-untyped-def]
    """Alice's budget, baselined, then 50 credits spent against 20."""
    limit = budget(db)
    evaluation.evaluate_all(db, client=None, now=AUGUST, actor=ACTOR)
    tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=50)
    ingestion.ingest_usage(db, client)
    db.commit()
    return limit


def audits(db: Session, action: str) -> list[AuditLogEntry]:
    db.expire_all()
    return list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == action)))


def notices(db: Session, like: str) -> list[Notification]:
    db.expire_all()
    return list(
        db.scalars(
            select(Notification).where(Notification.title.like(like)).order_by(Notification.id)
        )
    )


def state_of(db: Session, limit: CreditLimit) -> LimitPeriodState:
    db.expire_all()
    found = db.scalar(select(LimitPeriodState).where(LimitPeriodState.limit_id == limit.id))
    assert found is not None
    return found


def selftest_codes(db: Session, user_id: str = ALICE) -> list[str]:
    target = enforcement_selftest.TestTarget(enforcement.TARGET_USER, user_id, "Alice Archer")
    return [r.code for r in enforcement_selftest._db_refusals(db, target, demo=False)]


# ------------------------------------------------------------------------ #2


class TestProtectionIsDecidedTheSameWayEverywhere:
    def test_an_administrator_is_restricted_by_every_path_and_never_called_protected(
        self, db: Session
    ) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant()))
        limit = over_budget(db, tenant, client)

        [row] = preview_service.dry_run(db, now=AUGUST, client=client).rows
        assert row.would_enforce is True
        assert "protected" not in selftest_codes(db)
        # The fast check's entry point, then the full cycle's.
        evaluation.evaluate_all(
            db, client=client, now=AUGUST, actor=ACTOR, only=frozenset({limit.id})
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        action = db.scalar(select(EnforcementAction))
        assert action is not None and action.status == EnforcementStatus.APPLIED
        assert audits(db, "enforcement.protected") == []
        assert notices(db, "%protected%") == []

    def test_the_api_key_account_is_protected_by_every_path(self, db: Session) -> None:
        tenant, client = synced(db, populated_tenant())
        connection_service.save_connection(db, api_key=make_api_key(subject=ALICE), actor=ACTOR)
        db.commit()
        limit = over_budget(db, tenant, client)

        [row] = preview_service.dry_run(db, now=AUGUST, client=client).rows
        assert row.would_enforce is False and "API key" in (row.note or "")
        assert "api_key_user" in selftest_codes(db)
        evaluation.evaluate_all(
            db, client=client, now=AUGUST, actor=ACTOR, only=frozenset({limit.id})
        )
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert db.scalar(select(EnforcementAction)) is None
        assert all(role in tenant.role_mappings[ALICE] for role in AI)
        assert len(audits(db, "enforcement.protected")) == 1
        [breach] = notices(db, "%reached % credit limit")
        assert "was not restricted" in breach.body and "API key" in breach.body
        assert "being restricted now" not in breach.body
        assert "API key" in (state_of(db, limit).status_note or "")

    def test_a_restriction_after_a_protected_notice_says_the_protection_ended(
        self, db: Session
    ) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant()))
        limit = budget(db)
        settings_store.set_value(db, settings_store.KEY_PROTECTED_ROLES, "ast-admin")
        db.commit()
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()
        assert len(audits(db, "enforcement.protected")) == 1
        assert audits(db, enforcement.PROTECTION_ENDED) == []

        settings_store.set_value(db, settings_store.KEY_PROTECTED_ROLES, "")
        db.commit()
        for _ in range(2):
            enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
            db.commit()

        assert len(audits(db, "enforcement.applied")) == 1
        [ended] = audits(db, enforcement.PROTECTION_ENDED)
        assert ended.target_id == ALICE and "no role is protected now" in ended.detail
        [note] = notices(db, "% is no longer protected")
        assert "restricted now" in note.body


# ------------------------------------------------------------------------ #5


def test_entities_restricted_counts_restrictions_in_force_everywhere(
    db: Session, admin_client
) -> None:
    tenant, client = synced(db, populated_tenant())
    restricted = budget(db)
    enforcement.apply_enforcement(db, client, limit=restricted, period_key=PERIOD, actor=ACTOR)
    # Over the limit without a restriction (held, deferred), and an old
    # period's state: neither is a restriction in force.
    for entity_id, status in (("user-bob", LimitStatus.BREACHED), ("user-carol", "restricted")):
        other = budget(db, entity_id=entity_id)
        db.add(
            LimitPeriodState(
                limit_id=other.id,
                period_key="2026-07" if status == "restricted" else PERIOD,
                period_start=datetime(2026, 7, 1, tzinfo=UTC),
                usage_available=True,
                status=status,
            )
        )
    db.commit()

    assert dashboard.warning_and_restriction_counts(db)[1] == 1
    assert reporting_service.impact_summary(db).entities_restricted == 1
    assert admin_client.get("/api/ops/status").json()["entities_restricted"] == 1
    assert admin_client.get("/api/dashboard").json()["tiles"]["entities_restricted"] == 1


# ------------------------------------------------------------------------ #8


class TestTheBreachSaysWhatHappened:
    def test_a_restriction_is_announced_as_done(self, db: Session) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant()))
        limit = over_budget(db, tenant, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()
        [breach] = notices(db, "%reached % credit limit")
        assert "access was restricted" in breach.body
        assert "cannot fully bite" in breach.body
        assert "being restricted now" not in breach.body
        state = state_of(db, limit)
        assert state.status == LimitStatus.RESTRICTED
        assert (state.status_note or "").startswith("Restricted, but it cannot fully bite.")

    def test_a_recount_refusal_is_said_on_the_notice_and_the_budget(
        self, db: Session, admin_client, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def disagree(self, session, limit, window):  # type: ignore[no-untyped-def]
            return recount.Verdict(agrees=False, recount=Decimal("3"))

        monkeypatch.setattr(recount.Recounter, "check", disagree)
        tenant, client = synced(db, populated_tenant())
        limit = over_budget(db, tenant, client)
        evaluation.evaluate_all(db, client=client, now=AUGUST, actor=ACTOR)
        db.commit()

        assert db.scalar(select(EnforcementAction)) is None
        [breach] = notices(db, "%reached % credit limit")
        assert "Counts disagree" in breach.body and "not restricted" in breach.body
        assert "being restricted now" not in breach.body
        assert breach.severity == "warning"
        assert "Counts disagree" in (state_of(db, limit).status_note or "")
        from app.api.routes import limits as limits_route

        monkeypatch.setattr(
            limits_route, "current_window", lambda limit, *_a, **_k: current_window(limit, AUGUST)
        )
        [shown] = admin_client.get("/api/limits").json()
        assert shown["current_period"]["status"] == "breached"
        assert "Counts disagree" in shown["current_period"]["status_note"]

    def test_without_a_connection_it_does_not_claim_a_restriction(self, db: Session) -> None:
        tenant, client = synced(db, populated_tenant())
        limit = over_budget(db, tenant, client)
        evaluation.evaluate_all(db, client=None, now=AUGUST, actor=ACTOR)
        db.commit()
        [breach] = notices(db, "%reached % credit limit")
        assert "nothing has been restricted" in breach.body
        assert "No Checkmarx connection" in (state_of(db, limit).status_note or "")


# ------------------------------------------------------------------- #9, #25


def test_every_restriction_and_restore_is_notified_with_the_limit_then(
    db: Session, admin_client
) -> None:
    tenant, client = synced(db, populated_tenant())
    limit = budget(db, credit_limit=14)

    def restrict() -> None:
        enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
        db.commit()

    def restore() -> None:
        action = db.scalar(select(EnforcementAction))
        enforcement.restore_action(
            db, client, action=action, actor=ACTOR, reason="credit_increased"
        )
        db.commit()

    restrict()
    limit.credit_limit = 16
    db.commit()
    restore()
    restrict()

    restricted = notices(db, "User Alice Archer%restricted%")
    restored = notices(db, "User Alice Archer restored")
    assert len(restricted) == 2 and len(restored) == 1
    assert f"({credits_text.credits(14)} credits)" in restricted[0].body
    assert f"({credits_text.credits(16)} credits)" in restricted[1].body
    assert f"is now {credits_text.credits(16)} credits" in restored[0].body

    # Restore access only on the notice about the restriction in force now.
    items = {item["id"]: item for item in admin_client.get("/api/notifications").json()["items"]}
    assert items[restricted[1].id]["can_restore"] is True
    assert items[restricted[0].id]["can_restore"] is False
    assert items[restored[0].id]["can_restore"] is False

    restore()
    assert len(notices(db, "User Alice Archer restored")) == 2
    items = admin_client.get("/api/notifications").json()["items"]
    assert not any(item["can_restore"] for item in items)


# ----------------------------------------------------------------------- #10


def test_readiness_is_not_ok_while_an_item_is_pending(db: Session) -> None:
    from app.services import readiness

    current = readiness.report(db)
    assert not current.gate_active and not current.all_green
    assert readiness.drifted(db, current) == []
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "readiness")
    assert check.status == diagnostics.WARN


# ----------------------------------------------------------------------- #11


def test_a_cycle_that_reads_data_moves_the_connections_last_success(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = populated_tenant()
    connection_service.save_connection(db, api_key=make_api_key(), actor=ACTOR)
    db.commit()
    monkeypatch.setattr(connection_service, "get_client", lambda _session: tenant.client())
    assert db.get(CxConnection, 1).last_success_at is None
    before = utcnow()
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    last = db.get(CxConnection, 1).last_success_at
    assert last is not None and last >= before


# ----------------------------------------------------------------------- #12


def test_the_last_success_is_never_later_than_the_last_full_cycle(
    db: Session, admin_client
) -> None:
    start = datetime(2026, 11, 27, 21, 0, tzinfo=UTC)
    db.add_all(
        [
            SchedulerRun(
                kind="cycle",
                trigger="schedule",
                started_at=start,
                finished_at=start + timedelta(seconds=40),
                status=RunStatus.SUCCESS,
            ),
            SchedulerRun(
                kind="cycle",
                trigger="schedule",
                started_at=start + timedelta(minutes=11),
                finished_at=start + timedelta(minutes=12),
                status=RunStatus.PARTIAL,
            ),
        ]
    )
    db.commit()
    body = admin_client.get("/api/ops/status").json()
    last_run = datetime.fromisoformat(body["last_run_at"])
    last_success = datetime.fromisoformat(body["last_success_at"])
    assert body["last_run_status"] == "partial"
    assert last_run == start + timedelta(minutes=12)
    assert last_success == start + timedelta(seconds=40)
    assert last_success <= last_run
    assert "last_fast_check_at" in body and "fast_check_enabled" in body


# ----------------------------------------------------------------------- #13


def test_a_short_listing_names_the_row_it_could_not_read(db: Session) -> None:
    pages = [
        {"totalCount": 4, "projects": [{"id": "p-1", "name": "a"}, {"id": "p-2", "name": "b"}]},
        # The order shifted: p-2 again, p-3 skipped.
        {"totalCount": 4, "projects": [{"id": "p-2", "name": "b"}, {"id": "p-4", "name": "d"}]},
        {"totalCount": 4, "projects": []},
    ]
    calls = iter(pages)
    fake = SimpleNamespace(get_json=lambda *_args, **_kwargs: next(calls))
    listing = Listing()
    rows = list(
        CheckmarxClient.paginate(
            fake,  # type: ignore[arg-type]
            "/api/projects",
            items_key="projects",
            page_size=2,
            listing=listing,
        )
    )
    assert len(rows) == 4 and not listing.complete
    assert listing.note == (
        "3 of 4 rows could be read; id p-2 came back twice, so the listing's order shifted "
        "while it was read and as many rows were skipped"
    )
    result = org_sync.OrgSyncResult()
    org_sync._settle_listing(
        db, result, kind="project", listing=listing, known_missing={"p-3": "payments-api"}
    )
    assert "Not returned this time: p-3 (payments-api)." in result.warnings[0]


def test_a_project_row_without_a_name_or_with_a_numeric_id_is_kept() -> None:
    unnamed = platform.parse_project({"id": "p-9", "name": None})
    assert unnamed is not None and unnamed.name == "p-9"
    numbered = platform.parse_project({"id": 42, "name": "billing"})
    assert numbered is not None and numbered.id == "42"
    assert platform.parse_project({"name": "no id"}) is None


# ----------------------------------------------------------------------- #23


def test_a_budget_already_over_is_not_projected_to_breach(db: Session) -> None:
    tenant, client = synced(db, populated_tenant())
    limit = over_budget(db, tenant, client)
    limit.enforce = False
    db.commit()

    report = reporting_service.build_report(db, now=AUGUST)
    [projection] = report.projections
    assert projection.already_over is True and projection.exhaustion_at is None
    assert report.already_over == 1 and report.breaching_soon == 0
    assert "already over" in reporting_service.report_as_text(report)

    simulated = preview_service.dry_run(db, now=AUGUST)
    assert simulated.would_breach_count == 1 and simulated.would_warn_count == 0


# ----------------------------------------------------------------------- #24


def test_a_repeated_group_name_is_one_warning_not_also_an_error(db: Session) -> None:
    tenant = populated_tenant()
    tenant.add_group(group_id="grp-a", name="Platform", path="/Europe/Platform")
    tenant.add_group(group_id="grp-b", name="Platform", path="/America/Platform")
    tenant.add_user(
        user_id="user-dana",
        username="dana@example.com",
        email="dana@example.com",
        groups=["Platform"],
    )
    result = org_sync.sync_org_model(db, tenant.client())
    assert result.duplicate_group_names == ["platform"]
    assert not any("did not match any known group" in w for w in result.warnings)


def test_restore_keys_differ_per_application() -> None:
    first = datetime(2026, 8, 11, 8, 54, tzinfo=UTC)
    again = datetime(2026, 8, 11, 9, 3, tzinfo=UTC)
    assert notifications.enforcement_key(7, first) != notifications.enforcement_key(7, again)
    assert notifications.restoration_key(7, first) != notifications.restoration_key(7, again)
