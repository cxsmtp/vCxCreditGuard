"""The independent recount before every new restriction (app/services/recount.py)
and the onboarding readiness checklist (app/services/readiness.py).
Synthetic data only (example.com)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.db.base import utcnow
from app.db.migrate import alembic_config
from app.models import (
    ActivitySourceState,
    AuditLogEntry,
    BudgetUsage,
    CreditLimit,
    CxConnection,
    EnforcementSelfTest,
    Notification,
)
from app.models.enums import ConnectionStatus, EntityType, LimitStatus, PeriodType
from app.services import (
    diagnostics,
    evaluation,
    preview_service,
    readiness,
    recount,
    settings_store,
)
from app.services.audit import AuditActor, record_audit
from tests.activity_world import iso
from tests.conftest import TEST_DATABASE_URL, USING_SQLITE
from tests.test_summary_hold import World

ACTOR = AuditActor.system("test")
CAROL = "user-carol"
CAROL_EMAIL = "carol.chen@example.com"


def over(world: World, credits: int = 6) -> None:
    """Alice spends over her limit of 5; the log counts it."""
    world.evaluate()
    world.tick()
    world.spend(credits)
    world.ingest()


def warnings_about_recount(db: Session) -> list[Notification]:
    db.expire_all()
    return list(db.scalars(select(Notification).where(Notification.dedupe_key.like("recount.%"))))


# ------------------------------------------------------------------ recount


def test_agree_the_restriction_applies(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    result = world.evaluate()
    assert result.enforced == 1 and result.recount_held == 0
    assert world.restricted() and world.state(limit).status == LimitStatus.RESTRICTED
    assert warnings_about_recount(db) == []
    assert recount.records(db) == []
    # The recount read the log from page 1 with an explicit window.
    assert any(
        request.get("period") == [recount.PERIOD_30] and request.get("page") == ["1"]
        for request in world.tenant.activity_requests[-3:]
    )


def test_disagree_no_restriction_a_warning_and_diagnose_shows_it(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    # The log no longer holds what CreditGuard counted (say, a counting bug).
    assert world.tenant.activity is not None
    world.tenant.activity.clear()
    result = world.evaluate()
    assert result.enforced == 0 and result.recount_held == 1
    assert not world.restricted()
    assert world.state(limit).status == LimitStatus.BREACHED
    warned = warnings_about_recount(db)
    assert len(warned) == 1 and warned[0].severity == "warning"
    assert warned[0].body is not None and warned[0].body.startswith(
        "Counts disagree: CreditGuard's count is 6.0, a direct recount of the Checkmarx "
        "activity log is 0.0; not restricted. See Diagnose."
    )
    # Deduplicated per budget and period: the next cycle does not warn again.
    world.tick()
    assert world.evaluate().recount_held == 1
    assert len(warnings_about_recount(db)) == 1
    entries = recount.records(db)
    assert len(entries) == 1 and entries[0]["kind"] == recount.DISAGREE
    assert entries[0]["times"] == 2
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "recount")
    assert check.status == diagnostics.WARN and "the activity log 0.0" in check.detail
    assert check.label == "Recount before restricting"


def test_no_disagreements_on_diagnose(db: Session) -> None:
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "recount")
    assert check.status == diagnostics.OK and check.detail == "No disagreements."


def test_recount_unavailable_no_restriction_a_warning(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    world.tenant.activity_status = 503
    result = world.evaluate()
    assert result.enforced == 0 and result.recount_held == 1
    assert not world.restricted() and world.state(limit).status == LimitStatus.BREACHED
    warned = warnings_about_recount(db)
    assert len(warned) == 1 and "could not be done" in (warned[0].body or "")
    assert recount.records(db)[0]["kind"] == recount.UNAVAILABLE


def test_the_page_cap_reached_is_no_recount(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    world.budget()
    over(world)
    world.spend(1)  # a second row: two pages of one row each
    world.tenant.activity_page_cap = 1  # one row per page, at most 1 page read
    settings_store.set_value(db, settings_store.KEY_ACTIVITY_MAX_PAGES, 1)
    db.commit()
    result = world.evaluate()
    assert result.enforced == 0 and result.recount_held == 1
    assert "page cap" in (recount.records(db)[0]["reason"] or "")


def test_a_restriction_already_in_force_is_unaffected(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    assert world.evaluate().enforced == 1 and world.restricted()
    # The log becomes unreadable, and then disagrees: the restriction stays.
    world.tenant.activity_status = 503
    world.tick()
    first = world.evaluate()
    assert first.recount_held == 0
    world.tenant.activity_status = None
    assert world.tenant.activity is not None
    world.tenant.activity.clear()
    world.tick()
    second = world.evaluate()
    assert second.recount_held == 0
    assert world.restricted() and world.state(limit).status == LimitStatus.RESTRICTED
    assert warnings_about_recount(db) == []


def test_a_lift_is_unaffected(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    assert world.evaluate().enforced == 1 and world.restricted()
    world.tenant.activity_status = 503  # no recount possible
    db.expire_all()
    stored = db.get(CreditLimit, limit.id)
    assert stored is not None
    stored.credit_limit = 100
    db.commit()
    world.tick()
    result = world.evaluate()
    assert result.restored >= 1 and not world.restricted()
    assert warnings_about_recount(db) == []


def test_a_lifetime_budget_is_unaffected(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_summary_hold import over_on_summary

    world = World(db, monkeypatch, log=False)  # no activity log at all
    world.budget(period_type=PeriodType.LIFETIME)
    result = over_on_summary(world)
    assert result.enforced == 1 and result.recount_held == 0
    assert world.restricted()


def test_preview_and_simulation_agree_with_the_gate(
    db: Session, monkeypatch: pytest.MonkeyPatch, admin_client
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    rows = preview_service.dry_run(db, now=world.clock.value).rows
    row = next(r for r in rows if r.limit_id == limit.id)
    assert row.would_enforce and row.recount_required
    assert row.note is not None and "Would restrict if the recount agrees" in row.note
    response = admin_client.get("/api/preview/dry-run")
    assert response.status_code == 200, response.text
    api_row = next(r for r in response.json()["rows"] if r["limit_id"] == limit.id)
    assert api_row["recount_required"] is True
    # The safety ceiling counts only what the recount lets start: two budgets
    # over, a ceiling of one, and a log that confirms neither - no trip.
    db.add(
        CreditLimit(
            entity_type=EntityType.USER,
            entity_id="user-bob",
            entity_label="Bob Baker",
            credit_limit=5,
            period_type=PeriodType.MONTHLY,
            enforce=True,
            created_at=world.clock.value - timedelta(days=1),
        )
    )
    settings_store.set_value(db, settings_store.KEY_MAX_NEW_ENFORCEMENTS, 1)
    db.commit()
    world.tick()
    world.tenant.add_activity(
        date=iso(world.clock.value - timedelta(minutes=1)),
        credits="7",
        project_id="proj-api",
        user="Bob Baker",
        email="bob.baker@example.com",
    )
    world.ingest()
    assert world.tenant.activity is not None
    world.tenant.activity.clear()
    result = world.evaluate()
    assert result.enforcement_paused is None  # the ceiling did not trip
    assert result.enforced == 0 and result.recount_held == 2
    assert not settings_store.enforcement_guard(db).paused


def test_the_dry_run_of_a_restriction_in_force_needs_no_recount(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    limit = world.budget()
    over(world)
    world.evaluate()
    row = next(
        r for r in preview_service.dry_run(db, now=world.clock.value).rows if r.limit_id == limit.id
    )
    assert not row.recount_required


@pytest.mark.parametrize("project_budget", [True, False], ids=["project_budget", "no_budget"])
def test_a_user_budget_with_an_integration_account_follows_the_existing_rule(
    db: Session, monkeypatch: pytest.MonkeyPatch, project_budget: bool
) -> None:
    """Carol is listed as an integration account. Her usage counts towards her
    own user budget only when its project had no active project budget: the
    recount follows the same rule as the ledger."""
    world = World(db, monkeypatch, log=True)
    settings_store.set_value(db, settings_store.KEY_INTEGRATION_ACCOUNTS, [CAROL_EMAIL])
    created = world.clock.value - timedelta(days=1)
    if project_budget:
        db.add(
            CreditLimit(
                entity_type=EntityType.PROJECT,
                entity_id="proj-api",
                entity_label="payments/api",
                credit_limit=100_000,
                period_type=PeriodType.MONTHLY,
                enforce=False,
                created_at=created,
            )
        )
    carol = CreditLimit(
        entity_type=EntityType.USER,
        entity_id=CAROL,
        entity_label="Carol Chen",
        credit_limit=5,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        created_at=created,
    )
    db.add(carol)
    db.commit()
    world.evaluate()
    world.tick()
    world.tenant.add_activity(
        date=iso(world.clock.value - timedelta(minutes=1)),
        credits="6",
        project_id="proj-api",
        user="carol",
        email=CAROL_EMAIL,
    )
    world.ingest()
    db.expire_all()
    ledger = sum(
        (
            Decimal(row.credits)
            for row in db.scalars(select(BudgetUsage).where(BudgetUsage.limit_id == carol.id))
            if "-Q" not in row.period_key
        ),
        Decimal(0),
    )
    window = evaluation.current_window(carol, world.clock.value)
    verdict = recount.Recounter(world.client, now=world.clock.value).check(db, carol, window)
    assert verdict.recount == ledger == (Decimal(0) if project_budget else Decimal(6))
    result = world.evaluate()
    assert result.enforced == (0 if project_budget else 1)
    assert result.recount_held == 0


def test_a_group_budget_is_recounted_through_its_projects(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = World(db, monkeypatch, log=True)
    group = CreditLimit(
        entity_type=EntityType.GROUP,
        entity_id="grp-payments",
        entity_label="Payments",
        credit_limit=5,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        created_at=world.clock.value - timedelta(days=1),
    )
    db.add(group)
    db.commit()
    world.tick()
    world.ingest()  # the log takes the group budget over from here
    over(world)  # Alice's 6 credits on proj-api, a Payments project
    window = evaluation.current_window(group, world.clock.value)
    verdict = recount.Recounter(world.client, now=world.clock.value).check(db, group, window)
    assert verdict.agrees and verdict.recount == Decimal(6)
    result = world.evaluate()
    assert result.recount_held == 0 and result.enforced >= 1


def test_tied_rows_across_a_page_boundary_are_never_counted_twice() -> None:
    from tests.fake_tenant import FakeTenant

    tenant = FakeTenant()
    tenant.activity = []
    stamp = "2026-11-20T10:00:00Z"
    for _ in range(3):
        tenant.add_activity(date=stamp, credits="2", project_id="p-1")
    tenant.activity_page_cap = 2  # the three identical rows straddle two pages
    events = recount.read_log(tenant.client(), recount.PERIOD_30, 10)
    # One page shows two of them at most: the recount may fall short, never over.
    assert sum((event.credits for event in events), Decimal(0)) == Decimal(4)


# ---------------------------------------------------------------- readiness


def _green(db: Session) -> None:
    """Every readiness item green, from the data each one reads."""
    now = utcnow()
    db.add(
        CxConnection(
            id=1,
            api_key_encrypted="x",
            iam_base_url="https://iam.example.com",
            tenant_name="example",
            api_base_url="https://api.example.com",
            status=ConnectionStatus.HEALTHY,
        )
    )
    settings_store.set_value(db, settings_store.KEY_USAGE_SOURCE, "activity")
    db.add(
        ActivitySourceState(
            id=1,
            status="active",
            revision=1,
            last_fetch_at=now,
            last_success_at=now,
            reconciliation={"status": "match", "activity_credits": "10", "summary_credits": "10"},
        )
    )
    for noun, target in (("user", "user-1"), ("project", "proj-1")):
        db.add(
            EnforcementSelfTest(
                started_at=now - timedelta(days=1),
                finished_at=now - timedelta(days=1),
                status="passed",
                demo=False,
                result={
                    "targets": [
                        {
                            "target_type": noun,
                            "target_id": target,
                            "status": "passed",
                            "kinds": ["not_applicable"],
                        }
                    ]
                },
            )
        )
    db.commit()
    readiness.mark_reviewed(db, actor=ACTOR)


def _watch_only(db: Session) -> None:
    """A new install, as the data migration leaves it."""
    settings_store.set_value(db, settings_store.KEY_READINESS_GATE, True)
    settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, True)
    settings_store.set_value(
        db, settings_store.KEY_ENFORCEMENT_PAUSE_REASON, readiness.WATCH_ONLY_REASON
    )
    db.commit()


def _status(db: Session) -> dict[str, str]:
    db.expire_all()
    return {item.key: item.status for item in readiness.report(db).items}


def test_each_item_green(db: Session) -> None:
    _green(db)
    assert set(_status(db).values()) == {readiness.GREEN}
    assert readiness.report(db).all_green


def test_each_item_red_or_pending(db: Session) -> None:
    assert _status(db) == {
        "connection": readiness.RED,
        "activity_log": readiness.AMBER,
        "counts_match": readiness.AMBER,
        "selftest": readiness.AMBER,
        "dry_run_reviewed": readiness.AMBER,
    }
    _green(db)
    connection = db.get(CxConnection, 1)
    state = db.get(ActivitySourceState, 1)
    assert connection is not None and state is not None
    connection.status = ConnectionStatus.FAILED
    state.last_fetch_at = utcnow() + timedelta(minutes=1)
    state.last_error = "forced failure"
    state.reconciliation = {"status": "mismatch", "activity_credits": "10", "summary_credits": "20"}
    for row in db.scalars(select(EnforcementSelfTest)):
        row.result = {"targets": [{"target_type": "user", "status": "failed"}]}
    db.commit()
    # A budget change after the review: the dry run wants another look.
    record_audit(db, action="limit.updated", actor=ACTOR, target_type="limit")
    db.commit()
    assert _status(db) == {
        "connection": readiness.RED,
        "activity_log": readiness.RED,
        "counts_match": readiness.RED,
        "selftest": readiness.RED,
        "dry_run_reviewed": readiness.AMBER,
    }


def test_a_self_test_older_than_30_days_does_not_count(db: Session) -> None:
    _green(db)
    for row in db.scalars(select(EnforcementSelfTest)):
        row.started_at = utcnow() - timedelta(days=31)
    db.commit()
    assert _status(db)["selftest"] == readiness.AMBER


def test_enabling_enforcement_is_blocked_until_all_green(db: Session, admin_client) -> None:
    _watch_only(db)
    refused = admin_client.post("/api/readiness/enable", json={})
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["code"] == "readiness_not_green"
    assert {item["key"] for item in refused.json()["detail"]["items"]} >= {"connection"}
    by_settings = admin_client.put("/api/settings", json={"enforcement_paused": False})
    assert by_settings.status_code == 409, by_settings.text
    db.expire_all()
    assert settings_store.enforcement_guard(db).paused
    _green(db)
    enabled = admin_client.post("/api/readiness/enable", json={})
    assert enabled.status_code == 200, enabled.text
    db.expire_all()
    assert not settings_store.enforcement_guard(db).paused
    assert not readiness.gate_active(db)
    assert db.scalar(
        select(AuditLogEntry).where(AuditLogEntry.action == "readiness.enforcement_on")
    )


def test_the_settings_toggle_leaves_watch_only_when_all_green(db: Session, admin_client) -> None:
    _watch_only(db)
    _green(db)
    response = admin_client.put("/api/settings", json={"enforcement_paused": False})
    assert response.status_code == 200, response.text
    db.expire_all()
    assert not settings_store.enforcement_guard(db).paused and not readiness.gate_active(db)


def test_the_override_works_and_is_audited(db: Session, admin_client) -> None:
    _watch_only(db)
    wrong = admin_client.post("/api/readiness/enable", json={"confirm": "enforce please"})
    assert wrong.status_code == 409
    response = admin_client.post("/api/readiness/enable", json={"confirm": "ENFORCE"})
    assert response.status_code == 200, response.text
    db.expire_all()
    assert not settings_store.enforcement_guard(db).paused
    entry = db.scalar(select(AuditLogEntry).where(AuditLogEntry.action == "readiness.override"))
    assert entry is not None
    assert "connection" in entry.after["not_green"]
    assert "Connected to Checkmarx One" in (entry.detail or "")


def test_an_existing_install_is_not_blocked(db: Session, admin_client) -> None:
    settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_PAUSED, True)
    db.commit()
    assert not readiness.report(db).all_green
    response = admin_client.put("/api/settings", json={"enforcement_paused": False})
    assert response.status_code == 200, response.text
    db.expire_all()
    assert not settings_store.enforcement_guard(db).paused
    shown = admin_client.get("/api/readiness").json()
    assert shown["gate_active"] is False and shown["enforcement_on"] is True


def test_drift_raises_a_warning_but_does_not_turn_enforcement_off(db: Session) -> None:
    _green(db)
    assert readiness.check_drift(db) == []  # all green, remembered
    connection = db.get(CxConnection, 1)
    assert connection is not None
    connection.status = ConnectionStatus.FAILED
    db.commit()
    assert readiness.check_drift(db) == ["connection"]
    db.expire_all()
    warned = list(
        db.scalars(select(Notification).where(Notification.dedupe_key.like("readiness.drift:%")))
    )
    assert len(warned) == 1 and warned[0].severity == "warning"
    assert not settings_store.enforcement_guard(db).paused
    check = next(c for c in diagnostics.run_diagnostics(db).checks if c.key == "readiness")
    assert check.status == diagnostics.WARN and "Connected to Checkmarx One" in check.detail
    # Still red next cycle: no second warning.
    assert readiness.check_drift(db) == []


def test_viewer_sees_the_checklist_admin_acts(db: Session, client, admin_user, viewer_user) -> None:
    from tests.conftest import ADMIN_PASSWORD, VIEWER_PASSWORD, login

    _watch_only(db)
    assert login(client, viewer_user.username, VIEWER_PASSWORD).status_code == 200
    seen = client.get("/api/readiness")
    assert seen.status_code == 200 and seen.json()["gate_active"] is True
    assert len(seen.json()["items"]) == 5
    assert client.post("/api/readiness/reviewed").status_code == 403
    assert client.post("/api/readiness/enable", json={"confirm": "ENFORCE"}).status_code == 403
    client.post("/api/auth/logout")
    client.cookies.clear()
    assert login(client, admin_user.username, ADMIN_PASSWORD).status_code == 200
    reviewed = client.post("/api/readiness/reviewed")
    assert reviewed.status_code == 200, reviewed.text
    item = next(i for i in reviewed.json()["items"] if i["key"] == "dry_run_reviewed")
    assert item["status"] == readiness.GREEN


def _migration_url(tmp_path: Path) -> str:
    if USING_SQLITE:
        return f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    engine = create_engine(TEST_DATABASE_URL)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    return TEST_DATABASE_URL


def _setting(engine, key: str):  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        value = connection.execute(
            text("SELECT value FROM app_setting WHERE key = :k"), {"k": key}
        ).scalar()
    return json.loads(value) if value is not None else None


@pytest.mark.parametrize("existing", [False, True], ids=["new_install", "existing_install"])
def test_the_migration_starts_only_new_installs_watching(tmp_path: Path, existing: bool) -> None:
    url = _migration_url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, "a8d4f2c6e9b3")
    engine = create_engine(url)
    if existing:
        now = datetime.now(UTC)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO utility_user (id, username, password_hash, role, is_active, "
                    "totp_enabled, failed_login_count, must_change_password, created_at, "
                    "updated_at) VALUES (1, 'admin', 'x', 'admin', :t, :f, 0, :f, :now, :now)"
                ),
                {"t": True, "f": False, "now": now},
            )
    command.upgrade(config, "head")
    if existing:
        assert _setting(engine, settings_store.KEY_READINESS_GATE) is None
        assert _setting(engine, settings_store.KEY_ENFORCEMENT_PAUSED) is None
    else:
        assert _setting(engine, settings_store.KEY_READINESS_GATE) is True
        assert _setting(engine, settings_store.KEY_ENFORCEMENT_PAUSED) is True
    command.downgrade(config, "a8d4f2c6e9b3")
    assert _setting(engine, settings_store.KEY_READINESS_GATE) is None
    engine.dispose()
