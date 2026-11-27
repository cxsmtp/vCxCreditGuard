"""Everyone over budget is restricted, holders of ast-admin included.

* ``enforcement.protected_roles`` is empty by default; a list an admin sets
  still shields its holders.
* A user who keeps an AI role through a composite role (ast-admin contains the
  Fusion roles) or a group is still restricted: what can be removed is, and
  the audit log, one WARNING per user per period and the Simulation say it
  cannot fully bite and what to remove in Checkmarx One.
* With no direct AI mapping at all, nothing is written to Checkmarx One and
  the action is recorded as "nothing to remove, kept through composite".
* The API key's own account is still never restricted, and audited.
* Migration ``a4d8e2c6f1b9`` empties only a stored copy of the old default.

Synthetic tenant data only (example.com).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from alembic import command
from app.checkmarx.iam import DEFAULT_AI_ROLE_NAMES
from app.db.migrate import alembic_config
from app.models import AuditLogEntry, CreditLimit, EnforcementAction, Notification
from app.models.enums import EnforcementStatus, EntityType, PeriodType, Severity
from app.services import connection as connection_service
from app.services import (
    enforcement,
    evaluation,
    ingestion,
    org_sync,
    preview_service,
    settings_store,
)
from app.services.audit import AuditActor
from tests.conftest import TEST_DATABASE_URL, USING_SQLITE, make_api_key
from tests.fake_tenant import FakeTenant, populated_tenant

ACTOR = AuditActor.system("test")
AUGUST = datetime(2026, 8, 11, 12, 0, tzinfo=UTC)
PERIOD = "2026-08"
AI = list(DEFAULT_AI_ROLE_NAMES)


@pytest.fixture(autouse=True)
def _readings_in_august(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ingestion, "utcnow", lambda: datetime(2026, 8, 11, 11, 0, tzinfo=UTC))
    preview_service._role_cache.clear()


def with_ast_admin(tenant: FakeTenant, user_id: str, *, direct_ai: bool = True) -> FakeTenant:
    """ast-admin as on a live tenant: a composite role holding the AI roles."""
    tenant.add_client_role("ast-admin", contains=AI)
    keep = [r for r in tenant.role_mappings[user_id] if direct_ai or r not in AI]
    tenant.role_mappings[user_id] = [*keep, "ast-admin"]
    for user in tenant.users:
        if user["id"] == user_id:
            user["roles"] = [*keep, "ast-admin"]
    return tenant


def synced(db: Session, tenant: FakeTenant):
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    ingestion.ingest_usage(db, client)
    db.commit()
    return tenant, client


def limit_on(db: Session, entity_id: str) -> CreditLimit:
    limit = CreditLimit(
        entity_type=EntityType.USER,
        entity_id=entity_id,
        entity_label=entity_id,
        credit_limit=1,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        created_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    db.add(limit)
    db.commit()
    return limit


def apply(db: Session, client, limit: CreditLimit) -> enforcement.EnforcementOutcome:  # type: ignore[no-untyped-def]
    outcome = enforcement.apply_enforcement(db, client, limit=limit, period_key=PERIOD, actor=ACTOR)
    db.commit()
    return outcome


def audits(db: Session, action: str) -> list[AuditLogEntry]:
    db.expire_all()
    return list(db.scalars(select(AuditLogEntry).where(AuditLogEntry.action == action)))


def cannot_bite_notes(db: Session) -> list[Notification]:
    db.expire_all()
    return list(
        db.scalars(select(Notification).where(Notification.title.like("%keeps AI access%")))
    )


def deletes(tenant: FakeTenant) -> int:
    return len([1 for method, path in tenant.requests if method == "DELETE"])


class TestDefault:
    def test_no_role_is_protected_by_default(self, db: Session) -> None:
        assert settings_store.DEFAULTS[settings_store.KEY_PROTECTED_ROLES] == ""
        assert settings_store.enforcement_guard(db).protected_roles == frozenset()


class TestAnAdministratorOverBudget:
    def test_is_restricted_and_told_it_cannot_fully_bite(self, db: Session) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant(), "user-alice"))
        limit = limit_on(db, "user-alice")

        outcome = apply(db, client, limit)
        assert len(outcome.applied) == 1 and outcome.failed == []
        # The direct mappings are gone; ast-admin itself is not touched.
        mapped = tenant.role_mappings["user-alice"]
        assert not any(role in mapped for role in AI)
        assert "ast-admin" in mapped
        action = db.scalar(select(EnforcementAction))
        assert action.status == EnforcementStatus.APPLIED
        assert {r["name"] for r in action.undo_snapshot["removed_roles"]} == set(AI)
        assert {e["role"] for e in action.undo_snapshot["kept_effective"]} == set(AI)

        [note] = cannot_bite_notes(db)
        assert note.severity == Severity.WARNING
        assert note.body.startswith(
            f"Alice Archer is over budget and was restricted, but keeps {', '.join(AI)} "
            "through role ast-admin; the restriction cannot stop them using Fusion. "
            "Remove ast-admin from them in Checkmarx One to make it bite."
        )
        [audit] = audits(db, enforcement.AUDIT_NOT_EFFECTIVE)
        assert audit.detail.startswith("Cannot fully bite: Alice Archer keeps ")
        assert "through role ast-admin" in audit.detail
        assert audit.after["nothing_removed"] is False
        [applied] = audits(db, "enforcement.applied")
        assert "Cannot fully bite" in applied.detail

        # Later cycles in the same period say nothing new.
        for _ in range(2):
            again = apply(db, client, limit)
            assert again.failed == []
        assert len(cannot_bite_notes(db)) == 1
        assert len(audits(db, enforcement.AUDIT_NOT_EFFECTIVE)) == 1

    def test_with_no_direct_ai_role_nothing_is_written(self, db: Session) -> None:
        tenant, client = synced(
            db, with_ast_admin(populated_tenant(), "user-alice", direct_ai=False)
        )
        before = deletes(tenant)
        outcome = apply(db, client, limit_on(db, "user-alice"))

        assert len(outcome.applied) == 1 and outcome.failed == []
        assert deletes(tenant) == before  # no write to Checkmarx One
        action = db.scalar(select(EnforcementAction))
        assert action.undo_snapshot["removed_roles"] == []
        assert all(e["direct_removed"] is False for e in action.undo_snapshot["kept_effective"])
        [audit] = audits(db, enforcement.AUDIT_NOT_EFFECTIVE)
        assert audit.detail.startswith("Nothing to remove, kept through composite or group:")
        assert "nothing was written to Checkmarx One" in audit.detail
        assert audit.after["nothing_removed"] is True
        [applied] = audits(db, "enforcement.applied")
        assert "Nothing to remove, kept through composite or group" in applied.detail
        [note] = cannot_bite_notes(db)
        assert "through role ast-admin" in note.body and "to make it bite" in note.body

    def test_a_group_source_names_the_group(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_group(group_id="grp-ai", name="AI Users", roles=[AI[0]])
        tenant.join_group("user-bob", "grp-ai")
        tenant, client = synced(db, tenant)
        apply(db, client, limit_on(db, "user-bob"))
        [note] = cannot_bite_notes(db)
        assert note.body.startswith(
            f"Bob Baker is over budget and was restricted, but keeps {AI[0]} through group "
            "/AI Users; the restriction cannot stop them using Fusion. Take them out of group "
            "/AI Users in Checkmarx One to make it bite."
        )

    def test_the_simulation_says_it_cannot_fully_bite(self, db: Session) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant(), "user-alice"))
        limit_on(db, "user-alice")
        evaluation.evaluate_all(db, client=None, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()

        projection = preview_service.dry_run(db, now=AUGUST, client=client)
        [row] = [r for r in projection.rows if r.entity_id == "user-alice"]
        assert row.would_enforce is True and row.cannot_fully_bite is True
        assert row.note is not None
        assert row.note.startswith("Would enforce: Yes (cannot fully bite: keeps ")
        assert "through role ast-admin" in row.note
        assert projection.affected_users == 1

    def test_an_ordinary_user_is_not_flagged(self, db: Session) -> None:
        tenant, client = synced(db, populated_tenant())
        limit_on(db, "user-alice")
        evaluation.evaluate_all(db, client=None, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()
        [row] = preview_service.dry_run(db, now=AUGUST, client=client).rows
        assert row.would_enforce is True and row.cannot_fully_bite is False
        assert "cannot fully bite" not in (row.note or "")
        apply(db, client, db.scalar(select(CreditLimit)))
        assert cannot_bite_notes(db) == []

    def test_a_custom_protected_roles_list_still_shields(self, db: Session) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant(), "user-alice"))
        settings_store.set_value(db, settings_store.KEY_PROTECTED_ROLES, "iam-admin, ast-admin")
        db.commit()
        outcome = apply(db, client, limit_on(db, "user-alice"))
        assert outcome.applied == [] and outcome.failed == []
        assert all(role in tenant.role_mappings["user-alice"] for role in AI)
        assert any("protected role (ast-admin)" in note for note in outcome.skipped)
        assert db.scalar(select(func.count()).select_from(EnforcementAction)) == 0
        assert len(audits(db, "enforcement.protected")) == 1


class TestTheApiKeysAccount:
    def test_is_still_exempt_with_an_audit_entry(self, db: Session) -> None:
        tenant, client = synced(db, with_ast_admin(populated_tenant(), "user-alice"))
        connection_service.save_connection(
            db, api_key=make_api_key(subject="user-alice"), actor=ACTOR
        )
        db.commit()
        limit = limit_on(db, "user-alice")
        for _ in range(2):
            outcome = apply(db, client, limit)
            assert outcome.applied == [] and outcome.failed == []
        assert all(role in tenant.role_mappings["user-alice"] for role in AI)
        why = (
            "this is the account the Checkmarx One API key belongs to: restricting it could "
            "remove rights CreditGuard needs to restore others"
        )
        assert enforcement.protection_reason(db, "user-alice") == why
        [audit] = audits(db, "enforcement.protected")
        assert audit.detail == f"Over budget in {PERIOD}, not restricted: {why}."
        [note] = db.scalars(select(Notification).where(Notification.title.like("%protected")))
        assert why in note.body
        assert "protected roles" not in note.body  # no setting would change it

    def test_the_simulation_says_why(self, db: Session) -> None:
        tenant, client = synced(db, populated_tenant())
        connection_service.save_connection(
            db, api_key=make_api_key(subject="user-alice"), actor=ACTOR
        )
        db.commit()
        limit_on(db, "user-alice")
        evaluation.evaluate_all(db, client=None, now=AUGUST, actor=ACTOR)
        tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=50)
        ingestion.ingest_usage(db, client)
        db.commit()
        [row] = preview_service.dry_run(db, now=AUGUST).rows
        assert row.would_enforce is False
        assert row.note == (
            "Would breach, but this user is not restricted because this is the account the "
            "Checkmarx One API key belongs to: restricting it could remove rights CreditGuard "
            "needs to restore others."
        )


# ------------------------------------------------------------- the migration


def _migration_url(tmp_path: Path) -> str:
    if USING_SQLITE:
        return f"sqlite:///{(tmp_path / 'protected-roles.db').as_posix()}"
    engine = create_engine(TEST_DATABASE_URL)
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
    engine.dispose()
    return TEST_DATABASE_URL


KEY = "enforcement.protected_roles"


def _store(engine, value: str | None) -> None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM app_setting WHERE key = :key"), {"key": KEY})
        if value is not None:
            connection.execute(
                text(
                    "INSERT INTO app_setting (key, value, is_secret, created_at, updated_at) "
                    "VALUES (:key, :value, false, :now, :now)"
                ),
                {"key": KEY, "value": json.dumps(value), "now": datetime(2026, 11, 1, tzinfo=UTC)},
            )


def _read(engine) -> str | None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        value = connection.execute(
            text("SELECT value FROM app_setting WHERE key = :key"), {"key": KEY}
        ).scalar()
    return None if value is None else json.loads(value)


@pytest.mark.parametrize(
    ("stored", "after"),
    [
        ("ast-admin, iam-admin", ""),  # the old default, as the Settings page saves it
        ("iam-admin,ast-admin", ""),  # same names, other order and spacing
        ("  ast-admin ,  iam-admin  ", ""),
        (None, None),  # never stored: the code's default applies
        ("ast-admin", None),  # an admin's choice: kept
        ("ast-admin, iam-admin, owner", None),
        ("iam-admin", None),
    ],
)
def test_the_migration_switches_only_the_old_default(
    tmp_path: Path, stored: str | None, after: str | None
) -> None:
    url = _migration_url(tmp_path)
    config = alembic_config(url)
    command.upgrade(config, "b3e7f1a9c2d5")
    engine = create_engine(url)
    _store(engine, stored)
    command.upgrade(config, "a4d8e2c6f1b9")
    assert _read(engine) == (after if after is not None else stored)
    command.downgrade(config, "b3e7f1a9c2d5")
    expected_back = "ast-admin, iam-admin" if after is not None else stored
    assert _read(engine) == expected_back
    command.upgrade(config, "head")
    assert _read(engine) == (after if after is not None else stored)
    engine.dispose()
