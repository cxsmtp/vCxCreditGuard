"""The Alembic migration must build the same schema the models describe."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from app.db.migrate import upgrade_to_head
from app.models import Base
from tests.conftest import TEST_DATABASE_URL, USING_SQLITE

EXPECTED_TABLES = {
    "alembic_version",
    "app_setting",
    "audit_log_entry",
    "auto_triage_charge",
    "auto_triage_project_state",
    "credit_balance_snapshot",
    "credit_limit",
    "credit_request",
    "cx_application",
    "cx_application_project",
    "cx_connection",
    "cx_group",
    "cx_group_membership",
    "cx_project",
    "cx_project_group",
    "cx_user",
    "dimension_state",
    "entity_mapping",
    "usage_delta",
    "usage_activity_key",
    "usage_activity_state",
    "usage_activity_counter",
    "usage_budget_interval",
    "usage_missing_name",
    "budget_usage",
    "usage_entity_offset",
    "enforcement_action",
    "enforcement_selftest",
    "exemption",
    "fusion_scan_cost",
    "limit_period_state",
    "login_attempt",
    "notification",
    "password_reset_token",
    "policy_violation",
    "scheduler_lock",
    "scheduler_run",
    "unresolved_subject",
    "usage_record",
    "usage_snapshot",
    "utility_session",
    "utility_user",
}


@pytest.fixture
def migrated_url(tmp_path: Path) -> str:
    """A database built by running every migration from nothing.

    On PostgreSQL this is the real proof that the migrations work there: the
    schema the test fixture built from the models is thrown away first.
    """
    if USING_SQLITE:
        url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
    else:
        url = TEST_DATABASE_URL
        engine = create_engine(url)
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")
        engine.dispose()
    upgrade_to_head(url)
    return url


def test_migration_creates_every_table(migrated_url: str) -> None:
    inspector = inspect(create_engine(migrated_url))
    assert set(inspector.get_table_names()) == EXPECTED_TABLES


def test_migration_matches_the_model_metadata(migrated_url: str) -> None:
    """Guards against a model change that never made it into a migration."""
    inspector = inspect(create_engine(migrated_url))
    for table_name, table in Base.metadata.tables.items():
        migrated_columns = {column["name"] for column in inspector.get_columns(table_name)}
        assert {column.name for column in table.columns} == migrated_columns, table_name


def test_migration_is_idempotent(migrated_url: str) -> None:
    upgrade_to_head(migrated_url)
    inspector = inspect(create_engine(migrated_url))
    assert "credit_limit" in inspector.get_table_names()


def test_key_constraints_exist(migrated_url: str) -> None:
    inspector = inspect(create_engine(migrated_url))

    limit_uniques = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("credit_limit")
    }
    assert ("entity_type", "entity_id") in limit_uniques

    enforcement_indexes = {
        tuple(index["column_names"]) for index in inspector.get_indexes("enforcement_action")
    }
    assert ("idempotency_key",) in enforcement_indexes

    snapshot_uniques = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints("usage_record")
    }
    assert ("snapshot_id", "view_by", "subject_key") in snapshot_uniques
