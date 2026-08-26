"""The Alembic migration must build the same schema the models describe."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

from app.db.migrate import upgrade_to_head
from app.models import Base

EXPECTED_TABLES = {
    "alembic_version",
    "app_setting",
    "audit_log_entry",
    "credit_limit",
    "cx_application",
    "cx_application_project",
    "cx_connection",
    "cx_group",
    "cx_group_membership",
    "cx_project",
    "cx_project_group",
    "cx_user",
    "dimension_state",
    "enforcement_action",
    "exemption",
    "limit_period_state",
    "login_attempt",
    "notification",
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
    url = f"sqlite:///{(tmp_path / 'migrated.db').as_posix()}"
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
