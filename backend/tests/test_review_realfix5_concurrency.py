"""Fifth review of realfix: a mapping made while the ingest is waiting on Checkmarx is neither
blocked by it nor lost, and the ingest holds no transaction across the call."""

from __future__ import annotations

import threading
import time
from decimal import Decimal

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.db.session import get_session_factory
from app.models import EntityMapping, UsageDelta, UsageRecord
from app.models.enums import EntityType, UsageView
from app.services import connection as connection_service
from app.services import cycle, ingestion
from tests.conftest import USING_SQLITE
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME


def _map(name: str, entity_id: str) -> float:
    start = time.perf_counter()
    with get_session_factory()() as session:
        ingestion.attribution_lock(session)
        session.add(
            EntityMapping(
                view_by="project", subject_key=name, entity_id=entity_id, mapped_at=utcnow()
            )
        )
        session.flush()
        ingestion.move_subject(
            session,
            view=UsageView.PROJECT,
            subject_key=name,
            entity_type=EntityType.PROJECT,
            entity_id=entity_id,
            follows=lambda r: r.entity_id is None,
        )
        session.commit()
    return time.perf_counter() - start


def test_mapping_during_the_ingest_fetch(
    db: Session,
    connected,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    tenant.set_entity_credits(view="project", name=NAME, credits=870)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(view="project", name=NAME, credits=900)  # +30 before mapping

    entered, release = threading.Event(), threading.Event()
    real = ingestion._fetch_dimension

    def slow(client, *, view, **kw):  # type: ignore[no-untyped-def]
        if view == UsageView.PROJECT:
            entered.set()
            assert release.wait(30)
        return real(client, view=view, **kw)

    monkeypatch.setattr(ingestion, "_fetch_dimension", slow)
    errors: list[BaseException] = []

    def ingest() -> None:
        try:
            with get_session_factory()() as session:
                ingestion.ingest_usage(session, connection_service.get_client(session))
                session.commit()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    worker = threading.Thread(target=ingest)
    worker.start()
    assert entered.wait(30)
    if not USING_SQLITE:
        idle = db.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' "
                "AND pid <> pg_backend_pid() AND datname = current_database()"
            )
        ).scalar()
        db.rollback()
        assert idle == 0, idle
    took = _map(NAME, "proj-api")
    release.set()
    worker.join(60)
    assert not errors, errors
    assert took < 5, took
    db.expire_all()
    snap = ingestion.latest_live_snapshot(db, "project")
    row = db.scalar(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == snap.id, UsageRecord.subject_key == NAME
        )
    )
    # The ingest read the mapping after taking the lock: the reading counts the
    # name towards proj-api, and the 30 it reported since the last reading are
    # the project's from the mapping on (the usage ledger), nothing more.
    delta = db.scalar(
        select(UsageDelta).where(UsageDelta.snapshot_id == snap.id, UsageDelta.subject_key == NAME)
    )
    assert row.entity_id == "proj-api"
    assert (delta.entity_id, delta.credits) == ("proj-api", Decimal("30")), (
        delta.entity_id,
        delta.credits,
    )
