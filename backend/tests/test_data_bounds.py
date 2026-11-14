"""Values that do not fit, and queues that must not jam."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import CreditLimit, EnforcementAction, Notification, UsageRecord
from app.models.enums import EntityType, PeriodType, Severity
from app.models.org import CxUser
from app.services import (
    delivery,
    ingestion,
    limits_csv,
    limits_service,
    notifications,
    org_sync,
    settings_store,
)
from app.services.audit import AuditActor
from tests.fake_tenant import populated_tenant

ACTOR = AuditActor.system("test")


class TestOverLongText:
    """PostgreSQL refuses text longer than its column; SQLite does not notice.
    These run on both, and on PostgreSQL they used to abort the whole step."""

    def test_a_very_long_name_from_the_tenant_does_not_fail_the_sync(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.add_user(
            user_id="user-long",
            username="long.name@example.com",
            email="long.name@example.com",
            first_name="A" * 500,
            last_name="B" * 500,
        )
        result = org_sync.sync_org_model(db, tenant.client())
        db.commit()
        assert result.users == 4
        user = db.get(CxUser, "user-long")
        assert len(user.first_name) == 128 and len(user.last_name) == 128

    def test_a_very_long_usage_subject_does_not_fail_ingestion(self, db: Session) -> None:
        tenant = populated_tenant()
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        tenant.set_user_credits(name="N" * 900, email=f"{'e' * 600}@example.com", credits=4)
        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert result.errors == []
        longest = db.scalar(select(func.max(func.length(UsageRecord.subject_name))))
        assert longest == 320

    def test_identifiers_are_never_shortened(self, db: Session) -> None:
        """Trimming an id could make two different things look like one."""
        action = EnforcementAction(idempotency_key="k" * 500, target_id="t" * 500)
        assert len(action.idempotency_key) == 500 and len(action.target_id) == 64
        limit = CreditLimit(entity_type=EntityType.USER, entity_id="e" * 200, credit_limit=1)
        assert len(limit.entity_id) == 200  # part of the unique key: left to fail loudly

    def test_long_dedupe_keys_stay_distinct(self, db: Session) -> None:
        shared_prefix = "attribution:" + "x" * 300
        first = notifications.notify(
            db,
            category="attribution",
            severity=Severity.WARNING,
            title="one",
            dedupe_key=shared_prefix + "-a",
        )
        second = notifications.notify(
            db,
            category="attribution",
            severity=Severity.WARNING,
            title="two",
            dedupe_key=shared_prefix + "-b",
        )
        again = notifications.notify(
            db,
            category="attribution",
            severity=Severity.WARNING,
            title="one again",
            dedupe_key=shared_prefix + "-a",
        )
        db.commit()
        assert first is not None and second is not None and again is None
        assert len(first.dedupe_key) <= 160 and first.dedupe_key != second.dedupe_key


class TestLimitCeiling:
    def test_an_absurd_limit_is_refused_cleanly(self, db: Session) -> None:
        with pytest.raises(limits_service.LimitError, match="cannot be more than"):
            limits_service.create_limit(
                db,
                data=limits_service.LimitInput(
                    entity_type=EntityType.USER,
                    entity_id="u1",
                    credit_limit=5_000_000_000,
                    period_type=PeriodType.MONTHLY,
                ),
                actor=ACTOR,
            )

    def test_an_absurd_limit_in_a_csv_is_a_row_error_not_a_crash(self, db: Session) -> None:
        tenant = populated_tenant()
        org_sync.sync_org_model(db, tenant.client())
        db.commit()
        content = "entity_type,entity_id,credit_limit\nuser,user-harsh,99999999999\n"
        result = limits_csv.import_limits(db, content=content, actor=ACTOR, dry_run=False)
        assert result.errors and result.created == 0


class TestDeliveryQueue:
    def _webhook(self, db: Session, received: list[str]) -> httpx.Client:
        settings_store.set_secret(
            db, settings_store.KEY_WEBHOOK_URL, "https://hooks.example.com/cxcg"
        )
        settings_store.set_value(db, settings_store.KEY_NOTIFY_MIN_SEVERITY, "warning")
        db.commit()

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            received.append(json.loads(request.content)["title"])
            return httpx.Response(200)

        return httpx.Client(transport=httpx.MockTransport(handler))

    def test_a_backlog_of_low_severity_notices_cannot_block_important_ones(
        self, db: Session
    ) -> None:
        """Notices below the threshold were never marked, so they stayed at the
        front of the queue; once there were enough, nothing else was ever sent."""
        delivery.reset_attempts()
        received: list[str] = []
        client = self._webhook(db, received)
        old = utcnow() - timedelta(days=2)
        for n in range(delivery.DEFAULT_BATCH * 6):
            db.add(
                Notification(
                    created_at=old + timedelta(seconds=n),
                    severity=Severity.INFO,
                    category="automation",
                    title=f"info {n}",
                )
            )
        db.add(
            Notification(
                created_at=utcnow(),
                severity=Severity.CRITICAL,
                category="enforcement",
                title="someone was restricted",
            )
        )
        db.commit()

        result = delivery.deliver_pending(db, http_client=client)
        db.commit()

        assert received == ["someone was restricted"]
        assert result.delivered == 1
        # The low-severity backlog is settled, not left to be rescanned for ever.
        assert (
            db.scalar(
                select(func.count())
                .select_from(Notification)
                .where(Notification.delivery.is_(None))
            )
            == 0
        )

    def test_oldest_deliverable_first_within_the_batch(self, db: Session) -> None:
        delivery.reset_attempts()
        received: list[str] = []
        client = self._webhook(db, received)
        now = utcnow()
        for n in range(3):
            db.add(
                Notification(
                    created_at=now - timedelta(minutes=10 - n),
                    severity=Severity.ERROR,
                    category="sync_error",
                    title=f"error {n}",
                )
            )
        db.commit()
        delivery.deliver_pending(db, http_client=client)
        assert received == ["error 0", "error 1", "error 2"]
