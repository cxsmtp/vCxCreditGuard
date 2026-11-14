"""Tamper-evidence for the audit log: chaining, verification, and the prune boundary."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit import AuditLogEntry
from app.services import audit_chain, retention, settings_store
from app.services.audit import AuditActor, record_audit

ACTOR = AuditActor.system("test")


def _append(db: Session, n: int) -> list[AuditLogEntry]:
    entries = []
    for i in range(n):
        entries.append(record_audit(db, action=f"test.event.{i}", actor=ACTOR, detail=f"event {i}"))
    db.commit()
    return entries


class TestChaining:
    def test_first_entry_starts_at_genesis(self, db: Session) -> None:
        [entry] = _append(db, 1)
        assert entry.prev_hash == audit_chain.GENESIS
        assert entry.entry_hash  # populated

    def test_each_entry_chains_onto_the_previous(self, db: Session) -> None:
        entries = _append(db, 4)
        for earlier, later in zip(entries, entries[1:], strict=False):
            assert later.prev_hash == earlier.entry_hash
        assert audit_chain.chain_tip(db) == entries[-1].entry_hash

    def test_hashes_are_unique_per_entry(self, db: Session) -> None:
        entries = _append(db, 5)
        assert len({e.entry_hash for e in entries}) == 5


class TestVerification:
    def test_an_untouched_chain_verifies(self, db: Session) -> None:
        _append(db, 6)
        result = audit_chain.verify_chain(db)
        assert result.ok is True
        assert result.entries_checked == 6
        assert result.broken_at_id is None

    def test_an_empty_log_verifies(self, db: Session) -> None:
        result = audit_chain.verify_chain(db)
        assert result.ok is True
        assert result.entries_checked == 0

    def test_editing_an_entry_is_detected(self, db: Session) -> None:
        entries = _append(db, 4)
        victim = entries[1]
        # Rewrite history by hand, as a direct database tamper would.
        db.execute(
            AuditLogEntry.__table__.update()
            .where(AuditLogEntry.id == victim.id)
            .values(detail="forged detail")
        )
        db.commit()
        db.expire_all()  # drop the ORM cache so the verifier reads the tampered row
        result = audit_chain.verify_chain(db)
        assert result.ok is False
        assert result.broken_at_id == victim.id
        assert "hash" in (result.reason or "")

    def test_deleting_a_middle_entry_is_detected(self, db: Session) -> None:
        entries = _append(db, 4)
        db.execute(AuditLogEntry.__table__.delete().where(AuditLogEntry.id == entries[1].id))
        db.commit()
        result = audit_chain.verify_chain(db)
        assert result.ok is False
        # The row after the gap no longer links to its recorded predecessor.
        assert result.broken_at_id == entries[2].id

    def test_deleting_the_head_without_a_checkpoint_is_detected(self, db: Session) -> None:
        entries = _append(db, 4)
        db.execute(AuditLogEntry.__table__.delete().where(AuditLogEntry.id == entries[0].id))
        db.commit()
        result = audit_chain.verify_chain(db)
        assert result.ok is False
        assert result.broken_at_id == entries[1].id
        assert "head" in (result.reason or "")


class TestTruncation:
    def test_deleting_the_newest_row_is_detected(self, db: Session) -> None:
        entries = _append(db, 4)
        db.execute(AuditLogEntry.__table__.delete().where(AuditLogEntry.id == entries[-1].id))
        db.commit()
        db.expire_all()
        result = audit_chain.verify_chain(db)
        assert result.ok is False
        # The walk itself stays consistent; the stored head pointer is what flags it.
        assert "newest" in (result.reason or "")

    def test_deleting_the_whole_log_is_detected(self, db: Session) -> None:
        _append(db, 3)
        db.execute(AuditLogEntry.__table__.delete())
        db.commit()
        db.expire_all()
        result = audit_chain.verify_chain(db)
        assert result.ok is False
        assert result.entries_checked == 0


class TestLegacyPrefix:
    def _insert_legacy(self, db: Session, n: int) -> None:
        """Rows from before the feature shipped: real content, null hashes."""
        from app.db.base import utcnow

        for i in range(n):
            db.execute(
                AuditLogEntry.__table__.insert().values(
                    occurred_at=utcnow(),
                    actor_type="system",
                    action=f"legacy.event.{i}",
                    prev_hash=None,
                    entry_hash=None,
                )
            )
        db.commit()

    def test_an_all_legacy_log_verifies(self, db: Session) -> None:
        self._insert_legacy(db, 3)
        db.expire_all()
        result = audit_chain.verify_chain(db)
        assert result.ok is True
        assert result.entries_checked == 0  # nothing to cryptographically verify yet

    def test_new_entries_after_a_legacy_prefix_verify(self, db: Session) -> None:
        self._insert_legacy(db, 2)
        db.expire_all()
        # New appends chain from genesis (chain_tip reads null as genesis).
        _append(db, 3)
        db.expire_all()
        result = audit_chain.verify_chain(db)
        assert result.ok is True, result.reason
        assert result.entries_checked == 3

    def test_blanking_a_hash_after_the_chain_started_is_not_skipped(self, db: Session) -> None:
        entries = _append(db, 3)
        # An attacker cannot evade detection by nulling a committed row's hash.
        db.execute(
            AuditLogEntry.__table__.update()
            .where(AuditLogEntry.id == entries[1].id)
            .values(entry_hash=None)
        )
        db.commit()
        db.expire_all()
        result = audit_chain.verify_chain(db)
        assert result.ok is False
        assert result.broken_at_id == entries[1].id


class TestPayloadStability:
    def test_rich_before_after_round_trips_through_the_database(self, db: Session) -> None:
        # Guards the hash against a write-time vs verify-time serialization drift
        # for realistic before/after payloads.
        record_audit(
            db,
            action="limit.updated",
            actor=ACTOR,
            target_type="credit_limit",
            target_id="demo-1",
            target_label="Alan Turing",
            before={"credit_limit": 1000, "enforce": False, "tags": ["a", "b"], "note": None},
            after={"credit_limit": 1500, "enforce": True, "tags": ["a", "b", "c"], "note": "bump"},
            detail="raised the limit",
        )
        db.commit()
        db.expire_all()  # force the verifier to read DB-round-tripped values
        result = audit_chain.verify_chain(db)
        assert result.ok is True, result.reason
        assert result.entries_checked == 1


class TestPruneBoundary:
    def test_pruning_records_a_checkpoint_that_keeps_the_chain_valid(self, db: Session) -> None:
        # Age some entries past the retention window, keep newer ones.
        old = _append(db, 3)
        from datetime import timedelta

        from app.db.base import utcnow

        ancient = utcnow() - timedelta(days=5000)
        for entry in old:
            db.execute(
                AuditLogEntry.__table__.update()
                .where(AuditLogEntry.id == entry.id)
                .values(occurred_at=ancient)
            )
        db.commit()
        _append(db, 2)  # recent, survive the prune

        retention.prune(db, retention_days=30)
        db.commit()

        # The old rows are gone, a checkpoint was stored, and the chain still verifies.
        survivors = list(db.scalars(select(AuditLogEntry.id)))
        assert len(survivors) >= 2
        assert settings_store.get_value(db, audit_chain.CHECKPOINT_KEY, None)
        result = audit_chain.verify_chain(db)
        assert result.ok is True, result.reason


class TestEndpoint:
    def test_verify_endpoint_reports_intact(self, admin_client: TestClient, db: Session) -> None:
        _append(db, 3)
        response = admin_client.get("/api/ops/audit/verify")
        assert response.status_code == httpx.codes.OK, response.text
        body = response.json()
        assert body["ok"] is True
        assert body["entries_checked"] >= 3

    def test_verify_endpoint_reports_tampering(self, admin_client: TestClient, db: Session) -> None:
        entries = _append(db, 3)
        db.execute(
            AuditLogEntry.__table__.update()
            .where(AuditLogEntry.id == entries[0].id)
            .values(action="forged.action")
        )
        db.commit()
        body = admin_client.get("/api/ops/audit/verify").json()
        assert body["ok"] is False
        assert body["broken_at_id"] == entries[0].id

    def test_verify_requires_admin(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/ops/audit/verify").status_code == httpx.codes.FORBIDDEN
