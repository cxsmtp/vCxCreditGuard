"""Tamper-evidence for the audit log.

Each audit row stores ``entry_hash`` (a SHA-256 over the row's content plus the
hash of the row before it) and ``prev_hash`` (the chain tip at write time). The
writer in :mod:`app.services.audit` is the only producer. This module supplies
the hash function it calls and the verifier that re-walks the chain to prove it
has not been edited, had rows inserted, deleted, reordered, or truncated.

What the chain does and does not guarantee. Re-deriving every hash detects any
change to a row's content, and the linkage between ``prev_hash`` and the
preceding ``entry_hash`` detects a deletion or reordering inside the chain. A
stored head pointer (:data:`HEAD_KEY`) additionally detects truncation of the
newest rows and deletion of the whole log, which the walk alone cannot see. This
makes the log tamper-*evident* against anyone who edits the table without also
rewriting the matching anchors. It is not tamper-*proof*: a party with full write
access to this database can recompute the whole chain and both anchors, so true
immutability would need an external, append-only anchor (a WORM store or a
published tip), which is out of scope here.

Retention pruning deletes the oldest rows (:mod:`app.services.retention`), which
would leave the earliest surviving row pointing at a hash no row carries any
more. To keep that legitimate boundary distinguishable from tampering, the prune
records the earliest surviving row's ``prev_hash`` as a checkpoint; the verifier
accepts a chain head whose ``prev_hash`` is either the genesis value or that
recorded checkpoint.

Concurrency: appends are serialised so two writers (the scheduler thread and an
admin request thread share the engine) cannot both chain onto the same tip and
fork the chain. On PostgreSQL that is a transaction-scoped advisory lock held
until the caller commits; on SQLite the WAL single-writer lock plus this
single-node deployment gives the same ordering. See :func:`serialize_appends`.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models.audit import AuditLogEntry

# The ``prev_hash`` of the very first row in a chain. Empty, not None, so the
# value is explicit and survives a round trip through the database unchanged.
GENESIS = ""

# Where the retention prune records the boundary it created, so the verifier can
# tell a pruned head from a deleted one. Imported lazily to avoid a cycle.
CHECKPOINT_KEY = "audit.chain_checkpoint"

# The expected ``entry_hash`` of the newest row, advanced on every append. The
# verifier compares it to the tip it reached, which is the only way to notice
# that the most recent rows (or all of them) were deleted: a pure walk of what
# survives cannot see rows that are no longer there.
HEAD_KEY = "audit.chain_head"

# A fixed key for the PostgreSQL transaction advisory lock that serialises
# appends. Arbitrary but stable; "CxCG" as a 32-bit integer.
_APPEND_LOCK_KEY = 0x43784347


def _canonical(
    *,
    prev_hash: str,
    occurred_at: datetime | None,
    actor_type: str | None,
    actor_id: int | None,
    actor_name: str | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    target_label: str | None,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    detail: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> str:
    """A deterministic string over every field that defines the row's meaning.

    ``prev_hash`` is folded in so a row cannot be lifted out of one chain and
    dropped into another unchanged. ``id`` and the mutable ``user_agent`` length
    cap are excluded deliberately: the hash covers content, not storage detail.

    Stability depends on one invariant: ``before``/``after`` hold only
    JSON-native values (str, number, bool, None, list, dict). They are stored in
    a JSON column, so the write path and this hash see the same shapes, and the
    row round-trips identically on verify. ``occurred_at`` is folded in as an
    ISO string (and ``actor_type`` is a ``StrEnum`` that serialises to its value)
    so those are stable too. ``default=str`` is only a last-resort net; a
    non-JSON-native value would already raise at the storage layer. If the
    storage serialiser is ever customised (e.g. a ``json_serializer`` with its
    own ``default``), it must match this one or verification will diverge.
    """
    payload = {
        "prev": prev_hash,
        "occurred_at": occurred_at.isoformat() if occurred_at is not None else None,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "actor_name": actor_name,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "target_label": target_label,
        "before": before,
        "after": after,
        "detail": detail,
        "ip_address": ip_address,
        "user_agent": user_agent,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(
    *,
    prev_hash: str,
    occurred_at: datetime | None,
    actor_type: str | None,
    actor_id: int | None,
    actor_name: str | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    target_label: str | None,
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
    detail: str | None,
    ip_address: str | None,
    user_agent: str | None,
) -> str:
    """SHA-256 hex digest of the canonical form of one entry."""
    canonical = _canonical(
        prev_hash=prev_hash,
        occurred_at=occurred_at,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_name=actor_name,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=target_label,
        before=before,
        after=after,
        detail=detail,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_entry(entry: AuditLogEntry, prev_hash: str) -> str:
    """Recompute the hash an entry should carry, given the preceding tip."""
    return compute_hash(
        prev_hash=prev_hash,
        occurred_at=entry.occurred_at,
        actor_type=entry.actor_type,
        actor_id=entry.actor_id,
        actor_name=entry.actor_name,
        action=entry.action,
        target_type=entry.target_type,
        target_id=entry.target_id,
        target_label=entry.target_label,
        before=entry.before,
        after=entry.after,
        detail=entry.detail,
        ip_address=entry.ip_address,
        user_agent=entry.user_agent,
    )


def chain_tip(session: Session) -> str:
    """The ``entry_hash`` of the newest entry, or the genesis value if empty.

    This is what the next appended row chains onto. A pre-chain row that never
    got a hash (there should be none in a fresh database) reads as genesis so a
    legacy table does not wedge the writer.
    """
    tip = session.scalar(
        select(AuditLogEntry.entry_hash).order_by(AuditLogEntry.id.desc()).limit(1)
    )
    return tip or GENESIS


def serialize_appends(session: Session) -> None:
    """Serialise concurrent audit appends so two writers cannot fork the chain.

    The scheduler thread and request-handler threads share one engine, so two
    transactions could each read the same tip and chain onto it, which the
    verifier would (correctly, but unrepairably) read as a reordering. On
    PostgreSQL a transaction-scoped advisory lock makes the second writer wait
    until the first commits and then read the updated tip. On SQLite the WAL
    write lock already serialises writers on this single node, so this is a
    no-op there.
    """
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _APPEND_LOCK_KEY})


def advance_head(session: Session, entry_hash: str) -> None:
    """Record the newest entry's hash as the chain head.

    Written in the caller's transaction alongside the row, so the pointer and
    the row commit or roll back together. The verifier compares it to the tip it
    reaches to detect truncation of the newest rows.
    """
    from app.services import settings_store

    settings_store.set_value(
        session,
        HEAD_KEY,
        entry_hash,
        description="Expected hash of the newest audit entry (tamper-evidence anchor).",
    )


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """The outcome of re-walking the whole chain."""

    ok: bool
    entries_checked: int
    tip: str | None
    broken_at_id: int | None = None
    reason: str | None = None


def verify_chain(session: Session) -> ChainVerification:
    """Re-walk every entry in write order and prove the chain is intact.

    Ways a chain can be broken, each reported with the offending id:

    * a row's content no longer hashes to its stored ``entry_hash`` (edited),
    * a row's ``prev_hash`` does not match the previous row's ``entry_hash``
      (a row between them was deleted, or the order was changed),
    * the head row does not start at genesis or the recorded prune checkpoint,
    * the row reached last does not match the stored head pointer, or the log is
      empty while the head pointer expects a row (the newest rows, or all of
      them, were truncated).

    Rows written before this feature shipped carry no hash. A leading run of such
    rows (lowest ids, ``entry_hash`` null) is treated as a pre-chain prefix and
    skipped, so verifying an upgraded database does not read its history as
    tampering. A null hash appearing *after* the chain has started is not skipped:
    it fails the content check, so an attacker cannot blank a row's hash to hide.
    """
    from app.services import settings_store

    checkpoint = settings_store.get_value(session, CHECKPOINT_KEY, None)
    accepted_heads = {GENESIS} | ({checkpoint} if checkpoint else set())

    expected_prev: str | None = None
    in_prefix = True
    checked = 0
    tip: str | None = None

    for entry in session.scalars(
        select(AuditLogEntry).order_by(AuditLogEntry.id.asc()).execution_options(yield_per=500)
    ):
        if in_prefix and not entry.entry_hash:
            # A pre-chain row from before the feature shipped: nothing to verify.
            continue
        in_prefix = False

        stored = entry.entry_hash or ""
        recomputed = hash_entry(entry, entry.prev_hash or "")
        if recomputed != stored:
            return ChainVerification(
                ok=False,
                entries_checked=checked,
                tip=tip,
                broken_at_id=entry.id,
                reason="entry content does not match its recorded hash",
            )

        if expected_prev is None:
            # The head of the surviving chain.
            if (entry.prev_hash or "") not in accepted_heads:
                return ChainVerification(
                    ok=False,
                    entries_checked=checked,
                    tip=tip,
                    broken_at_id=entry.id,
                    reason="chain head does not start at genesis or a known prune checkpoint",
                )
        elif (entry.prev_hash or "") != expected_prev:
            return ChainVerification(
                ok=False,
                entries_checked=checked,
                tip=tip,
                broken_at_id=entry.id,
                reason="entry does not link to the previous entry (a row was removed or reordered)",
            )

        expected_prev = stored
        tip = stored
        checked += 1

    # Compare the row we reached against the head pointer advanced on every
    # append. A mismatch means the newest rows were deleted; an empty walk with a
    # non-genesis head means the whole log was. Only enforced once the pointer has
    # ever been set, so a pre-feature database with no head pointer still passes.
    stored_head = settings_store.get_value(session, HEAD_KEY, None)
    if stored_head and (tip or GENESIS) != stored_head:
        return ChainVerification(
            ok=False,
            entries_checked=checked,
            tip=tip,
            broken_at_id=None,
            reason="newest entries are missing: the chain head does not match the recorded tip",
        )

    return ChainVerification(ok=True, entries_checked=checked, tip=tip)


def record_prune_checkpoint(session: Session) -> None:
    """After an audit prune, remember the boundary so verification still passes.

    Stores the ``prev_hash`` of the earliest surviving row. The verifier accepts
    a head carrying that value even though the row it referenced is now gone. If
    nothing survives, the checkpoint is cleared: the next appended row starts a
    fresh chain from genesis.
    """
    from app.services import settings_store

    earliest_prev = session.scalar(
        select(AuditLogEntry.prev_hash).order_by(AuditLogEntry.id.asc()).limit(1)
    )
    settings_store.set_value(
        session,
        CHECKPOINT_KEY,
        earliest_prev if earliest_prev else GENESIS,
        description="Audit hash-chain boundary created by the last retention prune.",
    )
