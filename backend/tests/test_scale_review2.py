"""The follow-up review of the scale work: the reviewer's tests, and one per fix.

B1-a  a restriction that cannot be read back (no error, no readable answer)
      moves back in the rotation, is written again at most once per interval,
      and only after the new restrictions.
G1    auto-triage charges and cursors pin no snapshot; the charges stay.
G2    retention works with any number of ids (PostgreSQL: 65,535 parameters).
E1    domain errors written for admins keep their message.
Minor the "not read back" alert after the pass; outcome-unknown, failing lifts
      and deleted users counted; "verified" counted after the read; the raw
      cursor and released pins.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models import EnforcementAction
from app.models.enums import EnforcementStatus
from app.services import evaluation, settings_store
from tests.fake_tenant import populated_tenant
from tests.test_scale_pacing import (
    ACTOR,
    connected,  # noqa: F401 - fixture
    group_limit,
    setting,
)


def _tenant(count: int):  # type: ignore[no-untyped-def]
    tenant = populated_tenant()
    tenant.add_group(group_id="grp-many", name="Many")
    for index in range(count):
        project_id = f"proj-m{index:02d}"
        tenant.add_project(
            project_id=project_id,
            name=f"many/{index:02d}",
            group_ids=["grp-many"],
            repo_id=f"repo-{index:02d}",
        )
        tenant.set_entity_credits(
            view="project", name=f"many/{index:02d}", credits=5, entity_id=project_id
        )
    return tenant


def test_unreadable_pr_remediation_rows_starve_the_rotation(
    db: Session,
    connected,  # noqa: F811
) -> None:
    """B1 claim: a restriction that cannot be read back goes to the back of the
    rotation. Only a Checkmarx *error* does: a read that returns None (tenant
    does not expose the repo-settings read) is RECONCILE_UNVERIFIED, keeps its
    old last_verified_at and no last_checked_at, so it is first every cycle and
    re-written every cycle. Two of them with a cap of 2 starve every other
    restriction: an auto-triage drift is never found."""
    tenant = _tenant(4)
    client = connected(tenant)
    setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
    setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
    setting(db, settings_store.KEY_MAX_VERIFICATIONS, 2)
    limit = group_limit(db, actions=["auto_triage", "pr_remediation"])
    now = utcnow()
    evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
    rows = db.scalars(
        select(EnforcementAction).where(
            EnforcementAction.limit_id == limit.id,
            EnforcementAction.status == EnforcementStatus.APPLIED,
        )
    ).all()
    assert len(rows) == 8, [(r.kind, r.target_id) for r in rows]
    # The repo-settings read starts failing for two repos (403/500 -> None).
    tenant.fail_requests[("GET", "/repos-manager/repo/repo-00")] = 500
    tenant.fail_requests[("GET", "/repos-manager/repo/repo-01")] = 500
    # Make those two the oldest-verified, as after an upgrade.
    db.execute(
        EnforcementAction.__table__.update()  # type: ignore[attr-defined]
        .where(
            EnforcementAction.kind == "disable_pr_remediation",
            EnforcementAction.target_id.in_(["proj-m00", "proj-m01"]),
        )
        .values(last_verified_at=now - timedelta(hours=5))
    )
    db.commit()
    tenant.auto_triage["proj-m03"]["enabled"] = True  # drift elsewhere
    stats = []
    for step in range(1, 17):  # four hours of 15-minute cycles
        result = evaluation.evaluate_all(
            db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * step)
        )
        v = result.pacing["verification"]
        stats.append((v.get("unverified"), v.get("held"), v.get("reasserted"), v.get("failed")))
    assert tenant.auto_triage["proj-m03"]["enabled"] is False, (
        f"drift never found in 4 hours; (unverified, held, reasserted, failed) per cycle: {stats}"
    )


def test_auto_triage_charges_pin_every_project_snapshot(db: Session) -> None:
    """Residual risk (6): with attribution on, nearly every project snapshot
    shows some project's Auto Triage rise, so nearly every one carries a
    charge, and retention pins them all (for the whole consumption window).
    Nothing reads AutoTriageCharge.snapshot_id."""
    from decimal import Decimal

    from app.models.usage import AutoTriageCharge, UsageSnapshot
    from app.services import retention
    from tests.test_snapshot_thinning import _timeline

    now = utcnow()
    ids = _timeline(db, now)  # every 30 minutes for 45 days
    for snapshot_id in ids:
        db.add(
            AutoTriageCharge(
                project_id="proj-1",
                basis="observed",
                credits=Decimal("1"),
                window_start=now,
                window_end=now,
                snapshot_id=snapshot_id,
                created_at=now,
            )
        )
    db.commit()
    result = retention.prune(db, retention_days=365)
    db.commit()
    left = db.scalar(select(__import__("sqlalchemy").func.count()).select_from(UsageSnapshot))
    # Without charges: 3 days all (144) + 37 days hourly (888) + 5 daily ~ 1,040.
    assert result.thinned_snapshots > 0, (
        f"{len(ids)} snapshots, {left} left, thinned {result.thinned_snapshots}"
    )


def test_many_charge_pins_break_the_prune_query(db: Session) -> None:
    """pinned_snapshots() returns every distinct AutoTriageCharge.snapshot_id
    (one per cycle with any Auto Triage rise, kept for the whole lookback
    window), and _prune_snapshots sends them all as one NOT IN list. PostgreSQL
    (psycopg) refuses more than 65,535 parameters: at a 5-minute interval that is
    ~230 days of charges, at 2 minutes ~45 days. The retention step then fails
    every day: nothing is pruned, thinned or cleared."""
    from decimal import Decimal

    from sqlalchemy import insert

    from app.models.usage import AutoTriageCharge
    from app.services import retention

    now = utcnow()
    db.execute(
        insert(AutoTriageCharge),
        [
            {
                "project_id": "p",
                "basis": "observed",
                "credits": Decimal("1"),
                "scan_count": 0,
                "window_start": now,
                "window_end": now,
                "snapshot_id": 1_000_000 + n,
                "created_at": now,
            }
            for n in range(70_000)
        ],
    )
    db.commit()
    retention.prune(db, retention_days=365)


def test_unverified_alert_fires_for_restrictions_read_back_this_cycle(
    db: Session,
    connected,  # noqa: F811
) -> None:
    """The 2x-interval alert is decided in _plan_verification, before the
    verification pass: after downtime or a pause, the first cycle reads every
    restriction back successfully and still warns that they were not."""
    from app.models import Notification
    from tests.test_scale_pacing import tenant_with_projects

    tenant = tenant_with_projects(3)
    client = connected(tenant)
    setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
    setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
    group_limit(db)
    now = utcnow()
    evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
    later = now + timedelta(hours=5)  # the service was down for five hours
    result = evaluation.evaluate_all(db, client=client, actor=ACTOR, now=later)
    stats = result.pacing["verification"]
    assert stats["held"] == 3  # every one read back, in force
    alerts = db.scalars(
        select(Notification).where(Notification.title.like("%not read back%"))
    ).all()
    assert not alerts, [a.title for a in alerts]


def test_unreadable_rows_spend_the_write_budget_every_cycle(
    db: Session,
    connected,  # noqa: F811
) -> None:
    """Same root cause: each RECONCILE_UNVERIFIED re-apply is a budgeted
    re-assert, chosen first every cycle, so when they are at least the write
    budget a new breach elsewhere is never restricted."""
    from app.models import CreditLimit
    from app.models.enums import EntityType, PeriodType
    from tests.test_scale_pacing import applied

    tenant = _tenant(4)
    tenant.add_project(project_id="proj-x", name="solo/x", group_ids=[])
    client = connected(tenant)
    setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
    setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
    group_limit(db, actions=["pr_remediation"])
    now = utcnow()
    evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
    # The API key loses read access to repository settings (403 -> None).
    tenant.fail_requests[("GET", "/repos-manager/repo/")] = 403
    setting(db, settings_store.KEY_MAX_WRITES, 4)
    # Due (e.g. an hour later, or after an upgrade): from now on they never stop being due.
    db.execute(
        EnforcementAction.__table__.update().values(  # type: ignore[attr-defined]
            last_verified_at=now - timedelta(hours=5)
        )
    )
    db.commit()
    solo = CreditLimit(
        entity_type=EntityType.PROJECT,
        entity_id="proj-x",
        entity_label="solo/x",
        credit_limit=1,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        count_existing_usage=True,
        project_actions=["auto_triage"],
    )
    db.add(solo)
    db.commit()
    tenant.set_entity_credits(view="project", name="solo/x", credits=5, entity_id="proj-x")
    from app.services import ingestion

    ingestion.ingest_usage(db, client)
    db.commit()
    writes = []
    for step in range(1, 9):  # two hours
        result = evaluation.evaluate_all(
            db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * step)
        )
        writes.append(result.pacing["writes"])
    assert applied(db, solo.id) == 1, f"new breach never restricted; writes per cycle: {writes}"


# ------------------------------------------------------------ further tests


def test_unreadable_rows_are_reapplied_once_per_interval_and_counted(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = _tenant(2)
    client = connected(tenant)
    setting(db, settings_store.KEY_SCHEDULE_INTERVAL_MINUTES, 15)
    setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 60)
    group_limit(db, actions=["pr_remediation"])
    now = utcnow()
    evaluation.evaluate_all(db, client=client, actor=ACTOR, now=now)
    tenant.fail_requests[("GET", "/repos-manager/repo/")] = 403
    db.execute(
        EnforcementAction.__table__.update().values(  # type: ignore[attr-defined]
            last_verified_at=now - timedelta(hours=5)
        )
    )
    db.commit()
    writes = []
    unverified = []
    for step in range(1, 9):  # two hours of 15-minute cycles
        tenant.requests.clear()
        result = evaluation.evaluate_all(
            db, client=client, actor=ACTOR, now=now + timedelta(minutes=15 * step)
        )
        writes.append(
            sum(
                1 for method, path in tenant.requests if method != "GET" and "repos-manager" in path
            )
        )
        unverified.append(result.pacing["verification"]["unverified"])
    # Written again once, then not before the interval is up.
    assert writes[0] == 2 and sum(writes[1:4]) == 0, writes
    assert sum(writes) <= 2 * 2 + 2, writes
    assert unverified[0] == 2
    # Never silent: still named as not read back.
    from app.models import Notification

    alert = db.scalar(select(Notification).where(Notification.title.like("%not read back%")))
    assert alert is not None


def test_many_ids_in_retention_on_any_database(db: Session, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """G2: more pinned and more doomed ids than PostgreSQL takes as parameters
    (retention lowered from 365 to 30 days on a large history)."""
    from decimal import Decimal

    from sqlalchemy import func, insert

    from app.models.enums import UsageView
    from app.models.usage import UsageSnapshot
    from app.services import retention

    now = utcnow()
    count = 70_000
    db.execute(
        insert(UsageSnapshot),
        [
            {
                "collected_at": now - timedelta(days=31, minutes=n),
                "view_by": UsageView.ACTION.value,
                "period_param": "last_year",
                "total_credits": Decimal("1"),
                "pages_fetched": 0,
            }
            for n in range(count)
        ],
    )
    db.commit()
    ids = list(db.scalars(select(UsageSnapshot.id).order_by(UsageSnapshot.id)))
    pins = set(ids[-5:]) | {10_000_000 + n for n in range(count)}  # the oldest five
    monkeypatch.setattr(retention, "pinned_snapshots", lambda _s, _n: (pins, set(pins)))
    # The prune alone (thinning would also collapse the recent tail by hour).
    settings_store.set_value(db, settings_store.KEY_RETENTION_THIN_SNAPSHOTS, False)
    db.commit()
    result = retention.prune(db, retention_days=30)
    db.commit()
    left = db.scalar(select(func.count()).select_from(UsageSnapshot))
    assert left == 5 + retention.KEEP_RECENT_SNAPSHOTS
    assert result.usage_snapshots == count - left


def test_domain_errors_keep_their_message() -> None:
    from app.core.config import ConfigError
    from app.services import error_text
    from app.services.delivery import DeliveryError

    assert error_text.public_error(DeliveryError("SMTP authentication was rejected")) == (
        "SMTP authentication was rejected"
    )
    assert "master key" in error_text.public_error(ConfigError("The master key is wrong."))
    assert error_text.public_error(KeyError("secret")) == (
        "Unexpected error (KeyError); see the server log."
    )


def test_unknown_outcomes_failing_lifts_and_deleted_users_are_counted(
    db: Session,
    connected,  # noqa: F811
) -> None:
    from app.models import CreditLimit
    from app.models.enums import EntityType, PeriodType
    from app.models.org import CxUser
    from app.services import enforcement
    from tests.test_scale_pacing import tenant_with_projects

    tenant = tenant_with_projects(3)
    client = connected(tenant)
    limit = group_limit(db)
    user = CreditLimit(
        entity_type=EntityType.USER,
        entity_id="user-sean",
        entity_label="Sean",
        credit_limit=1,
        period_type=PeriodType.MONTHLY,
        enforce=True,
        count_existing_usage=True,
    )
    db.add(user)
    db.commit()
    evaluation.evaluate_all(db, client=client, actor=ACTOR)
    rows = db.scalars(select(EnforcementAction).where(EnforcementAction.limit_id == limit.id)).all()
    doubtful = rows[0]
    doubtful.status = EnforcementStatus.PENDING
    doubtful.undo_snapshot = {
        **(doubtful.undo_snapshot or {}),
        enforcement.OUTCOME_UNKNOWN: True,
        "enabled_before": True,
    }
    doubtful.created_at = utcnow() - timedelta(hours=5)
    db.get(CxUser, "user-sean").is_deleted = True
    db.commit()
    # The limit off, and lifting fails: still in force, counted.
    tenant.fail_requests[("PATCH", "/ai-agents-coordinator/projects/proj-m01")] = 500
    tenant.fail_requests[("PUT", "/ai-agents-coordinator/projects/proj-m01")] = 500
    tenant.fail_requests[("POST", "/ai-agents-coordinator/projects/proj-m01")] = 500
    stats = evaluation.evaluate_all(db, client=client, actor=ACTOR).pacing["verification"]
    assert stats["outcome_unknown"] >= 1
    assert stats["in_force"] >= stats["rotation"] + stats["outcome_unknown"]
    assert stats["target_deleted"] == 1  # the deleted user's restriction


def test_verified_counts_only_what_was_read_back(
    db: Session,
    connected,  # noqa: F811
) -> None:
    from tests.test_scale_pacing import tenant_with_projects

    tenant = tenant_with_projects(3)
    client = connected(tenant)
    setting(db, settings_store.KEY_VERIFY_INTERVAL_MINUTES, 0)
    group_limit(db)
    evaluation.evaluate_all(db, client=client, actor=ACTOR)
    tenant.fail_requests[("GET", "/ai-agents-coordinator/projects/proj-m00")] = 500
    stats = evaluation.evaluate_all(db, client=client, actor=ACTOR).pacing["verification"]
    assert stats["selected"] == 3 and stats["failed"] == 1
    assert stats["verified"] == 2


def test_raw_rows_of_a_released_pin_are_cleared(db: Session) -> None:
    from app.models.usage import UsageRecord, UsageSnapshot
    from app.services import retention
    from tests.test_snapshot_thinning import _timeline

    now = utcnow()
    _timeline(db, now)
    pinned = db.scalar(
        select(UsageSnapshot.id)
        .where(UsageSnapshot.collected_at <= now - timedelta(days=10))
        .order_by(UsageSnapshot.collected_at.desc())
        .limit(1)
    )
    real = retention.pinned_snapshots
    retention.pinned_snapshots = lambda s, n: tuple(  # type: ignore[assignment]
        pins | {pinned} for pins in real(s, n)
    )
    try:
        retention.prune(db, retention_days=365)
        db.commit()
    finally:
        retention.pinned_snapshots = real  # type: ignore[assignment]

    def raw_left() -> int:
        return len(
            db.scalars(
                select(UsageRecord.id).where(
                    UsageRecord.snapshot_id == pinned,
                    UsageRecord.entity_id.is_not(None),
                    UsageRecord.raw.is_not(None),
                )
            ).all()
        )

    assert raw_left() == 1  # pinned: kept, and the cursor moved past it
    retention.prune(db, retention_days=365)  # the pin released
    db.commit()
    assert raw_left() == 0
