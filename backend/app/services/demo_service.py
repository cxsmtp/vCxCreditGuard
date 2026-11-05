"""Demo data: a self-contained synthetic tenant for trying CxCreditGuard without
a live Checkmarx connection.

Seeding writes a small, believable organisation (users, groups, projects, an
application), a usage snapshot per dimension, and a couple of sample limits, all
with ids prefixed ``demo-`` so clearing removes exactly what was seeded and never
touches real synced data. Demo mode itself (a setting) also suppresses real
enforcement, so flipping it on is safe even against a connected tenant.
"""

from __future__ import annotations

import logging
from decimal import Decimal

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import EntityType, PeriodType, UsageView
from app.models.limits import CreditLimit, EnforcementAction, Exemption
from app.models.org import (
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.usage import UsageRecord, UsageSnapshot
from app.services.settings_store import DEMO_PERIOD_PARAM

logger = logging.getLogger(__name__)

DEMO_PREFIX = "demo-"

_USERS = [
    ("demo-user-ada", "Ada", "Lovelace", "ada.lovelace@demo.example", Decimal("420")),
    ("demo-user-alan", "Alan", "Turing", "alan.turing@demo.example", Decimal("1180")),
    ("demo-user-grace", "Grace", "Hopper", "grace.hopper@demo.example", Decimal("95")),
]
_GROUPS = [("demo-grp-platform", "Platform"), ("demo-grp-payments", "Payments")]
_PROJECTS = [
    ("demo-proj-web", "payments/web", "demo-grp-payments", "demo-repo-1", Decimal("760")),
    ("demo-proj-api", "payments/api", "demo-grp-payments", None, Decimal("540")),
    ("demo-proj-infra", "platform/infra", "demo-grp-platform", "demo-repo-2", Decimal("210")),
]
_APPS = [("demo-app-payments", "Payments", ["demo-proj-web", "demo-proj-api"], Decimal("1300"))]


def is_seeded(session: Session) -> bool:
    return (
        session.scalar(select(CxUser.id).where(CxUser.id.like(f"{DEMO_PREFIX}%")).limit(1))
        is not None
    )


def seed(session: Session) -> None:
    """Populate the synthetic demo dataset (idempotent: clears first)."""
    clear(session)
    now = utcnow()

    for gid, name in _GROUPS:
        session.add(CxGroup(id=gid, name=name, last_synced_at=now))
    for uid, first, last, email, _ in _USERS:
        session.add(
            CxUser(
                id=uid,
                username=email.split("@")[0],
                email=email,
                first_name=first,
                last_name=last,
                last_synced_at=now,
            )
        )
    for pid, name, _group_id, repo_id, _ in _PROJECTS:
        session.add(
            CxProject(
                id=pid,
                name=name,
                repo_id=repo_id,
                auto_triage_enabled=True,
                last_synced_at=now,
            )
        )
    for aid, name, _project_ids, _ in _APPS:
        session.add(CxApplication(id=aid, name=name, last_synced_at=now))
    # Flush the entities before any row that references them by foreign key: the
    # link tables use plain FK columns, so SQLAlchemy does not know to order them.
    session.flush()

    for pid, _name, group_id, _repo_id, _ in _PROJECTS:
        session.add(CxProjectGroup(project_id=pid, group_id=group_id, last_synced_at=now))
    for aid, _name, project_ids, _ in _APPS:
        for pid in project_ids:
            session.add(
                CxApplicationProject(application_id=aid, project_id=pid, last_synced_at=now)
            )
    # Put every demo user in the Payments group so group usage rolls up.
    for uid, *_ in _USERS:
        session.add(
            CxGroupMembership(group_id="demo-grp-payments", user_id=uid, last_synced_at=now)
        )

    _seed_usage(session, now=now)

    # A couple of sample limits so the governance surfaces are populated.
    session.add(
        CreditLimit(
            entity_type=EntityType.USER,
            entity_id="demo-user-alan",
            entity_label="Alan Turing",
            credit_limit=1000,
            period_type=PeriodType.MONTHLY,
            enforce=True,
            business_unit="Payments",
        )
    )
    session.add(
        CreditLimit(
            entity_type=EntityType.APPLICATION,
            entity_id="demo-app-payments",
            entity_label="Payments",
            credit_limit=2000,
            period_type=PeriodType.MONTHLY,
            business_unit="Payments",
        )
    )
    session.flush()


def _seed_usage(session: Session, *, now) -> None:  # type: ignore[no-untyped-def]
    """One snapshot per dimension, baselined a month ago so usage counts."""
    collected = now
    dimensions = {
        UsageView.USER: [(u[0], f"{u[1]} {u[2]}", u[3], u[4]) for u in _USERS],
        UsageView.PROJECT: [(p[0], p[1], None, p[4]) for p in _PROJECTS],
        UsageView.APPLICATION: [(a[0], a[1], None, a[3]) for a in _APPS],
        UsageView.GROUP: [
            ("demo-grp-payments", "Payments", None, Decimal("1510")),
            ("demo-grp-platform", "Platform", None, Decimal("210")),
        ],
    }
    for view, rows in dimensions.items():
        snapshot = UsageSnapshot(
            collected_at=collected,
            view_by=str(view),
            period_param=DEMO_PERIOD_PARAM,
            raw=[],
        )
        session.add(snapshot)
        session.flush()
        for entity_id, name, email, credits in rows:
            session.add(
                UsageRecord(
                    snapshot_id=snapshot.id,
                    view_by=str(view),
                    subject_key=entity_id,
                    subject_name=name,
                    subject_email=email,
                    entity_type=_entity_type_for(view),
                    entity_id=entity_id,
                    credits_used=credits,
                )
            )
    session.flush()


def _entity_type_for(view: UsageView) -> str:
    return {
        UsageView.USER: EntityType.USER,
        UsageView.PROJECT: EntityType.PROJECT,
        UsageView.APPLICATION: EntityType.APPLICATION,
        UsageView.GROUP: EntityType.GROUP,
    }[view]


def clear(session: Session) -> None:
    """Remove every demo row. Safe to call when nothing is seeded."""
    # Usage first (records reference snapshots).
    demo_snapshot_ids = list(
        session.scalars(
            select(UsageSnapshot.id).where(UsageSnapshot.period_param == DEMO_PERIOD_PARAM)
        )
    )
    if demo_snapshot_ids:
        session.execute(delete(UsageRecord).where(UsageRecord.snapshot_id.in_(demo_snapshot_ids)))
        session.execute(delete(UsageSnapshot).where(UsageSnapshot.id.in_(demo_snapshot_ids)))

    # Limits/links on demo entities, then the entities themselves. Enforcement
    # actions and exemptions on demo entities are cleared too (they only arise via
    # demo evaluation or a hand-added override) so no orphan survives.
    session.execute(
        delete(EnforcementAction).where(EnforcementAction.entity_id.like(f"{DEMO_PREFIX}%"))
    )
    session.execute(delete(Exemption).where(Exemption.entity_id.like(f"{DEMO_PREFIX}%")))
    session.execute(delete(CreditLimit).where(CreditLimit.entity_id.like(f"{DEMO_PREFIX}%")))
    session.execute(
        delete(CxGroupMembership).where(CxGroupMembership.user_id.like(f"{DEMO_PREFIX}%"))
    )
    session.execute(delete(CxProjectGroup).where(CxProjectGroup.project_id.like(f"{DEMO_PREFIX}%")))
    session.execute(
        delete(CxApplicationProject).where(
            CxApplicationProject.application_id.like(f"{DEMO_PREFIX}%")
        )
    )
    session.execute(delete(CxUser).where(CxUser.id.like(f"{DEMO_PREFIX}%")))
    session.execute(delete(CxProject).where(CxProject.id.like(f"{DEMO_PREFIX}%")))
    session.execute(delete(CxApplication).where(CxApplication.id.like(f"{DEMO_PREFIX}%")))
    session.execute(delete(CxGroup).where(CxGroup.id.like(f"{DEMO_PREFIX}%")))
    session.flush()
