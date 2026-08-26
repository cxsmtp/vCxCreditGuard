"""Populate a local database with representative data for a demo or screenshots.

Development helper only. It writes an organisation model, usage snapshots, limits,
notifications and audit entries directly, so the GUI can be exercised end to end
without a Checkmarx One tenant. It never calls Checkmarx and never enforces
anything.

    python -m scripts.seed_demo --admin-password 'Str0ng!Demo#Pass'

Then start the app and sign in as `demo-admin`.
"""

from __future__ import annotations

import argparse
import random
import sys
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.logging import configure_logging  # noqa: E402
from app.db.base import utcnow  # noqa: E402
from app.db.migrate import upgrade_to_head  # noqa: E402
from app.db.session import session_scope  # noqa: E402
from app.models.audit import Notification  # noqa: E402
from app.models.enums import (  # noqa: E402
    EntityType,
    LimitStatus,
    PeriodType,
    Severity,
    UsageView,
    UtilityRole,
)
from app.models.limits import CreditLimit, LimitPeriodState  # noqa: E402
from app.models.org import (  # noqa: E402
    CxApplication,
    CxApplicationProject,
    CxGroup,
    CxGroupMembership,
    CxProject,
    CxProjectGroup,
    CxUser,
)
from app.models.usage import UnresolvedSubject, UsageRecord, UsageSnapshot  # noqa: E402
from app.services import auth as auth_service  # noqa: E402
from app.services import notifications as notification_service  # noqa: E402
from app.services.audit import AuditActor, record_audit  # noqa: E402
from app.services.periods import current_window  # noqa: E402

USERS = [
    ("u-harsh", "harsh.gokani@example.com", "Harsh", "Gokani", ["Platform"], 148),
    ("u-sean", "sean.casey@example.com", "Sean", "Casey", ["Payments"], 96),
    ("u-akash", "akash.singh@example.com", "Akash", "Singh", ["Platform", "Payments"], 61),
    ("u-tiago", "tiago.torre@example.com", "Tiago", "Torre", ["Payments"], 44),
    ("u-jeremy", "jeremy.polansky@example.com", "Jeremy", "Polansky", ["Mobile"], 31),
    ("u-avery", "avery.speller@example.com", "Avery", "Speller", ["Mobile"], 22),
    ("u-frank", "frank.emery@example.com", "Frank", "Emery", ["Platform"], 12),
    ("u-julien", "julien.bruinaud@example.com", "Julien", "Bruinaud", ["Payments"], 7),
]

GROUPS = [("g-platform", "Platform"), ("g-payments", "Payments"), ("g-mobile", "Mobile")]

PROJECTS = [
    ("p-api", "payments/api", "g-payments", "repo-api", 132),
    ("p-web", "payments/web", "g-payments", "repo-web", 88),
    ("p-tools", "platform/tools", "g-platform", None, 74),
    ("p-infra", "platform/infra", "g-platform", "repo-infra", 51),
    ("p-android", "mobile/android", "g-mobile", None, 39),
    ("p-ios", "mobile/ios", "g-mobile", None, 17),
]

APPLICATIONS = [
    ("a-payments", "Payments platform", ["p-api", "p-web"], 220),
    ("a-internal", "Internal tooling", ["p-tools", "p-infra"], 125),
    ("a-mobile", "Mobile apps", ["p-android", "p-ios"], 56),
]

ACTIONS = [("triage", 268, 268), ("remediation", 141, 47), ("auto_triage", 62, 62)]
# The tenant total has to equal the sum of the action rows, or the dashboard tile
# and the breakdown percentages disagree with each other.
FINAL_TOTAL = Decimal(sum(credits for _action, credits, _transactions in ACTIONS))
POLL_COUNT = 24


def seed(admin_username: str, admin_password: str | None) -> None:
    upgrade_to_head()
    random.seed(20260811)

    with session_scope() as session:
        if session.query(CxUser).count() > 0:
            print("This database already has organisation data. Refusing to seed twice.")
            return

        now = utcnow()
        actor = AuditActor.system("seed_demo")

        for group_id, name in GROUPS:
            session.add(
                CxGroup(
                    id=group_id, name=name, path=f"/{name}", last_synced_at=now, is_deleted=False
                )
            )
        session.flush()

        group_by_name = {name: group_id for group_id, name in GROUPS}
        for user_id, email, first, last, groups, _credits in USERS:
            session.add(
                CxUser(
                    id=user_id,
                    username=email,
                    email=email,
                    first_name=first,
                    last_name=last,
                    enabled=True,
                    auth_provider="saml",
                    role_names=[
                        "view-projects",
                        "view-scans",
                        "view-risk-management",
                        "view-risk-management-dashboard",
                        "view-risk-management-tab",
                    ],
                    group_names=groups,
                    last_synced_at=now,
                    is_deleted=False,
                )
            )
        session.flush()

        for user_id, _email, _first, _last, groups, _credits in USERS:
            for group_name in groups:
                session.add(
                    CxGroupMembership(
                        group_id=group_by_name[group_name], user_id=user_id, last_synced_at=now
                    )
                )

        for project_id, name, group_id, repo_id, _credits in PROJECTS:
            session.add(
                CxProject(
                    id=project_id,
                    name=name,
                    repo_id=repo_id,
                    repo_url=f"https://github.com/example/{name.replace('/', '-')}",
                    auto_triage_enabled=True,
                    last_synced_at=now,
                    is_deleted=False,
                )
            )
            session.add(
                CxProjectGroup(project_id=project_id, group_id=group_id, last_synced_at=now)
            )

        for app_id, name, project_ids, _credits in APPLICATIONS:
            session.add(CxApplication(id=app_id, name=name, last_synced_at=now, is_deleted=False))
            for project_id in project_ids:
                session.add(
                    CxApplicationProject(
                        application_id=app_id, project_id=project_id, last_synced_at=now
                    )
                )
        session.flush()

        # A history of polls, so the trend chart has something to draw. The series
        # is normalised to finish exactly at FINAL_TOTAL.
        steps = [Decimal(random.randint(2, 34)) for _ in range(POLL_COUNT)]
        running = Decimal("0")
        raw_cumulative: list[Decimal] = []
        for step in steps:
            running += step
            raw_cumulative.append(running)
        for index, value in enumerate(raw_cumulative):
            collected_at = now - timedelta(minutes=15 * (POLL_COUNT - 1 - index))
            cumulative = (value / running * FINAL_TOTAL).quantize(Decimal("0.01"))
            _write_snapshot(session, collected_at, cumulative, index == POLL_COUNT - 1)

        # One row that cannot be attributed, which is a real condition worth showing.
        session.add(
            UnresolvedSubject(
                subject_key="departed.person@example.com",
                subject_name="departed.person@example.com",
                subject_email="departed.person@example.com",
                view_by=UsageView.USER,
                credits_used=Decimal("18"),
                first_seen_at=now - timedelta(days=3),
                last_seen_at=now,
                times_seen=12,
            )
        )

        limits = [
            (EntityType.USER, "u-harsh", "Harsh Gokani", 150, True, LimitStatus.RESTRICTED, 150),
            (EntityType.USER, "u-sean", "Sean Casey", 120, False, LimitStatus.WARNED, 96),
            (EntityType.USER, "u-akash", "Akash Singh", 200, False, LimitStatus.OK, 61),
            (EntityType.PROJECT, "p-api", "payments/api", 200, True, LimitStatus.OK, 132),
            (EntityType.PROJECT, "p-web", "payments/web", 100, False, LimitStatus.WARNED, 88),
            (EntityType.GROUP, "g-payments", "Payments", 400, False, LimitStatus.OK, 220),
            (
                EntityType.APPLICATION,
                "a-payments",
                "Payments platform",
                250,
                False,
                LimitStatus.WARNED,
                220,
            ),
        ]
        for entity_type, entity_id, label, budget, enforce, status, used in limits:
            limit = CreditLimit(
                entity_type=entity_type,
                entity_id=entity_id,
                entity_label=label,
                credit_limit=budget,
                period_type=PeriodType.MONTHLY,
                warning_threshold_pct=80,
                enforce=enforce,
                is_active=True,
            )
            session.add(limit)
            session.flush()
            window = current_window(limit, now)
            session.add(
                LimitPeriodState(
                    limit_id=limit.id,
                    period_key=window.key,
                    period_start=window.start,
                    period_end=window.end,
                    credits_used=Decimal(used),
                    baseline_credits=Decimal("0"),
                    reported_total=Decimal(used),
                    usage_available=True,
                    status=status,
                    last_evaluated_at=now,
                    warned_at=now - timedelta(hours=6)
                    if status in {LimitStatus.WARNED, LimitStatus.RESTRICTED}
                    else None,
                    breached_at=now - timedelta(hours=2)
                    if status == LimitStatus.RESTRICTED
                    else None,
                    restricted_at=now - timedelta(hours=2)
                    if status == LimitStatus.RESTRICTED
                    else None,
                )
            )
            record_audit(
                session,
                action="limit.created",
                actor=actor,
                target_type="credit_limit",
                target_id=str(limit.id),
                target_label=label,
                after={"credit_limit": budget, "enforce": enforce},
                detail="Seeded demo limit.",
            )

        notification_service.notify(
            session,
            category=notification_service.CATEGORY_WARNING,
            severity=Severity.WARNING,
            title="User Sean Casey reached 80% of its credit limit",
            body="96 of 120 credits used August 2026. The warning threshold is 80%.\n"
            "This limit is monitor only, so reaching the limit will only notify.",
            entity_type=EntityType.USER,
            entity_id="u-sean",
            entity_label="Sean Casey",
            dedupe_key="demo-warn-sean",
        )
        notification_service.notify(
            session,
            category=notification_service.CATEGORY_ATTRIBUTION,
            severity=Severity.WARNING,
            title="Credit usage could not be matched to a user: departed.person@example.com",
            body="18 credits are reported against departed.person@example.com, which does not "
            "match any synced Checkmarx user.",
            dedupe_key="demo-unresolved",
        )
        session.add(
            Notification(
                created_at=now - timedelta(minutes=90),
                severity=Severity.INFO,
                category=notification_service.CATEGORY_RESTORATION,
                title="Project mobile/ios: Auto Triage re-enabled",
                body="A new budget period started, so the restriction was lifted.",
                entity_type=EntityType.PROJECT,
                entity_id="p-ios",
                entity_label="mobile/ios",
                dedupe_key="demo-restored",
                read_at=now - timedelta(minutes=45),
            )
        )

        record_audit(
            session,
            action="org.synced",
            actor=actor,
            target_type="org_model",
            after={"users": len(USERS), "groups": len(GROUPS), "projects": len(PROJECTS)},
            detail="Seeded demo organisation model.",
        )

        if admin_password:
            try:
                auth_service.create_user(
                    session,
                    username=admin_username,
                    password=admin_password,
                    role=UtilityRole.ADMIN,
                    actor=actor,
                )
                print(f"Created admin account {admin_username!r}.")
            except ValueError as exc:
                print(f"Admin account not created: {exc}")

    print("Seeded demo data. Note that no Checkmarx connection is configured, so the")
    print("Setup page will still ask for an API key and cycles will report as skipped.")


def _write_snapshot(session, collected_at, cumulative: Decimal, is_latest: bool) -> None:
    """One poll per dimension. Only the newest one needs full per entity detail."""
    scale = cumulative / FINAL_TOTAL if FINAL_TOTAL else Decimal("0")

    scaled = [
        (
            action,
            (Decimal(credits) * scale).quantize(Decimal("0.01")),
            int(transactions * float(scale)),
        )
        for action, credits, transactions in ACTIONS
    ]
    action_snapshot = UsageSnapshot(
        collected_at=collected_at,
        view_by=UsageView.ACTION,
        period_param="last_year",
        total_credits=sum((credits for _action, credits, _tx in scaled), Decimal("0")),
        total_items=len(ACTIONS),
        pages_fetched=1,
        raw=[],
    )
    session.add(action_snapshot)
    session.flush()
    for action, credits, transactions in scaled:
        session.add(
            UsageRecord(
                snapshot_id=action_snapshot.id,
                view_by=UsageView.ACTION,
                subject_key=action,
                subject_name=action,
                credits_used=credits,
                transactions=transactions,
                actions={action: transactions},
            )
        )

    if not is_latest:
        return

    for view, rows in (
        (
            UsageView.USER,
            [
                (user_id, f"{first} {last}", email, credits)
                for user_id, email, first, last, _groups, credits in USERS
            ],
        ),
        (
            UsageView.PROJECT,
            [(project_id, name, None, credits) for project_id, name, _g, _r, credits in PROJECTS],
        ),
        (
            UsageView.APPLICATION,
            [(app_id, name, None, credits) for app_id, name, _p, credits in APPLICATIONS],
        ),
    ):
        snapshot = UsageSnapshot(
            collected_at=collected_at,
            view_by=view,
            period_param="last_year",
            total_credits=Decimal(sum(row[3] for row in rows)),
            total_items=len(rows),
            pages_fetched=1,
            raw=[],
        )
        session.add(snapshot)
        session.flush()
        total = sum(row[3] for row in rows) or 1
        for entity_id, label, email, credits in rows:
            session.add(
                UsageRecord(
                    snapshot_id=snapshot.id,
                    view_by=view,
                    subject_key=(email or label).lower(),
                    subject_name=label,
                    subject_email=email,
                    entity_type=(
                        EntityType.USER
                        if view == UsageView.USER
                        else EntityType.PROJECT
                        if view == UsageView.PROJECT
                        else EntityType.APPLICATION
                    ),
                    entity_id=entity_id,
                    credits_used=Decimal(credits),
                    percent_of_total=round(credits / total * 100, 2),
                    transactions=credits,
                    actions={"triage": credits},
                )
            )
        # The unattributed row, present only in the user dimension.
        if view == UsageView.USER:
            session.add(
                UsageRecord(
                    snapshot_id=snapshot.id,
                    view_by=view,
                    subject_key="departed.person@example.com",
                    subject_name="departed.person@example.com",
                    subject_email="departed.person@example.com",
                    entity_type=EntityType.USER,
                    entity_id=None,
                    credits_used=Decimal("18"),
                    transactions=18,
                    actions={"triage": 18},
                )
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admin-username", default="demo-admin")
    parser.add_argument(
        "--admin-password",
        default=None,
        help="Creates an Admin account. Must meet the password policy.",
    )
    args = parser.parse_args()
    configure_logging("INFO")
    seed(args.admin_username, args.admin_password)


if __name__ == "__main__":
    main()
