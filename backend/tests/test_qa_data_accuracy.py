"""Figures that must add up, from a QA pass against a live tenant.

Every name, id and figure here is synthetic. Each class names the finding it
guards: project usage that vanished (#1), auto triage reassigned to a person
(#3), one person shown twice (#6), a credit pool that did not add up (#7),
unmatched counts that did not reconcile (#14) and deleted projects handled two
ways (#18).
"""

from __future__ import annotations

from decimal import Decimal

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import credits as credits_api
from app.db.base import utcnow
from app.models import CreditLimit, UnresolvedSubject, UsageRecord
from app.models.enums import EntityType, PeriodType, RunStatus, UsageView
from app.models.org import CxProject
from app.models.usage import CreditBalanceSnapshot
from app.services import cycle, evaluation, ingestion
from app.services import dashboard as dashboard_service
from tests.fake_tenant import action_row, populated_tenant
from tests.test_real_tenant_usage import connected  # noqa: F401


def run() -> None:
    result = cycle.run_cycle(trigger="manual", force_org_sync=True)
    assert result.status in {RunStatus.SUCCESS, RunStatus.PARTIAL}, result.errors


def latest_record(db: Session, view: UsageView, key: str) -> UsageRecord:
    db.expire_all()
    snapshot = ingestion.latest_snapshot(db, view)
    assert snapshot is not None
    record = db.scalar(
        select(UsageRecord).where(
            UsageRecord.snapshot_id == snapshot.id, UsageRecord.subject_key == key
        )
    )
    assert record is not None
    return record


# ------------------------------------------------------------------ #1


class TestProjectUsageNeverVanishes:
    def test_usage_the_project_view_does_not_return_is_shown(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant = populated_tenant()
        # Tenant wide 3,114 credits; the project rows add up to 14. The rest
        # was reported under no project row (or a row the read did not get).
        tenant.consumption["action"] = [
            action_row("Triage", credits="3114", action_type="triage", transactions=40),
        ]
        connected(tenant)
        run()

        summary = admin_client.get("/api/dashboard").json()["attribution"]
        assert Decimal(summary["tenant_total_credits"]) == Decimal("3114")
        assert Decimal(summary["projects_unreported"]) == Decimal("3100")

    def test_a_complete_project_view_reports_no_gap(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = populated_tenant()
        tenant.consumption["action"] = [
            action_row("Triage", credits="14", action_type="triage", transactions=14),
        ]
        connected(tenant)
        run()
        assert dashboard_service.attribution_summary(db).projects_unreported == 0


# ------------------------------------------------------------------ #18


class TestDeletedProjects:
    def test_a_deleted_project_is_not_matched_and_says_why_everywhere(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant = populated_tenant()
        connected(tenant)
        run()
        # Checkmarx keeps reporting a deleted project's usage under its name.
        project = db.get(CxProject, "proj-web")
        assert project is not None
        project.is_deleted = True
        db.commit()
        ingestion.ingest_usage(db, tenant.client())
        db.commit()

        # One way: it counts towards no project budget, and is labelled.
        assert latest_record(db, UsageView.PROJECT, "payments/web").entity_id is None
        labels = {row.label: row.resolved for row in dashboard_service.top_projects(db)}
        assert labels["payments/web (deleted)"] is False
        assert labels["payments/api"] is True
        projects = dashboard_service.attribution_summary(db).projects
        assert ("payments/web (deleted)", 4) in [(n, int(c)) for n, c in projects.top]
        rows = {
            row["subject_key"]: row
            for row in admin_client.get("/api/usage/unmatched-entities").json()
        }
        assert rows["payments/web"]["deleted"] is True

    def test_a_live_project_of_the_same_name_is_not_called_deleted(self, db: Session) -> None:
        db.add_all(
            [
                CxProject(id="proj-old", name="team/app", is_deleted=True),
                CxProject(id="proj-new", name="team/app"),
                CxProject(id="proj-gone", name="team/gone", is_deleted=True),
            ]
        )
        db.commit()
        assert dashboard_service.deleted_names(
            db, CxProject, ["Team/App", "team/gone", "team/never"]
        ) == {"team/gone"}


# ------------------------------------------------------------------ #6


class TestOneRowPerPerson:
    def test_handles_of_one_person_are_one_row_and_a_namesake_shows_its_handle(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = populated_tenant()
        # A separate service account that carries Alice's display name.
        tenant.add_user(
            user_id="user-mailer",
            username="svc-mailer",
            email="svc-mailer@example.com",
            first_name="Alice",
            last_name="Archer",
        )
        tenant.set_user_credits(name="svc-mailer", email="svc-mailer@example.com", credits=20)
        # A second handle of Alice's, mapped to her by an admin.
        tenant.set_user_credits(name="cx-alice-handle", credits=6)
        connected(tenant)
        run()
        handle = db.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "cx-alice-handle")
        )
        assert handle is not None
        handle.mapped_user_id = "user-alice"
        db.commit()
        ingestion.ingest_usage(db, tenant.client())
        db.commit()

        rows = [row for row in dashboard_service.top_users(db) if row.entity_id]
        alice = [row for row in rows if row.entity_id == "user-alice"]
        assert len(alice) == 1
        assert alice[0].credits == Decimal("9")
        labels = {row.entity_id: row.label for row in rows}
        assert labels["user-alice"] == "Alice Archer (alice.archer@example.com)"
        assert labels["user-mailer"] == "Alice Archer (svc-mailer@example.com)"
        assert labels["user-bob"] == "Bob Baker"


# ------------------------------------------------------------------ #7


class TestCreditPoolAddsUp:
    def seed(self, db: Session, raw: dict) -> None:
        balance = credits_api.parse_credit_balance(raw)
        assert balance is not None
        db.add(
            CreditBalanceSnapshot(
                collected_at=utcnow(),
                total_credits=balance.total,
                used_credits=balance.used,
                available_credits=balance.available,
                raw=balance.raw,
            )
        )
        db.commit()

    def test_a_gap_in_checkmarx_own_figures_is_shown_with_what_it_reports(
        self, db: Session, admin_client: TestClient
    ) -> None:
        self.seed(
            db,
            {
                "totalCredits": 1000,
                "usedCredits": 800,
                "availableCredits": 186,
                "reservedCredits": 14,
                "tenantId": "12345",
            },
        )
        pool = admin_client.get("/api/dashboard").json()["credit_pool"]
        assert Decimal(pool["unexplained"]) == Decimal("14")
        assert pool["other_figures"] == {"reservedCredits": "14"}
        # The figures themselves are shown exactly as reported.
        assert Decimal(pool["available"]) == Decimal("186")

    def test_figures_that_add_up_have_no_gap(self, db: Session) -> None:
        self.seed(db, {"totalCredits": 1000, "usedCredits": 800, "availableCredits": 200})
        assert dashboard_service.credit_pool(db).unexplained is None

    def test_a_derived_figure_is_never_a_gap(self, db: Session) -> None:
        self.seed(db, {"totalCredits": 1000, "usedCredits": 800})
        pool = dashboard_service.credit_pool(db)
        assert pool.available == Decimal("200")
        assert pool.unexplained is None


# ------------------------------------------------------------------ #14


class TestUnmatchedCountsReconcile:
    def test_the_overview_says_how_its_counts_read_on_attribution(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = populated_tenant()
        tenant.set_user_credits(name="Auto-triage", credits=10, actions={"auto_triage": 10})
        tenant.set_user_credits(name="renovate[bot]", credits=4)
        tenant.set_user_credits(name="former.colleague@example.com", credits=2)
        connected(tenant)
        run()
        row = db.scalar(
            select(UnresolvedSubject).where(
                UnresolvedSubject.subject_key == "former.colleague@example.com"
            )
        )
        assert row is not None
        row.status = "disputed"
        db.commit()

        summary = dashboard_service.attribution_summary(db)
        # Auto-triage is Checkmarx One's own and not listed on the Attribution
        # page; the bot is listed there, under Unmatched.
        assert (summary.automation, summary.automation_builtin) == (2, 1)
        # One of the people waits under Disputes, the other under Unmatched.
        assert (summary.unmatched_people, summary.unmatched_people_disputed) == (2, 1)


# ------------------------------------------------------------------ #3


class _Headroom:
    def restrict_at(self, limit: CreditLimit, *_args) -> Decimal:  # type: ignore[no-untyped-def]
        return Decimal(limit.credit_limit)


class _Index:
    headroom = _Headroom()


class TestReassignedAutoTriageNeverRestricts:
    def limit(self, *, period: str, count_existing: bool = False) -> CreditLimit:
        return CreditLimit(
            id=1,
            entity_type=EntityType.USER,
            entity_id="user-a",
            credit_limit=50,
            period_type=period,
            count_existing_usage=count_existing,
            enforce=True,
        )

    def hold(self, db: Session, limit: CreditLimit, used: str, attributed: str | None):  # type: ignore[no-untyped-def]
        from app.services.periods import current_window

        return evaluation.summary_hold(
            db,
            limit=limit,
            window=current_window(limit),
            index=_Index(),  # type: ignore[arg-type]
            credits_used=Decimal(used),
            attributed=Decimal(attributed) if attributed is not None else None,
        )

    def test_a_budget_counting_totals_is_not_restricted_on_auto_triage_alone(
        self, db: Session
    ) -> None:
        for limit in (
            self.limit(period=PeriodType.LIFETIME),
            self.limit(period=PeriodType.MONTHLY, count_existing=True),
        ):
            # 98 of the person's own, but the budget is over only with the 20.
            assert self.hold(db, limit, "118", "20") is None
            # 40 of their own: only the reassigned auto triage takes it over.
            assert self.hold(db, limit, "60", "20") == evaluation.AUTO_TRIAGE_HOLD
            assert self.hold(db, limit, "60", None) is None
