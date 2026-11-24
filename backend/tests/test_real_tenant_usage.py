"""What a live tenant's usage looked like, and what every page must make of it.

Synthetic data only, with the shapes and ratios observed (2026-11):

* Fusion and DAST cost far more per transaction than their listed rate (Opus
  5.5: 31,024 credits / 285 transactions against a rate of 2; DAST
  correlation: 1,568 / 10 against 14); triage (1) and remediation (3) match.
* The largest consumer was an integration identity with no email, and bots
  ("[bot]") and auto-matched people were raised as unmatched users.
* Most project credits were reported under "org/repo" names that are no
  project.
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditLogEntry, Notification
from app.models.enums import EntityType, PeriodType, RunStatus, UsageView
from app.services import connection as connection_service
from app.services import (
    cycle,
    diagnostics,
    ingestion,
    key_permissions,
    limits_service,
    org_sync,
    settings_store,
    subject_matching,
    usage_mix,
    violations,
)
from app.services import dashboard as dashboard_service
from app.services.audit import AuditActor
from tests.conftest import make_api_key
from tests.fake_tenant import FakeTenant, action_row, populated_tenant

ACTOR = AuditActor.system("test")

# The live tenant's rates, as GET /api/v1/credits/action-rates listed them.
LIVE_RATES = [
    {
        "action_type": "dast_correlation",
        "credits_per_action": "14",
        "display_name": "DAST Correlation",
        "is_active": True,
    },  # noqa: E501
    {
        "action_type": "fusion_scan_-_haiku_4.5",
        "credits_per_action": "1.5",
        "display_name": "Fusion Scan - Haiku 4.5",
        "is_active": True,
    },  # noqa: E501
    {
        "action_type": "fusion_scan_-_opus_4.7",
        "credits_per_action": "2.5",
        "display_name": "Fusion Scan - Opus 4.7",
        "is_active": True,
    },  # noqa: E501
    {
        "action_type": "fusion_scan_-_opus_5.5",
        "credits_per_action": "2",
        "display_name": "Fusion Scan - Opus 5.5",
        "is_active": True,
    },  # noqa: E501
    {
        "action_type": "remediation",
        "credits_per_action": "3",
        "display_name": "Remediation",
        "is_active": True,
    },  # noqa: E501
    {
        "action_type": "triage",
        "credits_per_action": "1",
        "display_name": "Triage",
        "is_active": True,
    },  # noqa: E501
]

# The live tenant's action dimension: credits and transactions per action.
LIVE_ACTIONS = [
    action_row(
        "Fusion Scan - Opus 5.5",
        credits="31024",
        action_type="fusion_scan_-_opus_5.5",
        transactions=285,
    ),  # noqa: E501
    action_row("Triage", credits="4559", action_type="triage", transactions=4559),
    action_row("Remediation", credits="2043", action_type="remediation", transactions=681),
    action_row("DAST Correlation", credits="1568", action_type="dast_correlation", transactions=10),  # noqa: E501
    action_row(
        "Fusion Scan - Opus 4.7",
        credits="252.5",
        action_type="fusion_scan_-_opus_4.7",
        transactions=33,
    ),  # noqa: E501
    action_row(
        "Fusion Scan - Haiku 4.5",
        credits="43.5",
        action_type="fusion_scan_-_haiku_4.5",
        transactions=8,
    ),  # noqa: E501
]


def live_tenant() -> FakeTenant:
    tenant = populated_tenant()
    tenant.action_rates = [dict(rate) for rate in LIVE_RATES]
    tenant.consumption["action"] = [dict(row) for row in LIVE_ACTIONS]
    return tenant


@pytest.fixture
def connected(db: Session, monkeypatch: pytest.MonkeyPatch):
    def connect(tenant: FakeTenant) -> FakeTenant:
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="acme-corp"), actor=ACTOR
        )
        db.commit()
        client = tenant.client()
        monkeypatch.setattr(connection_service, "get_client", lambda _session: client)
        key_permissions.discard_pending_denials()
        return tenant

    yield connect
    key_permissions.discard_pending_denials()


# ------------------------------------------------------------------ pricing


class TestPricing:
    def test_the_price_table_uses_the_feed_where_the_rate_is_wrong(
        self, db: Session, connected
    ) -> None:
        connected(live_tenant())
        assert cycle.run_cycle(trigger="manual", force_org_sync=True).status in (
            RunStatus.SUCCESS,
            RunStatus.PARTIAL,
        )
        prices = usage_mix.price_table(db)
        opus = prices["fusion_scan___opus_5.5"]
        assert opus.source == usage_mix.PRICE_OBSERVED
        assert opus.rate == Decimal("2")
        assert opus.per_transaction.quantize(Decimal("0.01")) == Decimal("108.86")
        dast = prices["dast_correlation"]
        assert dast.source == usage_mix.PRICE_OBSERVED
        assert dast.per_transaction == Decimal("156.8")
        # Where the feed agrees (within 10%), the listed rate is used.
        assert prices["triage"].source == usage_mix.PRICE_RATE
        assert prices["triage"].per_transaction == Decimal("1")
        assert prices["remediation"].source == usage_mix.PRICE_RATE
        assert prices["remediation"].per_transaction == Decimal("3")
        # Opus 4.7: rate 2.5, feed ~7.65 per transaction.
        assert prices["fusion_scan___opus_4.7"].source == usage_mix.PRICE_OBSERVED

    def test_without_a_feed_figure_the_rate_is_used(self, db: Session, connected) -> None:
        tenant = live_tenant()
        tenant.consumption["action"] = []
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        prices = usage_mix.price_table(db)
        assert prices["fusion_scan___opus_5.5"].source == usage_mix.PRICE_RATE
        assert prices["fusion_scan___opus_5.5"].per_transaction == Decimal("2")

    def test_a_breach_prices_fusion_at_what_the_feed_observed(self, db: Session, connected) -> None:
        tenant = connected(live_tenant())
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=4,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_5.5": 2},
        )
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        limits_service.create_limit(
            db,
            data=limits_service.LimitInput(
                entity_type=EntityType.PROJECT,
                entity_id="proj-web",
                credit_limit=100,
                period_type=PeriodType.MONTHLY,
                enforce=False,
            ),
            actor=ACTOR,
        )
        db.commit()
        cycle.run_cycle(trigger="manual")  # the period's baseline
        # Two more Opus 5.5 scans cost 218 credits, as on the live tenant.
        tenant.set_entity_credits(
            view="project",
            name="payments/web",
            credits=222,
            entity_id="proj-web",
            actions={"fusion_scan_-_opus_5.5": 4},
        )
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        breach = db.scalar(
            select(Notification).where(Notification.title.like("%reached its credit limit"))
        )
        assert breach is not None
        # Never "2 scans = 4 credits": the listed rate is not the price here.
        assert "= 4 credits" not in breach.body
        assert "2 scans = about 217.71 credits" in breach.body, breach.body
        assert "the average observed in the consumption feed" in breach.body
        assert "the listed rate of 2 does not match it" in breach.body

    def test_fusion_share_weighs_counts_by_what_a_transaction_costs(self) -> None:
        mix = usage_mix.UsageMix(
            credits_used=Decimal("35583"),
            transactions={"fusion": 285, "triage": 4559},
            unit_prices={"fusion": Decimal("108.86"), "triage": Decimal("1")},
        )
        # By count Fusion is 6%; by credits it is most of the spending.
        assert mix.fusion_share() > 0.8
        assert mix.fusion_is_most()
        counted = usage_mix.UsageMix(
            credits_used=Decimal("35583"), transactions={"fusion": 285, "triage": 4559}
        )
        assert counted.fusion_share() < 0.1

    def test_a_violation_says_which_price_it_used(self) -> None:
        observed = usage_mix.ActionPrice(
            Decimal("108.8561"),
            "Fusion Scan - Opus 5.5",
            usage_mix.PRICE_OBSERVED,
            rate=Decimal("2"),
            observed=Decimal("108.8561"),
        )
        found = violations._fusion_price("opus-5.5", {"fusion_scan___opus_5.5": observed})
        assert found is observed
        assert "does not match" in found.source_words()

    def test_the_dashboard_shows_the_source(self, db: Session, connected) -> None:
        connected(live_tenant())
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        rows = {row.action_type: row for row in dashboard_service.action_breakdown(db)}
        assert set(rows) >= {"Fusion Scan - Opus 5.5", "Triage", "DAST Correlation"}
        opus = rows["Fusion Scan - Opus 5.5"]
        assert opus.price_source == "observed" and opus.listed_rate == Decimal("2")
        assert opus.credits_per_transaction == Decimal("108.86")
        assert opus.action_bucket == "fusion"
        assert rows["Triage"].price_source == "rate"


# ------------------------------------------------------------- people


def people_tenant() -> FakeTenant:
    tenant = live_tenant()
    # An integration identity: one handle, no email (62% of credits live).
    tenant.set_user_credits(name="acme-scm-integration", credits=24350)
    tenant.set_user_credits(name="renovate[bot]", credits=860)
    # A person the fuzzy matcher attributes (to Alice Archer).
    tenant.set_user_credits(name="alice.archer-cx", credits=12)
    return tenant


class TestUnmatchedPeople:
    def test_integration_identities(self) -> None:
        assert subject_matching.is_integration_identity("acme-scm-integration", None)
        assert not subject_matching.is_integration_identity("Jane Example", None)
        assert not subject_matching.is_integration_identity("jane@example.com", None)
        assert not subject_matching.is_integration_identity("jane", "jane@example.com")
        outcome = subject_matching.classify(
            subject_key="acme-scm-integration",
            name="acme-scm-integration",
            email=None,
            profiles=(),
            integrations=True,
        )
        assert outcome.is_bot and outcome.counted_user_id is None
        # Scan initiators (a bare login) are not classified this way.
        assert not subject_matching.classify(
            subject_key="jdoe", name="jdoe", email=None, profiles=()
        ).is_bot

    def test_one_number_everywhere_and_no_notice_for_automation(
        self, db: Session, connected, admin_client: TestClient
    ) -> None:
        connected(people_tenant())
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        stats = result.steps["ingest"]["user"]
        assert stats["automated"] == 2
        assert Decimal(stats["automated_credits"]) == Decimal("25210")
        db.expire_all()

        titles = list(
            db.scalars(
                select(Notification.title).where(
                    Notification.title.like("Credit usage could not be matched%")
                )
            )
        )
        # Only the person nothing matched; not the integration, the bot or the
        # auto-matched person.
        assert titles == [
            "Credit usage could not be matched to a user: departed.person@example.com"
        ]

        dashboard = admin_client.get("/api/dashboard").json()
        status = admin_client.get("/api/ops/status").json()
        diag = {c["key"]: c for c in admin_client.get("/api/ops/diagnostics").json()["checks"]}
        assert dashboard["tiles"]["unresolved_subjects"] == 1
        assert status["unresolved_subjects"] == 1
        assert diag["attribution"]["detail"].startswith("1 consumer(s) could not be matched")
        assert "2 automation identities" in diag["attribution"]["detail"]

        # Automation stays visible on the dashboard.
        users = {row["label"]: row for row in dashboard["top_users"]}
        assert users["acme-scm-integration"]["automation"] is True
        assert users["renovate[bot]"]["automation"] is True
        assert users["departed.person@example.com"]["automation"] is False
        summary = dashboard["attribution"]
        assert summary["automation"] == 2
        assert Decimal(summary["automation_credits"]) == Decimal("25210")
        assert summary["unmatched_people"] == 1

    def test_a_cycle_does_not_warn_about_merged_duplicates(
        self, db: Session, connected, caplog: pytest.LogCaptureFixture
    ) -> None:
        tenant = connected(people_tenant())
        # The same person twice (email and display name), as the live feed does.
        rows = tenant.consumption["user"]
        rows.append(dict(rows[0]))
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert not any("distinct subjects" in record.message for record in caplog.records)
        assert not any(
            "returned" in record.message and record.levelname == "WARNING"
            for record in caplog.records
            if record.name == "app.services.ingestion"
        )


# ------------------------------------------------------------- projects


class TestUnmatchedProjects:
    def _tenant(self) -> FakeTenant:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name="example-org/payments-api", credits=870)
        tenant.set_entity_credits(view="application", name="Gone App", credits=5)
        return tenant

    def test_counted_and_explained(self, db: Session, connected, admin_client: TestClient) -> None:
        connected(self._tenant())
        result = cycle.run_cycle(trigger="manual", force_org_sync=True)
        project = result.steps["ingest"]["project"]
        assert project["unmatched_entities"] == 1
        assert Decimal(project["unmatched_credits"]) == Decimal("870")
        assert result.steps["ingest"]["application"]["unmatched_entities"] == 1

        summary = admin_client.get("/api/dashboard").json()["attribution"]
        assert summary["projects"]["count"] == 1
        assert Decimal(summary["projects"]["credits"]) == Decimal("870")
        assert summary["projects"]["top"][0]["name"] == "example-org/payments-api"
        assert summary["applications"]["count"] == 1

        check = {c.key: c for c in diagnostics.run_diagnostics(db).checks}["unmatched_entities"]
        assert check.status == diagnostics.WARN
        assert "repository name that matches no project" in check.detail
        assert "example-org/payments-api" in check.detail

    def test_viewers_cannot_map(self, viewer_client: TestClient) -> None:
        assert viewer_client.get("/api/usage/unmatched-entities").status_code == 403
        response = viewer_client.post(
            "/api/usage/unmatched-entities/map",
            json={"view": "project", "subject_key": "x/y", "entity_id": None},
        )
        assert response.status_code == 403

    def test_an_admin_maps_a_name_to_a_project(
        self, db: Session, connected, admin_client: TestClient
    ) -> None:
        connected(self._tenant())
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        listed = admin_client.get("/api/usage/unmatched-entities").json()
        assert {row["subject_key"] for row in listed} >= {"example-org/payments-api"}

        response = admin_client.post(
            "/api/usage/unmatched-entities/map",
            json={
                "view": "project",
                "subject_key": "example-org/payments-api",
                "entity_id": "proj-api",
            },
        )
        assert response.status_code == httpx.codes.OK, response.text
        assert response.json()["mapped_label"] == "payments/api"
        db.expire_all()
        # At once on the latest reading...
        assert ingestion.latest_totals(db, UsageView.PROJECT)["proj-api"] == Decimal("878")
        # ...and on every later one.
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        assert ingestion.latest_totals(db, UsageView.PROJECT)["proj-api"] == Decimal("878")
        assert settings_store.entity_mappings(db)["project"] == {
            "example-org/payments-api": "proj-api"
        }
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.action == "usage.entity_mapped")
            )
            == 1
        )
        # Cleared again.
        admin_client.post(
            "/api/usage/unmatched-entities/map",
            json={"view": "project", "subject_key": "example-org/payments-api", "entity_id": None},
        )
        db.expire_all()
        assert ingestion.latest_totals(db, UsageView.PROJECT)["proj-api"] == Decimal("8")

    def test_an_unknown_project_is_refused(self, connected, admin_client: TestClient) -> None:
        connected(self._tenant())
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        response = admin_client.post(
            "/api/usage/unmatched-entities/map",
            json={"view": "project", "subject_key": "x/y", "entity_id": "nope"},
        )
        assert response.status_code == httpx.codes.BAD_REQUEST


# ------------------------------------------------------------- the rest


class TestGroupNames:
    def test_reported_once_as_a_warning_and_kept_for_diagnostics(
        self, db: Session, connected
    ) -> None:
        tenant = live_tenant()
        tenant.add_group(group_id="g-a", name="Demo Group", path="/a/Demo Group")
        tenant.add_group(group_id="g-b", name="Demo Group", path="/b/Demo Group")
        connected(tenant)
        statuses = [cycle.run_cycle(trigger="manual", force_org_sync=True).status for _ in range(3)]
        assert RunStatus.PARTIAL not in statuses
        notices = list(
            db.scalars(select(Notification).where(Notification.title.like("%not unique%")))
        )
        assert len(notices) == 1 and notices[0].severity == "warning"
        check = {c.key: c for c in diagnostics.run_diagnostics(db).checks}["group_names"]
        assert check.status == diagnostics.WARN and "demo group" in check.detail
        # A different set is news again.
        tenant.add_group(group_id="g-c", name="Ops", path="/a/Ops")
        tenant.add_group(group_id="g-d", name="Ops", path="/b/Ops")
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        assert (
            db.scalar(
                select(func.count())
                .select_from(Notification)
                .where(Notification.title.like("%not unique%"))
            )
            == 2
        )


class TestCreditInfo:
    def test_checkmarx_enforcement_is_shown_read_only(
        self, db: Session, connected, admin_client: TestClient
    ) -> None:
        tenant = live_tenant()
        tenant.credit_info = {
            "available": "6313",
            "total": "41000",
            "used": "34687",
            "actionsAvailable": 1578,
            "actionsPerformed": 5576,
            "enforcement": {
                "state": "warning",
                "consumptionPct": 85,
                "warningThresholdPct": 80,
                "cutoffThresholdPct": 100,
            },
        }
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        pool = admin_client.get("/api/dashboard").json()["credit_pool"]
        assert Decimal(pool["total"]) == Decimal("41000")
        assert pool["checkmarx_enforcement"] == {
            "state": "warning",
            "consumptionPct": 85,
            "warningThresholdPct": 80,
            "cutoffThresholdPct": 100,
        }

    def test_dimensions_include_group(self, admin_client: TestClient) -> None:
        assert "group" in admin_client.get("/api/usage/dimensions").json()


class TestHealth:
    def test_a_scheduler_that_never_started_is_not_alive(self, client: TestClient) -> None:
        assert client.get("/healthz").json()["scheduler_alive"] is False


class TestKeyPermissionWording:
    def test_ok_says_writes_were_not_tested_and_roles_are_server_side(
        self, db: Session, connected
    ) -> None:
        connected(live_tenant())
        org_sync.sync_org_model(db, connection_service.get_client(db))
        db.commit()
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        assessed = key_permissions.assess(report, key_permissions.current_context(db))
        assert "were not tested" in assessed["summary"]
        assert "every permission" not in assessed["summary"]
        roles = assessed["explanation"]["roles"]
        assert any("applies the roles of the user who owns" in line for line in roles)

    def test_the_repository_read_finds_a_project_with_a_repository(
        self, db: Session, connected
    ) -> None:
        tenant = FakeTenant()
        # Nothing synced yet (as when the connection is saved), and the first
        # project the listing returns has no repository id.
        tenant.add_project(project_id="p-1", name="cli/upload")
        tenant.add_project(project_id="p-2", name="org/repo", repo_id=4242)
        connected(tenant)
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        checks = {entry["id"]: entry for entry in report["checks"]}
        assert checks["repo_read"]["status"] == "ok"

    def test_a_repository_read_that_cannot_be_used_is_not_ok(self, db: Session, connected) -> None:
        tenant = live_tenant()
        tenant.repo_severities_shape = "string"
        connected(tenant)
        report = key_permissions.run_check(db, trigger=key_permissions.TRIGGER_MANUAL, actor=ACTOR)
        checks = {entry["id"]: entry for entry in report["checks"]}
        assert checks["repo_read"]["status"] == "error"
        assert "could not be used" in checks["repo_read"]["detail"]
