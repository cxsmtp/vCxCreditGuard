"""Snapshot ingestion and attribution of credit usage."""

from __future__ import annotations

from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DimensionState, UnresolvedSubject, UsageRecord, UsageSnapshot
from app.models.audit import AuditLogEntry
from app.models.enums import UsageView
from app.services import ingestion, org_sync
from tests.fake_tenant import FakeTenant, populated_tenant


def synced(db: Session, tenant: FakeTenant):
    client = tenant.client()
    org_sync.sync_org_model(db, client)
    db.commit()
    return client


class TestSnapshots:
    def test_creates_a_snapshot_per_dimension(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        views = {row.view_by for row in db.scalars(select(UsageSnapshot))}
        assert views == {"user", "action", "application", "project", "group"}
        assert all(dimension.supported for dimension in result.dimensions.values())

    def test_records_totals_per_snapshot(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()

        snapshot = ingestion.latest_snapshot(db, UsageView.USER)
        assert snapshot is not None
        # 3 + 5 + 7 from the fixture.
        assert snapshot.total_credits == Decimal("15")
        assert snapshot.total_items == 3

    def test_raw_payloads_are_kept_for_audit(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()

        snapshot = ingestion.latest_snapshot(db, UsageView.USER)
        assert snapshot is not None
        assert snapshot.raw
        assert snapshot.raw[0]["items"]

    def test_each_poll_adds_a_new_snapshot_rather_than_overwriting(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        tenant.set_user_credits(name="Sean Casey", credits=9, actions={"triage": 9})
        ingestion.ingest_usage(db, client)
        db.commit()

        snapshots = list(db.scalars(select(UsageSnapshot).where(UsageSnapshot.view_by == "user")))
        assert len(snapshots) == 2
        assert ingestion.latest_totals(db, UsageView.USER)["user-sean"] == Decimal("9")

    def test_pagination_is_walked(self, db: Session) -> None:
        tenant = FakeTenant()
        for index in range(12):
            tenant.add_user(user_id=f"u{index}", username=f"user{index}@example.com")
            tenant.set_user_credits(name=f"user{index}@example.com", credits=1)
        tenant.page_size_override = 5
        client = synced(db, tenant)

        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert result.dimensions["user"].records == 12


class TestAttribution:
    def test_matches_on_email(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert ingestion.latest_totals(db, UsageView.USER)["user-harsh"] == Decimal("3")

    def test_matches_on_display_name_when_there_is_no_email(self, db: Session) -> None:
        """The real feed has rows with a display name and nothing else."""
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert ingestion.latest_totals(db, UsageView.USER)["user-sean"] == Decimal("5")

    def test_matches_an_email_carried_in_the_name_field(self, db: Session) -> None:
        tenant = FakeTenant()
        tenant.add_user(
            user_id="u1", username="only.name@example.com", email="only.name@example.com"
        )
        tenant.set_user_credits(name="only.name@example.com", credits=4)
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert ingestion.latest_totals(db, UsageView.USER)["u1"] == Decimal("4")

    def test_matches_on_username_when_it_is_not_an_email(self, db: Session) -> None:
        tenant = FakeTenant()
        tenant.add_user(user_id="u1", username="akash", email="akash.singh@example.com")
        tenant.set_user_credits(name="akash", credits=6)
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert ingestion.latest_totals(db, UsageView.USER)["u1"] == Decimal("6")

    def test_ambiguous_display_names_are_not_guessed(self, db: Session) -> None:
        """Two people with the same name must not share one budget."""
        tenant = FakeTenant()
        tenant.add_user(
            user_id="u1", username="sean.casey@a.com", first_name="Sean", last_name="Casey"
        )
        tenant.add_user(
            user_id="u2", username="s.casey@b.com", first_name="Sean", last_name="Casey"
        )
        tenant.set_user_credits(name="Sean Casey", credits=5)
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()

        assert ingestion.latest_totals(db, UsageView.USER) == {}
        assert db.scalar(select(UnresolvedSubject)) is not None

    def test_unmatched_subjects_are_recorded_not_dropped(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        row = db.scalar(
            select(UnresolvedSubject).where(
                UnresolvedSubject.subject_key == "departed.person@checkmarx.com"
            )
        )
        assert row is not None
        assert row.credits_used == Decimal("7")
        assert result.dimensions["user"].unresolved == 1
        # The usage record still exists, just without an entity.
        record = db.scalar(
            select(UsageRecord).where(UsageRecord.subject_key == "departed.person@checkmarx.com")
        )
        assert record is not None
        assert record.entity_id is None

    def test_repeated_unresolved_subjects_increment_a_counter(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        ingestion.ingest_usage(db, client)
        db.commit()

        row = db.scalar(
            select(UnresolvedSubject).where(
                UnresolvedSubject.subject_key == "departed.person@checkmarx.com"
            )
        )
        assert row is not None
        assert row.times_seen == 2

    def test_an_admin_pinned_mapping_resolves_the_subject(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()

        row = db.scalar(
            select(UnresolvedSubject).where(
                UnresolvedSubject.subject_key == "departed.person@checkmarx.com"
            )
        )
        assert row is not None
        row.mapped_user_id = "user-akash"
        db.commit()

        ingestion.ingest_usage(db, client)
        db.commit()
        assert ingestion.latest_totals(db, UsageView.USER)["user-akash"] == Decimal("7")

    def test_applications_and_projects_match_by_id_then_name(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()

        assert ingestion.latest_totals(db, UsageView.APPLICATION)["app-payments"] == Decimal("12")
        projects = ingestion.latest_totals(db, UsageView.PROJECT)
        assert projects["proj-api"] == Decimal("8")
        assert projects["proj-web"] == Decimal("4")

    def test_projects_match_by_name_when_no_id_is_reported(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.consumption["project"] = [{"name": "payments/api", "creditsUsed": 15}]
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert ingestion.latest_totals(db, UsageView.PROJECT)["proj-api"] == Decimal("15")

    def test_the_action_dimension_has_no_entity(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        records = list(db.scalars(select(UsageRecord).where(UsageRecord.view_by == "action")))
        assert records
        assert all(record.entity_id is None for record in records)
        assert {record.subject_key for record in records} == {"triage", "remediation"}


class TestDimensionProbing:
    def test_an_unsupported_dimension_is_recorded_and_not_retried(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.unsupported_views.add("project")
        client = synced(db, tenant)

        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert result.dimensions["project"].supported is False
        assert any("does not report consumption by project" in w for w in result.warnings)
        assert db.get(DimensionState, "project").supported is False

        # Second pass must not call the endpoint again.
        tenant.requests.clear()
        ingestion.ingest_usage(db, client)
        db.commit()
        consumption_calls = [
            path for _method, path in tenant.requests if path.endswith("/credits/consumption")
        ]
        assert consumption_calls  # other dimensions still polled
        assert ingestion.dimension_supported(db, UsageView.PROJECT) is False

    def test_one_unsupported_dimension_does_not_stop_the_others(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.unsupported_views.add("project")
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert result.dimensions["user"].records == 3
        assert result.dimensions["application"].records == 1

    def test_a_permission_failure_is_reported_distinctly(self, db: Session) -> None:
        tenant = populated_tenant()
        tenant.fail_paths["/credits/consumption"] = 403
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()
        assert any("not permitted" in warning for warning in result.warnings)

    def test_supported_dimensions_are_marked_supported(self, db: Session) -> None:
        tenant = populated_tenant()
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert db.get(DimensionState, "user").supported is True
        assert ingestion.dimension_supported(db, UsageView.USER) is True


class TestFuzzyAttribution:
    """The similarity fall-through for handles the exact ladder cannot resolve."""

    def _tenant_with_handle(self, reported_as: str, credits: int = 4) -> FakeTenant:
        tenant = FakeTenant()
        tenant.add_user(
            user_id="user-ryan",
            username="ryan.wakeham@checkmarx.com",
            email="ryan.wakeham@checkmarx.com",
            first_name="Ryan",
            last_name="Wakeham",
        )
        tenant.set_user_credits(name=reported_as, credits=credits)
        return tenant

    def test_a_cx_handle_is_auto_matched_to_its_user(self, db: Session) -> None:
        tenant = self._tenant_with_handle("cx-ryan-wakeham")
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        # Its credits count towards the user, and it is not flagged as unmatched.
        assert ingestion.latest_totals(db, UsageView.USER)["user-ryan"] == Decimal("4")
        assert result.dimensions["user"].auto_matched == 1
        assert result.dimensions["user"].unresolved == 0

        row = db.scalar(select(UnresolvedSubject))
        assert row is not None
        assert row.status == "auto_matched"
        assert row.suggested_user_id == "user-ryan"
        assert row.match_score == 1.0

    def test_an_auto_match_is_audited_once(self, db: Session) -> None:
        tenant = self._tenant_with_handle("cx-ryan-wakeham")
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        ingestion.ingest_usage(db, client)  # steady state must not re-log
        db.commit()

        entries = list(
            db.scalars(
                select(AuditLogEntry).where(AuditLogEntry.action == "usage.subject_auto_matched")
            )
        )
        assert len(entries) == 1
        assert entries[0].after["suggested_user_id"] == "user-ryan"

    def test_a_first_name_only_is_disputed_with_suggestions(self, db: Session) -> None:
        tenant = self._tenant_with_handle("ryan")
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        # A dispute is not counted, but is surfaced for a human to confirm.
        assert ingestion.latest_totals(db, UsageView.USER) == {}
        assert result.dimensions["user"].disputed == 1
        assert result.dimensions["user"].unresolved == 1

        row = db.scalar(select(UnresolvedSubject))
        assert row is not None
        assert row.status == "disputed"
        assert row.suggestions[0]["user_id"] == "user-ryan"

    def test_a_bot_handle_is_flagged_and_not_disputed(self, db: Session) -> None:
        tenant = self._tenant_with_handle("dependabot[bot]")
        client = synced(db, tenant)
        result = ingestion.ingest_usage(db, client)
        db.commit()

        row = db.scalar(select(UnresolvedSubject))
        assert row is not None
        assert row.is_bot is True
        assert row.status == "unmatched"
        # A bot is automation, so it does not nag the unmatched-usage banner.
        assert result.dimensions["user"].unresolved == 0

    def test_a_review_row_is_cleared_once_the_subject_resolves_exactly(self, db: Session) -> None:
        # A subject reported by an email whose user has not synced yet.
        tenant = FakeTenant()
        tenant.set_user_credits(name="Ryan Wakeham", email="ryan.wakeham@checkmarx.com", credits=4)
        client = synced(db, tenant)
        ingestion.ingest_usage(db, client)
        db.commit()
        assert db.scalar(select(UnresolvedSubject)) is not None

        # Once the user is synced, the same subject resolves exactly and the
        # stale review row is dropped rather than left dangling.
        tenant.add_user(
            user_id="user-ryan",
            username="ryan.wakeham@checkmarx.com",
            email="ryan.wakeham@checkmarx.com",
            first_name="Ryan",
            last_name="Wakeham",
        )
        org_sync.sync_org_model(db, client)
        db.commit()
        ingestion.ingest_usage(db, client)
        db.commit()
        assert db.scalar(select(UnresolvedSubject)) is None
        assert ingestion.latest_totals(db, UsageView.USER)["user-ryan"] == Decimal("4")


def test_latest_totals_is_empty_before_any_ingestion(db: Session) -> None:
    assert ingestion.latest_totals(db, UsageView.USER) == {}
