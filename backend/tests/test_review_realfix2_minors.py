"""Second review of realfix: the smaller items.

Automation identities, the once-ever automation notice, coverage computed
with another key, the unmatched-names list (paged, overridden mappings) and
the confirmation wording. Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import Notification, UnresolvedSubject
from app.services import coverage, cycle, notifications, org_sync, settings_store
from app.services.subject_matching import is_integration_identity
from tests.test_real_tenant_usage import ACTOR, connected, live_tenant  # noqa: F401
from tests.test_review_followups import NAME, _map


class TestAutomationIdentities:
    @pytest.mark.parametrize(
        "name", ["jsmith2", "Jean-Luc", "mary_ann", "jenkinson", "Jenkins", "tokenaga", "Priya"]
    )
    def test_people_stay_people(self, name: str) -> None:
        assert not is_integration_identity(name, None)

    @pytest.mark.parametrize(
        "name",
        [
            "example-ci-bot",
            "build_bot",
            "svc-scanner",
            "scanner-svc",
            "github-actions",
            "gitlab-ci",
            "azure-pipelines",
            "jenkins",
            "renovate[bot]",
        ],
    )
    def test_automation_is_recognised(self, name: str) -> None:
        assert is_integration_identity(name, None)

    def test_an_email_always_means_a_person(self) -> None:
        assert not is_integration_identity("example-ci-bot", "ci@example.com")


class TestAutomationNoticeOnceEver:
    def test_said_once_even_after_the_notice_is_gone(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        tenant = live_tenant()
        tenant.set_user_credits(name="example-ci-bot", credits=40)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        db.expire_all()
        notice = db.scalar(
            select(Notification).where(Notification.title.like("New automation identity%"))
        )
        assert notice is not None
        # Credits are written as credits, not as a raw decimal.
        assert notice.body.startswith("40.0 credits"), notice.body
        # Cleared away (read and pruned): not raised again.
        db.execute(delete(Notification).where(Notification.id == notice.id))
        db.commit()
        cycle.run_cycle(trigger="manual")
        db.expire_all()
        assert (
            db.scalar(
                select(Notification).where(Notification.title.like("New automation identity%"))
            )
            is None
        )
        row = db.scalar(
            select(UnresolvedSubject).where(UnresolvedSubject.subject_key == "example-ci-bot")
        )
        assert row.automation_noticed_at is not None

    def test_a_long_handle_is_closed_by_its_bounded_key(
        self,
        db: Session,
        connected,  # noqa: F811
    ) -> None:
        handle = "example-ci-bot-" + "x" * 200
        tenant = live_tenant()
        tenant.set_user_credits(name=handle, credits=40)
        connected(tenant)
        notifications.notify(
            db,
            category=notifications.CATEGORY_ATTRIBUTION,
            severity="warning",
            title="Credit usage could not be matched to a user",
            dedupe_key=notifications.attribution_key(handle),
        )
        db.commit()
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        db.expire_all()
        old = db.scalar(
            select(Notification).where(
                Notification.dedupe_key
                == notifications.bounded_key(notifications.attribution_key(handle))
            )
        )
        assert old is not None and old.read_at is not None
        automation = list(
            db.scalars(
                select(Notification).where(Notification.title.like("New automation identity%"))
            )
        )
        assert len(automation) == 1


class TestCoverageOfAnotherKey:
    def test_never_returned_without_a_client_or_while_computing(self, db: Session) -> None:
        from app.services import connection as connection_service
        from tests.conftest import make_api_key
        from tests.test_enforcement_coverage import shaped_tenant

        tenant = shaped_tenant()
        connection_service.save_connection(
            db, api_key=make_api_key(tenant="example-tenant"), actor=ACTOR
        )
        db.commit()
        client = tenant.client()
        org_sync.sync_org_model(db, client)
        db.commit()
        assert coverage.current(db, client, refresh=True) is not None
        stored = coverage.cached(db)
        stored["key_fingerprint"] = "another-key"
        settings_store.set_value(db, settings_store.KEY_ENFORCEMENT_COVERAGE, stored)
        db.commit()
        assert coverage.current(db, None) is None
        assert coverage.cached_for_key(db) is None
        assert coverage._computing.acquire(blocking=False)
        try:
            assert coverage.current(db, client, refresh=True) is None
        finally:
            coverage._computing.release()
        # With the lock free it is computed with this key.
        found = coverage.current(db, client)
        assert found is not None and found["key_fingerprint"] != "another-key"


class TestUnmatchedList:
    def test_paged_and_an_overridden_mapping_says_so(
        self,
        db: Session,
        connected,  # noqa: F811
        admin_client: TestClient,
    ) -> None:
        tenant = live_tenant()
        tenant.set_entity_credits(view="project", name=NAME, credits=870)
        tenant.set_entity_credits(view="project", name="example-org/other", credits=20)
        connected(tenant)
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        _map(admin_client, "proj-tools", name="example-org/never-reported")

        def page(**params) -> list[dict]:  # type: ignore[no-untyped-def]
            response = admin_client.get("/api/usage/unmatched-entities", params=params)
            assert response.status_code == httpx.codes.OK, response.text
            return response.json()

        everything = [row["subject_key"] for row in page()]
        assert everything == [NAME, "example-org/other", "example-org/never-reported"]
        assert [row["subject_key"] for row in page(limit=1)] == [NAME]
        assert [row["subject_key"] for row in page(limit=1, offset=1)] == ["example-org/other"]
        assert [row["subject_key"] for row in page(limit=5, offset=2)] == [
            "example-org/never-reported"
        ]

        # Mapped, then the project is renamed to the reported name: the real
        # match wins, and the list says so.
        _map(admin_client, "proj-tools")
        for project in tenant.projects:
            if project["id"] == "proj-api":
                project["name"] = NAME
        cycle.run_cycle(trigger="manual", force_org_sync=True)
        rows = {row["subject_key"]: row for row in page()}
        assert rows[NAME]["overridden"] is True
        assert rows[NAME]["overridden_by"] == NAME
        body = _map(admin_client, "proj-web")
        assert "wins over a mapping" in body["confirmation"], body["confirmation"]
