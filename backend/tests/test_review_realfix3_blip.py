"""Third review of realfix: a one-cycle unmatched blip must not lose the
period's usage. A short listing no longer soft-deletes anything (the source),
and a name whose entity disappears is kept on it until the deletion is
confirmed (ingest).

Synthetic data only (tests/fake_tenant.py).
"""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checkmarx import iam
from app.models.enums import EntityType
from app.models.org import CxProject, CxUser
from app.services import cycle, org_sync
from tests.fake_tenant import FakeTenant
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def _capped_pages(monkeypatch: pytest.MonkeyPatch, cap: int) -> None:
    """The projects listing answers fewer rows than ``limit`` asked for (a
    server-side page cap): ``client.paginate`` takes the short page as the
    last one, so the listing is silently truncated."""
    real = FakeTenant._paged

    def paged(self, rows, key, params):  # type: ignore[no-untyped-def]
        if key == "projects":
            offset = int(params.get("offset", ["0"])[0])
            return httpx.Response(
                200, json={"totalCount": len(rows), key: rows[offset : offset + cap]}
            )
        return real(self, rows, key, params)

    monkeypatch.setattr(FakeTenant, "_paged", paged)


def test_project_paging_shortfall_for_one_sync_zeroes_the_period(
    db: Session,
    connected,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    group = _limit(db, EntityType.GROUP, "grp-payments")
    cycle.run_cycle(trigger="manual")  # baselines: proj-web 4, group 12
    tenant.set_entity_credits(view="project", name="payments/web", credits=104, entity_id=None)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100
    assert _state(db, group).credits_used == 100

    # One org sync whose project listing comes back short (only the first row
    # per page): the listing is now read to its reported total, so nothing is
    # missing and nothing is soft-deleted.
    _capped_pages(monkeypatch, 1)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    db.expire_all()
    assert not db.get(CxProject, "proj-web").is_deleted
    monkeypatch.undo()
    connected(tenant)

    # The next sync is complete again; nobody spent anything since.
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    db.expire_all()
    # The 100 credits spent this period no longer count anywhere.
    assert _state(db, project).credits_used == 100, (
        _state(db, project).credits_used,
        _state(db, project).baseline_credits,
    )
    assert _state(db, group).credits_used == 100


def test_iam_user_shortfall_for_one_sync_zeroes_the_period(
    db: Session,
    connected,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    bob = _limit(db, EntityType.USER, "user-bob")
    cycle.run_cycle(trigger="manual")  # baseline 5
    tenant.set_user_credits(name="Bob Baker", credits=105)
    cycle.run_cycle(trigger="manual")
    assert _state(db, bob).credits_used == 100

    real = iam.fetch_users

    def short(client, **kwargs):  # type: ignore[no-untyped-def]
        users, total, _warning = real(client, **kwargs)
        kept = [user for user in users if user.id != "user-bob"]
        # Exactly what fetch_users returns when a page comes back empty.
        return kept, total, f"IAM reported {total} users but only {len(kept)} could be read."

    monkeypatch.setattr(iam, "fetch_users", short)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    db.expire_all()
    # A short IAM listing deletes nobody, and says so.
    assert not db.get(CxUser, "user-bob").is_deleted
    from app.models import Notification

    notice = db.scalar(select(Notification).where(Notification.title.like("%org_sync%")))
    assert notice is not None and "no user it did not return" in notice.body, notice
    monkeypatch.setattr(iam, "fetch_users", real)

    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    state = _state(db, bob)
    assert state.credits_used == Decimal("100"), (state.credits_used, state.baseline_credits)


def test_org_sync_5xx_does_not_blip(
    db: Session,
    connected,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: a Checkmarx error during the project listing aborts the sync
    before anything is soft-deleted, so nothing blips."""
    tenant = live_tenant()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    project = _limit(db, EntityType.PROJECT, "proj-web")
    cycle.run_cycle(trigger="manual")
    tenant.set_entity_credits(view="project", name="payments/web", credits=104, entity_id=None)
    cycle.run_cycle(trigger="manual")

    from app.checkmarx import platform
    from app.checkmarx.errors import CheckmarxUnavailableError

    def boom(*_a, **_k):  # type: ignore[no-untyped-def]
        raise CheckmarxUnavailableError("503")

    monkeypatch.setattr(platform, "fetch_projects", boom)
    monkeypatch.setattr(org_sync.platform, "fetch_projects", boom)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    monkeypatch.undo()
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    cycle.run_cycle(trigger="manual")
    assert _state(db, project).credits_used == 100
