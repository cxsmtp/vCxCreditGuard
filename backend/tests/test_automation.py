"""Hands-off automation: auto-approval of pending credit requests within a cap."""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit import Notification
from app.models.enums import EntityType, PeriodType, RequestStatus
from app.models.limits import CreditLimit, CreditRequest
from app.services import limits_service, requests_service, settings_store
from app.services.audit import AuditActor

ACTOR = AuditActor.system("test")


def _request(db: Session, *, entity_id: str, requested: int, label: str = "User") -> CreditRequest:
    req = requests_service.create_request(
        db,
        data=requests_service.RequestInput(
            entity_type=EntityType.USER, entity_id=entity_id, requested_limit=requested
        ),
        actor=ACTOR,
    )
    req.entity_label = label
    db.flush()
    return req


def _limit(db: Session, *, entity_id: str, credit_limit: int) -> CreditLimit:
    return limits_service.create_limit(
        db,
        data=limits_service.LimitInput(
            entity_type=EntityType.USER,
            entity_id=entity_id,
            credit_limit=credit_limit,
            period_type=PeriodType.MONTHLY,
        ),
        actor=ACTOR,
    )


def _enable(db: Session, *, cap: int, expiry_days: int = 0) -> None:
    settings_store.set_value(db, settings_store.KEY_AUTOMATION_ENABLED, True)
    settings_store.set_value(db, settings_store.KEY_AUTO_APPROVE_MAX_INCREASE, cap)
    settings_store.set_value(db, settings_store.KEY_AUTO_APPROVE_EXPIRY_DAYS, expiry_days)
    db.flush()


class TestPolicyGating:
    def test_disabled_does_nothing(self, db: Session) -> None:
        _limit(db, entity_id="u1", credit_limit=100)
        req = _request(db, entity_id="u1", requested=150)
        db.commit()
        stats = requests_service.auto_decide_pending(db)
        assert stats["auto_approved"] == 0
        db.refresh(req)
        assert req.status == RequestStatus.PENDING

    def test_enabled_with_zero_cap_does_nothing(self, db: Session) -> None:
        _limit(db, entity_id="u1", credit_limit=100)
        req = _request(db, entity_id="u1", requested=150)
        _enable(db, cap=0)
        db.commit()
        stats = requests_service.auto_decide_pending(db)
        assert stats["auto_approved"] == 0
        db.refresh(req)
        assert req.status == RequestStatus.PENDING


class TestAutoApproval:
    def test_increase_within_cap_is_approved_and_raises_the_limit(self, db: Session) -> None:
        limit = _limit(db, entity_id="u1", credit_limit=100)
        req = _request(db, entity_id="u1", requested=150)  # +50
        _enable(db, cap=100)
        db.commit()

        stats = requests_service.auto_decide_pending(db)
        assert stats["auto_approved"] == 1
        db.refresh(req)
        db.refresh(limit)
        assert req.status == RequestStatus.APPROVED
        assert req.approved_limit == 150
        assert limit.credit_limit == 150
        # Operator is informed.
        note = db.scalar(select(Notification).where(Notification.category == "automation"))
        assert note is not None and "auto-approved" in note.body.lower()

    def test_increase_over_cap_is_left_for_an_admin(self, db: Session) -> None:
        _limit(db, entity_id="u1", credit_limit=100)
        req = _request(db, entity_id="u1", requested=400)  # +300
        _enable(db, cap=100)
        db.commit()

        stats = requests_service.auto_decide_pending(db)
        assert stats["auto_approved"] == 0
        assert stats["left_pending"] == 1
        db.refresh(req)
        assert req.status == RequestStatus.PENDING

    def test_new_entity_counts_the_whole_requested_amount_as_the_increase(
        self, db: Session
    ) -> None:
        # No existing limit: current budget is 0, so the increase is the full ask.
        within = _request(db, entity_id="u1", requested=80)
        over = _request(db, entity_id="u2", requested=200)
        _enable(db, cap=100)
        db.commit()

        requests_service.auto_decide_pending(db)
        db.refresh(within)
        db.refresh(over)
        assert within.status == RequestStatus.APPROVED
        assert over.status == RequestStatus.PENDING
        # The approved one created a monitor-only limit.
        created = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "u1"))
        assert created is not None and created.credit_limit == 80 and created.enforce is False

    def test_non_raise_request_is_left_pending(self, db: Session) -> None:
        _limit(db, entity_id="u1", credit_limit=200)
        req = _request(db, entity_id="u1", requested=150)  # a decrease
        _enable(db, cap=1000)
        db.commit()
        requests_service.auto_decide_pending(db)
        db.refresh(req)
        assert req.status == RequestStatus.PENDING

    def test_expiry_days_makes_the_grant_temporary(self, db: Session) -> None:
        _limit(db, entity_id="u1", credit_limit=100)
        req = _request(db, entity_id="u1", requested=150)
        _enable(db, cap=100, expiry_days=7)
        db.commit()
        requests_service.auto_decide_pending(db)
        db.refresh(req)
        assert req.status == RequestStatus.APPROVED
        assert req.expires_at is not None  # self-reverts via the grant-expiry step


class TestCapCannotCompound:
    def test_only_one_request_per_entity_is_auto_approved_per_cycle(self, db: Session) -> None:
        # Two per-cap requests for the SAME entity must not compound past the cap
        # in one cycle (each is individually within the 600 cap).
        _request(db, entity_id="u1", requested=500)
        _request(db, entity_id="u1", requested=1000)
        _enable(db, cap=600)
        db.commit()

        stats = requests_service.auto_decide_pending(db)
        assert stats["auto_approved"] == 1
        assert stats["left_pending"] == 1
        # The entity's limit rose by at most the cap, not the sum of both asks.
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "u1"))
        assert limit is not None and limit.credit_limit <= 600

    def test_a_later_cycle_can_grant_again_within_the_cap(self, db: Session) -> None:
        _request(db, entity_id="u1", requested=100)
        _enable(db, cap=600)
        db.commit()
        requests_service.auto_decide_pending(db)
        db.commit()
        # A fresh request next cycle is measured against the new budget and may grant.
        _request(db, entity_id="u1", requested=650)  # +550 over 100, within 600
        db.commit()
        requests_service.auto_decide_pending(db)
        limit = db.scalar(select(CreditLimit).where(CreditLimit.entity_id == "u1"))
        assert limit is not None and limit.credit_limit == 650


class TestPerRequestIsolation:
    def test_one_failing_request_does_not_abort_the_batch(self, db: Session, monkeypatch) -> None:
        bad = _request(db, entity_id="u1", requested=100)
        good = _request(db, entity_id="u2", requested=100)
        _enable(db, cap=600)
        db.commit()

        real_approve = requests_service.approve_request

        def flaky(session, *, request, **kwargs):
            if request.id == bad.id:
                raise RuntimeError("simulated restriction-lift failure")
            return real_approve(session, request=request, **kwargs)

        monkeypatch.setattr(requests_service, "approve_request", flaky)
        stats = requests_service.auto_decide_pending(db)

        assert stats["failed"] == 1
        assert stats["auto_approved"] == 1
        db.refresh(bad)
        db.refresh(good)
        # The failing request rolled back cleanly and stays pending; the other grants.
        assert bad.status == RequestStatus.PENDING
        assert good.status == RequestStatus.APPROVED


class TestSettingsApi:
    def test_automation_settings_round_trip(self, admin_client: TestClient) -> None:
        updated = admin_client.put(
            "/api/settings",
            json={
                "automation_enabled": True,
                "auto_approve_max_increase": 250,
                "auto_approve_expiry_days": 14,
            },
        )
        assert updated.status_code == httpx.codes.OK, updated.text
        body = updated.json()
        assert body["automation_enabled"] is True
        assert body["auto_approve_max_increase"] == 250
        assert body["auto_approve_expiry_days"] == 14
        assert admin_client.get("/api/settings").json()["auto_approve_max_increase"] == 250

    def test_negative_cap_is_rejected(self, admin_client: TestClient) -> None:
        response = admin_client.put("/api/settings", json={"auto_approve_max_increase": -5})
        assert response.status_code == httpx.codes.UNPROCESSABLE_ENTITY


def test_idempotent_second_run_approves_nothing_new(db: Session) -> None:
    _limit(db, entity_id="u1", credit_limit=100)
    _request(db, entity_id="u1", requested=150)
    _enable(db, cap=100)
    db.commit()
    first = requests_service.auto_decide_pending(db)
    db.commit()
    second = requests_service.auto_decide_pending(db)
    assert first["auto_approved"] == 1
    assert second["auto_approved"] == 0
    # One approved request, one notification.
    assert db.scalar(select(func.count()).select_from(Notification)) == 1
