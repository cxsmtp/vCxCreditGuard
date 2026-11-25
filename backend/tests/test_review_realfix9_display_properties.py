"""Ninth review: random page layouts of a user feed in which two people share
the display name "Bob Baker" (no id, no email). Both are read on one page in
the first readings (no history problem), then the ranking and the page size
move at random and they spend. A budget on user-bob can never count more than
the two of them spent after it was created. Synthetic data only."""

# ruff: noqa: F811 - the connected fixture is imported by name

from __future__ import annotations

import os
import random
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from app.models.enums import EntityType
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit
from tests.test_review_realfix9_findings import _user
from tests.test_usage_ledger_round7 import _Run

SEEDS = int(os.environ.get("CXCG_RR9_SEEDS", "20"))


@pytest.mark.parametrize("seed", range(SEEDS))
def test_display_name_layouts_never_count_more_than_was_spent(
    db: Session, connected, monkeypatch, seed: int
) -> None:
    rng = random.Random(seed)
    tenant = live_tenant()
    bobs = [300, 120]
    others = {f"user{i}@example.com": rng.randint(50, 400) for i in range(4)}

    def layout(joined: bool) -> None:
        rows = [_user(email.split("@")[0], credits, email) for email, credits in others.items()]
        bob_rows = [_user("Bob Baker", credits) for credits in bobs]
        if joined:
            tenant.page_size_override = len(rows) + 2
            rows = bob_rows + rows
        else:
            rng.shuffle(rows)
            for bob in bob_rows:
                rows.insert(rng.randint(0, len(rows)), bob)
            tenant.page_size_override = rng.choice([1, 2, 3])
        tenant.consumption["user"] = rows

    layout(True)
    connected(tenant)
    run = _Run(db, monkeypatch, datetime(2027, 1, 5, 6, tzinfo=UTC))
    run.step()
    bob = _limit(db, EntityType.USER, "user-bob")
    run.step()
    spent, log = 0, []
    for _ in range(25):
        if rng.random() < 0.4:
            who = rng.randrange(2)
            amount = rng.randint(1, 30)
            bobs[who] += amount
            spent += amount
        for email in others:
            if rng.random() < 0.3:
                others[email] += rng.randint(1, 30)
        layout(rng.random() < 0.3)
        log.append((list(bobs), tenant.page_size_override))
        run.step(hours=rng.choice([0.5, 1]))
    layout(True)
    run.step()
    run.step()
    assert run.used(bob) <= spent, (seed, spent, log)
