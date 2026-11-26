"""Fifth review of realfix: when a never-reported name starts to count towards an entity, every
other name of that entity missing from the same reading is neither carried nor
remembered (``_Anchors.carry`` skips ``self.fresh``). When the missing name comes
back it looks never-reported and counts in full: its history becomes usage.

Restated for the ledger: the missing name is remembered with its last total, so
its return adds nothing. The new key appears as another name leaves, so it may
be that name renamed (the feed cannot tell): it starts from the highest total
that left, and its first credit is not counted. Under-counting one interval is
the documented price of never counting a rename's history."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import EntityType
from app.services import cycle
from tests.test_real_tenant_usage import connected, live_tenant  # noqa: F401
from tests.test_review_followups import _limit, _state


def test_blip_of_one_key_while_a_new_key_appears_counts_no_history(
    db: Session,
    connected,  # noqa: F811
) -> None:
    tenant = live_tenant()
    tenant.set_user_credits(name="Bob Baker", credits=5000, actions={"triage": 5000})
    # Enough other usage that the blip is not a collapse of the whole feed.
    tenant.set_user_credits(name="Alice Archer", email="alice.archer@example.com", credits=20000)
    connected(tenant)
    cycle.run_cycle(trigger="manual", force_org_sync=True)
    bob = _limit(db, EntityType.USER, "user-bob")
    cycle.run_cycle(trigger="manual")
    assert _state(db, bob).credits_used == 0

    # One reading: "Bob Baker" missing (a feed blip), and Bob's first use under
    # his email (a new key, 1 credit of genuinely new usage).
    rows = tenant.consumption["user"]
    saved = [r for r in rows if r["name"] == "Bob Baker"]
    tenant.consumption["user"] = [r for r in rows if r["name"] != "Bob Baker"]
    tenant.set_user_credits(name="Bob B", email="bob.baker@example.com", credits=1)
    cycle.run_cycle(trigger="manual")
    dip = _state(db, bob).credits_used

    # Next reading: the blip is over.
    tenant.consumption["user"].extend(saved)
    cycle.run_cycle(trigger="manual")
    state = _state(db, bob)
    assert (dip, state.credits_used) == (0, 0), (dip, state.credits_used, state.baseline_credits)

    # From then on the new key counts what it adds.
    tenant.set_user_credits(name="Bob B", email="bob.baker@example.com", credits=4)
    cycle.run_cycle(trigger="manual")
    assert _state(db, bob).credits_used == 3
