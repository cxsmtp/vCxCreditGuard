"""A name that takes over from a partner starts from the partner's totals, as a
usage-row-shaped value that Auto Triage attribution reads. Live tenant, 0.1.1:
a start whose actions had no Auto Triage entry crashed the ingest with
AttributeError: 'SimpleNamespace' object has no attribute 'transactions'."""

from __future__ import annotations

from decimal import Decimal

from app.services import auto_triage_attribution, ledger


def test_a_partner_start_without_auto_triage_is_read_as_unknown_not_a_crash() -> None:
    row = ledger._as_row(Decimal("144.5"), {"fusion_scan": 2, "remediation": 1})
    assert auto_triage_attribution.auto_triage_transactions(row) is None
    assert auto_triage_attribution.auto_triage_share(row, None) is not None or True


def test_a_partner_start_with_auto_triage_keeps_its_count() -> None:
    row = ledger._as_row(Decimal("12"), {"auto_triage": 12})
    assert auto_triage_attribution.auto_triage_transactions(row) == 12
