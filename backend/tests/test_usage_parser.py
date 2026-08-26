"""Parsing of GET /api/credits/consumption."""

from __future__ import annotations

from decimal import Decimal

import httpx
import pytest

from app.checkmarx import usage
from app.models.enums import ActionType, UsageView
from tests.fake_tenant import FakeTenant

# Trimmed from a real response, keeping every awkward variation it contains.
REAL_SAMPLE = {
    "items": [
        {
            "name": "Aslesha Nargolkar",
            "email": "aslesha.nargolkar@checkmarx.com",
            "userEmail": "aslesha.nargolkar@checkmarx.com",
            "creditsUsed": 1,
            "percentOfTotal": 0.1,
            "actionsPerformed": {
                "actions": [{"actionType": "triage", "transactionCount": 1}],
                "total": 1,
            },
        },
        {
            "name": "Aaron Zhou",
            "creditsUsed": 1,
            "percentOfTotal": 0.1,
            "actionsPerformed": {
                "actions": [{"actionType": "triage", "transactionCount": 1}],
                "total": 1,
            },
        },
        {
            "name": "jonathan.davis@checkmarx.com",
            "creditsUsed": 1,
            "percentOfTotal": 0.1,
            "actionsPerformed": {
                "actions": [{"actionType": "triage", "transactionCount": 1}],
                "total": 1,
            },
        },
        {
            "name": "Harsh Gokani",
            "email": "harsh.gokani@checkmarx.com",
            "userEmail": "harsh.gokani@checkmarx.com",
            "creditsUsed": 3,
            "percentOfTotal": 0.3,
            "actionsPerformed": {
                "actions": [{"actionType": "remediation", "transactionCount": 1}],
                "total": 1,
            },
        },
        {
            "name": "Matthew Torkington",
            "creditsUsed": 4,
            "percentOfTotal": 0.39,
            "actionsPerformed": {
                "actions": [
                    {"actionType": "remediation", "transactionCount": 1},
                    {"actionType": "triage", "transactionCount": 1},
                ],
                "total": 2,
            },
        },
    ],
    "totalItems": 44,
    "totalPages": 3,
    "currentPage": 1,
}


class TestParsePage:
    def test_reads_pagination_metadata(self) -> None:
        page = usage.parse_usage_page(REAL_SAMPLE)
        assert page.total_items == 44
        assert page.total_pages == 3
        assert page.current_page == 1
        assert len(page.items) == 5

    def test_email_fields_are_preferred_for_the_subject_key(self) -> None:
        page = usage.parse_usage_page(REAL_SAMPLE)
        item = page.items[0]
        assert item.subject_key == "aslesha.nargolkar@checkmarx.com"
        assert item.subject_name == "Aslesha Nargolkar"
        assert item.subject_email == "aslesha.nargolkar@checkmarx.com"

    def test_display_name_only_rows_key_on_the_name(self) -> None:
        item = usage.parse_usage_page(REAL_SAMPLE).items[1]
        assert item.subject_key == "aaron zhou"
        assert item.subject_email is None

    def test_an_email_in_the_name_field_is_treated_as_an_email(self) -> None:
        """Several real rows carry the address in name and no email field."""
        item = usage.parse_usage_page(REAL_SAMPLE).items[2]
        assert item.subject_key == "jonathan.davis@checkmarx.com"
        assert item.subject_email == "jonathan.davis@checkmarx.com"

    def test_credits_are_decimal_not_float(self) -> None:
        item = usage.parse_usage_page(REAL_SAMPLE).items[3]
        assert item.credits_used == Decimal("3")
        assert isinstance(item.credits_used, Decimal)

    def test_credits_differ_from_transaction_count(self) -> None:
        """One remediation costs 3 credits. Budgets are in credits, not actions."""
        item = usage.parse_usage_page(REAL_SAMPLE).items[3]
        assert item.credits_used == Decimal("3")
        assert item.transactions == 1

    def test_multiple_action_types_are_kept_separately(self) -> None:
        item = usage.parse_usage_page(REAL_SAMPLE).items[4]
        assert item.actions == {ActionType.REMEDIATION: 1, ActionType.TRIAGE: 1}
        assert item.transactions == 2

    def test_percent_is_carried_through(self) -> None:
        assert usage.parse_usage_page(REAL_SAMPLE).items[4].percent_of_total == 0.39

    def test_raw_row_is_retained_for_audit(self) -> None:
        assert usage.parse_usage_page(REAL_SAMPLE).items[0].raw["name"] == "Aslesha Nargolkar"


class TestParseEdgeCases:
    def test_a_bare_array_body_is_accepted(self) -> None:
        page = usage.parse_usage_page([{"name": "someone", "creditsUsed": 2}])
        assert page.items[0].credits_used == Decimal("2")

    def test_unexpected_body_type_yields_no_items(self) -> None:
        assert usage.parse_usage_page("not json at all").items == []
        assert usage.parse_usage_page(None).items == []

    def test_rows_with_no_identity_are_skipped(self) -> None:
        page = usage.parse_usage_page({"items": [{"creditsUsed": 5}, {"name": "ok"}]})
        assert len(page.items) == 1

    def test_unparseable_credits_become_zero_rather_than_aborting(self) -> None:
        page = usage.parse_usage_page({"items": [{"name": "x", "creditsUsed": "not a number"}]})
        assert page.items[0].credits_used == Decimal("0")

    def test_fractional_credits_are_preserved_exactly(self) -> None:
        page = usage.parse_usage_page({"items": [{"name": "x", "creditsUsed": 1.5}]})
        assert page.items[0].credits_used == Decimal("1.5")

    def test_missing_actions_block_is_tolerated(self) -> None:
        page = usage.parse_usage_page({"items": [{"name": "x", "creditsUsed": 1}]})
        assert page.items[0].actions == {}
        assert page.items[0].transactions is None

    def test_malformed_action_entries_are_ignored(self) -> None:
        page = usage.parse_usage_page(
            {
                "items": [
                    {
                        "name": "x",
                        "creditsUsed": 1,
                        "actionsPerformed": {"actions": ["nonsense", {"actionType": "triage"}]},
                    }
                ]
            }
        )
        assert page.items[0].actions == {ActionType.TRIAGE: 0}

    def test_reported_ids_are_captured_when_present(self) -> None:
        page = usage.parse_usage_page(
            {"items": [{"id": "app-1", "name": "Payments", "creditsUsed": 9}]}
        )
        assert page.items[0].reported_id == "app-1"


class TestActionNormalisation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("triage", ActionType.TRIAGE),
            ("Triage", ActionType.TRIAGE),
            ("ai_triage", ActionType.TRIAGE),
            ("auto_triage", ActionType.AUTO_TRIAGE),
            ("auto-triage", ActionType.AUTO_TRIAGE),
            ("remediation", ActionType.REMEDIATION),
            ("AI Remediation", ActionType.REMEDIATION),
            ("dast_correlation", ActionType.DAST_CORRELATION),
            ("fusion", ActionType.FUSION),
            ("fusion_scan", ActionType.FUSION),
        ],
    )
    def test_known_types_map_onto_the_enum(self, raw: str, expected: str) -> None:
        assert usage.normalise_action_type(raw) == expected

    def test_unknown_types_keep_their_raw_name_rather_than_vanishing(self) -> None:
        """A newly billed action type must still count towards budgets."""
        assert usage.normalise_action_type("quantum_analysis") == "quantum_analysis"

    def test_none_becomes_unknown(self) -> None:
        assert usage.normalise_action_type(None) == ActionType.UNKNOWN


class TestFetchUsage:
    def test_walks_every_page(self) -> None:
        tenant = FakeTenant()
        for index in range(7):
            tenant.set_user_credits(name=f"user{index}@example.com", credits=index)
        tenant.page_size_override = 3

        pages = list(usage.fetch_usage(tenant.client(), view_by=UsageView.USER, page_size=3))
        collected = [item.subject_key for page in pages for item in page.items]
        assert len(collected) == 7
        assert len(set(collected)) == 7

    def test_sends_the_documented_query_parameters(self) -> None:
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if "openid-connect/token" in str(request.url):
                return httpx.Response(200, json={"access_token": "t", "expires_in": 1800})
            captured.update(dict(request.url.params))
            return httpx.Response(200, json={"items": [], "totalPages": 1})

        tenant = FakeTenant()
        tenant.handler = handler  # type: ignore[method-assign]
        list(usage.fetch_usage(tenant.client(), view_by=UsageView.APPLICATION, period="last_month"))
        assert captured["viewBy"] == "application"
        assert captured["period"] == "last_month"
        assert captured["page"] == "1"
        assert captured["sort_by"] == "creditsUsed"
        assert captured["sort_order"] == "desc"

    def test_stops_on_an_empty_page(self) -> None:
        tenant = FakeTenant()
        pages = list(usage.fetch_usage(tenant.client(), view_by=UsageView.USER))
        assert len(pages) == 1
        assert pages[0].items == []
