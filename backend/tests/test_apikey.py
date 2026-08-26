"""API key parsing and region derivation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.checkmarx.apikey import fingerprint_api_key, parse_api_key
from app.checkmarx.errors import ApiKeyError
from app.checkmarx.regions import derive_api_base_url
from tests.conftest import b64url, make_api_key


class TestParseApiKey:
    def test_extracts_iam_url_and_tenant(self) -> None:
        parsed = parse_api_key(
            make_api_key(iam_base_url="https://eu.iam.checkmarx.net", tenant="acme-corp")
        )
        assert parsed.iam_base_url == "https://eu.iam.checkmarx.net"
        assert parsed.tenant_name == "acme-corp"

    def test_builds_the_token_endpoint(self) -> None:
        parsed = parse_api_key(make_api_key(tenant="acme-corp"))
        assert parsed.token_endpoint == (
            "https://eu.iam.checkmarx.net/auth/realms/acme-corp/protocol/openid-connect/token"
        )

    def test_handles_an_iam_base_url_with_a_path(self) -> None:
        """Dedicated deployments can host IAM under a path prefix."""
        parsed = parse_api_key(
            make_api_key(issuer="https://cx.example.com/iam/auth/realms/my-tenant")
        )
        assert parsed.iam_base_url == "https://cx.example.com/iam"
        assert parsed.tenant_name == "my-tenant"

    def test_tolerates_a_trailing_slash_on_the_issuer(self) -> None:
        parsed = parse_api_key(
            make_api_key(issuer="https://iam.checkmarx.net/auth/realms/tenant-x/")
        )
        assert parsed.tenant_name == "tenant-x"

    def test_signature_is_not_verified(self) -> None:
        """The point of this parser: a bogus signature still parses."""
        key = make_api_key()
        head, payload, _ = key.split(".")
        assert parse_api_key(f"{head}.{payload}.nonsense").tenant_name == "acme-corp"

    def test_surrounding_whitespace_is_ignored(self) -> None:
        assert parse_api_key(f"  {make_api_key()}\n").tenant_name == "acme-corp"

    def test_exp_zero_means_no_expiry(self) -> None:
        parsed = parse_api_key(make_api_key(exp=0))
        assert parsed.expires_at is None
        assert parsed.is_expired is False

    def test_future_exp_is_parsed(self) -> None:
        future = int((datetime.now(UTC) + timedelta(days=30)).timestamp())
        parsed = parse_api_key(make_api_key(exp=future))
        assert parsed.expires_at is not None
        assert parsed.is_expired is False

    def test_past_exp_is_flagged_as_expired(self) -> None:
        past = int((datetime.now(UTC) - timedelta(days=1)).timestamp())
        assert parse_api_key(make_api_key(exp=past)).is_expired is True

    def test_offline_typ_is_accepted(self) -> None:
        assert parse_api_key(make_api_key(typ="Offline")).tenant_name == "acme-corp"

    def test_missing_typ_is_accepted(self) -> None:
        assert parse_api_key(make_api_key(typ=None)).tenant_name == "acme-corp"

    def test_access_token_is_rejected_with_guidance(self) -> None:
        with pytest.raises(ApiKeyError, match="not a refresh token"):
            parse_api_key(make_api_key(typ="Bearer"))

    @pytest.mark.parametrize("value", ["", "   ", "\n"])
    def test_empty_input_is_rejected(self, value: str) -> None:
        with pytest.raises(ApiKeyError, match="No API key supplied"):
            parse_api_key(value)

    @pytest.mark.parametrize("value", ["not-a-jwt", "only.two", "a.b.c.d", ".b.c"])
    def test_non_jwt_shapes_are_rejected(self, value: str) -> None:
        with pytest.raises(ApiKeyError, match="three dot separated segments"):
            parse_api_key(value)

    def test_undecodable_payload_is_rejected(self) -> None:
        with pytest.raises(ApiKeyError, match="valid JSON|base64url"):
            parse_api_key("aGVhZGVy.!!!not-base64!!!.c2ln")

    def test_payload_that_is_not_an_object_is_rejected(self) -> None:
        import base64

        array = base64.urlsafe_b64encode(b"[1,2,3]").decode().rstrip("=")
        with pytest.raises(ApiKeyError, match="not a JSON object"):
            parse_api_key(f"aGVhZGVy.{array}.c2ln")

    def test_missing_issuer_is_rejected(self) -> None:
        payload = b64url({"sub": "abc", "typ": "Refresh"})
        with pytest.raises(ApiKeyError, match="no 'iss' claim"):
            parse_api_key(f"aGVhZGVy.{payload}.c2ln")

    def test_unexpected_issuer_shape_is_rejected_with_the_value(self) -> None:
        with pytest.raises(ApiKeyError, match="https://sso.example.com/oauth2"):
            parse_api_key(make_api_key(issuer="https://sso.example.com/oauth2"))


class TestFingerprint:
    def test_is_stable_and_short(self) -> None:
        key = make_api_key()
        assert fingerprint_api_key(key) == fingerprint_api_key(f" {key} ")
        assert len(fingerprint_api_key(key)) == 12

    def test_differs_between_keys(self) -> None:
        assert fingerprint_api_key(make_api_key(tenant="a")) != fingerprint_api_key(
            make_api_key(tenant="b")
        )

    def test_does_not_contain_the_key(self) -> None:
        key = make_api_key()
        assert fingerprint_api_key(key) not in key


class TestRegionDerivation:
    @pytest.mark.parametrize(
        ("iam_host", "expected"),
        [
            ("https://iam.checkmarx.net", "https://ast.checkmarx.net/api"),
            ("https://us.iam.checkmarx.net", "https://us.ast.checkmarx.net/api"),
            ("https://eu.iam.checkmarx.net", "https://eu.ast.checkmarx.net/api"),
            ("https://eu-2.iam.checkmarx.net", "https://eu-2.ast.checkmarx.net/api"),
            ("https://deu.iam.checkmarx.net", "https://deu.ast.checkmarx.net/api"),
            ("https://anz.iam.checkmarx.net", "https://anz.ast.checkmarx.net/api"),
            ("https://ind.iam.checkmarx.net", "https://ind.ast.checkmarx.net/api"),
            ("https://sng.iam.checkmarx.net", "https://sng.ast.checkmarx.net/api"),
            ("https://uae.iam.checkmarx.net", "https://uae.ast.checkmarx.net/api"),
        ],
    )
    def test_known_regions_are_confident(self, iam_host: str, expected: str) -> None:
        derived = derive_api_base_url(iam_host)
        assert derived.api_base_url == expected
        assert derived.confident is True

    def test_unknown_region_falls_back_to_the_label_swap(self) -> None:
        derived = derive_api_base_url("https://newregion.iam.checkmarx.net")
        assert derived.api_base_url == "https://newregion.ast.checkmarx.net/api"
        assert derived.confident is False

    def test_case_is_normalised(self) -> None:
        assert derive_api_base_url("https://EU.IAM.CheckMarx.net").api_base_url == (
            "https://eu.ast.checkmarx.net/api"
        )

    def test_port_is_preserved(self) -> None:
        assert derive_api_base_url("https://iam.internal.example:8443").api_base_url == (
            "https://ast.internal.example:8443/api"
        )

    def test_custom_host_without_an_iam_label_needs_a_manual_override(self) -> None:
        derived = derive_api_base_url("https://cx.example.com/identity")
        assert derived.api_base_url is None
        assert derived.confident is False

    def test_empty_input_is_handled(self) -> None:
        assert derive_api_base_url("").api_base_url is None
