"""Log redaction: no secret may reach a log sink."""

from __future__ import annotations

import logging

import pytest

from app.core.logging import (
    REDACTED,
    RedactingFilter,
    configure_logging,
    redact,
    register_secret,
    unregister_secret,
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJpc3MiOiJodHRwczovL2lhbS5jaGVja21hcngubmV0L2F1dGgvcmVhbG1zL2FjbWUifQ"
    ".c2lnbmF0dXJl"
)


@pytest.mark.parametrize(
    "message",
    [
        f"Authorization: Bearer {JWT}",
        f"refresh_token={JWT}&grant_type=refresh_token",
        f'{{"access_token": "{JWT}"}}',
        f"api_key={JWT}",
        f"the key is {JWT} apparently",
    ],
)
def test_jwt_shaped_values_are_redacted(message: str) -> None:
    assert JWT not in redact(message)
    assert REDACTED in redact(message)


def test_bearer_header_is_redacted_even_for_opaque_tokens() -> None:
    assert "abc123opaquetoken" not in redact("Authorization: Bearer abc123opaquetoken")


@pytest.mark.parametrize(
    "message",
    [
        "password=hunter2andthensome",
        '{"password": "hunter2andthensome"}',
        "client_secret=hunter2andthensome",
        '"totp_secret": "hunter2andthensome"',
    ],
)
def test_credential_fields_are_redacted(message: str) -> None:
    assert "hunter2andthensome" not in redact(message)


def test_registered_literal_secret_is_scrubbed_anywhere() -> None:
    """An opaque access token with no recognisable shape still must not leak."""
    opaque = "Zq7Lm3Xr9Tv2Kp8Ns4Wd"
    assert opaque in redact(f"token is {opaque}")
    register_secret(opaque)
    try:
        assert opaque not in redact(f"token is {opaque}")
    finally:
        unregister_secret(opaque)


def test_short_values_are_not_registered() -> None:
    """Registering a very short string would redact half of every log line."""
    register_secret("abc")
    assert "abc" in redact("abc appears here")


def test_filter_rewrites_record_message_and_args(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("test.redaction")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO, logger="test.redaction"):
        logger.info("exchanging refresh_token=%s for a token", JWT)
    rendered = caplog.text
    assert JWT not in rendered


def test_configure_logging_attaches_the_filter(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")
    logging.getLogger("cxcg.test").info("Authorization: Bearer %s", JWT)
    captured = capsys.readouterr()
    assert JWT not in captured.out + captured.err
