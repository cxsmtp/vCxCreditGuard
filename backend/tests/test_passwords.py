"""Password hashing and policy."""

from __future__ import annotations

import pytest

from app.core.passwords import (
    PasswordPolicyError,
    hash_password,
    validate_password,
    verify_password,
)

GOOD = "Str0ng!Passw#rd"


def test_hash_verify_roundtrip() -> None:
    digest = hash_password(GOOD)
    assert digest.startswith("$argon2id$")
    assert verify_password(digest, GOOD)


def test_wrong_password_fails() -> None:
    assert not verify_password(hash_password(GOOD), GOOD + "x")


def test_hash_is_salted() -> None:
    assert hash_password(GOOD) != hash_password(GOOD)


def test_corrupt_hash_does_not_raise() -> None:
    assert not verify_password("not-a-hash", GOOD)


def test_good_password_passes() -> None:
    validate_password(GOOD, username="admin")


@pytest.mark.parametrize(
    ("password", "expected"),
    [
        ("Sh0rt!Aa", "at least 12"),
        ("alllowercase1!x", "uppercase"),
        ("ALLUPPERCASE1!X", "lowercase"),
        ("NoDigitsHere!!x", "digit"),
        ("NoSymbolsHere1x", "symbol"),
        ("Password123!aA" * 20, "at most 128"),
    ],
)
def test_policy_violations_are_reported(password: str, expected: str) -> None:
    with pytest.raises(PasswordPolicyError, match=expected):
        validate_password(password)


def test_common_password_is_rejected() -> None:
    with pytest.raises(PasswordPolicyError, match="commonly used"):
        validate_password("Password123!")


def test_password_containing_username_is_rejected() -> None:
    with pytest.raises(PasswordPolicyError, match="username"):
        validate_password("Str0ng!cxadmin#Pass", username="cxadmin")


def test_sequential_run_is_rejected() -> None:
    with pytest.raises(PasswordPolicyError, match="sequential"):
        validate_password("Ab!12345678xY")


def test_repeated_characters_are_rejected() -> None:
    with pytest.raises(PasswordPolicyError, match="repeat"):
        validate_password("Aaaaa!bcdef1X")


def test_all_problems_are_collected() -> None:
    with pytest.raises(PasswordPolicyError) as exc_info:
        validate_password("short")
    assert len(exc_info.value.problems) >= 3
