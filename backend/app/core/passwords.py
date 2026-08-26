"""Password hashing (Argon2id) and the utility's password policy."""

from __future__ import annotations

import re
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH: Final = 12
MAX_LENGTH: Final = 128

# Argon2id parameters: 64 MiB, 3 passes, 4 lanes. Comfortably above the OWASP
# minimum and still fast enough for an interactive login on a small host.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)

# Deliberately small: this blocks the passwords people actually try on an
# internal tool. It is not a substitute for a real breached-password check.
_COMMON_PASSWORDS: Final[frozenset[str]] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd",
        "administrator",
        "letmein",
        "welcome",
        "welcome1",
        "qwerty",
        "qwertyuiop",
        "iloveyou",
        "changeme",
        "checkmarx",
        "checkmarx1",
        "cxcreditguard",
        "admin",
        "admin123",
        "root",
        "123456",
        "1234567890",
        "abc123",
        "monkey",
        "dragon",
        "sunshine",
        "princess",
        "football",
        "baseball",
        "trustno1",
    }
)

_SEQUENCES: Final = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl")


class PasswordPolicyError(ValueError):
    """The supplied password does not meet the policy."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


def validate_password(password: str, *, username: str | None = None) -> None:
    """Raise PasswordPolicyError listing every problem with the password."""
    problems: list[str] = []

    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters")
    if len(password) > MAX_LENGTH:
        problems.append(f"must be at most {MAX_LENGTH} characters")
    if not re.search(r"[a-z]", password):
        problems.append("must contain a lowercase letter")
    if not re.search(r"[A-Z]", password):
        problems.append("must contain an uppercase letter")
    if not re.search(r"\d", password):
        problems.append("must contain a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("must contain a symbol")

    lowered = password.lower()
    # Exact match, and also containment for the longer entries: "Password123!"
    # is no stronger than "password" with decoration bolted on.
    if lowered in _COMMON_PASSWORDS or any(
        common in lowered for common in _COMMON_PASSWORDS if len(common) >= 6
    ):
        problems.append("must not be or contain a commonly used password")
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("must not contain the username")
    if any(
        lowered[i : i + 5] in sequence
        for sequence in _SEQUENCES
        for i in range(len(lowered) - 4)
        if len(lowered) >= 5
    ):
        problems.append("must not contain a run of 5 sequential characters")
    if re.search(r"(.)\1{3,}", password):
        problems.append("must not repeat the same character 4 or more times")

    if problems:
        raise PasswordPolicyError(problems)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash predates the current Argon2 parameters."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
