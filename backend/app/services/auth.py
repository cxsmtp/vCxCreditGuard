"""Authentication for the utility itself: accounts, login, sessions, TOTP.

Threat model notes that shaped this file:

* Login is rate limited per (username, client IP) and accounts lock with
  exponential backoff, so a stolen username does not enable online guessing.
* A failed login against an unknown username still performs an Argon2
  verification against a dummy hash, so response timing does not reveal which
  usernames exist.
* Session and CSRF tokens are random and stored only as SHA-256 digests.
* Sessions have both an idle timeout and an absolute cap.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import secrets
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import set_committed_value

from app.core.config import Settings, get_settings
from app.core.crypto import PURPOSE_RECOVERY_CODE, PURPOSE_TOTP_SECRET, get_secret_box
from app.core.passwords import (
    PasswordPolicyError,
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)
from app.core.tokens import hash_token, new_token, tokens_equal
from app.db import locking
from app.db.base import utcnow
from app.models.auth import (
    LoginAttempt,
    PasswordResetToken,
    UtilitySession,
    UtilityUser,
)
from app.models.enums import UtilityRole
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

RATE_LIMIT_WINDOW_SECONDS = 60
# The identifier of the per-address bucket that counts sign-in attempts across
# every username. Not a valid username, so it can never collide with one.
ANY_ACCOUNT = "*"
# An address may try this many times the per-username allowance, across all
# usernames, before it is throttled. Without it, varying the username would give
# an attacker a fresh allowance (and a fresh password hash for us to compute)
# on every request.
ADDRESS_RATE_MULTIPLIER = 3
# Failures from one address lock out that address. The account as a whole is
# only locked once failures across all addresses reach this many times the
# per-address threshold: enough to stop a distributed guessing attack, without
# letting a single address lock the real owner out.
ACCOUNT_LOCK_MULTIPLIER = 10
# Password hashing is deliberately expensive. Capping how many run at once keeps
# a burst of sign-in attempts from exhausting memory and CPU for everything else.
MAX_CONCURRENT_VERIFICATIONS = 4
# Two factor recovery codes: this many, each this many random bytes (shown as hex).
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 10
# The address value of the row that counts failures for a username across every
# address. Not a possible client address, so it cannot collide with one.
ACCOUNT_WIDE = "*account*"
# Account-wide failures older than this no longer count. Without a window, one
# patient address could wait out its own lockout again and again and, over a
# couple of days, lock the owner out everywhere.
ACCOUNT_FAILURE_WINDOW = timedelta(hours=1)
# Wrong passwords on a password re-check before the session is ended.
REAUTH_MAX_FAILURES = 5
VERIFICATION_WAIT_SECONDS = 5.0
_verification_slots = threading.BoundedSemaphore(MAX_CONCURRENT_VERIFICATIONS)


@contextmanager
def _verification_slot() -> Iterator[None]:
    if not _verification_slots.acquire(timeout=VERIFICATION_WAIT_SECONDS):
        raise RateLimited(retry_after_seconds=2)
    try:
        yield
    finally:
        _verification_slots.release()


TOTP_ISSUER = "CxCreditGuard"
TOTP_VALID_WINDOW = 1
# How long a password-reset token stays valid once issued.
PASSWORD_RESET_TTL = timedelta(hours=1)

# Computed once, used to keep failed logins for unknown usernames as slow as
# failed logins for real ones.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))


class AuthError(Exception):
    """Base class for login failures."""


class InvalidCredentials(AuthError):
    def __init__(self) -> None:
        # Deliberately identical for unknown user, wrong password and wrong code.
        super().__init__("Invalid username or password.")


class AccountLocked(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        minutes = max(1, round(retry_after_seconds / 60))
        super().__init__(
            f"This account is temporarily locked after repeated failed logins. "
            f"Try again in about {minutes} minute(s)."
        )


class AccountDisabled(AuthError):
    def __init__(self) -> None:
        super().__init__("This account is disabled.")


class TotpRequired(AuthError):
    def __init__(self) -> None:
        super().__init__("A two factor authentication code is required.")


class RateLimited(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__("Too many login attempts. Slow down and try again shortly.")


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """Returned to the route layer, which sets the cookies."""

    session_token: str
    csrf_token: str
    idle_expires_at: datetime
    absolute_expires_at: datetime
    user: UtilityUser


# ------------------------------------------------------------------- accounts


def count_users(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(UtilityUser)) or 0)


def get_user_by_username(session: Session, username: str) -> UtilityUser | None:
    normalised = username.strip().lower()
    return session.scalar(select(UtilityUser).where(UtilityUser.username == normalised))


def create_user(
    session: Session,
    *,
    username: str,
    password: str,
    role: UtilityRole,
    email: str | None = None,
    actor: AuditActor,
    must_change_password: bool = False,
) -> UtilityUser:
    normalised = username.strip().lower()
    if not normalised or len(normalised) < 3:
        raise ValueError("Username must be at least 3 characters.")
    if get_user_by_username(session, normalised) is not None:
        raise ValueError(f"A user named {normalised} already exists.")
    validate_password(password, username=normalised)

    user = UtilityUser(
        username=normalised,
        email=email,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
        password_changed_at=utcnow(),
        must_change_password=must_change_password,
    )
    session.add(user)
    session.flush()
    record_audit(
        session,
        action="account.created",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        after={"username": user.username, "role": user.role, "email": user.email},
    )
    return user


def set_password(
    session: Session, *, user: UtilityUser, new_password: str, actor: AuditActor
) -> None:
    _store_password_hash(
        session, user=user, password_hash=_new_password_hash(user, new_password), actor=actor
    )


def _new_password_hash(user: UtilityUser, new_password: str) -> str:
    """Check ``new_password`` against the policy and hash it. Writes nothing.

    The slow part of a password change (two Argon2 operations), kept apart so a
    caller can do it before it takes any lock.
    """
    validate_password(new_password, username=user.username)
    if user.password_hash and verify_password(user.password_hash, new_password):
        # Otherwise a forced change is satisfied by typing the temporary
        # password again, and the password an admin handed out lives on.
        raise PasswordPolicyError(["must be different from the current password"])
    return hash_password(new_password)


def _store_password_hash(
    session: Session, *, user: UtilityUser, password_hash: str, actor: AuditActor
) -> None:
    user.password_hash = password_hash
    user.password_changed_at = utcnow()
    user.must_change_password = False
    session.flush()
    record_audit(
        session,
        action="account.password_changed",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        detail="Password hash replaced. All other sessions for this account were revoked.",
    )
    revoke_all_sessions(session, user_id=user.id)


class InvalidResetToken(Exception):
    """The reset token is unknown, already used, or expired."""

    def __init__(self) -> None:
        super().__init__("This password reset link is invalid or has expired.")


def _issue_reset_token(
    session: Session, *, user: UtilityUser, ip_address: str | None, actor: AuditActor
) -> str:
    """Mint a fresh reset token for a user, invalidating any earlier unused one.

    Returns the plaintext token; only its digest is stored. The caller delivers
    the token (by email, or by handing it to an admin) and must never return it
    to an unauthenticated requester.
    """
    now = utcnow()
    session.execute(
        update(PasswordResetToken)
        .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
        .values(used_at=now)
    )
    token = new_token()
    session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(token),
            created_at=now,
            expires_at=now + PASSWORD_RESET_TTL,
            requested_ip=ip_address,
        )
    )
    session.flush()
    record_audit(
        session,
        action="auth.password_reset_requested",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        detail="A single-use password reset token was issued.",
    )
    return token


def request_password_reset(
    session: Session, *, identifier: str, ip_address: str | None = None
) -> tuple[UtilityUser, str] | None:
    """Resolve a username or email to an active account and issue a reset token.

    Returns ``(user, token)`` when a matching active account exists, else
    ``None``. The caller must give the same response either way, so that the
    endpoint does not reveal whether an account exists.
    """
    needle = (identifier or "").strip().lower()[:320]
    if not needle:
        return None
    user = get_user_by_username(session, needle)
    if user is None and "@" in needle:
        user = session.scalar(
            select(UtilityUser).where(func.lower(UtilityUser.email) == needle).limit(1)
        )
    if user is None or not user.is_active:
        return None
    token = _issue_reset_token(
        session,
        user=user,
        ip_address=ip_address,
        actor=AuditActor.anonymous(ip_address=ip_address),
    )
    return user, token


def admin_issue_reset_token(
    session: Session, *, user: UtilityUser, actor: AuditActor, ip_address: str | None = None
) -> str:
    """Issue a reset token on an admin's behalf (e.g. when email is not set up).

    The token is returned to the admin to hand to the user out of band.
    """
    return _issue_reset_token(session, user=user, ip_address=ip_address, actor=actor)


def complete_password_reset(
    session: Session, *, token: str, new_password: str, ip_address: str | None = None
) -> UtilityUser:
    """Redeem a reset token and set the new password.

    Raises :class:`InvalidResetToken` for an unknown, used, or expired token, and
    lets :class:`PasswordPolicyError` propagate for a weak new password (the token
    is left unspent so the user can retry with a stronger one). On success the
    account's failed-login lockout is cleared and every session is revoked.
    """
    actor = AuditActor.anonymous(ip_address=ip_address)
    row = session.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token))
    )
    now = utcnow()
    user = session.get(UtilityUser, row.user_id) if row is not None else None
    usable = (
        row is not None
        and row.used_at is None
        and row.expires_at > now
        and user is not None
        and user.is_active
    )
    password_hash: str | None = None
    if usable and row is not None and user is not None:
        # The policy check and the hashing (Argon2) first, before any lock is
        # taken: a weak password is refused with nothing written.
        password_hash = _new_password_hash(user, new_password)
        # Spend the token in one conditional statement, before anything else is
        # changed. Two redemptions of the same token at the same moment both see
        # it unused above; only one of them gets to mark it used.
        claimed = session.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.id == row.id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
            .execution_options(synchronize_session=False)
        ).rowcount
        usable = claimed == 1
        if usable:
            row.used_at = now
    if not usable or user is None or row is None or password_hash is None:
        # Audited so repeated invalid redemptions (a brute-force or a stale link
        # being retried) are visible; the endpoint that calls this is rate limited.
        record_audit(
            session,
            action="auth.password_reset_failed",
            actor=actor,
            target_type="utility_user",
            target_id=str(user.id) if user is not None else None,
            target_label=user.username if user is not None else None,
            detail="A password reset token was rejected (unknown, used, or expired).",
        )
        raise InvalidResetToken

    # The sign-in counters first, then the account: the order a sign-in takes
    # them in (LOCK ORDER, above authenticate), so a sign-in at the same moment
    # waits instead of deadlocking.
    clear_login_throttle(session, username=user.username)
    _store_password_hash(session, user=user, password_hash=password_hash, actor=actor)
    user.failed_login_count = 0
    user.locked_until = None
    session.flush()
    record_audit(
        session,
        action="auth.password_reset_completed",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        detail="Password set via reset token; account lockout cleared.",
    )
    return user


def bootstrap_admin_if_needed(
    session: Session, settings: Settings | None = None
) -> UtilityUser | None:
    """Create the first Admin from the environment when no accounts exist.

    Runs once. If the variables are set but the password fails policy, we log the
    reason and leave the utility with no accounts rather than weakening the policy.
    """
    settings = settings or get_settings()
    username = (settings.bootstrap_admin_username or "").strip()
    password = settings.bootstrap_admin_password or ""
    if not username or not password:
        return None
    if count_users(session) > 0:
        return None

    try:
        user = create_user(
            session,
            username=username,
            password=password,
            role=UtilityRole.ADMIN,
            actor=AuditActor.system("bootstrap"),
            # The password came from an environment file or a start-up log,
            # where it stays readable: it is for the first sign-in only.
            must_change_password=True,
        )
    except ValueError as exc:
        logger.error(
            "Bootstrap admin was not created: %s Set CXCG_BOOTSTRAP_ADMIN_PASSWORD to a "
            "value that meets the password policy and restart.",
            exc,
        )
        session.rollback()
        return None

    logger.warning(
        "Created bootstrap admin account %r from the environment. Log in, change the "
        "password, then remove CXCG_BOOTSTRAP_ADMIN_USERNAME and "
        "CXCG_BOOTSTRAP_ADMIN_PASSWORD from the environment.",
        user.username,
    )
    return user


# ---------------------------------------------------------------------- login


def _check_rate_limit(
    session: Session,
    *,
    identifier: str,
    ip_address: str,
    settings: Settings,
    limit: int | None = None,
) -> LoginAttempt:
    """Count one attempt against (identifier, address) and enforce the allowance."""
    allowance = limit if limit is not None else settings.login_rate_limit_per_minute
    now = utcnow()
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
    row = _locked_attempt_row(session, identifier=identifier, ip_address=ip_address, now=now)
    if row.window_started_at < window_start:
        row.window_started_at = now
        row.attempt_count = 1
        row.last_attempt_at = now
        session.flush()
        return row

    row.attempt_count += 1
    row.last_attempt_at = now
    session.flush()
    if row.attempt_count > allowance:
        elapsed = (now - row.window_started_at).total_seconds()
        raise RateLimited(retry_after_seconds=max(1, int(RATE_LIMIT_WINDOW_SECONDS - elapsed)))
    return row


def throttle(
    session: Session, *, bucket: str, ip_address: str, settings: Settings | None = None
) -> None:
    """Public rate-limit guard for a named action, reusing the login counter.

    Lets endpoints such as password-reset requests share the per-identifier,
    per-IP throttle that login uses. Raises :class:`RateLimited` when exceeded.
    """
    settings = settings or get_settings()
    _check_rate_limit(
        session,
        identifier=bucket[:128],
        ip_address=throttle_address(ip_address),
        settings=settings,
    )


def _lockout_seconds(failed_count: int, settings: Settings, *, threshold: int | None = None) -> int:
    """Exponential backoff once the attempt threshold is passed."""
    over = max(0, failed_count - (threshold or settings.login_max_attempts))
    delay = settings.login_lockout_base_seconds * (2 ** min(over, 30))
    return int(min(delay, settings.login_lockout_max_seconds))


def throttle_address(ip_address: str) -> str:
    """The address a client is throttled as.

    An IPv6 client usually controls a whole /64, so counting each of its
    addresses separately would hand it 2^64 fresh allowances. IPv4 addresses and
    anything unparseable are used as they are.
    """
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return ip_address[:64]
    if parsed.version == 6:
        return str(ipaddress.ip_network(f"{parsed}/64", strict=False))[:64]
    return str(parsed)


def _account_row(session: Session, identifier: str) -> LoginAttempt:
    """The row counting failed sign-ins for this username across all addresses.

    Kept for every username that is tried, real or not, so that the account-wide
    lock behaves identically either way and reveals nothing about which exist.
    """
    return _locked_attempt_row(
        session, identifier=identifier, ip_address=ACCOUNT_WIDE, now=utcnow()
    )


def _locked_attempt_row(
    session: Session, *, identifier: str, ip_address: str, now: datetime
) -> LoginAttempt:
    """The counter row for (identifier, address), locked until the transaction ends.

    Concurrent sign-ins must not each read the same count and each write it back
    plus one: a burst of guesses would then cost a single attempt, and a lockout
    one of them set would go unseen by the rest. So the row is locked before it
    is read (and created, ignoring a concurrent creation, if it is missing); a
    second request for the same row waits here for the first to commit and then
    reads what it wrote. A new row starts at zero attempts in a fresh window.
    """
    locking.begin_write(session)
    query = (
        select(LoginAttempt)
        .where(LoginAttempt.identifier == identifier, LoginAttempt.ip_address == ip_address)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    row = session.scalar(query)
    if row is None:
        session.execute(
            locking.insert_ignoring_conflict(session, LoginAttempt).values(
                identifier=identifier,
                ip_address=ip_address,
                window_started_at=now,
                attempt_count=0,
                last_attempt_at=now,
                failure_count=0,
            )
        )
        row = session.scalar(query)
        assert row is not None  # inserted above, or by whoever beat us to it
    return row


def _known_address(session: Session, user: UtilityUser | None, ip_address: str) -> bool:
    """Has this account signed in successfully from this address before?"""
    if user is None:
        return False
    return (
        session.scalar(
            select(UtilitySession.id)
            .where(UtilitySession.user_id == user.id, UtilitySession.ip_address == ip_address)
            .limit(1)
        )
        is not None
    )


def _register_failure(
    session: Session,
    source: LoginAttempt,
    account: LoginAttempt,
    user: UtilityUser | None,
    settings: Settings,
) -> None:
    """Record a failed sign-in against its source, and against the username.

    The source (this username from this address) is locked out quickly. The
    username as a whole is only locked after far more failures, within a time
    window, than one address can produce - and even then not for an address its
    owner has signed in from before - so knowing a username is not enough to
    keep its owner out.
    """
    now = utcnow()
    source.failure_count = (source.failure_count or 0) + 1
    if source.failure_count >= settings.login_max_attempts:
        source.locked_until = now + timedelta(
            seconds=_lockout_seconds(source.failure_count, settings)
        )

    if now - account.last_attempt_at > ACCOUNT_FAILURE_WINDOW:
        account.failure_count = 0
    account.failure_count = (account.failure_count or 0) + 1
    account.last_attempt_at = now
    account_threshold = settings.login_max_attempts * ACCOUNT_LOCK_MULTIPLIER
    if account.failure_count >= account_threshold:
        account.locked_until = now + timedelta(
            seconds=_lockout_seconds(account.failure_count, settings, threshold=account_threshold)
        )
    if user is not None:
        # Mirrored onto the account for the admin's account list and Unlock.
        user.failed_login_count = account.failure_count
        user.locked_until = account.locked_until
    session.flush()


def clear_login_throttle(session: Session, *, username: str) -> None:
    """Forget every per-address lockout for this username (unlock, password reset).

    In the lock order (see LOCK ORDER): the per-address rows, in id order, then
    the account-wide row. One DELETE of them all would lock them in whatever
    order the scan meets them, and a sign-in holding its per-address row while
    it waits for the account-wide one would deadlock against it.
    """
    identifier = username.strip().lower()[:128]
    locking.begin_write(session)
    session.scalars(
        select(LoginAttempt.id)
        .where(LoginAttempt.identifier == identifier, LoginAttempt.ip_address != ACCOUNT_WIDE)
        .order_by(LoginAttempt.id)
        .with_for_update()
    ).all()
    session.execute(
        delete(LoginAttempt).where(
            LoginAttempt.identifier == identifier, LoginAttempt.ip_address != ACCOUNT_WIDE
        )
    )
    session.execute(
        delete(LoginAttempt).where(
            LoginAttempt.identifier == identifier, LoginAttempt.ip_address == ACCOUNT_WIDE
        )
    )


# LOCK ORDER. Everything that locks more than one of these takes them in this
# order, so two transactions can wait for each other but never deadlock:
#   1. the per-address row of all usernames (ANY_ACCOUNT, address)
#   2. per-address rows of one username (username, address), in id order
#   3. the username's account-wide row (username, ACCOUNT_WIDE)
#   4. the utility_user row
#   5. the audit chain's append lock (record_audit)
# No lock is held while a password is hashed or verified (Argon2): a sign-in
# commits its attempt count first, checks the password with nothing locked,
# then locks again for the short write that records the outcome.


def _blocked(
    session: Session,
    *,
    source: LoginAttempt | None,
    account: LoginAttempt | None,
    user: UtilityUser | None,
    ip_address: str,
) -> tuple[int, str] | None:
    """(retry after, audit detail) when a lockout applies to this sign-in."""
    now = utcnow()
    if source is not None and source.locked_until is not None and source.locked_until > now:
        retry_after = max(1, int((source.locked_until - now).total_seconds()))
        return retry_after, f"Sign-ins from this address are locked for another {retry_after}s."
    if (
        account is not None
        and account.locked_until is not None
        and account.locked_until > now
        # The owner, at an address they have used before, is not kept out by
        # other people's guesses.
        and not _known_address(session, user, ip_address)
    ):
        retry_after = max(1, int((account.locked_until - now).total_seconds()))
        return retry_after, (
            f"Account locked for another {retry_after}s after failures from many addresses."
        )
    return None


def _read_attempt_row(session: Session, identifier: str, ip_address: str) -> LoginAttempt | None:
    """The counter row as last committed, without locking it."""
    return session.scalar(
        select(LoginAttempt)
        .where(LoginAttempt.identifier == identifier, LoginAttempt.ip_address == ip_address)
        .execution_options(populate_existing=True)
    )


def authenticate(
    session: Session,
    *,
    username: str,
    password: str,
    totp_code: str | None = None,
    ip_address: str = "unknown",
    user_agent: str | None = None,
    settings: Settings | None = None,
) -> UtilityUser:
    """Verify credentials, returning the user or raising an AuthError subclass.

    Commits as it goes (the attempt is counted whatever happens next). In three
    steps, so that no lock is held while the password is verified (LOCK ORDER):
    count the attempt and commit; decide the lockouts and verify the password
    with nothing locked; lock the counters again, re-check the lockouts and
    record the outcome. Concurrent sign-ins for one username therefore verify
    their passwords side by side, and the owner is not queued behind someone
    else's guesses.
    """
    settings = settings or get_settings()
    identifier = username.strip().lower()[:128]
    address = throttle_address(ip_address)
    actor = AuditActor.anonymous(ip_address=ip_address, user_agent=user_agent)

    # 1. Count the attempt: per address across all usernames first, then per
    #    username from this address. Locked, written and committed at once.
    _check_rate_limit(
        session,
        identifier=ANY_ACCOUNT,
        ip_address=address,
        settings=settings,
        limit=settings.login_rate_limit_per_minute * ADDRESS_RATE_MULTIPLIER,
    )
    _check_rate_limit(session, identifier=identifier, ip_address=address, settings=settings)
    session.commit()

    # 2. Nothing locked from here to the password's verdict. Both lockouts are
    #    decided before the password is looked at and apply whether or not the
    #    account exists, so neither says which usernames are real.
    user = get_user_by_username(session, identifier)
    blocked = _blocked(
        session,
        source=_read_attempt_row(session, identifier, address),
        account=_read_attempt_row(session, identifier, ACCOUNT_WIDE),
        user=user,
        ip_address=ip_address,
    )
    if blocked is not None:
        _audit_blocked(session, actor, user, identifier, blocked[1])
        raise AccountLocked(retry_after_seconds=blocked[0])

    with _verification_slot():
        # Constant work for unknown accounts.
        password_ok = verify_password(
            user.password_hash if user is not None else _DUMMY_HASH, password
        )
    password_ok = password_ok and user is not None
    new_hash = (
        hash_password(password)
        if password_ok and user is not None and needs_rehash(user.password_hash)
        else None
    )

    # 3. Lock the counters again (LOCK ORDER) and record the outcome. Another
    #    sign-in may have changed them meanwhile: they are read afresh.
    source = _locked_attempt_row(session, identifier=identifier, ip_address=address, now=utcnow())
    account = _account_row(session, identifier)

    if not password_ok or user is None:
        _register_failure(session, source, account, user, settings)
        record_audit(
            session,
            action="auth.login_failed",
            actor=actor,
            target_type="utility_user",
            target_id=str(user.id) if user is not None else None,
            target_label=user.username if user is not None else identifier,
            detail=(
                f"Wrong password. Failure count is now {user.failed_login_count}."
                if user is not None
                else "No such account."
            ),
        )
        raise InvalidCredentials

    # A lockout set by guesses that were verified alongside this one still
    # applies: the right password then gets the same answer as any other.
    blocked = _blocked(session, source=source, account=account, user=user, ip_address=ip_address)
    if blocked is not None:
        _audit_blocked(session, actor, user, identifier, blocked[1])
        raise AccountLocked(retry_after_seconds=blocked[0])

    # Only someone who knows the password learns that the account is disabled.
    if not user.is_active:
        record_audit(
            session,
            action="auth.login_failed",
            actor=actor,
            target_type="utility_user",
            target_id=str(user.id),
            target_label=user.username,
            detail="Account is disabled.",
        )
        raise AccountDisabled

    if user.totp_enabled:
        if not totp_code:
            # Not a failure: the client must prompt for the second factor. The
            # password was already verified, so this cannot be used as an oracle
            # by anyone who does not already know the password.
            raise TotpRequired
        # Each is spent in the database, under a condition or a lock, so two
        # sign-ins presenting the same code at once cannot both use it.
        if _consume_totp(session, user, totp_code):
            pass
        elif use_recovery_code(session, user=user, code=totp_code):
            remaining = len(user.totp_recovery_codes or [])
            record_audit(
                session,
                action="auth.recovery_code_used",
                actor=actor,
                target_type="utility_user",
                target_id=str(user.id),
                target_label=user.username,
                detail=f"Signed in with a one-time recovery code. {remaining} left.",
            )
        else:
            _register_failure(session, source, account, user, settings)
            record_audit(
                session,
                action="auth.login_failed",
                actor=actor,
                target_type="utility_user",
                target_id=str(user.id),
                target_label=user.username,
                detail="Incorrect two factor code.",
            )
            raise InvalidCredentials

    if new_hash is not None:
        user.password_hash = new_hash

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    source.failure_count = 0
    source.locked_until = None
    account.failure_count = 0
    account.locked_until = None
    session.flush()
    record_audit(
        session,
        action="auth.login",
        actor=AuditActor.admin(user, ip_address=ip_address, user_agent=user_agent),
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
    )
    return user


def _audit_blocked(
    session: Session,
    actor: AuditActor,
    user: UtilityUser | None,
    identifier: str,
    detail: str,
) -> None:
    record_audit(
        session,
        action="auth.login_blocked",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id) if user is not None else None,
        target_label=identifier,
        detail=detail,
    )


# -------------------------------------------------------------------- sessions


def issue_session(
    session: Session,
    *,
    user: UtilityUser,
    ip_address: str | None = None,
    user_agent: str | None = None,
    settings: Settings | None = None,
) -> IssuedSession:
    settings = settings or get_settings()
    now = utcnow()
    session_token = new_token()
    csrf_token = new_token()
    idle_expires_at = now + timedelta(minutes=settings.session_idle_ttl_minutes)
    absolute_expires_at = now + timedelta(hours=settings.session_absolute_ttl_hours)

    row = UtilitySession(
        user_id=user.id,
        session_token_hash=hash_token(session_token),
        csrf_token_hash=hash_token(csrf_token),
        created_at=now,
        last_seen_at=now,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        ip_address=ip_address,
        user_agent=(user_agent[:256] if user_agent else None),
    )
    session.add(row)
    session.flush()
    return IssuedSession(
        session_token=session_token,
        csrf_token=csrf_token,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        user=user,
    )


def load_session(session: Session, session_token: str) -> UtilitySession | None:
    """Look up a live session by token, sliding its idle window forward."""
    if not session_token:
        return None
    row = session.scalar(
        select(UtilitySession).where(UtilitySession.session_token_hash == hash_token(session_token))
    )
    if row is None:
        return None
    now = utcnow()
    if row.revoked_at is not None or row.idle_expires_at <= now or row.absolute_expires_at <= now:
        return None
    settings = get_settings()
    row.last_seen_at = now
    row.idle_expires_at = min(
        now + timedelta(minutes=settings.session_idle_ttl_minutes), row.absolute_expires_at
    )
    session.flush()
    return row


def verify_csrf(row: UtilitySession, presented_token: str | None) -> bool:
    if not presented_token:
        return False
    return tokens_equal(row.csrf_token_hash, presented_token)


def revoke_session(session: Session, *, row: UtilitySession) -> None:
    row.revoked_at = utcnow()
    session.flush()


def revoke_all_sessions(
    session: Session, *, user_id: int, keep_session_id: int | None = None
) -> int:
    now = utcnow()
    query = select(UtilitySession).where(
        UtilitySession.user_id == user_id, UtilitySession.revoked_at.is_(None)
    )
    revoked = 0
    for row in session.scalars(query):
        if keep_session_id is not None and row.id == keep_session_id:
            continue
        row.revoked_at = now
        revoked += 1
    session.flush()
    return revoked


def purge_expired_sessions(session: Session, *, older_than_days: int = 7) -> int:
    """Housekeeping: remove sessions that expired a while ago."""
    cutoff = utcnow() - timedelta(days=older_than_days)
    result = session.execute(
        delete(UtilitySession).where(UtilitySession.absolute_expires_at < cutoff)
    )
    return int(result.rowcount or 0)


# ------------------------------------------------------------------------ TOTP


def provision_totp(session: Session, *, user: UtilityUser) -> tuple[str, str]:
    """Generate and store an unconfirmed TOTP secret. Returns (secret, otpauth URI).

    ``totp_enabled`` stays False until the user proves possession by confirming a
    code, so a half finished enrolment cannot lock anyone out.
    """
    secret = pyotp.random_base32()
    user.totp_secret_encrypted = get_secret_box().encrypt(secret, purpose=PURPOSE_TOTP_SECRET)
    user.totp_enabled = False
    user.totp_last_step = None
    session.flush()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=TOTP_ISSUER)
    return secret, uri


def verify_totp(user: UtilityUser, code: str, *, consume: bool = False) -> bool:
    """Check an authenticator code.

    With ``consume`` the accepted time step is remembered on the user and no
    code from that step or an earlier one is accepted again, so a code observed
    in transit (or over a shoulder) cannot be replayed within its window.
    """
    step = _totp_step(user, code)
    if step is None:
        return False
    if user.totp_last_step is not None and step <= user.totp_last_step:
        return False
    if consume:
        user.totp_last_step = step
    return True


def _totp_step(user: UtilityUser, code: str) -> int | None:
    """The time step ``code`` is valid for, within the window, or None."""
    if not user.totp_secret_encrypted or not code:
        return None
    candidate = code.strip().replace(" ", "")
    if not candidate.isdigit():
        return None
    secret = get_secret_box().decrypt(user.totp_secret_encrypted, purpose=PURPOSE_TOTP_SECRET)
    totp = pyotp.TOTP(secret)
    current_step = int(utcnow().timestamp()) // totp.interval
    for step in range(current_step - TOTP_VALID_WINDOW, current_step + TOTP_VALID_WINDOW + 1):
        if hmac.compare_digest(totp.at(step * totp.interval), candidate):
            return step
    return None


def _consume_totp(session: Session, user: UtilityUser, code: str) -> bool:
    """Accept an authenticator code once: its step is recorded by a conditional
    UPDATE, so of two sign-ins presenting the same code (or an older one) only
    the first succeeds, whatever either of them read before."""
    step = _totp_step(user, code)
    if step is None:
        return False
    claimed = session.execute(
        update(UtilityUser)
        .where(
            UtilityUser.id == user.id,
            or_(UtilityUser.totp_last_step.is_(None), UtilityUser.totp_last_step < step),
        )
        .values(totp_last_step=step)
        .execution_options(synchronize_session=False)
    ).rowcount
    if claimed != 1:
        return False
    set_committed_value(user, "totp_last_step", step)
    return True


def _normalise_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.lower() if ch.isalnum())


def _recovery_digest(code: str) -> str:
    # Keyed with the master key, so a copy of the database alone is not enough
    # to test guesses against the stored values.
    return get_secret_box().digest(code, purpose=PURPOSE_RECOVERY_CODE)


def issue_recovery_codes(session: Session, *, user: UtilityUser) -> list[str]:
    """Replace the user's recovery codes and return the new ones, once.

    Only keyed digests are stored. Each code works a single time in place of the
    authenticator code, so a lost or broken phone does not lock the account.
    """
    codes = [secrets.token_hex(RECOVERY_CODE_BYTES) for _ in range(RECOVERY_CODE_COUNT)]
    user.totp_recovery_codes = [_recovery_digest(code) for code in codes]
    session.flush()
    # Shown in groups of four so they can be read and typed without mistakes.
    return ["-".join(code[i : i + 4] for i in range(0, len(code), 4)) for code in codes]


def use_recovery_code(session: Session, *, user: UtilityUser, code: str) -> bool:
    """Consume a recovery code. True if it was valid; it cannot be used again."""
    candidate = _normalise_recovery_code(code)
    if len(candidate) != RECOVERY_CODE_BYTES * 2 or not user.totp_recovery_codes:
        return False
    # Re-read the row under a lock (FOR UPDATE; on SQLite the write lock): two
    # sign-ins presenting the same code at the same moment must not both find
    # it unused. Held only for this short write, never across Argon2.
    locking.lock_row(session, user)
    stored = list(user.totp_recovery_codes or [])
    digest = _recovery_digest(candidate)
    match = next((item for item in stored if hmac.compare_digest(str(item), digest)), None)
    if match is None:
        return False
    stored.remove(match)
    # A new list object, so the JSON column is seen as changed.
    user.totp_recovery_codes = stored
    session.flush()
    return True


def confirm_totp(
    session: Session, *, user: UtilityUser, code: str, actor: AuditActor
) -> list[str] | None:
    """Turn two factor authentication on. Returns the recovery codes, or None if
    the code did not match."""
    if not verify_totp(user, code, consume=True):
        return None
    user.totp_enabled = True
    codes = issue_recovery_codes(session, user=user)
    record_audit(
        session,
        action="account.totp_enabled",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
    )
    return codes


def disable_totp(
    session: Session, *, user: UtilityUser, actor: AuditActor, action: str = "account.totp_disabled"
) -> None:
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_recovery_codes = None
    user.totp_last_step = None
    session.flush()
    record_audit(
        session,
        action=action,
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
    )


class ReauthLocked(AuthError):
    """Too many wrong passwords on a re-check: the session is ended."""

    def __init__(self) -> None:
        super().__init__(
            "Too many incorrect passwords. You have been signed out; sign in again to continue."
        )


def confirm_current_password(
    session: Session,
    *,
    user: UtilityUser,
    password: str,
    ip_address: str,
    actor: AuditActor | None = None,
) -> bool:
    """Re-check the signed-in user's password before a sensitive change.

    A session cookie alone is not enough to change how an account is protected:
    someone at an unlocked screen, or holding a stolen session, could otherwise
    enrol their own authenticator and lock the owner out.

    Attempts are throttled like sign-ins and audited. After a few wrong
    passwords in a row every session for the account is ended, so the guessing
    has to continue at the sign-in form, with its lockouts. Raises
    :class:`RateLimited` or :class:`ReauthLocked`.
    """
    identifier = f"reauth:{user.id}"
    address = throttle_address(ip_address)
    _check_rate_limit(session, identifier=identifier, ip_address=address, settings=get_settings())
    # Counted and committed before the password is verified: no lock is held
    # across Argon2 (LOCK ORDER, above authenticate).
    session.commit()
    with _verification_slot():
        correct = verify_password(user.password_hash, password)
    row = _locked_attempt_row(session, identifier=identifier, ip_address=address, now=utcnow())
    if correct:
        row.failure_count = 0
        session.flush()
        return True

    row.failure_count = (row.failure_count or 0) + 1
    locked = row.failure_count >= REAUTH_MAX_FAILURES
    record_audit(
        session,
        action="auth.reauth_failed",
        actor=actor or AuditActor.admin(user, ip_address=ip_address),
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
        detail=(
            "Wrong password on a re-check before a sensitive change."
            + (" All sessions for the account were ended." if locked else "")
        ),
    )
    if locked:
        row.failure_count = 0
        revoke_all_sessions(session, user_id=user.id)
        session.flush()
        raise ReauthLocked
    session.flush()
    return False
