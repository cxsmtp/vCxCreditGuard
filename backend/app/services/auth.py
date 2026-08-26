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

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

import pyotp
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.crypto import PURPOSE_TOTP_SECRET, get_secret_box
from app.core.passwords import hash_password, needs_rehash, validate_password, verify_password
from app.core.tokens import hash_token, new_token, tokens_equal
from app.db.base import utcnow
from app.models.auth import LoginAttempt, UtilitySession, UtilityUser
from app.models.enums import UtilityRole
from app.services.audit import AuditActor, record_audit

logger = logging.getLogger(__name__)

RATE_LIMIT_WINDOW_SECONDS = 60
TOTP_ISSUER = "CxCreditGuard"
TOTP_VALID_WINDOW = 1

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
    validate_password(new_password, username=user.username)
    user.password_hash = hash_password(new_password)
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
    session: Session, *, identifier: str, ip_address: str, settings: Settings
) -> None:
    now = utcnow()
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
    row = session.scalar(
        select(LoginAttempt).where(
            LoginAttempt.identifier == identifier, LoginAttempt.ip_address == ip_address
        )
    )
    if row is None:
        session.add(
            LoginAttempt(
                identifier=identifier,
                ip_address=ip_address,
                window_started_at=now,
                attempt_count=1,
                last_attempt_at=now,
            )
        )
        session.flush()
        return

    if row.window_started_at < window_start:
        row.window_started_at = now
        row.attempt_count = 1
        row.last_attempt_at = now
        session.flush()
        return

    row.attempt_count += 1
    row.last_attempt_at = now
    session.flush()
    if row.attempt_count > settings.login_rate_limit_per_minute:
        elapsed = (now - row.window_started_at).total_seconds()
        raise RateLimited(retry_after_seconds=max(1, int(RATE_LIMIT_WINDOW_SECONDS - elapsed)))


def _lockout_seconds(failed_count: int, settings: Settings) -> int:
    """Exponential backoff once the attempt threshold is passed."""
    over = max(0, failed_count - settings.login_max_attempts)
    delay = settings.login_lockout_base_seconds * (2**over)
    return int(min(delay, settings.login_lockout_max_seconds))


def _register_failure(session: Session, user: UtilityUser, settings: Settings) -> None:
    user.failed_login_count += 1
    if user.failed_login_count >= settings.login_max_attempts:
        user.locked_until = utcnow() + timedelta(
            seconds=_lockout_seconds(user.failed_login_count, settings)
        )
    session.flush()


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
    """Verify credentials, returning the user or raising an AuthError subclass."""
    settings = settings or get_settings()
    identifier = username.strip().lower()[:128]
    _check_rate_limit(session, identifier=identifier, ip_address=ip_address, settings=settings)

    actor = AuditActor.anonymous(ip_address=ip_address, user_agent=user_agent)
    user = get_user_by_username(session, identifier)

    if user is None:
        # Constant work for unknown accounts.
        verify_password(_DUMMY_HASH, password)
        record_audit(
            session,
            action="auth.login_failed",
            actor=actor,
            target_type="utility_user",
            target_label=identifier,
            detail="No such account.",
        )
        raise InvalidCredentials

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

    if user.locked_until is not None and user.locked_until > utcnow():
        retry_after = int((user.locked_until - utcnow()).total_seconds())
        record_audit(
            session,
            action="auth.login_blocked",
            actor=actor,
            target_type="utility_user",
            target_id=str(user.id),
            target_label=user.username,
            detail=f"Account locked for another {retry_after}s.",
        )
        raise AccountLocked(retry_after_seconds=retry_after)

    if not verify_password(user.password_hash, password):
        _register_failure(session, user, settings)
        record_audit(
            session,
            action="auth.login_failed",
            actor=actor,
            target_type="utility_user",
            target_id=str(user.id),
            target_label=user.username,
            detail=f"Wrong password. Failure count is now {user.failed_login_count}.",
        )
        raise InvalidCredentials

    if user.totp_enabled:
        if not totp_code:
            # Not a failure: the client must prompt for the second factor. The
            # password was already verified, so this cannot be used as an oracle
            # by anyone who does not already know the password.
            raise TotpRequired
        if not verify_totp(user, totp_code):
            _register_failure(session, user, settings)
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

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = utcnow()
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
    session.flush()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=TOTP_ISSUER)
    return secret, uri


def verify_totp(user: UtilityUser, code: str) -> bool:
    if not user.totp_secret_encrypted or not code:
        return False
    secret = get_secret_box().decrypt(user.totp_secret_encrypted, purpose=PURPOSE_TOTP_SECRET)
    return pyotp.TOTP(secret).verify(code.strip().replace(" ", ""), valid_window=TOTP_VALID_WINDOW)


def confirm_totp(session: Session, *, user: UtilityUser, code: str, actor: AuditActor) -> bool:
    if not verify_totp(user, code):
        return False
    user.totp_enabled = True
    session.flush()
    record_audit(
        session,
        action="account.totp_enabled",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
    )
    return True


def disable_totp(session: Session, *, user: UtilityUser, actor: AuditActor) -> None:
    user.totp_enabled = False
    user.totp_secret_encrypted = None
    session.flush()
    record_audit(
        session,
        action="account.totp_disabled",
        actor=actor,
        target_type="utility_user",
        target_id=str(user.id),
        target_label=user.username,
    )
