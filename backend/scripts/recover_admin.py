"""Get an administrator back in when nobody else can help them.

    python -m scripts.recover_admin <username>

For the case the app itself cannot solve: the only administrator has lost their
password, or their authenticator and their recovery codes, and there is no
second administrator to reset them from the Settings page.

For that one account this:

  * sets a temporary password, printed once here, that must be changed at the
    next sign-in,
  * switches two factor authentication off (set it up again afterwards),
  * clears sign-in lockouts and ends every session.

Nothing else changes: the account keeps its role, and a disabled account stays
disabled. The reset is written to the audit log. It needs a shell in the
container, which is already enough to read the database and the master key, so
it grants nothing that access did not.
"""

from __future__ import annotations

import argparse
import secrets
import string
import sys

from sqlalchemy import select

from app.core.passwords import hash_password, validate_password
from app.db.base import utcnow
from app.db.session import session_scope
from app.models.auth import UtilityUser
from app.services import auth as auth_service
from app.services.audit import AuditActor, record_audit


def temporary_password() -> str:
    """A random password that satisfies the policy whatever it currently is."""
    alphabet = string.ascii_letters + string.digits
    while True:
        body = "".join(secrets.choice(alphabet) for _ in range(20))
        candidate = f"{body[:10]}-{body[10:]}"
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
        ):
            return candidate


def recover(username: str) -> str | None:
    """Reset the account and return its temporary password, or None if unknown."""
    with session_scope() as session:
        user = auth_service.get_user_by_username(session, username)
        if user is None:
            return None
        password = temporary_password()
        validate_password(password, username=user.username)
        user.password_hash = hash_password(password)
        user.password_changed_at = utcnow()
        user.must_change_password = True
        had_two_factor = bool(user.totp_enabled)
        user.totp_enabled = False
        user.totp_secret_encrypted = None
        user.totp_recovery_codes = None
        user.totp_last_step = None
        auth_service.clear_login_throttle(session, username=user.username)
        ended = auth_service.revoke_all_sessions(session, user_id=user.id)
        record_audit(
            session,
            action="account.recovered",
            actor=AuditActor.system("recover_admin"),
            target_type="utility_user",
            target_id=str(user.id),
            target_label=user.username,
            after={"two_factor_removed": had_two_factor, "sessions_ended": ended},
            detail=(
                "Password replaced with a temporary one and two factor switched off from "
                "the command line. The account must choose a new password at next sign-in."
            ),
        )
        return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username", nargs="?", help="the account to recover")
    args = parser.parse_args(argv)
    if not args.username:
        print(__doc__)
        with session_scope() as session:
            names = session.scalars(select(UtilityUser.username).order_by(UtilityUser.username))
            print("Accounts: " + ", ".join(names))
        return 2
    password = recover(args.username)
    if password is None:
        print(f"There is no account named {args.username!r}. Nothing was changed.")
        return 1
    print(f"Temporary password for {args.username}: {password}")
    print(
        "It is shown only here. Sign in with it and choose a new one; two factor is off "
        "for this account until it is set up again."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
