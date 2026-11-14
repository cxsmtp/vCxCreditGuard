"""Clear every stored secret after the master key has been lost.

    python -m scripts.reset_secrets --yes

The master key encrypts the Checkmarx API key, the SMTP password, the webhook
URL and signing secret, and two factor secrets. If the key is lost none of them
can be read again, and the app refuses to start rather than run without them.

This removes those stored values so the app can start with a NEW master key.
Nothing else is touched: limits, exemptions, the audit log, usage history and
accounts (with their passwords) are kept. Afterwards an admin must:

  * re-enter the Checkmarx One API key on the Setup page,
  * re-enter SMTP and webhook secrets on the Settings page,
  * set up two factor authentication again (it is switched off for everyone).

Restrictions already applied in Checkmarx One are not affected; their undo
snapshots are not encrypted and Restore keeps working once the connection is
re-entered.
"""

from __future__ import annotations

import argparse
import sys

from sqlalchemy import delete, select

from app.db.session import session_scope
from app.models.auth import UtilitySession, UtilityUser
from app.models.connection import AppSetting, CxConnection
from app.services import master_key, settings_store
from app.services.audit import AuditActor, record_audit


def reset_secrets() -> dict[str, int]:
    counts = {"connection": 0, "settings": 0, "two_factor": 0}
    with session_scope() as session:
        counts["connection"] = int(session.execute(delete(CxConnection)).rowcount or 0)
        for key in (*settings_store.SECRET_KEYS, master_key.CHECK_KEY):
            row = session.get(AppSetting, key)
            if row is not None:
                session.delete(row)
                counts["settings"] += 1
        for user in session.scalars(
            select(UtilityUser).where(UtilityUser.totp_secret_encrypted.is_not(None))
        ):
            user.totp_enabled = False
            user.totp_secret_encrypted = None
            user.totp_recovery_codes = None
            user.totp_last_step = None
            counts["two_factor"] += 1
        # Recovery codes are keyed with the master key too.
        for user in session.scalars(
            select(UtilityUser).where(UtilityUser.totp_recovery_codes.is_not(None))
        ):
            user.totp_recovery_codes = None
        session.execute(delete(UtilitySession))
        record_audit(
            session,
            action="secrets.reset",
            actor=AuditActor.system("reset_secrets"),
            target_type="settings",
            after=counts,
            detail=(
                "Stored secrets were cleared from the command line after a master key "
                "change. The Checkmarx connection, notification secrets and two factor "
                "must be set up again."
            ),
        )
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--yes", action="store_true", help="confirm that the secrets are lost")
    args = parser.parse_args(argv)
    if not args.yes:
        print(__doc__)
        print("Nothing was changed. Re-run with --yes to clear the stored secrets.")
        return 2
    counts = reset_secrets()
    print(
        f"Cleared: {counts['connection']} connection, {counts['settings']} stored setting(s), "
        f"two factor for {counts['two_factor']} account(s). All sessions were ended."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
