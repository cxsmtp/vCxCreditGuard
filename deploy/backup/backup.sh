#!/bin/sh
# Scheduled database backups for the bundled PostgreSQL.
#
# Runs in the `backup` service of docker-compose.yml. Every BACKUP_INTERVAL_HOURS
# it writes a compressed, self-contained dump to /backups and deletes dumps older
# than BACKUP_KEEP_DAYS. A dump is written under a temporary name and renamed
# only when pg_dump has succeeded, so a file with the final name is always a
# complete backup.
#
#   backup.sh         run for ever, on the schedule
#   backup.sh once    take one dump now and exit
#
# The database is the only place the undo snapshots live: without them, access
# that CxCreditGuard has restricted in Checkmarx One cannot be given back
# automatically. Copy /backups somewhere off this host (see the README).
set -eu

INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
RETRY_SECONDS=600
DIR=/backups

# Whole numbers only: the shell cannot sleep "0.5 hours", and 0 would dump in a
# tight loop until the disk is full.
for pair in "BACKUP_INTERVAL_HOURS=$INTERVAL_HOURS" "BACKUP_KEEP_DAYS=$KEEP_DAYS"; do
    case "${pair#*=}" in
    '' | *[!0-9]* | 0*)
        echo "backup: ${pair%%=*} must be a whole number of at least 1, not '${pair#*=}'" >&2
        exit 2
        ;;
    esac
done

# The dumps hold password hashes and the audit log: readable by the owner only.
umask 077
mkdir -p "$DIR"

backup_once() {
    # Before the app's first start the database is empty, and an empty dump
    # that looks like a backup is worse than none.
    if [ "$(psql -Atc "select to_regclass('alembic_version') is not null" 2>/dev/null)" != "t" ]; then
        echo "backup: the database has no schema yet (the app has not started); nothing to back up" >&2
        return 1
    fi
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    final="$DIR/cxcreditguard-$stamp.dump"
    partial="$final.partial"
    if pg_dump --format=custom --no-owner --file="$partial"; then
        mv "$partial" "$final"
        echo "backup: wrote $final ($(du -h "$final" | cut -f1))"
    else
        rm -f "$partial"
        echo "backup: pg_dump FAILED at $stamp" >&2
        return 1
    fi
    # Remove what is past its keep-by date, but never the newest dump.
    newest="$(ls -1t "$DIR"/cxcreditguard-*.dump 2>/dev/null | head -n 1)"
    find "$DIR" -name 'cxcreditguard-*.dump' -mmin "+$((KEEP_DAYS * 1440))" ! -path "$newest" -delete
    find "$DIR" -name '*.partial' -mmin +120 -delete
}

if [ "${1:-}" = "once" ]; then
    backup_once
    exit $?
fi

# This shell is the container's first process, which ignores signals it has no
# handler for: without these, stopping the container waits out the full grace
# period and then kills it, possibly in the middle of a dump.
trap 'echo "backup: stopping"; exit 0' TERM INT

echo "backup: every ${INTERVAL_HOURS}h, keeping ${KEEP_DAYS} days, in $DIR"
while true; do
    if backup_once; then
        pause="$((INTERVAL_HOURS * 3600))"
    else
        # Not a whole interval later: a day without a backup because the
        # database was restarting at the wrong moment is a day too long.
        pause="$RETRY_SECONDS"
        echo "backup: trying again in $((RETRY_SECONDS / 60)) minutes" >&2
    fi
    sleep "$pause" &
    wait $!
done
