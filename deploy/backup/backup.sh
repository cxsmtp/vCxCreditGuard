#!/bin/sh
# Scheduled database backups for the bundled PostgreSQL.
#
# Runs in the `backup` service of docker-compose.yml. Every BACKUP_INTERVAL_HOURS
# it writes a compressed, self-contained dump to /backups and deletes dumps older
# than BACKUP_KEEP_DAYS. A dump is written under a temporary name and renamed
# only when pg_dump has succeeded, so a file with the final name is always a
# complete backup.
#
# The database is the only place the undo snapshots live: without them, access
# that CxCreditGuard has restricted in Checkmarx One cannot be given back
# automatically. Copy /backups somewhere off this host (see the README).
set -eu

INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
DIR=/backups

mkdir -p "$DIR"

backup_once() {
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
    find "$DIR" -name 'cxcreditguard-*.dump' -mtime "+$KEEP_DAYS" ! -path "$newest" -delete
    find "$DIR" -name '*.partial' -mmin +120 -delete
}

if [ "${1:-}" = "once" ]; then
    backup_once
    exit $?
fi

echo "backup: every ${INTERVAL_HOURS}h, keeping ${KEEP_DAYS} days, in $DIR"
while true; do
    backup_once || true
    sleep "$((INTERVAL_HOURS * 3600))"
done
