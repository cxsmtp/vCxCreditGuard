#!/bin/sh
# Restore the database from a dump written by backup.sh.
#
#   restore.sh /backups/cxcreditguard-20261114T020000Z.dump
#   restore.sh latest
#
# Runs in the `backup` service of docker-compose.yml, with the app stopped:
#
#   podman compose stop app
#   podman compose exec backup sh /usr/local/bin/restore.sh latest
#   podman compose start app
#
# The dump is restored into a new database first. Only when that has worked is
# it swapped into place, and the database it replaces is kept under another
# name rather than deleted, so a wrong file name, a truncated dump or a
# restore that fails half way leaves the running data exactly as it was.
set -eu

DB="${PGDATABASE:?PGDATABASE is not set}"
DIR=/backups

fail() {
    echo "restore: $*" >&2
    echo "restore: nothing was changed." >&2
    exit 1
}

file="${1:-}"
[ -n "$file" ] || fail "say which dump to restore (a path under $DIR, or 'latest')"
if [ "$file" = "latest" ]; then
    file="$(ls -1t "$DIR"/cxcreditguard-*.dump 2>/dev/null | head -n 1)"
    [ -n "$file" ] || fail "there are no dumps in $DIR"
fi
[ -f "$file" ] || fail "$file does not exist (the dumps are: $(ls "$DIR" 2>/dev/null | tr '\n' ' '))"
pg_restore --list "$file" >/dev/null 2>&1 || fail "$file is not a complete dump"

# Anything still connected (the app, most likely) would be writing to a
# database that is about to be set aside.
others="$(psql -d postgres -Atc "select count(*) from pg_stat_activity where datname = '$DB' and pid <> pg_backend_pid()")"
[ "$others" = "0" ] || fail "$others connection(s) are still open to $DB - stop the app first (podman compose stop app)"

stamp="$(date -u +%Y%m%dt%H%M%Sz)"
incoming="${DB}_restoring"
previous="${DB}_before_${stamp}"

echo "restore: loading $file"
dropdb --if-exists "$incoming"
createdb "$incoming"
if ! pg_restore --no-owner --exit-on-error -d "$incoming" "$file"; then
    dropdb --if-exists "$incoming"
    fail "the dump could not be loaded"
fi

psql -d postgres -v ON_ERROR_STOP=1 -q <<SQL
BEGIN;
ALTER DATABASE "$DB" RENAME TO "$previous";
ALTER DATABASE "$incoming" RENAME TO "$DB";
COMMIT;
SQL

echo "restore: done. $DB now holds the contents of $file."
echo "restore: the database it replaced is kept as $previous. Once you have started the"
echo "restore: app and checked it, remove that copy with:  dropdb $previous"
