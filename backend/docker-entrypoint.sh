#!/bin/sh
# Fail fast on a misconfigured container, then hand over to the command.
set -eu

if [ -z "${CXCG_MASTER_KEY:-}" ] && [ -z "${CXCG_MASTER_KEY_FILE:-}" ]; then
    echo "CxCreditGuard: neither CXCG_MASTER_KEY nor CXCG_MASTER_KEY_FILE is set." >&2
    echo "Generate one with:" >&2
    echo '  python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"' >&2
    exit 1
fi

# The server migrates the database itself when it starts, after it has made
# sure no other instance is using it. Doing it here as well would let a second
# copy (a new image started while the old container is still running) change
# the schema underneath the first before being refused. Any other command, such
# as one of the scripts, gets an up to date schema first.
case "${1:-}" in
uvicorn) ;;
*)
    echo "CxCreditGuard: applying database migrations"
    python -m app.db.migrate
    ;;
esac

exec "$@"
