#!/bin/sh
# Fail fast on a misconfigured container, then apply migrations before serving.
set -eu

if [ -z "${CXCG_MASTER_KEY:-}" ] && [ -z "${CXCG_MASTER_KEY_FILE:-}" ]; then
    echo "CxCreditGuard: neither CXCG_MASTER_KEY nor CXCG_MASTER_KEY_FILE is set." >&2
    echo "Generate one with:" >&2
    echo '  python -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"' >&2
    exit 1
fi

echo "CxCreditGuard: applying database migrations"
python -m app.db.migrate

exec "$@"
