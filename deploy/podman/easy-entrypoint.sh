#!/bin/sh
# Easy, self-contained entrypoint for the single-container CxCreditGuard image
# (deploy/podman/Dockerfile).
#
# Removes the scaffolding a hardened deployment needs (an operator-supplied
# master key, a TLS proxy, bootstrap env vars) so a bare `podman run` just
# works:
#   * generates an AES master key on first start and persists it on the data
#     volume, so secrets stay decryptable across restarts;
#   * creates a first "admin" account (password generated, or from the
#     environment) only when the database has no accounts yet.
#
# This convenience image intentionally runs in development mode over plain
# HTTP (see the ENV block in the Dockerfile). If you set CXCG_ENV=production
# you must also provide a TLS front-end and a real CXCG_MASTER_KEY; the
# existing backend/Dockerfile + docker-compose.yml is the supported path for
# that posture and this entrypoint does not weaken it.
set -eu

DATA_DIR="${CXCG_DATA_DIR:-/app/data}"
mkdir -p "$DATA_DIR"

# --- Master key -------------------------------------------------------------
# Use an explicit key or a mounted secret when the operator supplied one;
# otherwise generate a fresh one and keep it on the data volume.
if [ -z "${CXCG_MASTER_KEY:-}" ] && [ -z "${CXCG_MASTER_KEY_FILE:-}" ]; then
    KEY_FILE="$DATA_DIR/.master_key"
    if [ -s "$KEY_FILE" ]; then
        CXCG_MASTER_KEY="$(cat "$KEY_FILE")"
        echo "CxCreditGuard: using the master key persisted at $KEY_FILE"
    else
        CXCG_MASTER_KEY="$(python -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')"
        umask 177
        printf '%s\n' "$CXCG_MASTER_KEY" > "$KEY_FILE"
        chmod 600 "$KEY_FILE"
        echo "CxCreditGuard: generated a new master key and stored it at $KEY_FILE"
    fi
    export CXCG_MASTER_KEY
fi

# --- First admin account ----------------------------------------------------
# bootstrap_admin_if_needed() creates the account only when the database has no
# users yet, so on an existing data volume these values are harmless and just
# supply the app's normal bootstrap mechanism.
CXCG_BOOTSTRAP_ADMIN_USERNAME="${CXCG_BOOTSTRAP_ADMIN_USERNAME:-admin}"
if [ -z "${CXCG_BOOTSTRAP_ADMIN_PASSWORD:-}" ]; then
    PW_FILE="$DATA_DIR/.admin_password"
    if [ -s "$PW_FILE" ]; then
        CXCG_BOOTSTRAP_ADMIN_PASSWORD="$(cat "$PW_FILE")"
        # Reused data volume: the password was printed when it was first
        # generated and is not re-echoed here (it would land in the logs on every
        # restart). Point the operator at the file instead.
        echo "CxCreditGuard: admin account already initialised on this volume."
        echo "CxCreditGuard: username=$CXCG_BOOTSTRAP_ADMIN_USERNAME; the generated password is stored at $PW_FILE"
        echo "CxCreditGuard: read it with 'podman exec <container> cat $PW_FILE'"
    else
        # Generate a password that satisfies the app's policy, using the app's
        # own validator so a random string can never lock bootstrap out.
        CXCG_BOOTSTRAP_ADMIN_PASSWORD="$(
            python - <<'PY'
from app.core.passwords import validate_password
import secrets
import string
alphabet = string.ascii_letters + string.digits + "-_!@#$%^&*()"
while True:
    pw = "".join(secrets.choice(alphabet) for _ in range(18))
    try:
        validate_password(pw, username="admin")
        break
    except ValueError:
        pass
print(pw)
PY
        )"
        umask 177
        printf '%s\n' "$CXCG_BOOTSTRAP_ADMIN_PASSWORD" > "$PW_FILE"
        chmod 600 "$PW_FILE"
        echo "CxCreditGuard: initial credentials -> username=$CXCG_BOOTSTRAP_ADMIN_USERNAME password=$CXCG_BOOTSTRAP_ADMIN_PASSWORD"
        echo "CxCreditGuard: saved to $PW_FILE (change it in the UI after first login)"
    fi
fi
export CXCG_BOOTSTRAP_ADMIN_USERNAME CXCG_BOOTSTRAP_ADMIN_PASSWORD

# --- Migrations, then serve -------------------------------------------------
echo "CxCreditGuard: applying database migrations"
python -m app.db.migrate

exec "$@"