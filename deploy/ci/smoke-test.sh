#!/bin/sh
# End-to-end smoke test of the documented deployment (docker-compose.yml).
#
#   deploy/ci/smoke-test.sh up      build the image and start everything
#   deploy/ci/smoke-test.sh check   exercise it through the TLS proxy
#   deploy/ci/smoke-test.sh logs    print container logs
#   deploy/ci/smoke-test.sh down    stop and remove it, volumes included
#
# Optional environment: SMOKE_APP_IMAGE (test an image that is already built
# instead of building one), SMOKE_HTTPS_PORT (default 8443), SMOKE_WORK_DIR.
#
# CI runs it on every change; it works the same on a laptop. It uses its own
# compose project name, a throwaway .env and a self signed certificate, all
# under a temporary directory, so it never touches a real deployment's files.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${SMOKE_WORK_DIR:-${TMPDIR:-/tmp}/cxcg-smoke}"
PORT="${SMOKE_HTTPS_PORT:-8443}"
BASE="https://127.0.0.1:${PORT}"
ADMIN_PASSWORD='Sm0ke!Test#Adm1n-Pw'

compose() {
    docker compose -p cxcg-smoke --project-directory "$ROOT" --env-file "$WORK/.env" \
        -f "$ROOT/docker-compose.yml" -f "$WORK/override.yml" "$@"
}

fail() {
    echo "SMOKE TEST FAILED: $*" >&2
    exit 1
}

prepare() {
    mkdir -p "$WORK/certs"
    if [ ! -f "$WORK/.env" ]; then
        {
            echo "CXCG_ENV=production"
            echo "CXCG_MASTER_KEY=$(head -c 32 /dev/urandom | base64)"
            echo "POSTGRES_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
            echo "CXCG_BOOTSTRAP_ADMIN_USERNAME=admin"
            echo "CXCG_BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD"
            # Deliberately wrong: the compose file must not take this from .env.
            echo "CXCG_TRUSTED_PROXY_HOPS=0"
        } > "$WORK/.env"
    fi
    if [ ! -f "$WORK/certs/fullchain.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
            -keyout "$WORK/certs/privkey.pem" -out "$WORK/certs/fullchain.pem" \
            -subj "/CN=localhost" 2>/dev/null
    fi
    {
        echo "services:"
        echo "  app:"
        # The throwaway .env, not one in the repository root.
        echo "    env_file: !override"
        echo "      - path: $WORK/.env"
        echo "        required: true"
        if [ -n "${SMOKE_APP_IMAGE:-}" ]; then
            # Test an image that is already built instead of building one.
            echo "    image: ${SMOKE_APP_IMAGE}"
            echo "    build: !reset null"
        fi
    } > "$WORK/override.yml"
    cat >> "$WORK/override.yml" <<YAML
  proxy:
    ports: !override
      - "${PORT}:443"
    volumes: !override
      - ${SMOKE_NGINX_CONF:-$ROOT/deploy/nginx/nginx.conf}:/etc/nginx/conf.d/default.conf:ro
      - $WORK/certs:/etc/nginx/certs:ro
YAML
}

case "${1:-}" in
up)
    prepare
    if [ -n "${SMOKE_APP_IMAGE:-}" ]; then
        compose up -d
    else
        compose up -d --build
    fi
    echo "waiting for the app behind the proxy..."
    for _ in $(seq 1 60); do
        if [ "$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/healthz")" = "200" ]; then
            echo "up"
            exit 0
        fi
        sleep 3
    done
    compose ps
    fail "the stack did not become healthy"
    ;;

check)
    jar="$WORK/cookies"
    rm -f "$jar"

    health="$(curl -sk "$BASE/healthz")"
    echo "$health" | grep -q '"database":true' || fail "health check: $health"

    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)" != "200" ] \
        || fail "plain HTTP was served"

    # The app container must see exactly one trusted proxy, whatever .env says.
    hops="$(compose exec -T app printenv CXCG_TRUSTED_PROXY_HOPS)"
    [ "$hops" = "1" ] || fail "CXCG_TRUSTED_PROXY_HOPS is '$hops' in the app container, not 1"

    # Sign in through the proxy, claiming to be someone else.
    code="$(curl -sk -c "$jar" -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' -H 'X-Forwarded-For: 6.6.6.6' \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" "$BASE/api/auth/login")"
    [ "$code" = "200" ] || fail "sign-in returned $code"
    code="$(curl -sk -b "$jar" -o /dev/null -w '%{http_code}' "$BASE/api/me")"
    [ "$code" = "200" ] || fail "/api/me returned $code"

    forged="$(compose exec -T db sh -c \
        'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "select count(*) from audit_log_entry where ip_address = '"'"'6.6.6.6'"'"'"')"
    [ "$forged" = "0" ] || fail "a forged X-Forwarded-For reached the audit log"
    # ...and the sign-in was recorded, with an address (so the check above is
    # not passing just because nothing was written).
    recorded="$(compose exec -T db sh -c \
        'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "select count(*) from audit_log_entry where action = '"'"'auth.login'"'"' and ip_address is not null"')"
    [ "$recorded" = "1" ] || fail "the sign-in was not recorded with a client address"

    # The SPA is served, and the API schema is not exposed in production.
    curl -sk "$BASE/" | grep -qi '<div id="root"' || fail "the web app was not served"
    # (An unknown path answers with the web app's page, so look at the content.)
    if curl -sk "$BASE/openapi.json" | grep -q '"openapi"'; then
        fail "the API schema is exposed in production"
    fi

    # A backup can be taken and is a complete, restorable dump at the current schema.
    compose exec -T backup /bin/sh /usr/local/bin/backup.sh once
    compose exec -T backup sh -c '
        set -e
        latest="$(ls -1t /backups/cxcreditguard-*.dump | head -n 1)"
        dropdb --if-exists smoke_restore
        createdb smoke_restore
        pg_restore --no-owner -d smoke_restore "$latest"
        test "$(psql -d smoke_restore -Atc "select count(*) from utility_user")" = "1"
        psql -d smoke_restore -Atc "select version_num from alembic_version"
        dropdb smoke_restore
    ' || fail "the backup could not be restored"

    # A second instance against the same database must refuse to start.
    if compose run --rm --no-deps -T app >"$WORK/second.log" 2>&1; then
        fail "a second app instance started against the same database"
    fi
    grep -q "Another CxCreditGuard instance is already running" "$WORK/second.log" \
        || { cat "$WORK/second.log"; fail "the second instance failed for another reason"; }

    echo "SMOKE TEST PASSED"
    ;;

logs)
    compose logs --no-color --tail 80 || true
    ;;

down)
    compose down -v --remove-orphans || true
    ;;

*)
    echo "usage: $0 up|check|logs|down" >&2
    exit 2
    ;;
esac
