#!/bin/sh
# End-to-end smoke test of the documented deployment (docker-compose.yml).
#
#   deploy/ci/smoke-test.sh up      build the image and start everything
#   deploy/ci/smoke-test.sh check   exercise it through the TLS proxy
#   deploy/ci/smoke-test.sh logs    print container logs
#   deploy/ci/smoke-test.sh down    stop and remove it, volumes included
#   deploy/ci/smoke-test.sh single  build and try the single-container image
#                                   (deploy/podman/Dockerfile) on its own
#
# Optional environment: SMOKE_APP_IMAGE (test an image that is already built
# instead of building one), SMOKE_HTTPS_PORT (default 8443), SMOKE_HTTP_PORT
# (default 8080), SMOKE_WORK_DIR, SMOKE_NGINX_CONF (a different proxy config,
# for a host without IPv6), SMOKE_SINGLE_IMAGE and SMOKE_SINGLE_PORT (default
# 8000) for `single`.
#
# CI runs it on every change; it works the same on a laptop. It uses its own
# compose project name, a throwaway .env and a self signed certificate, all
# under a temporary directory, so it never touches a real deployment's files.
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${SMOKE_WORK_DIR:-${TMPDIR:-/tmp}/cxcg-smoke}"
PORT="${SMOKE_HTTPS_PORT:-8443}"
HTTP_PORT="${SMOKE_HTTP_PORT:-8080}"
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
      - "${HTTP_PORT}:80"
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

    # Plain HTTP only ever redirects to HTTPS.
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HTTP_PORT}/api/me" || true)"
    [ "$code" = "308" ] || fail "plain HTTP answered $code instead of redirecting to HTTPS"

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
    curl -fsk "$BASE/" | grep -qi '<div id="root"' || fail "the web app was not served"
    # (An unknown path answers with the web app's page, so look at the content.)
    schema="$(curl -fsk "$BASE/openapi.json")" || fail "could not ask for the API schema"
    if echo "$schema" | grep -q '"openapi"'; then
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
        # ...at the schema version the running app is on.
        dumped="$(psql -d smoke_restore -Atc "select version_num from alembic_version")"
        live="$(psql -Atc "select version_num from alembic_version")"
        test -n "$dumped" && test "$dumped" = "$live"
        dropdb smoke_restore
    ' || fail "the backup could not be restored"

    # A second instance against the same database must refuse to start. If it
    # did start it would serve for ever, so it gets a time limit.
    status=0
    timeout 120 docker compose -p cxcg-smoke --project-directory "$ROOT" --env-file "$WORK/.env" \
        -f "$ROOT/docker-compose.yml" -f "$WORK/override.yml" \
        run --rm --no-deps -T --name cxcg-smoke-second app >"$WORK/second.log" 2>&1 || status=$?
    docker rm -f cxcg-smoke-second >/dev/null 2>&1 || true
    [ "$status" != "0" ] && [ "$status" != "124" ] \
        || { tail -n 20 "$WORK/second.log"; fail "a second app instance started against the same database"; }
    grep -q "Another CxCreditGuard instance is already running" "$WORK/second.log" \
        || { cat "$WORK/second.log"; fail "the second instance failed for another reason"; }
    # ...and it must not have touched the schema on its way to being refused.
    if grep -q "applying database migrations" "$WORK/second.log"; then
        fail "the refused instance ran migrations before it was refused"
    fi

    # The documented restore: refuses a file that does not exist and changes
    # nothing, refuses while the app is connected, then restores for real and
    # the app comes back on the restored data.
    if compose exec -T backup sh /usr/local/bin/restore.sh /backups/no-such-file.dump >/dev/null 2>&1; then
        fail "restore accepted a dump that does not exist"
    fi
    if compose exec -T backup sh /usr/local/bin/restore.sh latest >/dev/null 2>&1; then
        fail "restore ran while the app was still connected"
    fi
    compose stop app >/dev/null 2>&1
    compose exec -T backup sh /usr/local/bin/restore.sh latest || fail "the restore failed"
    compose start app >/dev/null 2>&1
    restored=""
    for _ in $(seq 1 40); do
        restored="$(curl -sk "$BASE/healthz" || true)"
        echo "$restored" | grep -q '"database":true' && break
        sleep 3
    done
    echo "$restored" | grep -q '"database":true' || fail "the app did not come back after the restore"
    code="$(curl -sk -o /dev/null -w '%{http_code}' \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" "$BASE/api/auth/login")"
    [ "$code" = "200" ] || fail "sign-in after the restore returned $code"

    echo "SMOKE TEST PASSED"
    ;;

logs)
    compose logs --no-color --tail 80 || true
    ;;

down)
    compose down -v --remove-orphans || true
    ;;

single)
    # The quick-start image: no configuration, SQLite, plain HTTP. It must come
    # up by itself, print its first credentials, and let them sign in.
    image="${SMOKE_SINGLE_IMAGE:-}"
    if [ -z "$image" ]; then
        image=cxcreditguard:smoke-single
        docker build -q -f "$ROOT/deploy/podman/Dockerfile" -t "$image" "$ROOT"
    fi
    port="${SMOKE_SINGLE_PORT:-8000}"
    name=cxcg-smoke-single
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" -p "127.0.0.1:${port}:8000" "$image" >/dev/null
    finish() {
        docker logs "$name" 2>&1 | tail -n 30
        docker rm -f "$name" >/dev/null 2>&1 || true
        fail "single container: $*"
    }
    health=""
    for _ in $(seq 1 40); do
        health="$(curl -s "http://127.0.0.1:${port}/healthz" || true)"
        echo "$health" | grep -q '"database":true' && break
        sleep 3
    done
    echo "$health" | grep -q '"database":true' || finish "did not become healthy"
    password="$(docker logs "$name" 2>&1 | sed -n 's/.*initial credentials -> username=admin password=//p' | head -n 1)"
    [ -n "$password" ] || finish "did not print its first credentials"
    body="$(curl -s -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$password\"}" \
        "http://127.0.0.1:${port}/api/auth/login")"
    echo "$body" | grep -q '"must_change_password":true' \
        || finish "the printed credentials did not sign in, or were not flagged for change: $body"
    docker rm -f "$name" >/dev/null 2>&1 || true
    echo "SINGLE CONTAINER PASSED"
    ;;

*)
    echo "usage: $0 up|check|logs|down|single" >&2
    exit 2
    ;;
esac
