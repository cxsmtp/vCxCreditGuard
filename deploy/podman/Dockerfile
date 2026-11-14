# CxCreditGuard - easy, single-container image for local / Podman use.
#
# Builds the React SPA and the Python backend into ONE image that serves both
# the UI and the API on port 8000 over plain HTTP. This is a convenience image:
# no TLS proxy, no Postgres, no required environment variables - the easy
# entrypoint generates and persists a master key and a first admin account.
#
# Build from the repository root (so both directories are in the context):
#   podman build -f deploy/podman/Dockerfile -t cxcreditguard:podman .
#
# For the hardened multi-service deployment see the root docker-compose.yml,
# which uses backend/Dockerfile instead.

# --- Stage 1: build the SPA ------------------------------------------------
FROM node:22-alpine AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
# `npm ci` when a lock file is present so builds are reproducible.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY frontend/ ./
# Vite is configured to emit into ../backend/app/static, which does not exist in
# this stage, so redirect the output to a local directory instead.
RUN npx vite build --outDir dist --emptyOutDir

# --- Stage 2: runtime -------------------------------------------------------
# Alpine keeps the runtime image's OS-package CVE surface minimal.
FROM python:3.11-alpine AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first so a source change does not invalidate the install layer.
# libpq is the only runtime OS package; the build toolchain goes in a throwaway
# virtual package and is removed after.
# psycopg is installed with its C implementation, compiled against libpq-dev:
# the pure-Python mode cannot find libpq on Alpine once the toolchain is removed
# (see backend/Dockerfile). ".[postgres]" is not used because it pulls
# psycopg[binary], whose wheels are glibc-only (manylinux).
COPY backend/pyproject.toml backend/constraints.txt ./
# Python dependency versions are pinned in constraints.txt, and pinning apk
# --no-cache installs to exact versions is fragile across base-image updates.
# Suppress the KICS unpinned-version findings for this build step.
# kics-scan ignore-block
RUN apk add --no-cache libpq \
    && apk add --no-cache --virtual .build gcc musl-dev python3-dev libpq-dev \
    && pip install --no-cache-dir -c constraints.txt . "psycopg[c]" \
    && apk del .build \
    && (pip uninstall -y pip setuptools wheel 2>/dev/null || true)

COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
COPY backend/scripts ./scripts
COPY deploy/podman/easy-entrypoint.sh /usr/local/bin/easy-entrypoint.sh

# The built SPA. app/main.py mounts it when it is present and serves the API
# only when it is not.
COPY --from=frontend /build/dist ./app/static

# Alpine ships busybox adduser/addgroup rather than shadow's useradd.
# Strip any CR bytes first: a Windows checkout (core.autocrlf=true) can rewrite
# the script to CRLF, and the kernel then reads the shebang as "#!/bin/sh\r" and
# fails to exec with a misleading "No such file or directory". .gitattributes
# pins these files to LF, but this makes the image build correct even from a
# checkout that predates it.
RUN sed -i 's/\r$//' /usr/local/bin/easy-entrypoint.sh \
    && chmod +x /usr/local/bin/easy-entrypoint.sh \
    && addgroup -g 10001 cxcg \
    && adduser -D -H -u 10001 -G cxcg cxcg \
    && mkdir -p /app/data \
    && chown -R cxcg:cxcg /app

# Browser-first defaults: plain HTTP in development mode so session cookies do
# not need HTTPS (Set-Cookie:; Secure would otherwise be silently discarded by
# the browser and "login" would appear to do nothing). Override any of these
# with -e on `podman run` if you configure TLS.
ENV CXCG_ENV=development \
    CXCG_COOKIE_SECURE=false \
    CXCG_HSTS_ENABLED=false \
    CXCG_HOST=0.0.0.0 \
    CXCG_PORT=8000

USER cxcg

EXPOSE 8000

# Liveness probe via the bundled interpreter, so the image needs no extra
# tooling. A non-2xx response raises and exits non-zero, marking it unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

# The easy entrypoint generates/persists the master key and a first admin, then
# applies migrations. Pass the real uvicorn command via CMD.
ENTRYPOINT ["/usr/local/bin/easy-entrypoint.sh"]
# No --forwarded-allow-ips: the app does not let the web server rewrite the
# client address from headers. It reads X-Forwarded-For itself, and only as many
# hops as CXCG_TRUSTED_PROXY_HOPS says are trustworthy.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]