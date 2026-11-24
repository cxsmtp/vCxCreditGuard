# CxCreditGuard image: builds the SPA, then serves it from the Python app.
#
# Build from the repository root so both directories are in context:
#   docker build -f backend/Dockerfile -t cxcreditguard .
# docker-compose.yml already does this.

FROM node:22-alpine AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
# `npm ci` when a lock file is present, so builds are reproducible.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY frontend/ ./
# Vite is configured to emit into ../backend/app/static, which does not exist in
# this stage, so the output is redirected to a local directory instead.
RUN npx vite build --outDir dist --emptyOutDir


# Alpine keeps the runtime image's OS-package CVE surface minimal (Debian slim
# ships a large userland - apt, perl, coreutils, tar - each with its own CVEs).
FROM python:3.11-alpine AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first so a source change does not invalidate the install layer.
# libpq is the only runtime OS package. psycopg is installed with its C
# implementation ("psycopg[c]"), compiled here against libpq-dev: its pure-Python
# mode finds libpq through ctypes.util.find_library, which on Alpine (musl) needs
# gcc or binutils at run time and so fails once the toolchain is removed - the
# image would build and then be unable to open a PostgreSQL connection. The
# ".[postgres]" extra is not used because it pulls psycopg[binary], whose wheels
# are glibc-only (manylinux). The toolchain goes in a throwaway virtual package
# and is removed to keep the image lean.
COPY backend/pyproject.toml backend/constraints.txt ./
# Python dependency versions are pinned by constraints.txt (direct and
# transitive), so the image is reproducible; pinning apk --no-cache installs to
# exact versions is fragile across base-image updates.
# Suppress the KICS unpinned-version findings for this build step.
# The trailing "|| true" is parenthesised on purpose: unparenthesised it would
# apply to the whole chain and let a failed dependency install produce an image.
# kics-scan ignore-block
# Only the project's dependencies are installed, read from pyproject.toml (whose
# version is read from the app itself, which is copied in later).
RUN apk add --no-cache libpq \
    && apk add --no-cache --virtual .build gcc musl-dev python3-dev libpq-dev \
    && python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" > /tmp/requirements.txt \
    && pip install --no-cache-dir -c constraints.txt -r /tmp/requirements.txt "psycopg[c]" \
    && rm /tmp/requirements.txt \
    && apk del .build \
    && (pip uninstall -y pip setuptools wheel 2>/dev/null || true) \
    && mkdir -p /usr/local/share/cxcreditguard \
    && printf '{"created": "%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /usr/local/share/cxcreditguard/image.json

COPY backend/alembic.ini ./
COPY backend/alembic ./alembic
COPY backend/app ./app
COPY backend/scripts ./scripts
COPY backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# The built SPA. app/main.py mounts this when it is present and serves the API
# only when it is not.
COPY --from=frontend /build/dist ./app/static

# Run as an unprivileged user. /app/data is only used by the SQLite backend.
# Alpine ships busybox adduser/addgroup rather than shadow's useradd.
# Strip any CR bytes first: a Windows checkout (core.autocrlf=true) can rewrite
# the script to CRLF, and the kernel then reads the shebang as "#!/bin/sh\r" and
# fails to exec with a misleading "No such file or directory". .gitattributes
# pins these files to LF, but this makes the image build correct even from a
# checkout that predates it.
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh \
    && addgroup -g 10001 cxcg \
    && adduser -D -H -u 10001 -G cxcg cxcg \
    && mkdir -p /app/data \
    && chown cxcg:cxcg /app/data \
    && chmod -R u=rwX,go=rX /app/alembic /app/app /app/scripts
# /app stays owned by root and read-only for the app's user; only /app/data is
# writable. image.json records when the OS packages were installed: Settings ->
# Updates says when the image is older than 90 days.

# Settings -> Updates shows the steps for this deployment: it is updated by
# rebuilding the image from a release tag (README "Updates"), not in place.
ENV CXCG_DEPLOYMENT=compose

USER cxcg

EXPOSE 8000

# Liveness probe using the bundled interpreter, so the image needs no extra
# tooling. A non-2xx response raises and exits non-zero, marking the container
# unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

# The container listens on plain HTTP. TLS is terminated by the reverse proxy in
# docker-compose.yml, which is the documented deployment.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# No --forwarded-allow-ips: the app does not let the web server rewrite the
# client address from headers. It reads X-Forwarded-For itself, and only as many
# hops as CXCG_TRUSTED_PROXY_HOPS says are trustworthy.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
