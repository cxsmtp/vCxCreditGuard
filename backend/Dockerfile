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
# libpq is the only runtime OS package (psycopg's pure-Python mode loads it);
# the build toolchain goes in a throwaway virtual package so any dependency
# without a musl wheel can still compile, then is removed to keep the image lean.
# psycopg is installed directly rather than via the ".[postgres]" extra because
# that extra pulls psycopg[binary], whose wheels are glibc-only (manylinux).
COPY backend/pyproject.toml ./
RUN apk add --no-cache libpq \
    && apk add --no-cache --virtual .build gcc musl-dev python3-dev \
    && pip install --no-cache-dir . psycopg \
    && apk del .build \
    && pip uninstall -y pip setuptools wheel 2>/dev/null || true

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
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && addgroup -g 10001 cxcg \
    && adduser -D -H -u 10001 -G cxcg cxcg \
    && mkdir -p /app/data \
    && chown -R cxcg:cxcg /app

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
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
