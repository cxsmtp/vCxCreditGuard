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


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl is needed by the compose healthcheck. Nothing else is installed, and no
# compiler is present in the final image: every dependency ships a wheel.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first so a source change does not invalidate the install layer.
COPY backend/pyproject.toml ./
RUN pip install --no-cache-dir ".[postgres]" \
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
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --system --create-home --uid 10001 cxcg \
    && mkdir -p /app/data \
    && chown -R cxcg:cxcg /app

USER cxcg

EXPOSE 8000

# The container listens on plain HTTP. TLS is terminated by the reverse proxy in
# docker-compose.yml, which is the documented deployment.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
