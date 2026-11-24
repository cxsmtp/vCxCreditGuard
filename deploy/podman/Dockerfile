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
# This is also the release image (.github/workflows/release.yml publishes it to
# ghcr.io/cxsmtp/vcxcreditguard). Its main process is the launcher
# (backend/cxcg_launcher.py), which runs the app version selected on Settings ->
# Updates from the data volume, or the image's own. The app's files are the
# LAST layer, on their own, so an in-app update downloads only that layer.
#
# For the hardened multi-service deployment see the root docker-compose.yml,
# which uses backend/Dockerfile instead.

# The base image is part of the dependency hash (see below), named by its
# DIGEST: a rebuilt python:3.13-alpine3.24 (OS, Python, OpenSSL fixes) is another
# base, so its fixes arrive by replacing the image, never as an app layer. The
# release workflow passes the latest release's base (so app-only releases stay
# installable as a layer), or the tag's current digest when the release tag's
# message has a line "base: refresh"; this default is the digest last pinned by
# hand (keep the tag in step with backend/Dockerfile and with PYTHON_TAG in
# .github/workflows/release.yml). Python 3.13: the 3.11 images still ship pip
# 24.0, setuptools and wheel with known CVEs; 3.13 ships none of those.
ARG PYTHON_IMAGE=python:3.13-alpine3.24@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e

# --- Stage 1: build the SPA ------------------------------------------------
# Pinned by tag and digest like the base (keep in step with backend/Dockerfile).
# This stage only builds the SPA: none of its files reach the runtime image.
FROM node:22.23.5-alpine3.24@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
# `npm ci` when a lock file is present so builds are reproducible.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY frontend/ ./
# Vite is configured to emit into ../backend/app/static, which does not exist in
# this stage, so redirect the output to a local directory instead.
RUN npx vite build --outDir dist --emptyOutDir

# --- Stage 2: the runtime base (OS, Python packages, launcher) --------------
# Alpine keeps the runtime image's OS-package CVE surface minimal.
FROM ${PYTHON_IMAGE} AS base
ARG PYTHON_IMAGE

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
# Only the project's dependencies are installed, read from pyproject.toml: the
# app itself is the last layer, never a site-packages copy.
COPY backend/pyproject.toml backend/constraints.txt ./
# Python dependency versions are pinned in constraints.txt. apk packages are not
# pinned to exact versions (an Alpine branch keeps only the latest revision of a
# package, so an exact pin stops building at its next fix); instead the
# installed OS packages are recorded (os-packages.txt) and are part of the
# dependency hash, with the date they were installed (the image's age, shown on
# Settings -> Updates after 90 days).
# Suppress the KICS unpinned-version findings for this build step.
# kics-scan ignore-block
# "apk upgrade" first: the OS packages already in the base (OpenSSL, zlib, krb5,
# busybox...) take the fixes Alpine published since the base was built. What it
# installs is recorded in os-packages.txt like everything else, so a release
# whose upgrade brought new revisions is a new image, never an app layer.
RUN apk upgrade --no-cache \
    && apk add --no-cache libpq \
    && apk add --no-cache --virtual .build gcc musl-dev python3-dev libpq-dev \
    && python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" > /tmp/requirements.txt \
    && pip install --no-cache-dir -c constraints.txt -r /tmp/requirements.txt "psycopg[c]" \
    && rm /tmp/requirements.txt \
    && apk del .build \
    && (pip uninstall -y pip setuptools wheel 2>/dev/null || true) \
    && mkdir -p /usr/local/share/cxcreditguard \
    && apk info -v 2>/dev/null | sort > /usr/local/share/cxcreditguard/os-packages.txt \
    && date -u +%Y-%m-%dT%H:%M:%SZ > /usr/local/share/cxcreditguard/os-installed-at

# The image-level files an app update never replaces. Their content, the
# packages above and the base image make the dependency hash: a release built
# with a different hash is installed by replacing the image, never as a layer.
COPY backend/cxcg_launcher.py /usr/local/lib/cxcreditguard/launcher.py
COPY deploy/podman/easy-entrypoint.sh /usr/local/bin/easy-entrypoint.sh

# Alpine ships busybox adduser/addgroup rather than shadow's useradd.
# Strip any CR bytes first: a Windows checkout (core.autocrlf=true) can rewrite
# the script to CRLF, and the kernel then reads the shebang as "#!/bin/sh\r" and
# fails to exec with a misleading "No such file or directory". .gitattributes
# pins these files to LF, but this makes the image build correct even from a
# checkout that predates it.
RUN sed -i 's/\r$//' /usr/local/bin/easy-entrypoint.sh /usr/local/lib/cxcreditguard/launcher.py \
    && chmod +x /usr/local/bin/easy-entrypoint.sh \
    && python -I -B /usr/local/lib/cxcreditguard/launcher.py image-info \
        --write /usr/local/share/cxcreditguard/image.json \
        --constraints constraints.txt --pyproject pyproject.toml \
        --base-image "$PYTHON_IMAGE" \
        --launcher /usr/local/lib/cxcreditguard/launcher.py \
        --entrypoint /usr/local/bin/easy-entrypoint.sh \
        --os-packages /usr/local/share/cxcreditguard/os-packages.txt \
        --created "$(cat /usr/local/share/cxcreditguard/os-installed-at)" \
    && addgroup -g 10001 cxcg \
    && adduser -D -H -u 10001 -G cxcg cxcg \
    && mkdir -p /app/data \
    && chown cxcg:cxcg /app/data \
    && chmod 700 /app/data
# /app (the image's own version) stays owned by root and read-only for the app's
# user: only /app/data, the data volume, is writable.

# --- Stage 3: the app's own files, with their release manifest --------------
FROM base AS assemble
ARG CXCG_REVISION=""
COPY backend/alembic.ini /out/alembic.ini
COPY backend/alembic /out/alembic
COPY backend/app /out/app
COPY backend/scripts /out/scripts
# The built SPA. app/main.py mounts it when it is present and serves the API
# only when it is not.
COPY --from=frontend /build/dist /out/app/static
# Every file with its sha256 (release-manifest.json), so an installation can
# verify what it downloads. Built from the files, never from a timestamp: the
# same sources give the same bytes, which the release workflow signs. The list
# covers EVERY file of the layer: no bytecode is shipped (any is removed first,
# and the build refuses a tree that still has some), and nothing is written
# after it (-B).
RUN find /out \( -name __pycache__ -type d -prune -exec rm -rf {} + \) -o \( -name '*.py[co]' -exec rm -f {} + \) \
    && chmod -R u=rwX,go=rX /out \
    && cd /out \
    && python -B -m scripts.release_manifest build --root /out --revision "$CXCG_REVISION" \
        --image-info /usr/local/share/cxcreditguard/image.json

# Just the manifest, for the release workflow to sign: --target release-manifest
FROM scratch AS release-manifest
COPY --from=assemble /out/release-manifest.json /

# The signature (base64, from the release workflow), when there is one. The
# private key never enters the build: only its signature does.
FROM assemble AS signed
ARG CXCG_RELEASE_SIGNATURE=""
RUN if [ -n "$CXCG_RELEASE_SIGNATURE" ]; then \
        printf '%s\n' "$CXCG_RELEASE_SIGNATURE" > /out/release-manifest.sig; \
    fi

# --- Stage 4: runtime -------------------------------------------------------
FROM base AS runtime

# Browser-first defaults: plain HTTP in development mode so session cookies do
# not need HTTPS (Set-Cookie:; Secure would otherwise be silently discarded by
# the browser and "login" would appear to do nothing). Override any of these
# with -e on `podman run` if you configure TLS.
ENV CXCG_ENV=development \
    CXCG_COOKIE_SECURE=false \
    CXCG_HSTS_ENABLED=false \
    CXCG_HOST=0.0.0.0 \
    CXCG_PORT=8000 \
    CXCG_DATA_DIR=/app/data \
    CXCG_DEPLOYMENT=single

USER cxcg

EXPOSE 8000

# Liveness probe via the bundled interpreter, so the image needs no extra
# tooling. A non-2xx response raises and exits non-zero, marking it unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]

# How many trailing layers hold the app (the in-app updater downloads only those).
LABEL io.cxcreditguard.app-layers="1"

# The easy entrypoint generates/persists the master key and a first admin, then
# hands over to the launcher, which runs uvicorn with the selected version.
ENTRYPOINT ["/usr/local/bin/easy-entrypoint.sh"]
CMD ["launch"]

# The app's own files: ONE layer, and the last. Keep it that way - an in-app
# update downloads exactly the layers counted by io.cxcreditguard.app-layers.
# Owned by root, so the app (uid 10001) cannot change the image's own version.
COPY --from=signed /out/ /app/
