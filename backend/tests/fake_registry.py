"""A synthetic GHCR for the updater tests: token exchange, tags, manifests, blobs.

Releases are built in memory the way the release workflow builds them: an app
layer (a gzipped tar of ``app/...``) holding the app files and their
release-manifest.json (optionally signed), a config blob with the labels, an
image manifest and an OCI index per tag.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.updates.manifest import manifest_bytes, sign

REPO = "cxsmtp/vcxcreditguard"
GOOD_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" * 2
BEARER = "pull-token-xyz"
STORAGE_HOST = "pkg-containers.githubusercontent.com"


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def app_files(version: str, *, migrations: tuple[str, ...] = ("aaa",)) -> dict[str, bytes]:
    files = {
        "app/__init__.py": f'__version__ = "{version}"\n'.encode(),
        "app/main.py": b"app = None\n",
        "app/static/index.html": b"<!doctype html>\n",
        "alembic.ini": b"[alembic]\n",
        "alembic/env.py": b"# env\n",
        "scripts/tool.py": b"print('x')\n",
    }
    for index, rev in enumerate(migrations):
        files[f"alembic/versions/{index:04d}_{rev}.py"] = f'revision = "{rev}"\n'.encode()
    return files


def tar_gz(entries: list[tarfile.TarInfo | tuple[str, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for entry in entries:
            if isinstance(entry, tarfile.TarInfo):
                archive.addfile(entry)
                continue
            name, data = entry
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def app_layer(files: dict[str, bytes]) -> bytes:
    return tar_gz([(f"app/{rel}", data) for rel, data in sorted(files.items())])


@dataclass
class Release:
    version: str
    deps: str = "deps-1"
    private_key_pem: bytes | None = None
    migrations: tuple[str, ...] = ("aaa",)
    notes: str = ""
    # Change the files after the manifest is written (a tampered release).
    tamper: Callable[[dict[str, bytes]], None] | None = None
    # Replace the app layer entirely (unsafe archives).
    layer_override: bytes | None = None
    arch: str = "amd64"

    def build(self) -> dict[str, Any]:
        files = app_files(self.version, migrations=self.migrations)
        manifest = {
            "format": 1,
            "version": self.version,
            "revision": "abcdef0123456789",
            "deps_hash": self.deps,
            "files": {rel: hashlib.sha256(data).hexdigest() for rel, data in sorted(files.items())},
        }
        raw_manifest = manifest_bytes(manifest)
        files["release-manifest.json"] = raw_manifest
        if self.private_key_pem:
            files["release-manifest.sig"] = (
                sign(raw_manifest, self.private_key_pem) + "\n"
            ).encode()
        if self.tamper:
            self.tamper(files)
        layer = self.layer_override or app_layer(files)
        base_layer = tar_gz([("etc/os-release", b"alpine\n")])
        config = json.dumps(
            {
                "created": "2026-11-01T00:00:00Z",
                "config": {
                    "Labels": {
                        "org.opencontainers.image.version": self.version,
                        "org.opencontainers.image.revision": "abcdef0123456789",
                        "io.cxcreditguard.deps": self.deps,
                        "io.cxcreditguard.app-layers": "1",
                        "io.cxcreditguard.signed": "true" if self.private_key_pem else "false",
                        "io.cxcreditguard.release-notes": self.notes,
                    }
                },
            }
        ).encode()
        image_manifest = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": digest_of(config), "size": len(config)},
                "layers": [
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": digest_of(base_layer),
                        "size": len(base_layer),
                    },
                    {
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": digest_of(layer),
                        "size": len(layer),
                    },
                ],
            }
        ).encode()
        index = json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": digest_of(image_manifest),
                        "size": len(image_manifest),
                        "platform": {"os": "linux", "architecture": self.arch},
                    }
                ],
            }
        ).encode()
        return {
            "index": index,
            "manifest": image_manifest,
            "blobs": {
                digest_of(config): config,
                digest_of(layer): layer,
                digest_of(base_layer): base_layer,
            },
            "app_layer_digest": digest_of(layer),
            "config_digest": digest_of(config),
        }


@dataclass
class FakeRegistry:
    releases: list[Release] = field(default_factory=list)
    extra_tags: list[str] = field(default_factory=lambda: ["latest", "sha-abc1234", "9.9.9-rc1"])
    token: str = GOOD_TOKEN
    page_size: int = 0  # >0: paginate the tag list
    # Corrupt a blob on the way out (digest mismatch).
    corrupt: set[str] = field(default_factory=set)
    redirect_host: str = STORAGE_HOST
    requests: list[httpx.Request] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.built: dict[str, dict[str, Any]] = {}
        self.rebuild()

    def rebuild(self) -> None:
        self.built = {r.version: r.build() for r in self.releases}
        self.manifests: dict[str, bytes] = {}
        self.blobs: dict[str, bytes] = {}
        for version, built in self.built.items():
            self.manifests[version] = built["index"]
            self.manifests[digest_of(built["index"])] = built["index"]
            self.manifests[digest_of(built["manifest"])] = built["manifest"]
            self.blobs.update(built["blobs"])

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def paths(self) -> list[str]:
        return [f"{r.url.host}{r.url.path}" for r in self.requests]

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = request.url
        if url.host == "ghcr.io" and url.path == "/token":
            auth = request.headers.get("authorization", "")
            expected = "Basic " + base64.b64encode(f"cxcreditguard:{self.token}".encode()).decode()
            if auth != expected:
                return httpx.Response(401, json={"errors": [{"code": "DENIED"}]})
            assert url.params.get("scope") == f"repository:{REPO}:pull"
            assert url.params.get("service") == "ghcr.io"
            return httpx.Response(200, json={"token": BEARER})
        if url.host == self.redirect_host and url.path.startswith("/blob/"):
            assert "authorization" not in request.headers, "the registry token leaked"
            digest = url.path.removeprefix("/blob/")
            data = self.blobs.get(digest)
            if data is None:
                return httpx.Response(404)
            if digest in self.corrupt:
                data = data + b"tampered"
            return httpx.Response(200, content=data, headers={"content-length": str(len(data))})
        if url.host != "ghcr.io":
            return httpx.Response(599)
        if request.headers.get("authorization") != f"Bearer {BEARER}":
            return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="https://evil"'})
        prefix = f"/v2/{REPO}"
        path = url.path.removeprefix(prefix)
        if path == "/tags/list":
            tags = sorted([*self.built.keys(), *self.extra_tags])
            if self.page_size:
                last = url.params.get("last")
                start = tags.index(last) + 1 if last else 0
                page = tags[start : start + self.page_size]
                headers = {}
                if start + self.page_size < len(tags):
                    headers["link"] = (
                        f'<{prefix}/tags/list?last={page[-1]}&n={self.page_size}>; rel="next"'
                    )
                return httpx.Response(200, json={"name": REPO, "tags": page}, headers=headers)
            return httpx.Response(200, json={"name": REPO, "tags": tags})
        if path.startswith("/manifests/"):
            ref = path.removeprefix("/manifests/")
            body = self.manifests.get(ref)
            if body is None:
                return httpx.Response(404)
            return httpx.Response(
                200, content=body, headers={"docker-content-digest": digest_of(body)}
            )
        if path.startswith("/blobs/"):
            digest = path.removeprefix("/blobs/")
            if digest not in self.blobs:
                return httpx.Response(404)
            return httpx.Response(
                307, headers={"location": f"https://{self.redirect_host}/blob/{digest}?sig=x"}
            )
        return httpx.Response(404)


def ed25519_keypair() -> tuple[bytes, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    return private, public.decode()
