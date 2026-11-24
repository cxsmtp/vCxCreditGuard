"""A read-only client for CxCreditGuard's own release images on GHCR.

Only one image is ever read: ``ghcr.io/cxsmtp/vcxcreditguard``. The hosts are
fixed in code - nothing an admin types, and nothing a registry answers, can point
the server at another address (no SSRF): the token comes from the fixed token
URL, never from a ``WWW-Authenticate`` realm, and a blob redirect is followed
only to GitHub's package storage host, over https, without the registry token.

Everything is content-addressed: every manifest fetched by digest and every blob
is checked against its sha256 before it is used, and sizes are bounded.
"""

from __future__ import annotations

import hashlib
import io
import json
import platform
import re
import tarfile
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

REGISTRY_HOST = "ghcr.io"
REPOSITORY = "cxsmtp/vcxcreditguard"
IMAGE = f"{REGISTRY_HOST}/{REPOSITORY}"
TOKEN_URL = f"https://{REGISTRY_HOST}/token"
# Where ghcr.io sends blob downloads. Followed without the registry token.
BLOB_HOSTS = frozenset({"pkg-containers.githubusercontent.com", REGISTRY_HOST})
EGRESS_HOSTS = ("ghcr.io", "pkg-containers.githubusercontent.com")
USER_AGENT = "cxcreditguard-updater"
TOKEN_USERNAME = "cxcreditguard"  # noqa: S105 - a user name, not a secret

LABEL_VERSION = "org.opencontainers.image.version"
LABEL_REVISION = "org.opencontainers.image.revision"
LABEL_DEPS = "io.cxcreditguard.deps"
LABEL_APP_LAYERS = "io.cxcreditguard.app-layers"
LABEL_SIGNED = "io.cxcreditguard.signed"
LABEL_NOTES = "io.cxcreditguard.release-notes"

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_LAYER_BYTES = 96 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_FILES = 20_000
MAX_TAG_PAGES = 20
MAX_REDIRECTS = 3

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")

INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
LAYER_TYPES = (
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar",
)
ACCEPT = ", ".join((*INDEX_TYPES, *MANIFEST_TYPES))
ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


class RegistryError(Exception):
    """The registry could not be read. The message is safe to show and to log."""


class RegistryAuthError(RegistryError):
    """The registry refused the token (missing, expired, or without read:packages)."""


class DigestMismatch(RegistryError):
    """Downloaded content did not match the digest it was asked for."""


class UnsafeArchive(RegistryError):
    """A layer holds something that would leave the install folder, or is too large."""


@dataclass(frozen=True)
class Layer:
    digest: str
    size: int
    media_type: str


@dataclass
class ReleaseImage:
    ref: str
    digest: str
    labels: dict[str, str]
    layers: list[Layer]
    created: str = ""
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> str:
        return str(self.labels.get(LABEL_VERSION) or "")

    @property
    def deps_hash(self) -> str:
        return str(self.labels.get(LABEL_DEPS) or "")

    @property
    def revision(self) -> str:
        return str(self.labels.get(LABEL_REVISION) or "")

    @property
    def notes(self) -> str:
        return str(self.labels.get(LABEL_NOTES) or "")[:4000]

    @property
    def signed_label(self) -> bool:
        return str(self.labels.get(LABEL_SIGNED) or "").lower() == "true"

    def app_layers(self) -> list[Layer]:
        """The trailing layers holding the app's own files (the label says how many)."""
        try:
            count = int(self.labels.get(LABEL_APP_LAYERS) or 0)
        except ValueError:
            count = 0
        if count < 1 or count > len(self.layers) or count > 4:
            raise RegistryError(
                "That image does not say which of its layers hold the app, so it cannot be "
                "installed from this page."
            )
        return self.layers[-count:]


def machine_arch() -> str:
    machine = platform.machine().lower()
    return ARCH.get(machine, machine)


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class RegistryClient:
    """Reads the release image. ``transport`` is injectable for tests."""

    def __init__(
        self,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
        arch: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self._token = token
        self._bearer: str | None = None
        self.arch = arch or machine_arch()
        self.downloaded = 0
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
            trust_env=True,
        )

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def __repr__(self) -> str:  # never the token
        return f"RegistryClient({IMAGE}, arch={self.arch})"

    # -- authentication

    def authenticate(self) -> None:
        """Exchange the stored token for a pull token on the fixed token URL."""
        if not self._token:
            raise RegistryAuthError("No registry token is configured.")
        try:
            response = self._client.get(
                TOKEN_URL,
                params={"scope": f"repository:{REPOSITORY}:pull", "service": REGISTRY_HOST},
                auth=(TOKEN_USERNAME, self._token),
            )
        except httpx.HTTPError as exc:
            raise RegistryError(_unreachable(REGISTRY_HOST, exc)) from exc
        if response.status_code in (401, 403):
            raise RegistryAuthError(
                f"{REGISTRY_HOST} refused the registry token (HTTP {response.status_code}). It may "
                "have expired or been revoked, or lack the read:packages scope or access to "
                f"{IMAGE}."
            )
        if response.status_code != 200:
            raise RegistryError(
                f"{REGISTRY_HOST} answered HTTP {response.status_code} to the token exchange."
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise RegistryError(f"{REGISTRY_HOST} sent an unreadable token answer.") from exc
        bearer = (body.get("token") or body.get("access_token")) if isinstance(body, dict) else None
        if not isinstance(bearer, str) or not bearer:
            raise RegistryAuthError(f"{REGISTRY_HOST} did not grant a pull token for {IMAGE}.")
        self._bearer = bearer

    # -- requests

    def _registry_get(self, path: str, *, accept: str | None = None) -> httpx.Response:
        if self._bearer is None:
            self.authenticate()
        url = f"https://{REGISTRY_HOST}/v2/{REPOSITORY}{path}"
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {self._bearer}"}
            if accept:
                headers["Accept"] = accept
            try:
                response = self._client.get(url, headers=headers)
            except httpx.HTTPError as exc:
                raise RegistryError(_unreachable(REGISTRY_HOST, exc)) from exc
            if response.status_code == 401 and attempt == 1:
                # The pull token expired between requests: one fresh exchange.
                self.authenticate()
                continue
            return response
        return response

    def _json(self, path: str, *, accept: str | None = None) -> tuple[Any, bytes, httpx.Response]:
        response = self._registry_get(path, accept=accept)
        _raise_for(response, path)
        body = response.content
        if len(body) > MAX_JSON_BYTES:
            raise RegistryError("The registry answer is larger than expected.")
        try:
            return json.loads(body), body, response
        except ValueError as exc:
            raise RegistryError("The registry sent an answer that is not JSON.") from exc

    def tags(self) -> list[str]:
        """Every tag of the image, across the registry's pages."""
        path = "/tags/list?n=1000"
        out: list[str] = []
        for _ in range(MAX_TAG_PAGES):
            body, _raw, response = self._json(path, accept="application/json")
            tags = body.get("tags") if isinstance(body, dict) else None
            if isinstance(tags, list):
                out.extend(t for t in tags if isinstance(t, str) and TAG_RE.match(t))
            next_path = _next_page(response.headers.get("link", ""))
            if not next_path:
                break
            path = next_path
        return sorted(set(out))

    def manifest(self, ref: str) -> tuple[dict[str, Any], str]:
        """A manifest (or index) by tag or digest, with its digest, checked."""
        if not (TAG_RE.match(ref) or DIGEST_RE.match(ref)):
            raise RegistryError(f"Not a tag or digest: {ref[:80]!r}")
        body, raw, response = self._json(f"/manifests/{ref}", accept=ACCEPT)
        digest = sha256_digest(raw)
        if DIGEST_RE.match(ref) and digest != ref:
            raise DigestMismatch(f"The manifest for {ref[:19]}... did not match its digest.")
        header = response.headers.get("docker-content-digest", "")
        if header and DIGEST_RE.match(header) and header != digest:
            raise DigestMismatch("The registry's manifest did not match the digest it named.")
        if not isinstance(body, dict):
            raise RegistryError(f"{ref} is not an image manifest.")
        return body, digest

    def image(self, ref: str) -> ReleaseImage:
        """The image for ``ref`` on this server's platform: labels and layers."""
        body, digest = self.manifest(ref)
        media = str(body.get("mediaType") or "")
        if media in INDEX_TYPES or isinstance(body.get("manifests"), list):
            match = None
            for entry in body.get("manifests") or []:
                plat = (entry.get("platform") or {}) if isinstance(entry, dict) else {}
                if (
                    isinstance(plat, dict)
                    and plat.get("os") == "linux"
                    and plat.get("architecture") == self.arch
                ):
                    match = entry
                    break
            if match is None or not DIGEST_RE.match(str(match.get("digest") or "")):
                raise RegistryError(f"{ref} has no build for linux/{self.arch}.")
            body, digest = self.manifest(str(match["digest"]))
        config_ref = body.get("config") if isinstance(body.get("config"), dict) else None
        layers_raw = body.get("layers")
        if not config_ref or not isinstance(layers_raw, list):
            raise RegistryError(f"{ref} is not an image manifest.")
        layers = []
        for layer in layers_raw:
            if not isinstance(layer, dict) or not DIGEST_RE.match(str(layer.get("digest") or "")):
                raise RegistryError(f"{ref} lists a layer without a valid digest.")
            layers.append(
                Layer(
                    digest=str(layer["digest"]),
                    size=int(layer.get("size") or 0),
                    media_type=str(layer.get("mediaType") or ""),
                )
            )
        config_raw = self.blob(str(config_ref.get("digest") or ""), max_bytes=MAX_CONFIG_BYTES)
        try:
            config = json.loads(config_raw)
        except ValueError as exc:
            raise RegistryError(f"{ref}'s configuration is not JSON.") from exc
        labels = (config.get("config") or {}).get("Labels") or {}
        return ReleaseImage(
            ref=ref,
            digest=digest,
            labels={str(k): str(v) for k, v in labels.items()} if isinstance(labels, dict) else {},
            layers=layers,
            created=str(config.get("created") or ""),
            config=config,
        )

    def blob(self, digest: str, *, max_bytes: int = MAX_LAYER_BYTES) -> bytes:
        """A blob, following GHCR's redirect to its storage host, checked against ``digest``."""
        if not DIGEST_RE.match(digest):
            raise RegistryError(f"Not a sha256 digest: {digest[:80]!r}")
        response = self._registry_get(f"/blobs/{digest}")
        hops = 0
        while response.status_code in (301, 302, 303, 307, 308):
            hops += 1
            location = response.headers.get("location", "")
            target = httpx.URL(response.url).join(location) if location else None
            if hops > MAX_REDIRECTS or target is None:
                raise RegistryError("The registry redirected the download too many times.")
            host = (target.host or "").lower()
            if target.scheme != "https" or host not in BLOB_HOSTS:
                raise RegistryError(
                    f"The registry sent the download to {host or 'an unknown host'}, which this "
                    f"server does not call (only {', '.join(sorted(BLOB_HOSTS))})."
                )
            # The storage URL is pre-signed: the registry token never goes along.
            headers = {"Authorization": f"Bearer {self._bearer}"} if host == REGISTRY_HOST else {}
            try:
                response = self._client.get(target, headers=headers)
            except httpx.HTTPError as exc:
                raise RegistryError(_unreachable(host, exc)) from exc
        _raise_for(response, f"/blobs/{digest}")
        declared = int(response.headers.get("content-length") or 0)
        if declared > max_bytes:
            raise UnsafeArchive(f"A layer is larger than allowed ({declared} bytes).")
        data = response.content
        if len(data) > max_bytes:
            raise UnsafeArchive(f"A layer is larger than allowed ({len(data)} bytes).")
        actual = sha256_digest(data)
        if actual != digest:
            raise DigestMismatch(
                f"A download did not match its digest (expected {digest[:19]}..., got "
                f"{actual[:19]}...): nothing was installed."
            )
        self.downloaded += len(data)
        return data


def _raise_for(response: httpx.Response, path: str) -> None:
    if response.status_code < 300:
        return
    host = response.url.host or REGISTRY_HOST
    if response.status_code in (401, 403):
        raise RegistryAuthError(
            f"{host} refused access to {IMAGE} (HTTP {response.status_code}). Check that the "
            "registry token has read:packages and can see the package."
        )
    if response.status_code == 404:
        raise RegistryError(f"{IMAGE}: not found ({path.rsplit('/', 1)[-1][:24]}).")
    raise RegistryError(f"{host} answered HTTP {response.status_code}.")


def _unreachable(host: str, exc: Exception) -> str:
    return (
        f"Could not reach {host} ({type(exc).__name__}). The server needs outbound HTTPS to "
        f"{' and '.join(EGRESS_HOSTS)}."
    )


_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?')


def _next_page(link: str) -> str | None:
    """The next tags page, only as a path on the same image (never another host)."""
    match = _LINK.search(link or "")
    if not match:
        return None
    parts = urlsplit(match.group(1))
    if parts.netloc and parts.netloc.lower() != REGISTRY_HOST:
        return None
    prefix = f"/v2/{REPOSITORY}/tags/list"
    if parts.path != prefix:
        return None
    return "/tags/list" + (f"?{parts.query}" if parts.query else "")


# ----------------------------------------------------------------- unpacking


@dataclass
class Unpacked:
    files: dict[str, bytes] = field(default_factory=dict)
    total: int = 0


def extract_app_files(
    blob: bytes, *, into: Unpacked | None = None, prefix: str = "app/"
) -> Unpacked:
    """The regular files under ``prefix`` in one image layer, by relative path.

    Refuses, rather than skips, anything unsafe inside the app folder: absolute
    or ``..`` paths, links of any kind, devices; and stops at size limits, so a
    crafted layer cannot write outside the install folder or fill the volume.
    """
    out = into or Unpacked()
    try:
        archive = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")  # noqa: SIM115
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UnsafeArchive(f"A layer could not be unpacked: {exc}") from exc
    with archive:
        try:
            for member in archive:
                _take(archive, member, out, prefix)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise UnsafeArchive(f"A layer could not be unpacked: {exc}") from exc
    return out


def _take(archive: tarfile.TarFile, member: tarfile.TarInfo, out: Unpacked, prefix: str) -> None:
    name = member.name
    while name.startswith("./"):
        name = name[2:]
    parts = name.split("/")
    if name.startswith("/") or "\\" in name or ".." in parts or "\x00" in name:
        raise UnsafeArchive(f"A layer holds an unsafe path ({name[:80]!r}): not installed.")
    if not (name + "/").startswith(prefix):
        return
    rel = name[len(prefix) :].strip("/")
    if not rel:
        return
    base = rel.rsplit("/", 1)[-1]
    if base.startswith(".wh."):
        # A whiteout: a later layer deleting what an earlier one added.
        gone = rel[: -len(base)] + base[4:]
        if base == ".wh..wh..opq":
            gone = rel[: -len(base)].rstrip("/")
        for key in [k for k in out.files if k == gone or k.startswith(gone + "/")]:
            del out.files[key]
        return
    if member.issym() or member.islnk():
        raise UnsafeArchive(f"A layer holds a link ({rel[:80]}): not installed.")
    if member.isdir():
        return
    if not member.isreg():
        raise UnsafeArchive(f"A layer holds a special file ({rel[:80]}): not installed.")
    if member.size > MAX_FILE_BYTES:
        raise UnsafeArchive(f"{rel[:80]} is larger than allowed.")
    out.total += member.size
    if out.total > MAX_UNPACKED_BYTES:
        raise UnsafeArchive("The release is larger than allowed.")
    if len(out.files) >= MAX_FILES and rel not in out.files:
        raise UnsafeArchive("The release has more files than allowed.")
    handle = archive.extractfile(member)
    if handle is None:
        raise UnsafeArchive(f"{rel[:80]} could not be read.")
    out.files[rel] = handle.read(member.size + 1)[: member.size]
