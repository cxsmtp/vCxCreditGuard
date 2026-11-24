"""A release's signed list of files.

The release build writes ``release-manifest.json`` at the root of the app layer:
every file of the app (path and sha256), the version, the commit and the
dependency hash of the image it was built for. The release workflow signs those
exact bytes with an ed25519 key held as a repository secret, and the signature is
written next to it as ``release-manifest.sig`` (base64).

An installation verifies the signature with the public key embedded in the
running app (``release-signing-key.pub`` beside this file, or
``CXCG_UPDATE_PUBLIC_KEY``). Once a key is configured, a release without a valid
signature, or whose files differ from its list, is never installed.

Imports nothing from the rest of the app, so the release build can run it
before the app is configured.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.updates import parse_version

MANIFEST_FILE = "release-manifest.json"
SIGNATURE_FILE = "release-manifest.sig"
VERSION_FILE = "version.json"
UNCOVERED = frozenset({MANIFEST_FILE, SIGNATURE_FILE, VERSION_FILE})
FORMAT = 1
PUBLIC_KEY_FILE = Path(__file__).resolve().with_name("release-signing-key.pub")
PUBLIC_KEY_ENV = "CXCG_UPDATE_PUBLIC_KEY"


class ReleaseRejected(ValueError):
    """The downloaded release is not one this installation will run."""


def covered(rel: str) -> bool:
    parts = rel.split("/")
    return rel not in UNCOVERED and "__pycache__" not in parts and not rel.endswith(".pyc")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_files(root: Path) -> dict[str, str]:
    """Every covered regular file under ``root`` with its sha256. Links are refused."""
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if not covered(rel):
                continue
            if path.is_symlink():
                raise ReleaseRejected(f"{rel} is a link; a release holds regular files only.")
            out[rel] = sha256_hex(path.read_bytes())
    return dict(sorted(out.items()))


def build_manifest(root: Path, *, version: str, revision: str, deps_hash: str) -> dict[str, Any]:
    if parse_version(version) is None:
        raise ReleaseRejected(f"{version!r} is not a release version (X.Y.Z).")
    return {
        "format": FORMAT,
        "version": version,
        "revision": revision,
        "deps_hash": deps_hash,
        "files": tree_files(root),
    }


def manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """The exact bytes that are signed: deterministic for the same content."""
    return (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode("utf-8")


# ------------------------------------------------------------------- signing


def sign(data: bytes, private_key_pem: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("The release signing key must be an ed25519 private key (PEM).")
    return base64.b64encode(key.sign(data)).decode("ascii")


def load_public_key(text: str | bytes | None) -> Any:
    """An ed25519 public key from PEM (comment lines starting with # ignored), or None."""
    if not text:
        return None
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    pem = "\n".join(
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    if "BEGIN PUBLIC KEY" not in pem:
        return None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    key = load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("The release public key must be an ed25519 key.")
    return key


def configured_public_key() -> Any:
    """The key releases must be signed with: the environment's, else the embedded one."""
    from_env = os.environ.get(PUBLIC_KEY_ENV, "").strip()
    if from_env:
        return load_public_key(from_env)
    try:
        return load_public_key(PUBLIC_KEY_FILE.read_text(encoding="utf-8"))
    except OSError:
        return None


def verify_signature(data: bytes, signature_b64: str, public_key: Any) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        signature = base64.b64decode(signature_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


# -------------------------------------------------------------- verification


@dataclass(frozen=True)
class VerifiedRelease:
    version: str
    revision: str
    deps_hash: str
    # True only when the signature was checked against a configured key.
    signed: bool
    # Whether the release carries a signature at all (checked or not).
    has_signature: bool
    files: int


def _differences(listed: Mapping[str, str], actual: Mapping[str, str]) -> list[str]:
    out: list[str] = []
    for rel, digest in listed.items():
        if rel not in actual:
            out.append(f"missing {rel}")
        elif actual[rel] != digest:
            out.append(f"changed {rel}")
    out.extend(f"unexpected {rel}" for rel in actual if rel not in listed)
    return out


def verify_release(files: Mapping[str, bytes], *, public_key: Any) -> VerifiedRelease:
    """Check a downloaded release's files against its manifest and signature."""
    raw = files.get(MANIFEST_FILE)
    if raw is None:
        raise ReleaseRejected("The release has no file manifest, so it cannot be verified.")
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReleaseRejected("The release's file manifest cannot be read.") from exc
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise ReleaseRejected("The release's file manifest is not in a known format.")
    listed = manifest.get("files")
    if not isinstance(listed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in listed.items()
    ):
        raise ReleaseRejected("The release's file manifest has no file list.")
    version = str(manifest.get("version") or "")
    if parse_version(version) is None:
        raise ReleaseRejected("The release's file manifest names no release version.")

    signature = files.get(SIGNATURE_FILE)
    signed = False
    if public_key is not None:
        if not signature:
            raise ReleaseRejected(
                f"{version} is not signed, and this installation only installs signed releases."
            )
        if not verify_signature(raw, signature.decode("ascii", "replace"), public_key):
            raise ReleaseRejected(
                f"{version}'s signature does not match the release signing key: not installed."
            )
        signed = True

    actual = {rel: sha256_hex(data) for rel, data in files.items() if covered(rel)}
    problems = _differences(listed, actual)
    if problems:
        shown = ", ".join(problems[:3]) + (" ..." if len(problems) > 3 else "")
        raise ReleaseRejected(
            f"{version}'s files do not match its manifest ({len(problems)} difference(s): "
            f"{shown}): not installed."
        )
    return VerifiedRelease(
        version=version,
        revision=str(manifest.get("revision") or ""),
        deps_hash=str(manifest.get("deps_hash") or ""),
        signed=signed,
        has_signature=bool(signature),
        files=len(actual),
    )


def verify_tree(root: Path) -> list[str]:
    """Differences between an installed folder and the manifest inside it."""
    try:
        manifest = json.loads((root / MANIFEST_FILE).read_text(encoding="utf-8"))
        listed = manifest["files"]
    except (OSError, ValueError, KeyError, TypeError):
        return ["no readable release manifest"]
    try:
        actual = tree_files(root)
    except ReleaseRejected as exc:
        return [str(exc)]
    return _differences(listed, actual)
