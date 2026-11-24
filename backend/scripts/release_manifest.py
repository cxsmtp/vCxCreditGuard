"""Write, sign and check a release's file manifest.

Used by the image build and the release workflow (.github/workflows/release.yml):

    # in the image build, over the assembled app folder
    python -m scripts.release_manifest build --root /out --revision <commit> \\
        --image-info /usr/local/share/cxcreditguard/image.json

    # in the release workflow, with the private key from the repository secret
    python -m scripts.release_manifest sign --manifest release-manifest.json \\
        --key-file key.pem            # prints the base64 signature

    # check a signature against the public key committed in the app (fails when
    # there is no key: a release is never published unverifiable)
    python -m scripts.release_manifest verify --manifest release-manifest.json \\
        --signature <base64> [--public-key app/updates/release-signing-key.pub]

    # fail unless a real public key is committed (not the placeholder)
    python -m scripts.release_manifest check-key [--public-key ...]

The version is the ``__version__`` in ``<root>/app/__init__.py`` (stamped from the
release tag by the workflow). The private key never enters the image build. The
manifest lists every file under the root; a root holding bytecode, ``.pth``
files or interpreter start-up hooks is refused (remove ``__pycache__`` first).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from app.updates.manifest import (
    MANIFEST_FILE,
    PUBLIC_KEY_FILE,
    build_manifest,
    load_public_key,
    manifest_bytes,
    sign,
    verify_signature,
)

_VERSION_LINE = re.compile(r"""^__version__\s*=\s*["']([^"']+)["']""", re.M)


def _version(root: Path) -> str:
    match = _VERSION_LINE.search((root / "app" / "__init__.py").read_text(encoding="utf-8"))
    if not match:
        raise SystemExit("No __version__ in app/__init__.py")
    return match.group(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="write release-manifest.json at the root")
    build.add_argument("--root", type=Path, required=True)
    build.add_argument("--revision", default="")
    build.add_argument("--image-info", type=Path, required=True)
    signing = sub.add_parser("sign", help="print the base64 ed25519 signature of a manifest")
    signing.add_argument("--manifest", type=Path, required=True)
    signing.add_argument("--key-file", type=Path, required=True)
    verify = sub.add_parser("verify", help="check a signature against a public key")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--signature", required=True)
    verify.add_argument("--public-key", type=Path, default=PUBLIC_KEY_FILE)
    check_key = sub.add_parser("check-key", help="fail unless a public key is committed")
    check_key.add_argument("--public-key", type=Path, default=PUBLIC_KEY_FILE)
    args = parser.parse_args(argv)

    if args.command == "build":
        info = json.loads(args.image_info.read_text(encoding="utf-8"))
        manifest = build_manifest(
            args.root,
            version=_version(args.root),
            revision=args.revision.strip(),
            deps_hash=str(info["deps_hash"]),
        )
        (args.root / MANIFEST_FILE).write_bytes(manifest_bytes(manifest))
        print(
            f"release manifest: {manifest['version']}, {len(manifest['files'])} files, "
            f"deps {manifest['deps_hash'][:12]}"
        )
        return 0
    if args.command == "sign":
        print(sign(args.manifest.read_bytes(), args.key_file.read_bytes()))
        return 0
    key = load_public_key(args.public_key.read_text(encoding="utf-8"))
    if key is None:
        print(
            f"No public key in {args.public_key} (still the placeholder): releases cannot be "
            "verified. Run scripts/release_keygen.py and commit the public key.",
            file=sys.stderr,
        )
        return 2
    if args.command == "check-key":
        print("A release public key is committed.")
        return 0
    if not verify_signature(args.manifest.read_bytes(), args.signature, key):
        print("The signature does NOT match the public key.", file=sys.stderr)
        return 1
    print("The signature matches the public key.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
