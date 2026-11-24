"""Create the release signing key pair, once, on a trusted machine.

    python backend/scripts/release_keygen.py [--out cxcg-release-signing-key.pem]

Writes the PRIVATE key to ``--out`` (mode 600; refuses to overwrite) and prints
the PUBLIC key. Then:

1. Store the private key file's whole contents as the repository secret
   ``CXCG_RELEASE_SIGNING_KEY`` (GitHub: Settings -> Secrets and variables ->
   Actions), keep an offline copy somewhere safe, and delete the file.
2. Paste the printed public key into
   ``backend/app/updates/release-signing-key.pub`` and commit it.

From the first release built with that commit on, installations only install
releases whose signature verifies. Never commit the private key.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("cxcg-release-signing-key.pem"))
    args = parser.parse_args(argv)
    if args.out.exists():
        print(f"{args.out} already exists; not overwriting it.", file=sys.stderr)
        return 1
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_pem = key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    print(f"Private key written to {args.out} (keep it secret; never commit it).")
    print("Store its contents as the repository secret CXCG_RELEASE_SIGNING_KEY.\n")
    print("Public key - paste into backend/app/updates/release-signing-key.pub:\n")
    print(public_pem.decode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
