"""In-app updates: published releases from the registry, installed in the data volume.

* ``registry`` reads the release images from GHCR (fixed host, read-only token).
* ``manifest`` builds, signs and verifies a release's list of files.
* ``store`` keeps installed versions and the files the launcher reads.
* ``service`` checks, installs, rolls back and runs auto-update.

The launcher that runs the selected version is ``cxcg_launcher.py`` next to the
``app`` package: it is part of the image, not of an update.
"""

from __future__ import annotations

import re

VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
BUILT_IN = "built-in"


def parse_version(value: object) -> tuple[int, int, int] | None:
    text = str(value or "")
    if not VERSION_RE.match(text):
        return None
    major, minor, patch = (int(part) for part in text.split("."))
    return (major, minor, patch)


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1. Anything that is not a plain release version sorts lowest."""
    pa, pb = parse_version(a) or (-1, -1, -1), parse_version(b) or (-1, -1, -1)
    return (pa > pb) - (pa < pb)


def is_release_tag(tag: str) -> bool:
    """The releases channel: plain ``X.Y.Z`` tags only (no latest, no commit or rc tags)."""
    return parse_version(tag) is not None
