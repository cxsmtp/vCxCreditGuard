"""Mapping from a tenant's IAM URL to its platform API base URL.

Checkmarx One hosts IAM and the platform API on sibling hostnames that differ by
one label: ``eu.iam.checkmarx.net`` pairs with ``eu.ast.checkmarx.net``. The
known regions are listed explicitly, with the label swap as a fallback for
regions added after this was written.

Dedicated and on premise style deployments do not follow the pattern at all, so
derivation always stays overridable from the Settings page.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

# iam hostname -> (region label, platform hostname)
KNOWN_REGIONS: dict[str, tuple[str, str]] = {
    "iam.checkmarx.net": ("US", "ast.checkmarx.net"),
    "us.iam.checkmarx.net": ("US 2", "us.ast.checkmarx.net"),
    "eu.iam.checkmarx.net": ("EU", "eu.ast.checkmarx.net"),
    "eu-2.iam.checkmarx.net": ("EU 2", "eu-2.ast.checkmarx.net"),
    "deu.iam.checkmarx.net": ("Germany", "deu.ast.checkmarx.net"),
    "anz.iam.checkmarx.net": ("Australia and New Zealand", "anz.ast.checkmarx.net"),
    "ind.iam.checkmarx.net": ("India", "ind.ast.checkmarx.net"),
    "sng.iam.checkmarx.net": ("Singapore", "sng.ast.checkmarx.net"),
    "uae.iam.checkmarx.net": ("UAE", "uae.ast.checkmarx.net"),
}


@dataclass(frozen=True, slots=True)
class DerivedApiBase:
    api_base_url: str | None
    region_label: str
    # False when we fell back to the label swap or could not derive at all, which
    # the Setup page surfaces as "confirm this is correct".
    confident: bool


def derive_api_base_url(iam_base_url: str) -> DerivedApiBase:
    """Best effort platform API base URL for an IAM base URL."""
    parts = urlsplit(iam_base_url if "//" in iam_base_url else f"https://{iam_base_url}")
    host = (parts.hostname or "").lower()
    if not host:
        return DerivedApiBase(api_base_url=None, region_label="unknown", confident=False)

    scheme = parts.scheme or "https"
    port = f":{parts.port}" if parts.port else ""

    known = KNOWN_REGIONS.get(host)
    if known is not None:
        region_label, api_host = known
        return DerivedApiBase(
            api_base_url=f"{scheme}://{api_host}{port}/api",
            region_label=region_label,
            confident=True,
        )

    labels = host.split(".")
    if "iam" in labels:
        labels[labels.index("iam")] = "ast"
        return DerivedApiBase(
            api_base_url=f"{scheme}://{'.'.join(labels)}{port}/api",
            region_label="derived from IAM hostname",
            confident=False,
        )

    return DerivedApiBase(api_base_url=None, region_label="custom", confident=False)


def normalise_api_base_url(url: str) -> str:
    """Trim trailing slashes so path joins stay predictable.

    The ``/api`` suffix is intentionally not added or removed here: an admin
    overriding this value for a dedicated tenant needs the URL respected exactly
    as entered.
    """
    return url.strip().rstrip("/")
