"""Mapping from a tenant's IAM URL to its platform API base URL.

Checkmarx One hosts IAM and the platform API on sibling hostnames that differ by
one label: ``eu.iam.checkmarx.net`` pairs with ``eu.ast.checkmarx.net``. The
known regions are listed explicitly, with the label swap as a fallback for
regions added after this was written.

Dedicated and on premise style deployments do not follow the pattern at all, so
derivation always stays overridable from the Settings page.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.checkmarx.errors import CheckmarxError

# Hosts the utility will send tenant credentials to without being told to.
# Everything Checkmarx One hosts lives under this domain.
DEFAULT_TRUSTED_HOST_SUFFIXES: tuple[str, ...] = ("checkmarx.net",)


class UntrustedHostError(CheckmarxError):
    """A tenant URL points somewhere the deployment has not agreed to talk to."""


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


def _host_matches(host: str, suffix: str) -> bool:
    suffix = suffix.strip().lower().lstrip(".")
    return bool(suffix) and (host == suffix or host.endswith(f".{suffix}"))


def check_tenant_url(
    url: str,
    *,
    what: str,
    extra_trusted_hosts: tuple[str, ...] = (),
    allow_plain_http: bool = False,
) -> None:
    """Refuse a tenant URL the utility must not send credentials to.

    The access token (and, for the IAM URL, the API key itself) is sent to
    whatever host these URLs name. The IAM URL comes from an unsigned claim in
    the pasted key and the API URL can be typed into the GUI, so neither can be
    taken on trust: without this check, one wrong value hands the tenant's
    credentials to another server, or turns the utility into a way of reaching
    hosts on its own network.

    Allowed: HTTPS to a host under ``checkmarx.net``, or under a suffix the
    operator listed in ``CXCG_CX_ALLOWED_HOSTS`` (for dedicated deployments).
    """
    try:
        parts = urlsplit(url.strip())
        host = (parts.hostname or "").lower()
        _ = parts.port  # raises for a malformed port
    except ValueError as exc:
        raise UntrustedHostError(f"The {what} is not a valid URL.") from exc
    if parts.scheme not in ("https", "http") or not host:
        raise UntrustedHostError(f"The {what} must be an https:// URL.")
    if parts.scheme == "http" and not allow_plain_http:
        raise UntrustedHostError(
            f"The {what} must use https://, so credentials are never sent in the clear."
        )
    if parts.username or parts.password:
        raise UntrustedHostError(f"The {what} must not contain a username or password.")
    if parts.query or parts.fragment:
        raise UntrustedHostError(f"The {what} must not contain a query string or fragment.")

    trusted = (*DEFAULT_TRUSTED_HOST_SUFFIXES, *extra_trusted_hosts)
    if any(_host_matches(host, suffix) for suffix in trusted):
        return

    try:
        ipaddress.ip_address(host)
        kind = "an IP address"
    except ValueError:
        kind = "not a Checkmarx One host"
    raise UntrustedHostError(
        f"The {what} points at {host}, which is {kind}. Tenant credentials are only sent "
        f"to hosts under {', '.join(DEFAULT_TRUSTED_HOST_SUFFIXES)} unless the deployment "
        f"allows more. For a dedicated deployment, add the host to CXCG_CX_ALLOWED_HOSTS "
        f"in the environment and restart."
    )
