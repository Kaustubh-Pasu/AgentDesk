"""Hostname policy for OUR agents (Gate 3).

Generated agent hostnames must be sanitised single-label children of ``BASE_DOMAIN``. A user can never
pick an arbitrary DNS name, a reserved label, or a label that smuggles shell/path/DNS metacharacters.
"""

from __future__ import annotations

import re

from app.security.ssrf import SSRFBlocked, canonical_hostname

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)\Z")

RESERVED_LABELS = frozenset(
    {
        "desk",
        "www",
        "admin",
        "api",
        "app",
        "mail",
        "smtp",
        "imap",
        "pop",
        "ftp",
        "ns",
        "ns1",
        "ns2",
        "mx",
        "autodiscover",
        "autoconfig",
        "localhost",
        "internal",
        "root",
        "proof",
        "status",
        "static",
        "assets",
        "cdn",
        "login",
        "auth",
        "sso",
        "oauth",
        "security",
        "support",
        "billing",
        "ans",
        "godaddy",
        "caddy",
        "postgres",
        "redis",
        "scraper",
        "controlplane",
    }
)


class HostPolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalize_label(label: str) -> str:
    label = label.strip().lower()
    if not _LABEL.match(label):
        raise HostPolicyError("label_invalid", "subdomain must be 1-63 chars of a-z, 0-9 or hyphen")
    if label.startswith("xn--"):
        raise HostPolicyError("label_invalid", "punycode labels are not allowed for generated agents")
    if "--" in label:
        raise HostPolicyError("label_invalid", "double hyphen is not allowed")
    if label.startswith("_"):
        raise HostPolicyError("label_invalid", "underscore labels are reserved for DNS validation records")
    return label


def agent_host_for_label(label: str, base_domain: str, *, allow_reserved: bool = False) -> str:
    """Return ``<label>.<base_domain>`` after full validation (the automatic, owned-domain path)."""
    label = normalize_label(label)
    if label in RESERVED_LABELS and not allow_reserved:
        raise HostPolicyError("label_reserved", "that subdomain is reserved")
    host = f"{label}.{base_domain}"
    return validate_agent_host(host, base_domain)


def validate_agent_host(host: str, base_domain: str) -> str:
    """Canonicalise ``host`` and require it to be a DIRECT child of ``base_domain``."""
    try:
        canonical = canonical_hostname(host.strip().lower())
    except SSRFBlocked as exc:
        raise HostPolicyError("host_invalid", "malformed hostname") from exc
    base = base_domain.strip().lower().rstrip(".")
    suffix = "." + base
    if not canonical.endswith(suffix):
        raise HostPolicyError("host_outside_base_domain", "agent host must be a child of BASE_DOMAIN")
    label = canonical[: -len(suffix)]
    if not label or "." in label:
        raise HostPolicyError("host_depth", "agent host must be a direct child of BASE_DOMAIN")
    normalize_label(label)
    return canonical


def is_allowed_request_host(
    host_header: str, *, base_domain: str, extra: frozenset[str] = frozenset()
) -> bool:
    """TrustedHost check: exact base-domain children only. Port is ignored; everything else must match."""
    host = host_header.strip().lower()
    if not host or len(host) > 260 or any(ch in host for ch in "/\\@?#\r\n\t ,"):
        return False
    if host.startswith("["):
        return False
    name, sep, port = host.partition(":")
    if sep and not (port.isdigit() and 0 < int(port) < 65536):
        return False
    if name in extra:
        return True
    try:
        validate_agent_host(name, base_domain)
    except HostPolicyError:
        return False
    return True


def host_without_port(host_header: str) -> str:
    return host_header.strip().lower().partition(":")[0]
