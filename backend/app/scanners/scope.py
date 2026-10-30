from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit


ALLOWED_PORTS = {80, 443}
Resolver = Callable[[str, int], tuple[str, ...]]
BLOCKED_HOSTS = {
    "localhost", "metadata", "metadata.google.internal", "metadata.google", "metadata.azure.internal",
    "instance-data.ec2.internal", "metadata.aws.internal",
}


class ScopeError(ValueError):
    """A target URL or resolved destination is outside safe authorized scope."""


def normalize_hostname(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw or any(c in value for c in "/\\:@?#[]*%\x00"):
        raise ScopeError("Hostname must be an exact hostname without a wildcard or URL path")
    try:
        normalized = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeError("Hostname is not valid IDNA") from exc
    if len(normalized) > 253 or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in normalized.split(".")):
        raise ScopeError("Hostname is not valid")
    if normalized in BLOCKED_HOSTS or normalized.endswith((".localhost", ".local", ".internal", ".home.arpa")):
        raise ScopeError("Local, reserved and metadata hostnames are not allowed")
    return normalized


def validate_public_ip(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise ScopeError("Destination did not resolve to a valid IP address") from exc
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if (not address.is_global or address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved or address.is_unspecified):
        raise ScopeError("Private, loopback, link-local, reserved and metadata destinations are blocked")
    return str(address)


def resolve_public_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        return (validate_public_ip(str(literal)),)
    if "." not in hostname:
        raise ScopeError("Single-label internal hostnames are not permitted")
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise ScopeError("The approved hostname could not be resolved") from exc
    addresses = sorted({str(record[4][0]) for record in records})
    if not addresses:
        raise ScopeError("The approved hostname has no address records")
    # Fail closed if even one answer is not public; do not pick a favorable answer from a mixed DNS set.
    return tuple(validate_public_ip(address) for address in addresses)


def validate_target_url(
    url: str,
    allowed_hostnames: list[str] | tuple[str, ...] | set[str],
    *,
    allow_query: bool = False,
    resolver: Resolver | None = None,
) -> tuple[str, str, int, tuple[str, ...]]:
    if not isinstance(url, str) or not url or len(url) > 2048 or url != url.strip() or any(ord(ch) < 32 or ch.isspace() for ch in url):
        raise ScopeError("Target URL is empty, too long, or contains whitespace/control characters")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ScopeError("Target URL or port is invalid") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ScopeError("Only HTTP and HTTPS targets are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise ScopeError("URLs containing credentials are not permitted")
    if parsed.fragment or (parsed.query and not allow_query) or (allow_query and len(parsed.query) > 512):
        raise ScopeError("Target base URLs may not include query parameters or fragments")
    if not parsed.hostname:
        raise ScopeError("Target URL must include a hostname")
    hostname = normalize_hostname(parsed.hostname)
    expected_port = 443 if scheme == "https" else 80
    port = expected_port if port is None else port
    if port not in ALLOWED_PORTS or port != expected_port:
        raise ScopeError("Only the standard HTTP port 80 and HTTPS port 443 are permitted")
    if not allowed_hostnames or len(allowed_hostnames) > 20:
        raise ScopeError("Provide between one and twenty exact authorized hostnames")
    allowed = tuple(sorted({normalize_hostname(host) for host in allowed_hostnames}))
    if hostname not in allowed:
        raise ScopeError("The base hostname must be explicitly included in the authorized host allowlist")
    # Resolve once for this request; the safe transport pins one of these public IPs for its socket.
    (resolver or resolve_public_addresses)(hostname, port)
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    path = parsed.path or "/"
    canonical_url = urlunsplit((scheme, netloc, path, parsed.query if allow_query else "", ""))
    return canonical_url, hostname, port, allowed
