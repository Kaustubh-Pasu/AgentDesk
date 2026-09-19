"""SSRF defence for every arbitrary outbound URL (website import AND remote-agent/metadata fetches).

Layers
1. ``validate_url`` – deterministic URL acceptance policy (scheme, port, userinfo, control characters,
   backslashes, IP literals incl. decimal/hex/octal shapes, IDNA, special-use names, parser differentials).
2. ``GlobalOnlyPolicy`` – every resolved A/AAAA answer must be globally routable; loopback, RFC1918,
   link-local/metadata, CGNAT, documentation/test, multicast, reserved, NAT64/6to4/v4-mapped wrappers
   are denied. If ANY answer is bad the whole lookup is rejected (no mixed-answer rebinding tricks).
3. ``PinnedNetworkBackend`` – the resolution that is *validated* is the one that is *connected to*:
   the HTTP stack never performs its own second DNS lookup, so DNS rebinding / TOCTOU cannot swap the
   address between check and use. TLS still verifies the certificate against the original hostname.
4. ``PinnedTransport`` – re-validates the URL of every request (so each redirect hop and any URL an SDK
   decides to call is checked), never follows redirects by itself, ignores proxy environment variables.

A deployment-level egress firewall (deploy/firewall.sh) is the independent second layer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

import certifi
import httpcore
import httpx
import idna

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

USER_AGENT = "AgentDeskFetcher/1.0 (+read-only; respects limits)"


class SSRFBlocked(Exception):
    """Raised whenever a URL or destination violates outbound policy. ``code`` is safe to show users."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------- URL policy
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
_URL_SHAPE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^#]*)(#.*)?\Z")
_NUMERIC_LABEL = re.compile(r"^(\d+|0x[0-9a-f]*)\Z")

_SPECIAL_USE_SUFFIXES = (
    "localhost",
    "local",
    "localdomain",
    "internal",
    "intranet",
    "private",
    "corp",
    "home",
    "lan",
    "home.arpa",
    "in-addr.arpa",
    "ip6.arpa",
    "test",
    "example",
    "invalid",
    "onion",
    "alt",
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class UrlPolicy:
    allowed_schemes: frozenset[str] = frozenset({"https"})
    allowed_ports: frozenset[int] = frozenset({443})
    allow_fragment: bool = False
    max_length: int = 2048
    denied_suffixes: tuple[str, ...] = _SPECIAL_USE_SUFFIXES
    # exact hostnames exempt from the special-use suffix rule (tests only; never set from user input)
    exempt_hosts: frozenset[str] = frozenset()


#: Website import: https only. (http is tolerated ONLY as a hop that immediately redirects to https – see
#: safe_fetch.py – and only on port 80.)
IMPORT_URL_POLICY = UrlPolicy()
IMPORT_URL_POLICY_WITH_HTTP_UPGRADE = UrlPolicy(
    allowed_schemes=frozenset({"https", "http"}), allowed_ports=frozenset({443, 80})
)
#: Remote agents / metadata discovered through ANS: https on 443 only.
REMOTE_AGENT_URL_POLICY = UrlPolicy()


@dataclass(frozen=True)
class ValidatedUrl:
    scheme: str
    host: str  # canonical lower-case A-label hostname
    port: int
    target: str  # path + query (never a fragment)

    @property
    def url(self) -> str:
        default = _DEFAULT_PORTS.get(self.scheme)
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.target or '/'}"

    @property
    def origin(self) -> str:
        default = _DEFAULT_PORTS.get(self.scheme)
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"


def canonical_hostname(host: str) -> str:
    """IDNA/UTS-46 canonical A-label form, or raise SSRFBlocked."""
    if not host or host.endswith(".") or host.startswith("."):
        raise SSRFBlocked("hostname_invalid", "empty or dot-terminated hostname")
    try:
        ascii_host = idna.encode(host, uts46=True, std3_rules=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError) as exc:
        raise SSRFBlocked("hostname_invalid", "IDNA canonicalisation failed") from exc
    labels = ascii_host.split(".")
    if len(ascii_host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise SSRFBlocked("hostname_invalid", "malformed DNS label")
    return ascii_host


def validate_url(raw: str, policy: UrlPolicy = IMPORT_URL_POLICY) -> ValidatedUrl:
    if not isinstance(raw, str) or not raw or len(raw) > policy.max_length:
        raise SSRFBlocked("url_invalid", "missing or too long")
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in raw):
        raise SSRFBlocked("url_invalid", "whitespace/control characters")
    if "\\" in raw:
        raise SSRFBlocked("url_invalid", "backslash in URL")
    match = _URL_SHAPE.match(raw)
    if not match:
        raise SSRFBlocked("url_invalid", "not an absolute URL")
    scheme, authority, target, fragment = (
        match.group(1).lower(),
        match.group(2),
        match.group(3),
        match.group(4),
    )
    if scheme not in policy.allowed_schemes:
        raise SSRFBlocked("scheme_not_allowed", scheme)
    if fragment and not policy.allow_fragment:
        raise SSRFBlocked("fragment_not_allowed")
    if "@" in authority:
        raise SSRFBlocked("userinfo_not_allowed")
    if "%" in authority:
        raise SSRFBlocked("url_invalid", "percent-encoding in authority")
    if authority.startswith("[") or authority.count(":") > 1:
        raise SSRFBlocked("ip_literal_not_allowed")
    host_part, sep, port_part = authority.partition(":")
    if sep:
        if not port_part.isdigit() or len(port_part) > 5:
            raise SSRFBlocked("port_not_allowed", "malformed port")
        port = int(port_part)
    else:
        port = _DEFAULT_PORTS[scheme] if scheme in _DEFAULT_PORTS else -1
    if port not in policy.allowed_ports:
        raise SSRFBlocked("port_not_allowed", str(port))
    if scheme in _DEFAULT_PORTS and port != _DEFAULT_PORTS[scheme] and port in _DEFAULT_PORTS.values():
        # e.g. https://host:80 – cross-protocol confusion
        raise SSRFBlocked("port_not_allowed", "scheme/port mismatch")

    host = canonical_hostname(host_part)
    labels = host.split(".")
    if _NUMERIC_LABEL.match(labels[-1]):
        raise SSRFBlocked("ip_literal_not_allowed", "numeric host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SSRFBlocked("ip_literal_not_allowed")
    if len(labels) < 2:
        raise SSRFBlocked("hostname_not_public", "single-label hostname")
    if host not in policy.exempt_hosts:
        for suffix in policy.denied_suffixes:
            if host == suffix or host.endswith("." + suffix):
                raise SSRFBlocked("hostname_not_public", "special-use name")

    # Parser-differential guard: the stdlib parser must agree with ours about the host and port.
    try:
        parts = urlsplit(raw)
        std_host, std_port = parts.hostname, parts.port
    except ValueError as exc:
        raise SSRFBlocked("url_invalid", "stdlib parser rejected URL") from exc
    if (
        std_host is None
        or std_host.lower() != host_part.lower()
        or (std_port or _DEFAULT_PORTS.get(scheme)) != port
    ):
        raise SSRFBlocked("url_invalid", "parser disagreement")

    if target and not target.startswith(("/", "?")):
        raise SSRFBlocked("url_invalid", "malformed path")
    return ValidatedUrl(scheme=scheme, host=host, port=port, target=target or "/")


# --------------------------------------------------------------------------- address policy
_DENIED_V4 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local incl. 169.254.169.254 cloud metadata
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",  # TEST-NET-1
        "192.88.99.0/24",  # 6to4 relay anycast
        "192.168.0.0/16",
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # TEST-NET-2
        "203.0.113.0/24",  # TEST-NET-3
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved + broadcast
    )
)
_DENIED_V6 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "::/128",
        "::1/128",
        "::ffff:0:0/96",  # v4-mapped (also unwrapped below)
        "64:ff9b::/96",  # NAT64 (also unwrapped below)
        "64:ff9b:1::/48",
        "100::/64",  # discard
        "2001::/23",  # IETF protocol assignments incl. Teredo
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4
        "fc00::/7",  # unique-local incl. fd00:ec2::254 (AWS IMDS over IPv6)
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


class AddressPolicy(Protocol):
    def check(self, ip: IPAddress, port: int) -> None:
        """Raise SSRFBlocked if connecting to ip:port is not allowed."""


class GlobalOnlyPolicy:
    """Production policy: globally routable unicast addresses only."""

    def check(self, ip: IPAddress, port: int) -> None:
        if isinstance(ip, ipaddress.IPv6Address):
            # Wrapped IPv4 (v4-mapped / NAT64) is never a legitimate way to reach a public website and is a
            # classic filter bypass, so it is rejected outright instead of being unwrapped and re-checked.
            if ip.ipv4_mapped is not None:
                raise SSRFBlocked("address_not_public", "IPv4-mapped IPv6 address")
            if ip in _NAT64:
                raise SSRFBlocked("address_not_public", "NAT64 address")
            if ip.sixtofour is not None or ip.teredo is not None:
                raise SSRFBlocked("address_not_public", "tunnelled IPv6 address")
            denied: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network] = _DENIED_V6
        else:
            denied = _DENIED_V4
        for net in denied:
            if ip in net:
                raise SSRFBlocked("address_not_public", f"{ip} is in denied range {net}")
        if (
            not ip.is_global
            or ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise SSRFBlocked("address_not_public", f"{ip} is not globally routable")


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, family=socket.AF_UNSPEC)
    except socket.gaierror as exc:
        raise SSRFBlocked("dns_failure", "hostname did not resolve") from exc
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


async def resolve_and_validate(
    host: str, port: int, policy: AddressPolicy, resolver: Resolver = system_resolver
) -> list[IPAddress]:
    """Resolve ``host`` and validate EVERY answer. Returns the validated addresses (IPv4 first)."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        policy.check(literal, port)
        return [literal]
    answers = await resolver(host, port)
    if not answers:
        raise SSRFBlocked("dns_failure", "no addresses")
    if len(answers) > 32:
        raise SSRFBlocked("dns_failure", "too many addresses")
    validated: list[IPAddress] = []
    for answer in answers:
        try:
            ip = ipaddress.ip_address(answer.split("%", 1)[0])
        except ValueError as exc:
            raise SSRFBlocked("dns_failure", "unparseable address") from exc
        policy.check(ip, port)  # any bad answer rejects the whole lookup
        validated.append(ip)
    validated.sort(key=lambda a: a.version)
    return validated


# --------------------------------------------------------------------------- pinned transport
class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """httpcore backend that connects ONLY to addresses it has itself resolved and validated."""

    def __init__(self, address_policy: AddressPolicy, resolver: Resolver = system_resolver) -> None:
        self._policy = address_policy
        self._resolver = resolver
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(  # type: ignore[override]
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        addresses = await resolve_and_validate(host, port, self._policy, self._resolver)
        last_exc: Exception | None = None
        for ip in addresses[:4]:
            try:
                return await self._inner.connect_tcp(
                    str(ip), port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                last_exc = exc
        raise httpcore.ConnectError(f"could not connect to validated address for {host}") from last_exc

    async def connect_unix_socket(self, *args: object, **kwargs: object) -> httpcore.AsyncNetworkStream:
        raise SSRFBlocked("scheme_not_allowed", "unix sockets are never allowed")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def strict_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class PinnedTransport(httpx.AsyncHTTPTransport):
    """httpx transport: per-request URL policy + validated/pinned DNS + strict TLS. No proxies."""

    def __init__(
        self,
        *,
        url_policy: UrlPolicy,
        address_policy: AddressPolicy | None = None,
        resolver: Resolver = system_resolver,
        max_connections: int = 10,
    ) -> None:
        ssl_context = strict_ssl_context()
        super().__init__(verify=ssl_context, trust_env=False, retries=0)
        self._url_policy = url_policy
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=max_connections,
            max_keepalive_connections=0,  # no connection reuse → every request re-validates DNS
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(address_policy or GlobalOnlyPolicy(), resolver),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        validated = validate_url(str(request.url), self._url_policy)
        if validated.host != request.url.host.lower():
            raise SSRFBlocked("url_invalid", "host canonicalisation mismatch")
        try:
            return await super().handle_async_request(request)
        except httpx.ConnectError as exc:
            cause: BaseException | None = exc
            while cause is not None:  # surface policy violations raised inside the backend
                if isinstance(cause, SSRFBlocked):
                    raise cause from exc
                cause = cause.__cause__ or cause.__context__
            raise


@dataclass
class SafeClientConfig:
    url_policy: UrlPolicy = field(default_factory=UrlPolicy)
    address_policy: AddressPolicy | None = None
    resolver: Resolver = system_resolver
    connect_timeout_s: float = 5.0
    read_timeout_s: float = 10.0
    total_timeout_s: float = 15.0
    headers: dict[str, str] = field(default_factory=dict)


def build_safe_client(config: SafeClientConfig | None = None) -> httpx.AsyncClient:
    """httpx client for UNTRUSTED destinations. Never forwards cookies/authorization of ours."""
    config = config or SafeClientConfig()
    transport = PinnedTransport(
        url_policy=config.url_policy, address_policy=config.address_policy, resolver=config.resolver
    )
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, identity", **config.headers}
    return httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,  # redirects are handled manually with full re-validation per hop
        trust_env=False,  # ignore HTTP(S)_PROXY / NO_PROXY / netrc
        timeout=httpx.Timeout(
            config.total_timeout_s, connect=config.connect_timeout_s, read=config.read_timeout_s, pool=5.0
        ),
        headers=headers,
        max_redirects=0,
    )


async def read_capped(response: httpx.Response, max_bytes: int) -> bytes:
    """Read a streamed response body with a hard DECODED-size cap and bounded decompression.

    Must be used with ``client.stream(...)``. Only ``identity``/``gzip``/``deflate`` encodings are
    accepted; decompression output is bounded per chunk, so a compression bomb cannot balloon memory.
    """
    import zlib

    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise SSRFBlocked("response_too_large", "declared content-length over limit")
    if encoding in ("", "identity"):
        decompressor = None
    elif encoding in ("gzip", "x-gzip"):
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif encoding == "deflate":
        decompressor = zlib.decompressobj()
    else:
        raise SSRFBlocked("encoding_not_allowed", encoding[:20])

    total = 0
    raw_total = 0
    chunks: list[bytes] = []
    async for raw in response.aiter_raw():
        raw_total += len(raw)
        if raw_total > max_bytes:
            raise SSRFBlocked("response_too_large", "raw body over limit")
        if decompressor is None:
            data = raw
        else:
            data = b""
            buf = raw
            while buf:
                try:
                    piece = decompressor.decompress(buf, max_bytes - total - len(data) + 1)
                except zlib.error as exc:
                    raise SSRFBlocked("encoding_invalid", "corrupt compressed body") from exc
                data += piece
                if total + len(data) > max_bytes:
                    raise SSRFBlocked("response_too_large", "decompressed body over limit")
                buf = decompressor.unconsumed_tail
        total += len(data)
        if total > max_bytes:
            raise SSRFBlocked("response_too_large", "body over limit")
        chunks.append(data)
    return b"".join(chunks)
