"""Security tests 1-5 + 20: SSRF URL policy, address policy, pinned resolution / DNS rebinding."""

from __future__ import annotations

import ipaddress

import httpx
import pytest

from app.security.ssrf import (
    IMPORT_URL_POLICY,
    REMOTE_AGENT_URL_POLICY,
    GlobalOnlyPolicy,
    SafeClientConfig,
    SSRFBlocked,
    build_safe_client,
    read_capped,
    resolve_and_validate,
    validate_url,
)
from tests.helpers import FakeResolver, LoopbackTestPolicy, Reply, TinyServer, gzip_bomb, local_url_policy

PUBLIC = "public-site.agentdesk-tests.com"


# ------------------------------------------------------------------ 1. localhost IPv4 / IPv6
@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/",
        "https://LOCALHOST/",
        "https://foo.localhost/",
        "https://127.0.0.1/",
        "https://127.1/",
        "https://2130706433/",  # decimal 127.0.0.1
        "https://0x7f000001/",  # hex
        "https://0x7f.0.0.1/",
        "https://0177.0.0.1/",  # octal
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://[0:0:0:0:0:0:0:1]/",
        "https://0.0.0.0/",
        "https://0/",
    ],
)
def test_localhost_forms_rejected(url: str) -> None:
    with pytest.raises(SSRFBlocked):
        validate_url(url, IMPORT_URL_POLICY)


# ------------------------------------------------------------------ 2. private / link-local / metadata
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "127.8.8.8",
        "10.0.0.5",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "169.254.0.1",
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
        "192.0.2.10",
        "198.51.100.7",
        "203.0.113.9",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",  # AWS IMDS IPv6
        "ff02::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:8.8.8.8",  # even a public v4 wrapped in v6 is refused
        "64:ff9b::7f00:1",  # NAT64 → 127.0.0.1
        "2002:7f00:1::",  # 6to4 → 127.0.0.1
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    ],
)
def test_non_global_addresses_rejected(ip: str) -> None:
    with pytest.raises(SSRFBlocked):
        GlobalOnlyPolicy().check(ipaddress.ip_address(ip), 443)


@pytest.mark.parametrize("ip", ["93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_global_addresses_allowed(ip: str) -> None:
    GlobalOnlyPolicy().check(ipaddress.ip_address(ip), 443)


async def test_hostname_resolving_to_metadata_is_blocked() -> None:
    resolver = FakeResolver({"metadata.agentdesk-tests.com": ["169.254.169.254"]})
    with pytest.raises(SSRFBlocked) as exc:
        await resolve_and_validate("metadata.agentdesk-tests.com", 443, GlobalOnlyPolicy(), resolver)
    assert exc.value.code == "address_not_public"


async def test_mixed_public_and_private_answers_reject_whole_lookup() -> None:
    resolver = FakeResolver({PUBLIC: ["93.184.216.34", "10.0.0.7"]})
    with pytest.raises(SSRFBlocked):
        await resolve_and_validate(PUBLIC, 443, GlobalOnlyPolicy(), resolver)


# ------------------------------------------------------------------ 3. userinfo / parser ambiguity
@pytest.mark.parametrize(
    "url",
    [
        "https://user@example.com/",
        "https://user:pass@example.com/",
        "https://example.com@evil.com/",
        "https://example.com:443@evil.com/",
        "https://example.com\\@evil.com/",
        "https://example.com\\.evil.com/",
        "https://example.com%2f@evil.com/",
        "https://exa mple.com/",
        "https://example.com/\r\nHost: evil",
        "https://example.com/\x00",
        "\thttps://example.com/",
        "https://example.com./",
        "https://.example.com/",
        "https://example..com/",
        "https://-bad.example.com/",
        "https://example.com:8080/",
        "https://example.com:80/",
        "https://example.com:0/",
        "https://example.com:65536/",
        "https://example.com:443abc/",
        "https://example.com#@evil.com/",
        "https://example.com/#frag",
        "https:///etc/passwd",
        "https:/example.com",
        "//example.com/",
        "example.com",
        "http://example.com/",  # http is not accepted by the strict import policy
        "ftp://example.com/",
        "file:///etc/passwd",
        "gopher://example.com/",
        "javascript:alert(1)",
        "data:text/html,hi",
        "vbscript:msgbox(1)",
        "https://intranet/",  # single label
        "https://router.lan/",
        "https://db.internal/",
        "https://printer.local/",
        "https://service.home.arpa/",
        "https://xn--/",
        "https://" + "a" * 64 + ".com/",
        "https://" + ".".join(["a" * 60] * 5) + ".com/",
        "https://example.com/" + "a" * 3000,
    ],
)
def test_ambiguous_or_disallowed_urls_rejected(url: str) -> None:
    with pytest.raises(SSRFBlocked):
        validate_url(url, IMPORT_URL_POLICY)


def test_valid_url_is_canonicalised() -> None:
    v = validate_url("https://EXAMPLE.com/Menu?x=1", IMPORT_URL_POLICY)
    assert (v.scheme, v.host, v.port, v.target) == ("https", "example.com", 443, "/Menu?x=1")
    assert v.url == "https://example.com/Menu?x=1"
    assert validate_url("https://example.com", IMPORT_URL_POLICY).url == "https://example.com/"


def test_idn_is_converted_to_a_label_and_fullwidth_is_normalised() -> None:
    assert validate_url("https://bücher.example.org/", IMPORT_URL_POLICY).host == "xn--bcher-kva.example.org"
    assert validate_url("https://ｅｘａｍｐｌｅ.com/", IMPORT_URL_POLICY).host == "example.com"


def test_remote_agent_policy_is_https_443_only() -> None:
    validate_url("https://agent.example.org/a2a", REMOTE_AGENT_URL_POLICY)
    for bad in ("http://agent.example.org/a2a", "https://agent.example.org:8443/a2a", "https://10.0.0.1/a2a"):
        with pytest.raises(SSRFBlocked):
            validate_url(bad, REMOTE_AGENT_URL_POLICY)


# ------------------------------------------------------------------ 5. pinned resolution / DNS rebinding
async def test_pinned_transport_connects_only_to_the_validated_answer() -> None:
    async with TinyServer({"/": Reply(body=b"<html>ok</html>")}) as server:
        resolver = FakeResolver({PUBLIC: ["127.0.0.1"]})
        config = SafeClientConfig(
            url_policy=local_url_policy(server.port),
            address_policy=LoopbackTestPolicy(server.port),
            resolver=resolver,
        )
        async with build_safe_client(config) as client:
            resp = await client.get(server.url(PUBLIC))
        assert resp.status_code == 200
        assert resolver.calls == [PUBLIC]  # exactly ONE resolution: the validated one is the one used
        assert len(server.hits) == 1
        assert server.hits[0][1]["host"] == f"{PUBLIC}:{server.port}"


async def test_dns_rebinding_second_answer_is_blocked_and_never_connected() -> None:
    async with TinyServer({"/": Reply(body=b"ok")}) as server:
        # 1st lookup → the allowed fixture address; 2nd lookup (rebinding) → cloud metadata address
        resolver = FakeResolver({PUBLIC: [["127.0.0.1"], ["169.254.169.254"]]})
        config = SafeClientConfig(
            url_policy=local_url_policy(server.port),
            address_policy=LoopbackTestPolicy(server.port),
            resolver=resolver,
        )
        async with build_safe_client(config) as client:
            first = await client.get(server.url(PUBLIC))
            assert first.status_code == 200
            with pytest.raises(SSRFBlocked) as exc:
                await client.get(server.url(PUBLIC))
        assert exc.value.code == "address_not_public"
        assert len(server.hits) == 1  # the rebound request never produced a connection
        assert len(resolver.calls) == 2  # one validated lookup per connection, no unvalidated extra lookups


async def test_production_policy_blocks_loopback_even_when_dns_says_so() -> None:
    async with TinyServer({"/": Reply(body=b"secret-internal-page")}) as server:
        resolver = FakeResolver({PUBLIC: ["127.0.0.1"]})
        config = SafeClientConfig(
            url_policy=local_url_policy(server.port), resolver=resolver
        )  # GlobalOnlyPolicy
        async with build_safe_client(config) as client:
            with pytest.raises(SSRFBlocked):
                await client.get(server.url(PUBLIC))
        assert server.hits == []


async def test_transport_revalidates_url_policy_on_every_request() -> None:
    async with build_safe_client() as client:  # strict production config
        for bad in (
            "http://example.com/",
            "https://127.0.0.1/",
            "https://example.com:8443/",
            "https://u@example.com/",
        ):
            with pytest.raises(SSRFBlocked):
                await client.get(bad)


async def test_client_ignores_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    async with TinyServer({"/": Reply(body=b"direct")}) as server:
        config = SafeClientConfig(
            url_policy=local_url_policy(server.port),
            address_policy=LoopbackTestPolicy(server.port),
            resolver=FakeResolver({PUBLIC: ["127.0.0.1"]}),
        )
        async with build_safe_client(config) as client:
            assert client.trust_env is False
            resp = await client.get(server.url(PUBLIC))
        assert resp.text == "direct"


async def test_client_never_follows_redirects_itself() -> None:
    async with TinyServer(
        {"/": Reply(status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})}
    ) as server:
        config = SafeClientConfig(
            url_policy=local_url_policy(server.port),
            address_policy=LoopbackTestPolicy(server.port),
            resolver=FakeResolver({PUBLIC: ["127.0.0.1"]}),
        )
        async with build_safe_client(config) as client:
            resp = await client.get(server.url(PUBLIC))
        assert resp.status_code == 302 and len(server.hits) == 1


# ------------------------------------------------------------------ 6. size / decompression caps
async def _get_capped(server: TinyServer, path: str, cap: int) -> bytes:
    config = SafeClientConfig(
        url_policy=local_url_policy(server.port),
        address_policy=LoopbackTestPolicy(server.port),
        resolver=FakeResolver({PUBLIC: ["127.0.0.1"]}),
    )
    async with build_safe_client(config) as client, client.stream("GET", server.url(PUBLIC, path)) as resp:
        return await read_capped(resp, cap)


async def test_read_capped_limits() -> None:
    routes = {
        "/small": Reply(body=b"x" * 1000),
        "/declared-big": Reply(body=b"x" * 5000),
        "/stream-big": Reply(body=b"y" * 1024, repeat=64),
        "/bomb": Reply(
            body=gzip_bomb(20 * 1024 * 1024),
            headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
        ),
        "/gzip-ok": Reply(
            body=__import__("gzip").compress(b"hello gzip"),
            headers={"Content-Type": "text/html", "Content-Encoding": "gzip"},
        ),
        "/br": Reply(body=b"zzzz", headers={"Content-Type": "text/html", "Content-Encoding": "br"}),
        "/corrupt": Reply(
            body=b"not-gzip-at-all", headers={"Content-Type": "text/html", "Content-Encoding": "gzip"}
        ),
    }
    async with TinyServer(routes) as server:
        assert await _get_capped(server, "/small", 2000) == b"x" * 1000
        assert await _get_capped(server, "/gzip-ok", 2000) == b"hello gzip"
        for path, code in [
            ("/declared-big", "response_too_large"),
            ("/stream-big", "response_too_large"),
            ("/bomb", "response_too_large"),
            ("/br", "encoding_not_allowed"),
            ("/corrupt", "encoding_invalid"),
        ]:
            with pytest.raises(SSRFBlocked) as exc:
                await _get_capped(server, path, 4096)
            assert exc.value.code == code, path


def test_httpx_is_the_only_resolver_path() -> None:
    """Guard: the pinned transport must keep keep-alive reuse disabled so each request re-validates DNS."""
    from app.security.ssrf import PinnedTransport

    transport = PinnedTransport(url_policy=IMPORT_URL_POLICY)
    assert transport._pool._max_keepalive_connections == 0
    assert isinstance(transport, httpx.AsyncHTTPTransport)
