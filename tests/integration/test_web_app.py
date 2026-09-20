"""Full-application tests through the real middleware stack (spec §39 security test list)."""

from __future__ import annotations

import json
import logging
import uuid

import pytest
from sqlalchemy import select

from app.models.db import AuditEvent, Tenant, TenantState
from app.security.headers import CSP
from tests.integration.conftest import BASE, DEMO, DESK, ORIGIN, PASSWORD, PAT, XSS, Web, make_web

SAME = {"Origin": ORIGIN}


async def create_tenant(
    web: Web, client, label: str = "bluedoor", url: str = "https://blue-door.example.org/"
) -> str:  # type: ignore[no-untyped-def]
    page = await client.get("/create")
    csrf, keys = web.form_tokens(page.text)
    response = await client.post(
        "/admin/tenants",
        headers=SAME,
        data={
            "csrf_token": csrf,
            "idempotency_key": keys[0],
            "display_name": "Blue Door",
            "source_url": url,
            "agent_label": label,
        },
    )
    assert response.status_code == 303, response.text
    return response.headers["location"]


async def publish(web: Web, client, location: str, **fields: str) -> object:  # type: ignore[no-untyped-def]
    page = await client.get(location)
    csrf, keys = web.form_tokens(page.text)
    import re

    row_version = re.search(r'name="row_version" value="(\d+)"', page.text).group(1)  # type: ignore[union-attr]
    data = {
        "csrf_token": csrf,
        "idempotency_key": keys[0],
        "row_version": row_version,
        "business_name": "Blue Door Cafe",
        "description": "Coffee.",
        "category": "restaurant",
        "hours": "Mon-Fri | 7am - 6pm",
        "capabilities": ["business_information", "hours"],
        "confirm": "yes",
        **fields,
    }
    return await client.post(f"{location}/publish", headers=SAME, data=data)


# --------------------------------------------------------------------------- public surface
async def test_health_home_and_security_headers(web: Web) -> None:
    async with web.client() as client:
        health = await client.get("/healthz")
        home = await client.get("/")
    assert health.json() == {"status": "ok"}
    assert (
        "Create agent" in home.text
        and "Find agent" in home.text
        and "discover → verify → communicate" in home.text
    )
    h = home.headers
    assert h["content-security-policy"] == CSP and "'unsafe-inline'" not in CSP and "script-src 'self'" in CSP
    assert (
        h["strict-transport-security"].startswith("max-age=63072000")
        and h["x-content-type-options"] == "nosniff"
    )
    assert (
        h["x-frame-options"] == "DENY"
        and h["referrer-policy"] == "no-referrer"
        and h["cross-origin-opener-policy"] == "same-origin"
    )
    assert "camera=()" in h["permissions-policy"] and "server" not in h and "x-request-id" in h
    assert (
        "<script" not in home.text and "style=" not in home.text
    )  # nothing inline; CSP would block it anyway


async def test_gate1_protocols_on_both_hosts_through_the_full_stack(web: Web) -> None:
    mcp_headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    for host, tool in ((DESK, "about_agent_desk"), (DEMO, "get_hours")):
        async with web.client(host) as client:
            card = (await client.get("/.well-known/agent-card.json")).json()
            assert card["supportedInterfaces"][0]["url"] == f"https://{host}/a2a"
            meta = (await client.get("/.well-known/mcp.json")).json()
            assert meta["endpoint"] == f"https://{host}/mcp" and meta["readOnly"] is True
            a2a = await client.post(
                "/a2a",
                headers={"A2A-Version": "1.0"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "SendMessage",
                    "params": {
                        "message": {
                            "messageId": "m",
                            "role": "ROLE_USER",
                            "parts": [{"text": "what can you do? help"}],
                        }
                    },
                },
            )
            assert a2a.json()["result"]["message"]["parts"][0]["text"]
            call = await client.post(
                "/mcp",
                headers=mcp_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": {}},
                },
            )
            assert call.json()["result"]["isError"] is False


async def test_host_header_poisoning_rejected(web: Web) -> None:
    for host in (
        "evil.example.com",
        f"desk.{BASE}.evil.com",
        "localhost",
        "127.0.0.1",
        f"a.b.{BASE}",
        f"{DESK}@evil.com",
    ):
        async with web.client(host) as client:
            response = await client.get("/")
        assert response.status_code == 400 and response.json()["error"]["code"] == "invalid_host"
    async with web.client() as client:
        page = await client.get("/", headers={"X-Forwarded-Host": "evil.example.com"})
    assert "evil.example.com" not in page.text


async def test_tls_ask_is_reachable_only_from_the_proxy_network_under_the_internal_name(web: Web) -> None:
    """Caddy's on-demand-TLS ``ask`` arrives as http://desk:8000/internal/tls-ask (Host = the service name).
    Regression: it used to be rejected as an unknown Host, so no generated tenant could ever get a certificate."""
    import httpx

    def caller(peer: str) -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=web.app, client=(peer, 40000))  # type: ignore[arg-type]
        return httpx.AsyncClient(transport=transport, base_url="http://desk:8000")

    async with caller("127.0.0.1") as proxy:  # 127.0.0.1/32 is TRUSTED_PROXY_CIDRS in the test settings
        served = await proxy.get("/internal/tls-ask", params={"domain": DEMO})
        unknown = await proxy.get("/internal/tls-ask", params={"domain": f"not-a-tenant.{BASE}"})
        foreign = await proxy.get("/internal/tls-ask", params={"domain": "evil.example.com"})
        missing = await proxy.get("/internal/tls-ask")
        health = await proxy.get("/healthz")
        # The exception is path- and method-exact: nothing else is served under the internal name.
        for path in ("/", "/login", "/proof", "/api/proof", "/.well-known/agent-card.json", "/internal/x"):
            assert (await proxy.get(path)).status_code == 400, path
        assert (await proxy.post("/internal/tls-ask", params={"domain": DEMO})).status_code == 400
        for spoof in ("desk.evil.com", "desk:notaport", "xdesk", "desk.", f"desk.{BASE}.evil.com"):
            r = await proxy.get("/internal/tls-ask", params={"domain": DEMO}, headers={"Host": spoof})
            assert r.status_code == 400, spoof
    statuses = [r.status_code for r in (served, unknown, foreign, missing, health)]
    assert statuses == [200, 404, 404, 404, 200]

    # Same Host header from an untrusted TCP peer → still an unknown host.
    async with caller("203.0.113.9") as outsider:
        rejected = await outsider.get("/internal/tls-ask", params={"domain": DEMO})
    assert rejected.status_code == 400 and rejected.json()["error"]["code"] == "invalid_host"


async def test_admin_surface_does_not_exist_on_tenant_hosts(web: Web) -> None:
    async with web.client(DEMO) as client:
        for path in ("/login", "/create", "/find", "/security", f"/admin/tenants/{uuid.uuid4()}"):
            assert (await client.get(path)).status_code == 404
        home = await client.get("/")
    assert "Hokie Bean Cafe" in home.text and "/mcp" in home.text


async def test_cors_is_not_open(web: Web) -> None:
    async with web.client() as client:
        preflight = await client.options(
            "/api/find",
            headers={"Origin": "https://evil.example.com", "Access-Control-Request-Method": "POST"},
        )
        simple = await client.get("/api/proof", headers={"Origin": "https://evil.example.com"})
    for response in (preflight, simple):
        assert not any(name.lower().startswith("access-control-") for name in response.headers)


async def test_oversized_body_rejected(web: Web) -> None:
    async with web.client() as client:
        response = await client.post("/api/find", headers=SAME, content=b"{" + b" " * (300 * 1024) + b"}")
    assert response.status_code == 413


async def test_errors_are_safe_and_carry_a_correlation_id(web: Web, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    async def boom(*_: object, **__: object) -> None:
        raise RuntimeError(f"db password is hunter2 and PAT is {PAT}")

    monkeypatch.setattr(web.services.find, "find", boom)
    async with web.client() as client:
        response = await client.post("/api/find", headers=SAME, json={"query": "coffee"})
        missing = await client.get("/nope")
    body = response.json()["error"]
    assert response.status_code == 500 and body["code"] == "internal_error" and body["correlation_id"]
    assert "hunter2" not in response.text and PAT not in response.text and "Traceback" not in response.text
    assert missing.status_code == 404 and "Traceback" not in missing.text


# --------------------------------------------------------------------------- authentication / sessions
async def test_login_logout_and_session_cookie_attributes(web: Web) -> None:
    async with web.client() as client:
        assert (await client.get("/create")).status_code == 303  # anonymous → login
        response = await web.login(client)
        assert response.status_code == 303 and response.headers["location"] == "/create"
        cookie = next(
            v
            for k, v in response.headers.multi_items()
            if k == "set-cookie" and v.startswith("__Host-agentdesk_session=")
        )
        lowered = cookie.lower()
        assert (
            "secure" in lowered
            and "httponly" in lowered
            and "samesite=strict" in lowered
            and "path=/" in lowered
            and "domain" not in lowered
        )
        page = await client.get("/create")
        assert page.status_code == 200 and page.headers["cache-control"] == "no-store"
        token = client.cookies.get("__Host-agentdesk_session")
        csrf, _ = web.form_tokens(page.text)
        assert (await client.post("/logout", headers=SAME, data={"csrf_token": csrf})).status_code == 303
        client.cookies.set(
            "__Host-agentdesk_session", token, domain=DESK
        )  # replay the old cookie after logout
        assert (await client.get("/create")).status_code == 303


async def test_generic_login_failure_and_rate_limit(web: Web) -> None:
    async with web.client() as client:
        unknown = await web.login(client, email="nobody@agentdesk-demo.org")
        wrong = await web.login(client, password="wrong password value")
        assert unknown.status_code == wrong.status_code == 401
        assert "Invalid email or password." in unknown.text and "Invalid email or password." in wrong.text
        for _ in range(4):
            await web.login(client, password="wrong password value")
        locked = await web.login(client)  # even the right password is refused while locked out
    assert locked.status_code == 429 and "retry-after" in locked.headers


async def test_session_fixation_is_not_possible(web: Web) -> None:
    async with web.client() as client:
        client.cookies.set(
            "__Host-agentdesk_session", "attacker-chosen-session-token-0000000000000", domain=DESK
        )
        await web.login(client)
        assert client.cookies.get("__Host-agentdesk_session") != "attacker-chosen-session-token-0000000000000"
    async with web.client() as victimless:
        victimless.cookies.set(
            "__Host-agentdesk_session", "attacker-chosen-session-token-0000000000000", domain=DESK
        )
        assert (await victimless.get("/create")).status_code == 303


# --------------------------------------------------------------------------- CSRF
async def test_csrf_missing_bad_and_cross_origin_rejected(web: Web) -> None:
    async with web.client() as client:
        await web.login(client)
        page = await client.get("/create")
        csrf, keys = web.form_tokens(page.text)
        good = {
            "csrf_token": csrf,
            "idempotency_key": keys[0],
            "display_name": "X",
            "source_url": "https://x.example.org/",
            "agent_label": "xlabel",
        }
        cases = [
            ({}, {**good}),  # no Origin/Referer at all
            ({"Origin": "https://evil.example.com"}, {**good}),
            ({"Origin": ORIGIN, "Sec-Fetch-Site": "cross-site"}, {**good}),
            ({"Referer": "https://evil.example.com/page"}, {**good}),
            (SAME, {**good, "csrf_token": ""}),
            (SAME, {**good, "csrf_token": "A" * 43}),
        ]
        for headers, data in cases:
            response = await client.post("/admin/tenants", headers=headers, data=data)
            assert response.status_code == 403, (headers, response.status_code)
        async with web.services.db.session() as session:
            assert (await session.execute(select(Tenant).where(Tenant.is_demo.is_(False)))).first() is None
        assert (await client.post("/admin/tenants", headers=SAME, data=good)).status_code == 303
    async with web.client() as anonymous:
        assert (
            await anonymous.post(
                "/login", data={"email": "a@b.co", "password": "x", "csrf_token": "forged"}, headers=SAME
            )
        ).status_code == 403


async def test_get_requests_never_change_state(web: Web) -> None:
    async with web.client() as client:
        await web.login(client)
        for path in (
            "/admin/tenants",
            "/logout",
            f"/admin/tenants/{uuid.uuid4()}/publish",
            f"/admin/tenants/{uuid.uuid4()}/ans/submit",
        ):
            assert (await client.get(path)).status_code in (404, 405)


# --------------------------------------------------------------------------- CREATE end to end
async def test_create_flow_xss_inert_idempotent_and_registered(web: Web, caplog) -> None:  # type: ignore[no-untyped-def]
    host = f"bluedoor.{BASE}"
    async with web.client() as client:
        await web.login(client)
        location = await create_tenant(web, client)
        preview = await client.get(location)
        assert "DRAFT" in preview.text and "Monday - Friday" in preview.text
        assert (
            "<script>alert" not in preview.text and "&lt;script&gt;" in preview.text
        )  # imported text is inert
        async with web.client(host) as public:
            assert (
                await public.get("/.well-known/agent-card.json")
            ).status_code == 404  # not public before confirmation

        unconfirmed = await publish(web, client, location, confirm="")
        assert unconfirmed.status_code == 422
        evil = await publish(
            web,
            client,
            location,
            business_name=XSS[:100],
            description="{{ 7*7 }} ${7*7} <svg/onload=alert(1)>",
        )
        assert evil.status_code == 303
        page = await client.get(location)
        assert (
            "<script>alert" not in page.text
            and "<svg/onload" not in page.text
            and "{{ 7*7 }}" in page.text
            and ">49<" not in page.text
        )

        async with web.client(host) as public:
            card = await public.get("/.well-known/agent-card.json")
            landing = await public.get("/")
            proof = await public.get("/proof")
        assert card.status_code == 200 and card.headers["content-type"].startswith("application/json")
        for html in (landing.text, proof.text):
            assert "<script>alert" not in html and "onerror=alert" not in html.replace(
                "onerror=alert(1)&gt;", ""
            )

        # --- ANS registration through the UI: status only ever mirrors the (fake) registry
        page = await client.get(location)
        csrf, keys = web.form_tokens(page.text)
        with caplog.at_level(logging.DEBUG):
            first = await client.post(
                f"{location}/ans/submit", headers=SAME, data={"csrf_token": csrf, "idempotency_key": keys[2]}
            )
            replay = await client.post(
                f"{location}/ans/submit", headers=SAME, data={"csrf_token": csrf, "idempotency_key": keys[2]}
            )
        assert first.status_code == replay.status_code == 303
        registers = [r for r in web.ans.requests if r.url.path == "/v1/agents/register"]
        assert len(registers) == 1  # the duplicate POST did not register twice
        assert PAT not in caplog.text and "PRIVATE KEY" not in caplog.text
        page = await client.get(location)
        assert (
            "PENDING_VALIDATION" in page.text
            and f"_acme-challenge.{host}" in page.text
            and "acme-value-123" in page.text
        )
        assert "tok-SECRETISH" not in page.text and PAT not in page.text
        for step, expected in (("verify_acme", "PENDING_DNS"), ("verify_dns", "ACTIVE")):
            csrf, keys = web.form_tokens((await client.get(location)).text)
            assert (
                await client.post(
                    f"{location}/ans/{step}",
                    headers=SAME,
                    data={"csrf_token": csrf, "idempotency_key": keys[3]},
                )
            ).status_code == 303
            assert expected in (await client.get(location)).text
    async with web.services.db.session() as session:
        tenant = (await session.execute(select(Tenant).where(Tenant.agent_host == host))).scalar_one()
        assert tenant.state is TenantState.ACTIVE
        actions = {e.action for e in (await session.execute(select(AuditEvent))).scalars()}
    assert {
        "auth.login.success",
        "tenant.create",
        "import.done",
        "config.publish",
        "ans.register",
        "ans.active",
    } <= actions
    assert (web.settings.keys_path / host / "v1.0.0" / "identity.key.pem").stat().st_mode & 0o077 == 0


async def test_blocked_import_shows_safe_state(web: Web) -> None:
    async with web.client() as client:
        await web.login(client)
        location = await create_tenant(web, client, label="blocked", url="https://blocked.example.org/")
        page = await client.get(location)
    assert "Nothing imported yet" in page.text and "10.0.0.1" not in page.text


async def test_cross_tenant_idor_and_mass_assignment(web: Web) -> None:
    async with web.client() as owner, web.client() as rival:
        await web.login(owner)
        location = await create_tenant(web, owner)
        await web.login(rival, email="rival@agentdesk-demo.org")
        assert (await rival.get(location)).status_code == 404
        assert (
            "Blue Door" not in (await rival.get(location)).text
            and "Blue Door" not in (await rival.get("/create")).text
        )
        csrf, keys = web.form_tokens((await rival.get("/create")).text)
        for action in ("import", "publish", "ans/submit", "disable"):
            data = {
                "csrf_token": csrf,
                "idempotency_key": keys[0] + action[:3],
                "business_name": "Hijack",
                "confirm": "yes",
                "row_version": "1",
                "capabilities": "business_information",
                "password": PASSWORD,
            }
            assert (await rival.post(f"{location}/{action}", headers=SAME, data=data)).status_code == 404
        # mass assignment: extra fields are simply never read
        page = await owner.get("/create")
        csrf, keys = web.form_tokens(page.text)
        await owner.post(
            "/admin/tenants",
            headers=SAME,
            data={
                "csrf_token": csrf,
                "idempotency_key": keys[0],
                "display_name": "Second",
                "agent_label": "second",
                "source_url": "https://second.example.org/",
                "owner_id": str(web.owners["rival"].id),
                "state": "ACTIVE",
                "is_demo": "true",
                "agent_host": DESK,
                "role": "ADMIN",
            },
        )
    async with web.services.db.session() as session:
        second = (
            await session.execute(select(Tenant).where(Tenant.agent_host == f"second.{BASE}"))
        ).scalar_one()
    assert (
        second.owner_id == web.owners["owner"].id
        and second.state is not TenantState.ACTIVE
        and second.is_demo is False
    )


@pytest.mark.parametrize(
    "bad_id", ["1 OR 1=1", "../../etc/passwd", "'; DROP TABLE tenants;--", "%2e%2e%2f", "0" * 400]
)
async def test_injection_strings_in_identifiers_are_just_404(web: Web, bad_id: str) -> None:
    async with web.client() as client:
        await web.login(client)
        assert (await client.get(f"/admin/tenants/{bad_id}")).status_code == 404
    async with web.services.db.session() as session:
        assert (await session.execute(select(Tenant))).first() is not None  # table intact


# --------------------------------------------------------------------------- FIND + PROOF through the UI
async def test_find_page_and_api(web: Web) -> None:
    web.ans.add_active_agent(DEMO, name="Hokie Bean Cafe (demo)")
    async with web.client() as client:
        page = await client.post(
            "/find",
            headers=SAME,
            data={"query": "coffee shop hours", "question": "When are you open on Saturday?"},
        )
        api = await client.post(
            "/api/find", headers=SAME, json={"query": "coffee shop hours", "connect": False}
        )
        bad = await client.post(
            "/api/find", headers=SAME, json={"query": "x", "url": "http://169.254.169.254/"}
        )
    assert (
        page.status_code == 200
        and "Untrusted remote content" in page.text
        and "8:00 AM - 5:00 PM" in page.text
        and "15 verification checks" in page.text
    )
    body = api.json()
    assert (
        body["chosen"] == DEMO and body["remote_reply"] is None and body["candidates"][0]["verified"] is True
    )
    assert bad.status_code == 422 and "169.254" not in bad.text
    sent_headers = json.dumps([h for _, _, h in web.remote.requests]).lower()
    assert (
        "cookie" not in sent_headers and "authorization" not in sent_headers
    )  # nothing of ours/the caller's is forwarded


async def test_proof_before_and_after_ans_active(web: Web) -> None:
    async with web.client(DEMO) as client:
        before = (await client.get("/api/proof")).json()
        assert {g["gate"]: g["status"] for g in before["gates"]} == {
            1: "PASS",
            2: "PASS",
            3: "INCOMPLETE",
            4: "INCOMPLETE",
            5: "FAIL",
        }
        assert before["verified"] is False  # never PASS without a live ACTIVE registration
    web.ans.add_active_agent(DEMO, name="Hokie Bean Cafe (demo)")
    web.services.proof._cache.clear()
    async with web.client(DEMO) as client:
        after = (await client.get("/api/proof")).json()
        html = await client.get("/proof")
    assert {g["gate"]: g["status"] for g in after["gates"]} == {
        1: "PASS",
        2: "PASS",
        3: "PASS",
        4: "PASS",
        5: "PASS",
    }
    assert (
        after["verification"]["mcp"]["probe_ok"] is True and "Gate 4" in html.text and "ACTIVE" in html.text
    )
    text = json.dumps(after)
    for secret in (PAT, web.settings.session_secret.get_secret_value(), "PRIVATE KEY", "127.0.0.1", "sqlite"):
        assert secret not in text


# --------------------------------------------------------------------------- limits, breakers, logging
async def test_public_rate_limits(tmp_path) -> None:  # type: ignore[no-untyped-def]
    async for web in make_web(tmp_path, rl_protocol_per_min=3, rl_proof_per_min=2):
        async with web.client(DEMO) as client:
            codes = [(await client.get("/.well-known/agent-card.json")).status_code for _ in range(4)]
            a2a = [(await client.post("/a2a", json={})).status_code for _ in range(5)]
        assert codes[:2] == [200, 200] and codes[-1] == 429
        assert a2a[-1] == 429 and a2a[0] != 429


async def test_circuit_breakers_through_the_ui(tmp_path) -> None:  # type: ignore[no-untyped-def]
    async for web in make_web(tmp_path, disable_agent_creation=True, disable_remote_agent_calls=True):
        async with web.client() as client:
            await web.login(client)
            csrf, keys = web.form_tokens((await client.get("/create")).text)
            response = await client.post(
                "/admin/tenants",
                headers=SAME,
                data={
                    "csrf_token": csrf,
                    "idempotency_key": keys[0],
                    "display_name": "X",
                    "source_url": "https://x.example.org/",
                    "agent_label": "xx",
                },
            )
            assert response.status_code == 503 and "temporarily disabled" in response.text
            security = await client.get("/security")
            assert "DISABLED" in security.text
            assert (await client.get("/healthz")).status_code == 200 and (
                await client.get("/proof")
            ).status_code == 200  # read-only surfaces survive


async def test_canary_secret_never_reaches_logs(web: Web, caplog, capsys) -> None:  # type: ignore[no-untyped-def]
    canary = web.settings.session_secret.get_secret_value()
    with caplog.at_level(logging.DEBUG):
        async with web.client() as client:
            await client.get(
                "/",
                headers={
                    "Authorization": f"Bearer {canary}",
                    "Cookie": f"__Host-agentdesk_session={canary}",
                    "X-Api-Key": PAT,
                },
            )
            await client.get(f"/find?token={canary}")
            await web.login(client, password=canary)
        logging.getLogger("app").info("operator mistake: secret=%s pat=%s", canary, PAT)
    output = capsys.readouterr().out + caplog.text
    formatted = "\n".join(
        h.format(r) for r in caplog.records for h in logging.getLogger().handlers if h.formatter
    )
    assert canary not in formatted and PAT not in formatted, "secret leaked into formatted log output"
    assert canary not in output.replace(caplog.text, "")
