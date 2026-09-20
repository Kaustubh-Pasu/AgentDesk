"""deploy/ans_register.py end to end against the fake registry: resumable, stops for DNS, never fakes ACTIVE."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

from app.ans import client as ans_client_module
from tests.ans.conftest import PAT
from tests.ans.fake_ans import FakeANS

BASE = "agentdesk-demo.org"
HOST = f"demo.{BASE}"
SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "ans_register.py"


def load_script():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("ans_register_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def args(**overrides: object) -> argparse.Namespace:
    base = {
        "host": HOST,
        "status": False,
        "verify": False,
        "verify_dns": False,
        "gddy_dns": False,
        "zone": "",
        "yes": False,
        "skip_preflight": False,
        "timeout": 1.0,
    }
    return argparse.Namespace(**{**base, **overrides})


@pytest.fixture
def go_live(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    from app.settings import reset_settings_cache

    fake = FakeANS()
    env = {
        "ENV": "development",
        "BASE_DOMAIN": BASE,
        "GODADDY_PAT": PAT,
        "KEYS_DIR": str(tmp_path / "keys"),
        "ARTIFACTS_DIR": str(tmp_path / "artifacts"),
        "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'app.db'}",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    reset_settings_cache()
    module = load_script()
    original_init = ans_client_module.AnsClient.__init__

    def patched_init(self, settings, **kwargs):  # type: ignore[no-untyped-def]
        original_init(self, settings, transport=fake.transport, backoff_s=0)

    monkeypatch.setattr(ans_client_module.AnsClient, "__init__", patched_init)
    public_ok = {"value": True}

    async def fake_public(settings, host):  # type: ignore[no-untyped-def]
        return public_ok["value"]

    monkeypatch.setattr(module, "check_public", fake_public)
    monkeypatch.setattr(module, "gddy_report", lambda: None)
    yield module, fake, tmp_path, public_ok
    reset_settings_cache()


async def seed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from app.agents.seed import seed_demo_agent
    from app.models.db import Database
    from app.settings import get_settings

    db = Database(get_settings().database_url)
    await db.create_all()
    await seed_demo_agent(db, get_settings())
    await db.dispose()


async def test_full_resumable_flow(go_live, capsys) -> None:  # type: ignore[no-untyped-def]
    module, fake, tmp_path, _ = go_live
    await seed(tmp_path)

    assert await module.main_async(args()) == module.EXIT_ACTION_REQUIRED
    out = capsys.readouterr().out
    assert f"_acme-challenge.{HOST}" in out and "acme-value-123" in out and "PENDING_VALIDATION" in out
    assert PAT not in out and "SECRETISH" not in out and "PRIVATE KEY" not in out

    assert (
        await module.main_async(args()) == module.EXIT_ACTION_REQUIRED
    )  # re-run without --verify: no second registration
    assert sum(r.url.path == "/v1/agents/register" for r in fake.requests) == 1

    assert await module.main_async(args(verify=True)) == module.EXIT_ACTION_REQUIRED
    out = capsys.readouterr().out
    assert f"_ans.{HOST}" in out and "IGNORED" in out and "unrelated.victim.example" in out

    fake.dns_ok = False
    assert (
        await module.main_async(args(verify_dns=True)) == module.EXIT_FAILED
    )  # 422 from the registry is reported, not hidden
    assert "ACTIVE ✔" not in capsys.readouterr().out
    fake.dns_ok = True
    assert await module.main_async(args(verify_dns=True)) == module.EXIT_OK
    out = capsys.readouterr().out
    assert "ACTIVE ✔" in out
    bundles = list((tmp_path / "artifacts").glob("ans-active-*.json"))
    assert len(bundles) == 1
    text = bundles[0].read_text()
    evidence = json.loads(text)
    assert (
        evidence["registration"]["status"] == "ACTIVE"
        and evidence["registration"]["environment"] == "production"
    )
    assert PAT not in text and "PRIVATE KEY" not in text
    state = json.loads((tmp_path / "artifacts" / f"ans-state-{HOST}.json").read_text())
    assert state["status"] == "ACTIVE" and PAT not in json.dumps(state)


async def test_refuses_when_public_endpoints_are_down(go_live, capsys) -> None:  # type: ignore[no-untyped-def]
    module, fake, tmp_path, public_ok = go_live
    await seed(tmp_path)
    public_ok["value"] = False
    assert await module.main_async(args()) == module.EXIT_FAILED
    assert not any(r.url.path == "/v1/agents/register" for r in fake.requests)
    assert "Nothing was registered" in capsys.readouterr().out


async def test_skip_preflight_is_explicit_opt_in_and_is_announced(go_live, capsys) -> None:  # type: ignore[no-untyped-def]
    """--skip-preflight exists for hosts that cannot reach their own public name (hairpin NAT).
    It must be an explicit operator choice, must be visible in the output, and must never be the default."""
    module, fake, tmp_path, public_ok = go_live
    await seed(tmp_path)
    public_ok["value"] = False  # the in-container check would fail …
    assert await module.main_async(args(skip_preflight=True)) == module.EXIT_ACTION_REQUIRED
    out = capsys.readouterr().out
    assert "Public preflight skipped" in out  # … and the operator's override is on the record
    assert sum(r.url.path == "/v1/agents/register" for r in fake.requests) == 1
    assert "ACTIVE ✔" not in out  # skipping a preflight never shortcuts the registry's own validation


def test_skip_preflight_defaults_to_off(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    module = load_script()
    captured: dict[str, object] = {}

    async def fake_main(parsed):  # type: ignore[no-untyped-def]
        captured["skip"] = parsed.skip_preflight
        return 0

    monkeypatch.setattr(module, "main_async", fake_main)
    monkeypatch.setattr("sys.argv", ["ans_register.py", "--host", HOST])
    assert module.main() == 0 and captured["skip"] is False


async def test_bad_credential_is_reported_without_echoing_it(go_live, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    from app.settings import reset_settings_cache

    module, _, tmp_path, _ = go_live
    await seed(tmp_path)
    monkeypatch.setenv("GODADDY_PAT", "gd_pat_wrong_credential_9999")
    reset_settings_cache()
    assert await module.main_async(args()) == module.EXIT_FAILED
    out = capsys.readouterr().out
    assert "401" in out and "gd_pat_wrong_credential_9999" not in out
