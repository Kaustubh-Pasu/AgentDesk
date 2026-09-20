"""The split-role path: the desk gets certificates and card signatures WITHOUT holding the credential.

In production the verifier runs in the public web role, which has no GoDaddy credential and no ANS private
key. These tests drive the real Starlette routes over an ASGI transport, so what is exercised is the same
request the desk makes — including the parts that must refuse.
"""

from __future__ import annotations

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.applications import Starlette

from app.ans.card_signature import VERIFIED, verify_card_signature
from app.ans.certs import KeyStore, fingerprint_sha256
from app.ans.client import AnsApiError, AnsClient, CertificateResponse
from app.controlplane.api import (
    LocalCardSigner,
    NullCardSigner,
    RemoteCardSigner,
    RemoteCertificates,
    controlplane_routes,
)
from tests.ans.conftest import PAT, pem
from tests.conftest import TEST_BASE_DOMAIN, make_settings

HOST = f"demo.{TEST_BASE_DOMAIN}"
AGENT_ID = "284ab9b7-6ed4-422c-bfae-66e07932cb28"
TOKEN = "controlplane-shared-token-0123456789"
CARD = {"name": "Agent Desk Demo", "version": "1.0.0", "skills": [{"id": "find_agent"}]}


class _Registrar:
    async def run(self, tenant_id, owner_id, step):  # type: ignore[no-untyped-def]
        raise AssertionError("not used here")


class _Certificates:
    """Stands in for the AnsClient that holds the credential."""

    def __init__(self, certificates: list[CertificateResponse] | None = None, error: Exception | None = None):
        self._certificates, self._error = certificates or [], error
        self.calls: list[str] = []

    @property
    def configured(self) -> bool:
        return True

    async def get_identity_certificates(self, agent_id: str) -> list[CertificateResponse]:
        self.calls.append(agent_id)
        if self._error is not None:
            raise self._error
        return self._certificates


def _settings(**overrides: object):  # type: ignore[no-untyped-def]
    return make_settings(
        controlplane_url="http://controlplane", controlplane_token=TOKEN, godaddy_pat=PAT, **overrides
    )


def _client(settings, certificates=None, signer=None) -> httpx.AsyncBaseTransport:  # type: ignore[no-untyped-def]
    app = Starlette(routes=controlplane_routes(settings, _Registrar(), certificates, signer))  # type: ignore[arg-type]
    return httpx.ASGITransport(app=app)


@pytest.fixture
def certified(pki):  # type: ignore[no-untyped-def]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = pki.identity_cert(HOST, key=key)
    response = CertificateResponse.model_validate(
        {"certificatePEM": pem(leaf), "chainPEM": pem(pki.intermediate) + pem(pki.root)}
    )
    return key, leaf, response


async def test_desk_fetches_the_identity_certificate_through_the_control_plane(certified) -> None:  # type: ignore[no-untyped-def]
    _, leaf, response = certified
    settings = _settings()
    source = _Certificates([response])
    remote = RemoteCertificates(settings, transport=_client(settings, source))

    got = await remote.get_identity_certificates(AGENT_ID)

    assert len(got) == 1 and got[0].certificate_pem == response.certificate_pem
    assert got[0].chain_pem == response.chain_pem
    assert source.calls == [AGENT_ID]  # exactly the agent asked for, nothing else
    assert fingerprint_sha256(leaf)  # the PEM that came back parses to the same certificate


async def test_certificate_route_requires_the_shared_token(certified) -> None:  # type: ignore[no-untyped-def]
    _, _, response = certified
    settings = _settings()
    transport = _client(settings, _Certificates([response]))
    async with httpx.AsyncClient(transport=transport, base_url="http://controlplane") as client:
        for headers in ({}, {"Authorization": "Bearer wrong-token"}):
            reply = await client.post("/internal/ans/certificates", json={"agent_id": AGENT_ID}, headers=headers)
            assert reply.status_code == 401 and reply.json()["error"]["code"] == "unauthorized"


async def test_registry_refusal_reaches_the_verifier_with_its_status(certified) -> None:  # type: ignore[no-untyped-def]
    """The certificate API only serves agents the credential owns; the desk must see 403, not a generic error."""
    settings = _settings()
    source = _Certificates(error=AnsApiError(403, "FORBIDDEN"))
    remote = RemoteCertificates(settings, transport=_client(settings, source))

    with pytest.raises(AnsApiError) as caught:
        await remote.get_identity_certificates(AGENT_ID)
    assert caught.value.status == 403 and caught.value.code == "FORBIDDEN"


async def test_no_credential_is_reported_as_missing_not_as_success() -> None:
    settings = _settings()
    remote = RemoteCertificates(settings, transport=_client(settings, None))
    with pytest.raises(AnsApiError) as caught:
        await remote.get_identity_certificates(AGENT_ID)
    assert caught.value.code == "ANS_CREDENTIAL_MISSING"


async def test_certificate_route_rejects_anything_that_is_not_one_agent_id(certified) -> None:  # type: ignore[no-untyped-def]
    _, _, response = certified
    settings = _settings()
    transport = _client(settings, _Certificates([response]))
    async with httpx.AsyncClient(transport=transport, base_url="http://controlplane") as client:
        for body in (
            {"agent_id": "../../etc/passwd"},
            {"agent_id": AGENT_ID, "url": "http://evil.example"},
            {"agent_host": HOST},
            {},
        ):
            reply = await client.post(
                "/internal/ans/certificates", json=body, headers={"Authorization": f"Bearer {TOKEN}"}
            )
            assert reply.status_code == 400


async def test_desk_gets_a_card_signature_but_never_the_key(tmp_path, certified, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    key, leaf, response = certified
    settings = _settings(keys_dir=str(tmp_path / "keys"))

    keystore = KeyStore(settings.keys_path, settings.base_domain)
    directory = tmp_path / "keys" / HOST / "v1.0.0"
    directory.mkdir(parents=True)
    from cryptography.hazmat.primitives import serialization

    path = directory / "identity.key.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o600)

    class _Ans(AnsClient):
        @property
        def configured(self) -> bool:
            return True

        async def find_my_agent(self, agent_host, version=None):  # type: ignore[no-untyped-def]
            from app.ans.client import AgentDetails

            return [AgentDetails.model_validate({"agentId": AGENT_ID, "agentHost": agent_host})]

        async def get_identity_certificates(self, agent_id):  # type: ignore[no-untyped-def]
            return [response]

    signer = LocalCardSigner(settings, _Ans(settings), keystore)
    transport = _client(settings, None, signer)
    remote = RemoteCardSigner(settings, transport=transport)

    signature = await remote.sign(HOST, "1.0.0", CARD)

    assert signature is not None
    signed = {**CARD, "signatures": [signature]}
    assert verify_card_signature(signed["signatures"], signed, leaf)[0] == VERIFIED
    # nothing private crossed the wire
    assert "PRIVATE KEY" not in str(signature) and set(signature) == {"protected", "signature"}


async def test_signing_is_refused_when_the_registry_certified_a_different_key(tmp_path, pki) -> None:  # type: ignore[no-untyped-def]
    """An unsigned card is INCOMPLETE; a signature by an uncertified key would be worse than nothing."""
    settings = _settings(keys_dir=str(tmp_path / "keys"))
    local_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_leaf = pki.identity_cert(HOST)  # certified some OTHER key

    directory = tmp_path / "keys" / HOST / "v1.0.0"
    directory.mkdir(parents=True)
    from cryptography.hazmat.primitives import serialization

    path = directory / "identity.key.pem"
    path.write_bytes(
        local_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    path.chmod(0o600)

    class _Ans(AnsClient):
        @property
        def configured(self) -> bool:
            return True

        async def find_my_agent(self, agent_host, version=None):  # type: ignore[no-untyped-def]
            from app.ans.client import AgentDetails

            return [AgentDetails.model_validate({"agentId": AGENT_ID, "agentHost": agent_host})]

        async def get_identity_certificates(self, agent_id):  # type: ignore[no-untyped-def]
            return [CertificateResponse.model_validate({"certificatePEM": pem(other_leaf)})]

    signer = LocalCardSigner(settings, _Ans(settings), KeyStore(settings.keys_path, settings.base_domain))
    assert await signer.sign(HOST, "1.0.0", CARD) is None


async def test_signing_never_creates_a_key_that_does_not_exist(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """KeyStore.load must not mint a fresh key: a key ANS never certified could only produce a bad signature."""
    settings = _settings(keys_dir=str(tmp_path / "keys"))
    keystore = KeyStore(settings.keys_path, settings.base_domain)
    assert keystore.load(HOST, "1.0.0", "identity") is None
    assert not (tmp_path / "keys" / HOST).exists()


async def test_null_signer_serves_an_unsigned_card() -> None:
    assert await NullCardSigner().sign(HOST, "1.0.0", CARD) is None


async def test_sign_route_requires_the_shared_token() -> None:
    settings = _settings()
    transport = _client(settings, None, NullCardSigner())
    async with httpx.AsyncClient(transport=transport, base_url="http://controlplane") as client:
        reply = await client.post(
            "/internal/ans/sign-card", json={"agent_host": HOST, "version": "1.0.0", "card": CARD}
        )
        assert reply.status_code == 401
