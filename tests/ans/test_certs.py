from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from app.ans.certs import (
    CertError,
    KeyStore,
    TrustAnchors,
    build_identity_csr,
    build_server_csr,
    check_binding,
    fingerprint_sha256,
    generate_rsa_key,
    load_certificates,
    summarize,
    verify_chain,
)
from tests.ans.conftest import FakePKI, pem
from tests.conftest import TEST_BASE_DOMAIN

HOST = f"demo.{TEST_BASE_DOMAIN}"


def test_identity_csr_shape() -> None:
    key = generate_rsa_key(2048)
    text = build_identity_csr(key, HOST, "1.2.3")
    assert text.startswith("-----BEGIN CERTIFICATE REQUEST-----\n") and text.count("BEGIN") == 1
    assert "PRIVATE" not in text
    csr = x509.load_pem_x509_csr(text.encode())
    assert csr.is_signature_valid and csr.signature_hash_algorithm.name == "sha256"  # type: ignore[union-attr]
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == HOST
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [HOST]
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [f"ans://v1.2.3.{HOST}"]


def test_server_csr_shape_and_key_rules() -> None:
    csr = x509.load_pem_x509_csr(build_server_csr(generate_rsa_key(2048), HOST).encode())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [HOST] and not san.get_values_for_type(
        x509.UniformResourceIdentifier
    )
    with pytest.raises(CertError, match="2048 or 4096"):
        build_server_csr(generate_rsa_key(3072), HOST)
    with pytest.raises(CertError):
        generate_rsa_key(1024)


@pytest.mark.parametrize(
    "host", ["Demo.Example.Test", "demo.example.test.", "a b.example.test", "x" * 70 + ".example.test"]
)
def test_csr_rejects_non_canonical_hosts(host: str) -> None:
    with pytest.raises(CertError):
        build_identity_csr(generate_rsa_key(2048), host, "1.0.0")


def test_keystore_permissions_and_reuse(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = KeyStore(tmp_path / "keys", TEST_BASE_DOMAIN)
    key = store.load_or_create(HOST, "1.0.0", "identity")
    path = tmp_path / "keys" / HOST / "v1.0.0" / "identity.key.pem"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    again = store.load_or_create(HOST, "1.0.0", "identity")
    assert again.public_key().public_numbers() == key.public_key().public_numbers()
    assert (
        store.load_or_create(HOST, "1.0.0", "server").public_key().public_numbers()
        != key.public_key().public_numbers()
    )
    os.chmod(path, 0o644)
    with pytest.raises(CertError, match="group/world"):
        store.load_or_create(HOST, "1.0.0", "identity")


@pytest.mark.parametrize(
    ("host", "version"),
    [
        ("../../etc", "1.0.0"),
        ("evil.other.com", "1.0.0"),
        (HOST, "../1.0.0"),
        (HOST, "1.0"),
        ("a.b." + TEST_BASE_DOMAIN, "1.0.0"),
    ],
)
def test_keystore_never_builds_paths_from_untrusted_text(tmp_path, host: str, version: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        KeyStore(tmp_path / "keys", TEST_BASE_DOMAIN).load_or_create(host, version, "identity")
    assert not (tmp_path / "keys").exists() or not any((tmp_path / "keys").rglob("*.pem"))


def test_binding_checks(pki: FakePKI) -> None:
    good = pki.identity_cert(HOST, "1.0.0")
    assert check_binding(good, HOST, "1.0.0")[0] == "PASS"
    assert check_binding(good, "other.example.test", "1.0.0")[0] == "FAIL"
    assert check_binding(good, HOST, "2.0.0")[0] == "FAIL"
    assert check_binding(pki.identity_cert(HOST, uri=""), HOST, "1.0.0")[0] == "FAIL"
    assert (
        check_binding(pki.identity_cert(HOST, uri="ans://v1.0.0.evil.example.test"), HOST, "1.0.0")[0]
        == "FAIL"
    )
    assert check_binding(good, HOST, "1.0.0", now=datetime.now(UTC) + timedelta(days=400))[0] == "FAIL"
    assert check_binding(pki.identity_cert(HOST, start_days_ago=-5), HOST, "1.0.0")[0] == "FAIL"


def test_chain_verification_uses_only_provisioned_anchor(pki: FakePKI, tmp_path) -> None:  # type: ignore[no-untyped-def]
    leaf = pki.identity_cert(HOST)
    bundle = tmp_path / "anchor.pem"
    bundle.write_text(pem(pki.root))
    anchors = TrustAnchors.load(str(bundle), set())
    assert verify_chain(leaf, [pki.intermediate], anchors)[0] == "PASS"
    # pinned fingerprint must match
    assert TrustAnchors.load(str(bundle), {fingerprint_sha256(pki.root)}).certificates
    assert not TrustAnchors.load(str(bundle), {"00" * 32}).certificates
    # no anchor provisioned → INCOMPLETE, never PASS
    status, reason = verify_chain(leaf, [pki.intermediate, pki.root], TrustAnchors.load("", set()))
    assert status == "INCOMPLETE" and "trust anchor" in reason
    # a DIFFERENT PKI sending its own root along does not become trusted
    attacker = FakePKI("Attacker Root")
    forged = attacker.identity_cert(HOST)
    assert verify_chain(forged, [attacker.intermediate, attacker.root], anchors)[0] == "FAIL"
    # missing intermediate → FAIL (not an exception)
    assert verify_chain(leaf, [], anchors)[0] == "FAIL"


def test_pem_loader_is_strict(pki: FakePKI) -> None:
    key_pem = (
        generate_rsa_key(2048)
        .private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        .decode()
    )
    for bad in (
        "",
        "not pem",
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
        pem(pki.root) + key_pem,
        pem(pki.root) * 20,
        "A" * 100_000,
    ):
        with pytest.raises(CertError):
            load_certificates(bad)
    summary = summarize(load_certificates(pem(pki.identity_cert(HOST)))[0])
    assert f"DNS:{HOST}" in summary.san and len(summary.sha256) == 64 and summary.chain_status == "INCOMPLETE"
    assert "PRIVATE" not in summary.model_dump_json()
