from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.ans.fake_ans import FakeANS
from tests.conftest import make_settings

PAT = "gd_pat_test_credential_0001"


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


class FakePKI:
    """Throw-away root → intermediate → leaf PKI (EC keys for speed)."""

    def __init__(self, name: str = "Test ANS Root") -> None:
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = self._ca(name, self.root_key, None, None)
        self.int_key = ec.generate_private_key(ec.SECP256R1())
        self.intermediate = self._ca(f"{name} Issuing", self.int_key, self.root, self.root_key)

    @staticmethod
    def _ca(cn: str, key, issuer, issuer_key) -> x509.Certificate:  # type: ignore[no-untyped-def]
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.now(UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(issuer.subject if issuer else name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        )
        if issuer is not None:
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
            )
        return builder.sign(issuer_key or key, hashes.SHA256())

    def identity_cert(
        self,
        host: str,
        version: str = "1.0.0",
        *,
        uri: str | None = None,
        days: int = 90,
        start_days_ago: int = 1,
    ) -> x509.Certificate:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(UTC)
        sans: list[x509.GeneralName] = [x509.DNSName(host)]
        if uri != "":
            sans.append(x509.UniformResourceIdentifier(uri or f"ans://v{version}.{host}"))
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self.intermediate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=start_days_ago))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.int_key.public_key()), critical=False
            )
            .sign(self.int_key, hashes.SHA256())
        )


@pytest.fixture(scope="session")
def pki() -> FakePKI:
    return FakePKI()


@pytest.fixture
def fake_ans() -> FakeANS:
    return FakeANS()


@pytest.fixture
def ans_settings(tmp_path):  # type: ignore[no-untyped-def]
    return make_settings(
        godaddy_pat=PAT, keys_dir=str(tmp_path / "keys"), artifacts_dir=str(tmp_path / "artifacts")
    )
