"""Keys, CSRs and certificate inspection for ANS.

- Private keys come from the OS CSPRNG (``cryptography`` → OpenSSL RAND), are written once with mode 0600
  inside a 0700 per-agent directory, and are never returned by any function that feeds a web response.
- CSR shapes follow docs/research/ANS_API_NOTES.md §6: identity CSR = CN + DNS SAN + mandatory
  ``URI:ans://v{version}.{host}`` SAN; server CSR = CN + DNS SAN, RSA 2048/4096 only, SHA-256.
- Chain verification trusts ONLY the operator-provisioned anchor bundle (optionally fingerprint-pinned).
  A chain sent by the registry or a remote agent supplies intermediates, never roots. No anchors → INCOMPLETE.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from app.models.schemas import CertificateSummary, Status, ans_name_for, parse_semver
from app.security.hosts import HostPolicyError, validate_agent_host
from app.security.ssrf import SSRFBlocked, canonical_hostname

KeyKind = Literal["identity", "server"]
IDENTITY_KEY_BITS = (
    2048  # portable across RA deployments (EC P-256 is rejected with 422 by some; see notes §6)
)
SERVER_KEY_BITS = 2048  # the RA accepts RSA 2048 or 4096 ONLY for server CSRs
_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)
MAX_PEM_BYTES = 64 * 1024
MAX_CHAIN_CERTS = 8


class CertError(ValueError):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


# --------------------------------------------------------------------------- keys + CSRs
def generate_rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    if bits not in (2048, 3072, 4096):
        raise CertError("key_size_not_allowed")
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _csr(key: rsa.RSAPrivateKey, host: str, sans: list[x509.GeneralName]) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _checked_host(host: str) -> str:
    try:
        canonical = canonical_hostname(host)
    except SSRFBlocked as exc:
        raise CertError("host_invalid") from exc
    if canonical != host or len(canonical) > 64:  # CN is limited to 64 characters
        raise CertError("host_invalid", "host must be canonical and at most 64 characters")
    return canonical


def build_identity_csr(key: rsa.RSAPrivateKey, host: str, version: str) -> str:
    host = _checked_host(host)
    ans_uri = ans_name_for(host, version)
    return _csr(key, host, [x509.DNSName(host), x509.UniformResourceIdentifier(ans_uri)])


def build_server_csr(key: rsa.RSAPrivateKey, host: str) -> str:
    if key.key_size not in (2048, 4096):
        raise CertError("key_size_not_allowed", "server CSR keys must be RSA 2048 or 4096")
    host = _checked_host(host)
    return _csr(key, host, [x509.DNSName(host)])


@dataclass(frozen=True)
class CsrBundle:
    identity_csr_pem: str
    server_csr_pem: str


class KeyStore:
    """Filesystem key store: ``<keys_dir>/<agent_host>/v<version>/<kind>.key.pem`` (dir 0700, file 0600).

    Path components are never user text: ``agent_host`` must pass the BASE_DOMAIN child policy and ``version``
    must be strict semver, so no traversal or metacharacter can reach the filesystem.
    """

    def __init__(self, keys_dir: Path, base_domain: str) -> None:
        self._root = keys_dir
        self._base_domain = base_domain

    def _dir(self, agent_host: str, version: str) -> Path:
        try:
            host = validate_agent_host(agent_host, self._base_domain)
        except HostPolicyError as exc:
            raise CertError("host_invalid") from exc
        major, minor, patch = parse_semver(version)
        return self._root / host / f"v{major}.{minor}.{patch}"

    def load(self, agent_host: str, version: str, kind: KeyKind) -> rsa.RSAPrivateKey | None:
        """Existing key only — never generates. Signing must use the key the registry already certified."""
        if kind not in ("identity", "server"):
            raise CertError("key_kind_invalid")
        path = self._dir(agent_host, version) / f"{kind}.key.pem"
        if not path.exists():
            return None
        if path.stat().st_mode & 0o077:
            raise CertError("key_permissions", "private key file must not be group/world accessible")
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise CertError("key_type_invalid")
        return key

    def load_or_create(self, agent_host: str, version: str, kind: KeyKind) -> rsa.RSAPrivateKey:
        if kind not in ("identity", "server"):
            raise CertError("key_kind_invalid")
        directory = self._dir(agent_host, version)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        for parent in (directory, directory.parent):
            os.chmod(parent, 0o700)
        path = directory / f"{kind}.key.pem"
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise CertError("key_permissions", "private key file must not be group/world accessible")
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise CertError("key_type_invalid")
            return key
        key = generate_rsa_key(IDENTITY_KEY_BITS if kind == "identity" else SERVER_KEY_BITS)
        pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # never widens, never overwrites
        try:
            os.write(fd, pem)
        finally:
            os.close(fd)
        return key

    def csr_bundle(self, agent_host: str, version: str) -> CsrBundle:
        return CsrBundle(
            identity_csr_pem=build_identity_csr(
                self.load_or_create(agent_host, version, "identity"), agent_host, version
            ),
            server_csr_pem=build_server_csr(self.load_or_create(agent_host, version, "server"), agent_host),
        )


# --------------------------------------------------------------------------- inspection
def load_certificates(pem: str | bytes, *, limit: int = MAX_CHAIN_CERTS) -> list[x509.Certificate]:
    data = pem.encode("ascii", errors="ignore") if isinstance(pem, str) else pem
    if len(data) > MAX_PEM_BYTES:
        raise CertError("pem_too_large")
    if b"PRIVATE KEY" in data:
        raise CertError("pem_contains_private_key", "refusing to handle PEM that contains a private key")
    blocks = _PEM_CERT.findall(data)
    if not blocks or len(blocks) > limit:
        raise CertError("pem_invalid", f"expected 1..{limit} certificates")
    try:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    except ValueError as exc:
        raise CertError("pem_invalid", "unparseable certificate") from exc


def fingerprint_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def subject_alt_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return []
    assert isinstance(san, x509.SubjectAlternativeName)
    names = [f"DNS:{n}" for n in san.get_values_for_type(x509.DNSName)]
    names += [f"URI:{n}" for n in san.get_values_for_type(x509.UniformResourceIdentifier)]
    return names[:50]


def check_binding(
    cert: x509.Certificate, host: str, version: str | None, *, now: datetime | None = None
) -> tuple[Status, str]:
    """Validity window + hostname binding (+ ANS URI binding when ``version`` is given: identity certs)."""
    now = now or datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        return "FAIL", "certificate is not yet valid"
    if now > cert.not_valid_after_utc:
        return "FAIL", "certificate has expired"
    sans = subject_alt_names(cert)
    cn = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    if f"DNS:{host}" not in sans and host not in cn:
        return "FAIL", "certificate is not bound to the agent host"
    if version is not None:
        expected = f"URI:{ans_name_for(host, version)}"
        uris = [s for s in sans if s.startswith("URI:ans://")]
        if not uris:
            return "FAIL", "no ans:// URI SAN: not an ANS identity certificate"
        if expected not in uris:
            return "FAIL", "ANS URI SAN does not match the agent's ANS name"
    return "PASS", "validity window, host and ANS name binding verified"


@dataclass(frozen=True)
class TrustAnchors:
    certificates: tuple[x509.Certificate, ...]
    problem: str = ""

    @classmethod
    def load(cls, path: str, pinned_sha256: set[str]) -> TrustAnchors:
        """Operator-provisioned bundle only. Every anchor must match a pin when pins are configured."""
        if not path:
            return cls((), "no official ANS trust anchor has been provisioned (ANS_TRUST_ANCHOR_PATH)")
        try:
            certs = load_certificates(Path(path).read_bytes(), limit=16)
        except (OSError, CertError):
            return cls((), "configured ANS trust anchor bundle could not be read")
        if pinned_sha256 and any(fingerprint_sha256(c) not in pinned_sha256 for c in certs):
            return cls((), "ANS trust anchor bundle does not match the pinned fingerprints")
        return cls(tuple(certs))


def verify_chain(
    leaf: x509.Certificate,
    intermediates: list[x509.Certificate],
    anchors: TrustAnchors,
    *,
    now: datetime | None = None,
) -> tuple[Status, str]:
    if not anchors.certificates:
        return "INCOMPLETE", anchors.problem or "no trust anchor provisioned"
    anchor_prints = {fingerprint_sha256(c) for c in anchors.certificates}
    # Anything the other side supplied is at most an intermediate; supplied self-signed roots are ignored.
    untrusted = [
        c for c in intermediates if fingerprint_sha256(c) not in anchor_prints and c.issuer != c.subject
    ]
    builder = PolicyBuilder().store(Store(list(anchors.certificates))).max_chain_depth(4)
    if now is not None:
        builder = builder.time(now)
    try:
        builder.build_client_verifier().verify(leaf, untrusted)
    except VerificationError as exc:
        return "FAIL", f"chain does not verify to the provisioned ANS trust anchor ({str(exc)[:120]})"
    return "PASS", "chain verifies to the provisioned ANS trust anchor"


def summarize(cert: x509.Certificate) -> CertificateSummary:
    return CertificateSummary(
        issuer=cert.issuer.rfc4514_string()[:512],
        subject=cert.subject.rfc4514_string()[:512],
        san=subject_alt_names(cert),
        serial=format(cert.serial_number, "X"),
        sha256=fingerprint_sha256(cert),
        valid_from=cert.not_valid_before_utc,
        valid_to=cert.not_valid_after_utc,
    )
