"""Agent Card signatures anchored in the ANS identity certificate (spec §26.1 check 13).

Why this exists
- A2A lets an agent attach a JWS to its own card, but the key is published by the agent itself, so a caller
  that trusts it is trusting the agent's word about the agent. The verifier therefore refuses to treat a
  self-published key as a trust input, and the check stays INCOMPLETE.
- The ANS registry publishes no ``metaDataHash`` for an endpoint (confirmed live against the detail, search
  and transparency-log APIs), so there is no registry-side digest to compare either.
- What *is* anchored: the identity certificate issued by the GoDaddy ANS private CA, which binds a public key
  to ``ans://v{version}.{host}``. A card signed with THAT key, verified against a certificate retrieved from
  the authenticated certificate API and chained to the operator-provisioned ANS trust anchor, is an integrity
  statement rooted in the registry's PKI rather than in the agent's own say-so.

Shape
- Detached JWS (RFC 7515 §A.5) over ``signing_payload(card)``: the canonical JSON of the card with the
  ``signatures`` member removed, so the signature covers everything else exactly as served.
- ``alg`` is RS256 (ANS identity keys are RSA 2048; see ``certs.IDENTITY_KEY_BITS``).
- The protected header carries ``x5t#S256`` (the SHA-256 thumbprint of the signing certificate) and ``ans``
  (the ANS name), so a verifier can tell which registry identity the signer *claims* before checking it. Both
  are claims: neither is trusted until the fetched certificate is confirmed to match.

Nothing here reads a key or certificate out of a card. The verifier supplies the certificate it obtained from
ANS; a certificate or key embedded in a remote card is ignored.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import Certificate

from app.ans.certs import fingerprint_sha256
from app.models.schemas import canonical_json

Outcome = Literal["VERIFIED", "MISMATCH", "UNRELATED"]
VERIFIED: Outcome = "VERIFIED"
MISMATCH: Outcome = "MISMATCH"
UNRELATED: Outcome = "UNRELATED"

ALG = "RS256"
TYP = "JOSE"
SIGNATURE_FIELD = "signatures"
MAX_SIGNATURES = 10
MAX_HEADER_BYTES = 4096


class CardSigner(Protocol):
    """Produces one ``AgentCardSignature`` for a card, or ``None`` when no ANS key can sign it."""

    async def sign(self, agent_host: str, version: str, card: dict[str, Any]) -> dict[str, str] | None: ...


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    if not text or len(text) > MAX_HEADER_BYTES or any(c in text for c in "+/= \n\r\t"):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _thumbprint(cert: Certificate) -> str:
    """base64url of the raw SHA-256 of the DER certificate (RFC 7515 ``x5t#S256``)."""
    return _b64u(bytes.fromhex(fingerprint_sha256(cert)))


def signing_payload(card: dict[str, Any]) -> bytes:
    """Canonical JSON of the card WITHOUT ``signatures`` — the bytes a card signature covers."""
    return canonical_json({k: v for k, v in card.items() if k != SIGNATURE_FIELD}).encode()


def sign_card(
    key: rsa.RSAPrivateKey, certificate: Certificate, ans_name: str, card: dict[str, Any]
) -> dict[str, str]:
    """Produce one detached-JWS ``AgentCardSignature`` for ``card``. Runs only where the ANS key lives."""
    if key.key_size < 2048:
        raise ValueError("identity key is too small to sign with")
    header = {"alg": ALG, "typ": TYP, "x5t#S256": _thumbprint(certificate), "ans": ans_name}
    protected = _b64u(canonical_json(header).encode())
    payload = _b64u(signing_payload(card))
    signature = key.sign(f"{protected}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return {"protected": protected, "signature": _b64u(signature)}


def verify_card_signature(
    signatures: list[dict[str, Any]], card: dict[str, Any], certificate: Certificate
) -> tuple[Outcome, str]:
    """Is any card signature a valid RS256 JWS made by ``certificate``'s key over this exact card?

    ``certificate`` MUST be one the caller already retrieved from the ANS certificate API and validated.

    The three outcomes are deliberately distinct, because only one of them is evidence of a problem:

    - ``VERIFIED``  — a signature by the ANS-certified key covers exactly these bytes.
    - ``MISMATCH``  — a signature claims THIS certificate (matching ``x5t#S256``) but does not verify, or is
      malformed. Something signed for this identity and the bytes no longer agree: that is a real failure.
    - ``UNRELATED`` — the card is signed, but by a key ANS did not certify. That is the ordinary case for an
      agent using its own published key. It proves nothing, so it is "not proven", never "broken".
    """
    if not signatures:
        return UNRELATED, "card carries no signature"
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return UNRELATED, "identity certificate does not carry an RSA key"
    expected_thumbprint = _thumbprint(certificate)
    payload = _b64u(signing_payload(card))
    outcome, reason = UNRELATED, "card is signed, but not with the key in the ANS identity certificate"
    for entry in signatures[:MAX_SIGNATURES]:
        if not isinstance(entry, dict):
            continue
        protected, signature = entry.get("protected"), entry.get("signature")
        if not isinstance(protected, str) or not isinstance(signature, str):
            continue
        try:
            header = json.loads(_b64u_decode(protected))
            raw_signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        except (ValueError, json.JSONDecodeError):
            continue
        if not isinstance(header, dict) or header.get("x5t#S256") != expected_thumbprint:
            continue  # a signature for some other key: irrelevant, not evidence of tampering
        if header.get("alg") != ALG:
            outcome, reason = MISMATCH, "card signature does not use the expected algorithm"
            continue
        try:
            public_key.verify(
                raw_signature, f"{protected}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
            )
        except InvalidSignature:
            outcome = MISMATCH
            reason = "card signature claims the ANS identity certificate but does not cover these bytes"
            continue
        return VERIFIED, "card is signed by the key in the ANS-issued identity certificate"
    return outcome, reason


def certificate_pem(certificate: Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
