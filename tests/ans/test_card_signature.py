"""Check 13: an Agent Card signature is evidence only when the ANS-issued identity key made it.

The three outcomes carry different meanings and the tests here pin all three, because collapsing them is
exactly how "could not be proven" quietly becomes "fine":

- signed by the certified key      -> PASS
- signed by some other key         -> INCOMPLETE (the ordinary self-published-key case; proves nothing)
- claims the certified key, broken -> FAIL (something signed for this identity and the bytes disagree)
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.ans.card_signature import (
    MISMATCH,
    UNRELATED,
    VERIFIED,
    sign_card,
    signing_payload,
    verify_card_signature,
)
from app.models.schemas import canonical_json

HOST = "demo.agentdesk-demo.org"
ANS_NAME = f"ans://v1.0.0.{HOST}"


@pytest.fixture(scope="module")
def identity_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def certificate(pki, identity_key):  # type: ignore[no-untyped-def]
    return pki.identity_cert(HOST, key=identity_key)


@pytest.fixture
def card() -> dict[str, object]:
    return {
        "name": "Agent Desk Demo",
        "version": "1.0.0",
        "protocolVersion": "1.0",
        "skills": [{"id": "find_agent", "name": "Find Agent"}],
        "supportedInterfaces": [{"url": f"https://{HOST}/a2a", "protocolBinding": "JSONRPC"}],
    }


def test_signature_by_the_certified_key_verifies(identity_key, certificate, card) -> None:  # type: ignore[no-untyped-def]
    signature = sign_card(identity_key, certificate, ANS_NAME, card)
    signed = {**card, "signatures": [signature]}
    outcome, reason = verify_card_signature(signed["signatures"], signed, certificate)
    assert outcome == VERIFIED and "ANS-issued identity certificate" in reason


def test_signature_covers_the_card_and_not_the_signatures_member(identity_key, certificate, card) -> None:  # type: ignore[no-untyped-def]
    """Attaching the signature must not invalidate it, and the payload is the card without ``signatures``."""
    signature = sign_card(identity_key, certificate, ANS_NAME, card)
    assert signing_payload({**card, "signatures": [signature]}) == canonical_json(card).encode()
    signed = {**card, "signatures": [signature]}
    assert verify_card_signature(signed["signatures"], signed, certificate)[0] == VERIFIED


def test_any_edit_to_the_card_breaks_the_signature(identity_key, certificate, card) -> None:  # type: ignore[no-untyped-def]
    signature = sign_card(identity_key, certificate, ANS_NAME, card)
    tampered = {**card, "name": "Totally Different Agent", "signatures": [signature]}
    outcome, reason = verify_card_signature(tampered["signatures"], tampered, certificate)
    assert outcome == MISMATCH and "does not cover these bytes" in reason


def test_adding_a_skill_breaks_the_signature(identity_key, certificate, card) -> None:  # type: ignore[no-untyped-def]
    signature = sign_card(identity_key, certificate, ANS_NAME, card)
    tampered = {
        **card,
        "skills": [*card["skills"], {"id": "exfiltrate", "name": "Exfiltrate"}],  # type: ignore[misc]
        "signatures": [signature],
    }
    assert verify_card_signature(tampered["signatures"], tampered, certificate)[0] == MISMATCH


def test_a_self_published_key_is_not_proof_and_is_not_a_failure(pki, certificate, card) -> None:  # type: ignore[no-untyped-def]
    """The ordinary A2A case: the agent signs with a key it publishes itself. Not proven, not broken."""
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_cert = pki.identity_cert(HOST, key=other_key)
    signed = {**card, "signatures": [sign_card(other_key, other_cert, ANS_NAME, card)]}
    outcome, reason = verify_card_signature(signed["signatures"], signed, certificate)
    assert outcome == UNRELATED and "not with the key in the ANS identity certificate" in reason


def test_unsigned_card_is_not_proven(certificate, card) -> None:  # type: ignore[no-untyped-def]
    assert verify_card_signature([], card, certificate)[0] == UNRELATED


@pytest.mark.parametrize(
    "signatures",
    [
        [{"protected": "not-base64url!!", "signature": "AAAA"}],
        [{"protected": "e30", "signature": "AAAA"}],  # {} : no x5t#S256
        [{"signature": "AAAA"}],
        [{"protected": 5, "signature": None}],
        ["not-an-object"],
        [{}],
    ],
)
def test_malformed_signatures_never_verify(certificate, card, signatures) -> None:  # type: ignore[no-untyped-def]
    assert verify_card_signature(signatures, card, certificate)[0] != VERIFIED


def test_swapping_the_algorithm_does_not_verify(identity_key, certificate, card) -> None:  # type: ignore[no-untyped-def]
    """A signature that claims our certificate but declares another alg is a mismatch, never a pass."""
    signature = sign_card(identity_key, certificate, ANS_NAME, card)
    header = json.loads(base64.urlsafe_b64decode(signature["protected"] + "=="))
    header["alg"] = "none"
    forged = base64.urlsafe_b64encode(canonical_json(header).encode()).rstrip(b"=").decode()
    signed = {**card, "signatures": [{"protected": forged, "signature": signature["signature"]}]}
    assert verify_card_signature(signed["signatures"], signed, certificate)[0] == MISMATCH


def test_signature_names_the_certificate_it_was_made_with(identity_key, certificate, card) -> None:  # type: ignore[no-untyped-def]
    from app.ans.certs import fingerprint_sha256

    signature = sign_card(identity_key, certificate, ANS_NAME, card)
    header = json.loads(base64.urlsafe_b64decode(signature["protected"] + "=="))
    thumbprint = base64.urlsafe_b64decode(header["x5t#S256"] + "==").hex()
    assert thumbprint == fingerprint_sha256(certificate)
    assert header["ans"] == ANS_NAME and header["alg"] == "RS256"
