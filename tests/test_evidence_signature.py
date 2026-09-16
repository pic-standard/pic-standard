from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from pic_standard.evidence import EvidenceSystem

# --- helpers (tests-only) ---


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _make_keypair():
    """
    Generate an Ed25519 keypair using cryptography.
    These tests require 'cryptography' to be installed (your [crypto] extra).
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:  # pragma: no cover
        pytest.skip("cryptography not installed; install via `pip install 'pic-standard[crypto]'`")

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_raw


def _proposal_with_sig(*, payload: str, signature_b64: str, key_id: str) -> dict:
    return {
        "evidence": [
            {
                "id": "approval_123",
                "type": "sig",
                "ref": "inline:approval_payload",
                "payload": payload,
                "alg": "ed25519",
                "signature": signature_b64,
                "key_id": key_id,
                "signer": key_id,
                "attestor": "test",
            }
        ],
        # provenance included because your system upgrades provenance IDs (not strictly required for verify_all)
        "provenance": [{"id": "approval_123", "trust": "untrusted", "source": "evidence"}],
        "claims": [{"text": "Pay", "evidence": ["approval_123"]}],
        "protocol": "PIC/1.0",
        "intent": "Test",
        "impact": "money",
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


# --- tests ---


def test_sig_evidence_verifies_ok(monkeypatch, tmp_path: Path):
    priv, pub_raw = _make_keypair()

    payload = "amount=500;currency=USD;invoice=123"
    sig_raw = priv.sign(payload.encode("utf-8"))
    sig_b64 = _b64(sig_raw)

    # Write a hermetic keyring file and point PIC_KEYS_PATH to it
    keys_path = tmp_path / "pic_keys.json"
    keys_path.write_text(
        json.dumps(
            {"trusted_keys": {"demo_signer_v1": _b64(pub_raw)}},
            indent=2,
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PIC_KEYS_PATH", str(keys_path))

    proposal = _proposal_with_sig(payload=payload, signature_b64=sig_b64, key_id="demo_signer_v1")

    es = EvidenceSystem()
    report = es.verify_all(proposal, base_dir=tmp_path)

    assert report.ok is True
    assert "approval_123" in report.verified_ids
    assert any(r.id == "approval_123" and r.ok for r in report.results)


def test_sig_evidence_fails_when_payload_tampered(monkeypatch, tmp_path: Path):
    priv, pub_raw = _make_keypair()

    payload_signed = "amount=500;currency=USD;invoice=123"
    sig_raw = priv.sign(payload_signed.encode("utf-8"))
    sig_b64 = _b64(sig_raw)

    keys_path = tmp_path / "pic_keys.json"
    keys_path.write_text(
        json.dumps({"trusted_keys": {"demo_signer_v1": _b64(pub_raw)}}, indent=2),
        encoding="utf-8",
    )
    monkeypatch.setenv("PIC_KEYS_PATH", str(keys_path))

    # Tamper payload but keep same signature -> must fail
    proposal = _proposal_with_sig(
        payload="amount=600;currency=USD;invoice=123",
        signature_b64=sig_b64,
        key_id="demo_signer_v1",
    )

    es = EvidenceSystem()
    report = es.verify_all(proposal, base_dir=tmp_path)

    assert report.ok is False
    assert "approval_123" not in report.verified_ids
    # Ensure the failure message is about signature
    msgs = [r.message for r in report.results if r.id == "approval_123"]
    assert msgs and any("signature" in m.lower() for m in msgs)


def test_sig_evidence_fails_unknown_key_id(monkeypatch, tmp_path: Path):
    priv, pub_raw = _make_keypair()

    payload = "amount=500;currency=USD;invoice=123"
    sig_raw = priv.sign(payload.encode("utf-8"))
    sig_b64 = _b64(sig_raw)

    # Keyring does NOT contain the key_id we reference in evidence
    keys_path = tmp_path / "pic_keys.json"
    keys_path.write_text(
        json.dumps({"trusted_keys": {"some_other_key": _b64(pub_raw)}}, indent=2),
        encoding="utf-8",
    )
    monkeypatch.setenv("PIC_KEYS_PATH", str(keys_path))

    proposal = _proposal_with_sig(payload=payload, signature_b64=sig_b64, key_id="demo_signer_v1")

    es = EvidenceSystem()
    report = es.verify_all(proposal, base_dir=tmp_path)

    assert report.ok is False
    assert "approval_123" not in report.verified_ids
    msgs = [r.message for r in report.results if r.id == "approval_123"]
    assert msgs and any("unknown key_id" in m.lower() or "not present" in m.lower() for m in msgs)


def test_sig_evidence_blocks_large_payload(monkeypatch, tmp_path: Path):
    priv, pub_raw = _make_keypair()

    payload = "x" * (16 * 1024 + 1)  # exceeds default max_payload_bytes=16KB
    sig_raw = priv.sign(payload.encode("utf-8"))
    sig_b64 = _b64(sig_raw)

    keys_path = tmp_path / "pic_keys.json"
    keys_path.write_text(
        json.dumps({"trusted_keys": {"demo_signer_v1": _b64(pub_raw)}}, indent=2),
        encoding="utf-8",
    )
    monkeypatch.setenv("PIC_KEYS_PATH", str(keys_path))

    proposal = _proposal_with_sig(payload=payload, signature_b64=sig_b64, key_id="demo_signer_v1")

    es = EvidenceSystem()
    report = es.verify_all(proposal, base_dir=tmp_path)

    assert report.ok is False
    msgs = [r.message for r in report.results if r.id == "approval_123"]
    assert msgs and any("payload too large" in m.lower() for m in msgs)


# ---------------------------------------------------------------------------
# Base64 signature representation strictness (MAINT-F2 / HERMETICUM Phase 1)
# ---------------------------------------------------------------------------
#
# Per docs/spec-evidence.md §4.1.2, the ``signature`` field is validated as
# represented on the wire: standard RFC 4648 alphabet + required ``=``
# padding, no whitespace anywhere, and the decoded payload MUST be exactly
# 64 bytes for Ed25519. Under v0.9.0a2 the runtime rejects each of these
# non-conformant forms fail-closed via ``_b64decode`` pre-checks (URL-safe
# alphabet, padding modulo, embedded whitespace) and the caller-side
# Ed25519 decoded-length check. These tests protect that boundary against
# a regression that would restore lenient decoding.
#
# Corrupted signatures are hand-crafted rather than derived from a real
# Ed25519 signing operation: ``_b64decode`` fails BEFORE any crypto runs,
# so a real signature is not required. The keyring is still set up so
# ``_resolve_public_key`` succeeds and the flow reaches
# ``_verify_ed25519_signature``.


def _keyring_only_setup(monkeypatch, tmp_path: Path) -> None:
    """Register a valid Ed25519 pub key under 'demo_signer_v1'."""
    _, pub_raw = _make_keypair()
    keys_path = tmp_path / "pic_keys.json"
    keys_path.write_text(
        json.dumps({"trusted_keys": {"demo_signer_v1": _b64(pub_raw)}}, indent=2),
        encoding="utf-8",
    )
    monkeypatch.setenv("PIC_KEYS_PATH", str(keys_path))


@pytest.mark.parametrize(
    "corrupted_signature,marker",
    [
        pytest.param(
            "A" * 43 + "-" + "A" * 42 + "==",
            "url-safe",
            id="url_safe_alphabet",
        ),
        pytest.param(
            "A" * 86,
            "padding",
            id="unpadded",
        ),
        pytest.param(
            "A" * 86 + "===",
            "padding",
            id="overpadded",
        ),
        pytest.param(
            "A" * 40 + " " + "A" * 45 + "==",
            "whitespace",
            id="embedded_whitespace",
        ),
        pytest.param(
            base64.b64encode(b"\x00" * 63).decode("ascii"),
            "length",
            id="wrong_decoded_length_63_bytes",
        ),
    ],
)
def test_signature_strictness_rejects_non_conformant_representation(
    monkeypatch, tmp_path: Path, corrupted_signature: str, marker: str
) -> None:
    """Non-conformant signature representations fail-closed.

    Each parameterized case exercises a distinct wire-representation
    boundary from docs/spec-evidence.md §4.1.2 and the caller-side
    Ed25519 decoded-length check. The stable diagnostic marker is
    asserted as a substring, not the full message wording.
    """
    _keyring_only_setup(monkeypatch, tmp_path)
    proposal = _proposal_with_sig(
        payload="amount=500;currency=USD",
        signature_b64=corrupted_signature,
        key_id="demo_signer_v1",
    )

    report = EvidenceSystem().verify_all(proposal, base_dir=tmp_path)
    assert report.ok is False
    assert report.results, "expected at least one evidence result"
    result = report.results[0]
    assert result.id == "approval_123"
    assert result.ok is False
    assert marker in result.message.lower(), (
        f"expected marker {marker!r} in evidence message, got: {result.message!r}"
    )
