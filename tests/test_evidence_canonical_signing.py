"""Persistent test suite for v0.8.2 PR V8.2-5 canonical-mode signing.

Covers the canonical-mode invariants in
``sdk-python/pic_standard/evidence.py`` per spec-evidence.md §6.2-§6.4:

  - Canonical happy path with AND without optional fields (intent_digest,
    expires_at are SHOULD/OPTIONAL — both branches MUST be covered).
  - Mode discriminator (legacy / canonical / canonical-looking-malformed).
  - Digest binding (args, claims, intent) with constant-time comparison.
  - Field binding (tool, impact, provenance_ids).
  - Freshness (expires_at past, naive, whitespace-padded).
  - Field shape (missing MUST, uppercase hex).
  - Duplicate keys at root AND nested levels (object_pairs_hook recursion).
  - Legacy mode preservation (all 3 §6.2 branches: non-JSON, JSON
    non-object, JSON object without attestation_version).
  - Mixed-mode (one proposal with legacy + canonical sigs).
  - Post-canonical size cap (canonical bytes can grow vs raw payload
    bytes for very large numbers; RFC 8785 §3.2.2.3 decimal expansion).

Each negative test asserts BOTH:
  1. ``report.ok is False``
  2. A specific message substring appears in ``report.results``
     — prevents "failed for the wrong reason" false greens.

Persistent counterpart to the commit-1 scratch smoke gate at
``C:/Users/Fabio/g3-scratch/smoke_canonical_signing_v82_5.py``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import pytest
from pic_standard.canonical import canonicalize
from pic_standard.evidence import EvidenceReport, EvidenceSystem
from pic_standard.keyring import StaticKeyRingResolver, TrustedKeyRing

# ---------------------------------------------------------------------------
# Test-local helpers (NOT public producer API per v0.8.2 plan §4.5.0 Q6;
# producer helpers are deferred to v0.9.0).
# ---------------------------------------------------------------------------


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _make_keypair():
    """Generate an Ed25519 keypair; skip if cryptography is missing."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception:  # pragma: no cover
        pytest.skip("cryptography not installed")
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub_raw


def _make_evidence_system(pub_raw: bytes) -> EvidenceSystem:
    """Build an EvidenceSystem with a hermetic keyring containing test_signer."""
    keyring = TrustedKeyRing.from_dict(
        {"trusted_keys": {"test_signer": _b64(pub_raw)}, "revoked_keys": []}
    )
    return EvidenceSystem(key_resolver=StaticKeyRingResolver(keyring))


def _proposal_template() -> Dict[str, Any]:
    """Return a fresh PIC/1.0 proposal dict (money-impact, single source)."""
    return {
        "protocol": "PIC/1.0",
        "intent": "Pay $500 vendor",
        "impact": "money",
        "provenance": [{"id": "approval_001", "trust": "untrusted"}],
        "claims": [{"text": "Approved", "evidence": ["approval_001"]}],
        "action": {"tool": "payments_send", "args": {"amount": 500, "vendor": "X"}},
    }


def _build_attestation(
    proposal: Dict[str, Any],
    *,
    include_intent_digest: bool = True,
    include_expires_at: bool = True,
    expires_at_value: str = "2999-01-01T00:00:00Z",
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build an attestation object matching the proposal, with optional overrides.

    Default includes every MUST field + intent_digest (SHOULD) + expires_at
    (OPTIONAL). Tests that need to omit optional fields pass
    include_intent_digest=False / include_expires_at=False.
    """
    args_digest = hashlib.sha256(canonicalize(proposal["action"]["args"])).hexdigest()
    claims_digest = hashlib.sha256(canonicalize(proposal["claims"])).hexdigest()
    attest: Dict[str, Any] = {
        "attestation_version": "PIC-ATT/1.0",
        "tool": proposal["action"]["tool"],
        "impact": proposal["impact"],
        "args_digest": args_digest,
        "claims_digest": claims_digest,
        "provenance_ids": [p["id"] for p in proposal["provenance"]],
    }
    if include_intent_digest:
        attest["intent_digest"] = hashlib.sha256(proposal["intent"].encode("utf-8")).hexdigest()
    if include_expires_at:
        attest["expires_at"] = expires_at_value
    if overrides:
        attest.update(overrides)
    return attest


def _canonical_sig_evidence(
    attestation: Dict[str, Any],
    priv,
    *,
    payload_str: Optional[str] = None,
    ev_id: str = "approval_001",
    key_id: str = "test_signer",
) -> Dict[str, Any]:
    """Sign canonicalize(attestation) and embed in a sig evidence entry.

    If payload_str is None, transports as indented json.dumps(attestation)
    — non-canonical JSON, proving canonical re-serialization works.
    """
    canonical_bytes = canonicalize(attestation)
    sig_b64 = _b64(priv.sign(canonical_bytes))
    if payload_str is None:
        payload_str = json.dumps(attestation, indent=2)
    return {
        "id": ev_id,
        "type": "sig",
        "ref": "inline:attestation",
        "payload": payload_str,
        "alg": "ed25519",
        "signature": sig_b64,
        "key_id": key_id,
    }


def _legacy_sig_evidence(
    payload_str: str,
    priv,
    *,
    ev_id: str = "approval_001",
    key_id: str = "test_signer",
) -> Dict[str, Any]:
    """Sign raw UTF-8 bytes of payload_str (legacy mode)."""
    sig_b64 = _b64(priv.sign(payload_str.encode("utf-8")))
    return {
        "id": ev_id,
        "type": "sig",
        "ref": "inline:legacy",
        "payload": payload_str,
        "alg": "ed25519",
        "signature": sig_b64,
        "key_id": key_id,
    }


def _verify(proposal: Dict[str, Any], ev_sys: EvidenceSystem) -> EvidenceReport:
    return ev_sys.verify_all(proposal, base_dir=Path.cwd())


# ---------------------------------------------------------------------------
# Canonical happy path (2 tests — full and minimal attestation)
# ---------------------------------------------------------------------------


def test_canonical_happy_path_full_attestation():
    """Canonical mode with all optional fields (intent_digest + Z-expires_at)."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert report.ok, report.results
    assert any("signature verified" in r.message for r in report.results)


def test_canonical_happy_path_minimal_attestation():
    """Canonical mode with optional fields ABSENT (no intent_digest, no expires_at).

    Per spec-evidence.md §6.4, intent_digest is SHOULD and expires_at is
    OPTIONAL — both MAY be omitted. This test pins the "absent and still
    valid" path so a future refactor cannot accidentally make either
    field required.
    """
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(
        proposal,
        include_intent_digest=False,
        include_expires_at=False,
    )
    # Sanity: attestation has only MUST fields
    assert "intent_digest" not in attestation
    assert "expires_at" not in attestation

    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert report.ok, report.results
    assert any("signature verified" in r.message for r in report.results)


# ---------------------------------------------------------------------------
# Canonical signature negative (1 test)
# ---------------------------------------------------------------------------


def test_canonical_tampered_signature_fails():
    """Canonical payload with tampered signature — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    ev = _canonical_sig_evidence(attestation, priv)
    # Tamper signature: flip the first base64 char (preserves base64
    # length + padding so the decoded signature is still 64 bytes; only
    # the actual byte content differs, exercising the ed25519 verify
    # path rather than the length-check guard).
    sig = ev["signature"]
    ev["signature"] = ("X" if sig[0] != "X" else "Y") + sig[1:]
    proposal["evidence"] = [ev]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("signature invalid" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Raw-byte negative (THE cross-language disaster case)
# ---------------------------------------------------------------------------


def test_canonical_raw_byte_signature_fails():
    """Canonical-looking payload signed over raw bytes (not canonical) must fail.

    This is the most dangerous cross-language mistake. The signature must
    verify against canonicalize(parsed_attestation_object), NOT against
    the raw payload string's UTF-8 bytes. Canonical mode must reject the
    raw-byte signature even though the payload "looks" canonical.
    """
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    payload_string = json.dumps(attestation, indent=2)
    # Sign RAW BYTES, not canonical bytes — the disaster case
    sig_b64 = _b64(priv.sign(payload_string.encode("utf-8")))
    proposal["evidence"] = [
        {
            "id": "approval_001",
            "type": "sig",
            "ref": "inline:attestation",
            "payload": payload_string,
            "alg": "ed25519",
            "signature": sig_b64,
            "key_id": "test_signer",
        }
    ]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("signature invalid" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Mode discriminator negatives (2 tests)
# ---------------------------------------------------------------------------


def test_canonical_non_string_attestation_version_fails():
    """attestation_version: 2 (non-string) — must fail closed; no legacy fallback."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal, overrides={"attestation_version": 2})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("attestation_version must be a string" in r.message for r in report.results), (
        report.results
    )


def test_canonical_unknown_attestation_version_fails():
    """attestation_version: 'PIC-ATT/2.0' (string but not in allowlist) — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal, overrides={"attestation_version": "PIC-ATT/2.0"})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("unsupported attestation_version" in r.message for r in report.results), (
        report.results
    )


# ---------------------------------------------------------------------------
# Digest binding negatives (3 tests)
# ---------------------------------------------------------------------------


def test_canonical_args_digest_mismatch_fails():
    """args_digest tampered to wrong value — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    bad_digest = "0" * 64  # valid shape, wrong value
    attestation = _build_attestation(proposal, overrides={"args_digest": bad_digest})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("args_digest mismatch" in r.message for r in report.results), report.results


def test_canonical_claims_digest_mismatch_fails():
    """claims_digest tampered to wrong value — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    bad_digest = "0" * 64
    attestation = _build_attestation(proposal, overrides={"claims_digest": bad_digest})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("claims_digest mismatch" in r.message for r in report.results), report.results


def test_canonical_intent_digest_mismatch_fails():
    """intent_digest tampered to wrong value — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    bad_digest = "0" * 64
    attestation = _build_attestation(proposal, overrides={"intent_digest": bad_digest})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("intent_digest mismatch" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Field binding negatives (3 tests)
# ---------------------------------------------------------------------------


def test_canonical_tool_mismatch_fails():
    """attestation.tool != proposal.action.tool — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal, overrides={"tool": "different_tool"})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("attestation tool mismatch" in r.message for r in report.results), report.results


def test_canonical_impact_mismatch_fails():
    """attestation.impact != proposal.impact — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal, overrides={"impact": "privacy"})
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("attestation impact mismatch" in r.message for r in report.results), report.results


def test_canonical_provenance_ids_order_mismatch_fails():
    """provenance_ids in wrong order — must fail (array order is part of binding)."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    # Add a second provenance entry so we can reorder
    proposal["provenance"].append({"id": "approval_002", "trust": "untrusted"})
    attestation = _build_attestation(proposal)
    # Reverse the order in the attestation
    attestation["provenance_ids"] = list(reversed(attestation["provenance_ids"]))
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("provenance_ids mismatch" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Freshness negatives (3 tests — expired, naive, whitespace per R18)
# ---------------------------------------------------------------------------


def test_canonical_expired_attestation_fails():
    """expires_at in the past — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    attestation = _build_attestation(proposal, expires_at_value=past)
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("attestation expired" in r.message for r in report.results), report.results


def test_canonical_naive_expires_at_fails():
    """expires_at without timezone designator (naive) — must fail closed."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    # No Z, no +HH:MM — naive timestamp; regex rejects pre-fromisoformat
    attestation = _build_attestation(proposal, expires_at_value="2999-01-01T00:00:00")
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("invalid RFC 3339 timestamp" in r.message for r in report.results), report.results


def test_canonical_whitespace_padded_expires_at_fails():
    """expires_at with leading/trailing whitespace — must fail closed (R18 lock).

    Locks against a future refactor reintroducing .strip() on the
    timestamp string, which would widen accepted RFC 3339 syntax.
    """
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal, expires_at_value=" 2999-01-01T00:00:00Z ")
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("invalid RFC 3339 timestamp" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Field shape negatives (2 tests — missing MUST, uppercase hex)
# ---------------------------------------------------------------------------


def test_canonical_missing_required_field_fails():
    """args_digest MUST field missing — must fail."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    del attestation["args_digest"]  # remove MUST field
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("args_digest must be a string" in r.message for r in report.results), report.results


def test_canonical_uppercase_hex_digest_fails():
    """args_digest with uppercase hex — must fail closed per §6.4 field shape rule."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    # Deterministic uppercase hex — 'A' is a valid hex char, so failure
    # is specifically the lowercase rule, not 'not hex at all'.
    attestation["args_digest"] = "A" * 64
    proposal["evidence"] = [_canonical_sig_evidence(attestation, priv)]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("must be lowercase 64-char hex" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Duplicate key negatives (2 tests — root + nested per R21)
# ---------------------------------------------------------------------------


def test_canonical_duplicate_root_key_fails():
    """Root-level duplicate key in canonical payload — must fail closed."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    canonical_bytes = canonicalize(attestation)
    sig_b64 = _b64(priv.sign(canonical_bytes))
    # Hand-craft payload with duplicate root-level key
    payload = (
        '{"attestation_version":"PIC-ATT/1.0",'
        '"tool":"payments_send",'
        '"tool":"payments_send",'  # DUPLICATE root key
        f'"impact":{json.dumps(attestation["impact"])},'
        f'"args_digest":{json.dumps(attestation["args_digest"])},'
        f'"claims_digest":{json.dumps(attestation["claims_digest"])},'
        f'"intent_digest":{json.dumps(attestation["intent_digest"])},'
        '"provenance_ids":["approval_001"],'
        f'"expires_at":{json.dumps(attestation["expires_at"])}}}'
    )
    proposal["evidence"] = [
        {
            "id": "approval_001",
            "type": "sig",
            "ref": "inline:attestation",
            "payload": payload,
            "alg": "ed25519",
            "signature": sig_b64,
            "key_id": "test_signer",
        }
    ]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("duplicate object keys" in r.message for r in report.results), report.results


def test_canonical_duplicate_nested_key_fails():
    """Nested duplicate key in canonical payload — must fail closed (R21 lock).

    Proves object_pairs_hook detection is recursive — protects against
    TS/Rust/Go implementations that only detect duplicates at root level.
    """
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    attestation = _build_attestation(proposal)
    canonical_bytes = canonicalize(attestation)
    sig_b64 = _b64(priv.sign(canonical_bytes))
    # Hand-craft payload with nested duplicate inside an extensions object
    payload = (
        '{"attestation_version":"PIC-ATT/1.0",'
        '"tool":"payments_send",'
        f'"impact":{json.dumps(attestation["impact"])},'
        f'"args_digest":{json.dumps(attestation["args_digest"])},'
        f'"claims_digest":{json.dumps(attestation["claims_digest"])},'
        f'"intent_digest":{json.dumps(attestation["intent_digest"])},'
        '"provenance_ids":["approval_001"],'
        f'"expires_at":{json.dumps(attestation["expires_at"])},'
        '"extensions":{"a":1,"a":2}}'  # NESTED DUPLICATE
    )
    proposal["evidence"] = [
        {
            "id": "approval_001",
            "type": "sig",
            "ref": "inline:attestation",
            "payload": payload,
            "alg": "ed25519",
            "signature": sig_b64,
            "key_id": "test_signer",
        }
    ]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("duplicate object keys" in r.message for r in report.results), report.results


# ---------------------------------------------------------------------------
# Legacy mode preservation (3 tests — all §6.2 legacy branches)
# ---------------------------------------------------------------------------


def test_legacy_non_json_payload_verifies():
    """Non-JSON payload → legacy raw-byte verification path (§6.2 branch 1)."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    proposal["evidence"] = [_legacy_sig_evidence("amount=500;invoice=123;currency=USD", priv)]

    report = _verify(proposal, ev_sys)
    assert report.ok, report.results
    assert any("signature verified" in r.message for r in report.results)


def test_legacy_json_non_object_payload_verifies():
    """JSON non-object payload (array) → legacy raw-byte verification (§6.2 branch 2)."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    proposal["evidence"] = [_legacy_sig_evidence("[1,2,3]", priv)]

    report = _verify(proposal, ev_sys)
    assert report.ok, report.results
    assert any("signature verified" in r.message for r in report.results)


def test_legacy_json_object_without_attestation_version_verifies():
    """JSON object without attestation_version → legacy raw-byte verification (§6.2 branch 3)."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    proposal["evidence"] = [_legacy_sig_evidence('{"amount":500,"invoice":"INV-001"}', priv)]

    report = _verify(proposal, ev_sys)
    assert report.ok, report.results
    assert any("signature verified" in r.message for r in report.results)


# ---------------------------------------------------------------------------
# Mixed-mode (1 test — legacy + canonical sigs in same proposal)
# ---------------------------------------------------------------------------


def test_mixed_legacy_and_canonical_sigs_both_verify():
    """One proposal carries a legacy sig AND a canonical sig — both verify."""
    priv, pub_raw = _make_keypair()
    ev_sys = _make_evidence_system(pub_raw)
    proposal = _proposal_template()
    # Add a second provenance entry to bind the legacy evidence id
    proposal["provenance"].append({"id": "legacy_approval", "trust": "untrusted"})

    attestation = _build_attestation(proposal)
    canonical_ev = _canonical_sig_evidence(attestation, priv, ev_id="approval_001")
    legacy_ev = _legacy_sig_evidence("legacy_payload_text", priv, ev_id="legacy_approval")
    proposal["evidence"] = [canonical_ev, legacy_ev]

    report = _verify(proposal, ev_sys)
    assert report.ok, report.results
    assert len(report.results) == 2
    assert all(r.ok for r in report.results)
    assert all("signature verified" in r.message for r in report.results)


# ---------------------------------------------------------------------------
# Post-canonical size cap (1 test — R8 / commit-1 guard)
# ---------------------------------------------------------------------------


def test_canonical_post_canonical_size_cap_fails():
    """Canonical bytes exceeding max_payload_bytes must fail closed.

    Pins the post-canonical size guard: raw payload size is not the
    only DoS boundary, because canonicalization can change byte
    length. With a value like ``1e20`` inside the reserved
    ``extensions`` namespace, Python's ``json.dumps`` emits
    ``"1e+20"`` (5 chars) but PIC canonical (RFC 8785 §3.2.2.3)
    emits ``"100000000000000000000"`` (21 chars), so canonical
    bytes > raw bytes. Setting ``max_payload_bytes`` to the raw
    size exercises the post-canonical guard specifically (raw
    passes pre-parse check, canonical fails post-canonicalization).

    Uses the ``extensions`` namespace per spec-evidence.md §3 /
    spec-core.md §3 (extension fields SHOULD use a reserved
    namespace) rather than an arbitrary top-level key.
    """
    priv, pub_raw = _make_keypair()
    keyring = TrustedKeyRing.from_dict(
        {"trusted_keys": {"test_signer": _b64(pub_raw)}, "revoked_keys": []}
    )
    resolver = StaticKeyRingResolver(keyring)

    proposal = _proposal_template()
    # 1e20 forces RFC 8785 decimal expansion (21 chars) while Python's
    # json.dumps uses scientific notation (5 chars). Stays below 1e21
    # boundary where RFC 8785 itself switches to scientific notation.
    attestation = _build_attestation(
        proposal,
        include_intent_digest=False,
        include_expires_at=False,
        overrides={"extensions": {"n": 1e20}},
    )

    payload = json.dumps(attestation, separators=(",", ":"))
    canonical_bytes = canonicalize(attestation)
    raw_size = len(payload.encode("utf-8"))
    canonical_size = len(canonical_bytes)
    # Sanity: canonical must be larger than raw to actually exercise
    # the post-canonical guard rather than the pre-parse guard.
    assert raw_size < canonical_size, (
        f"test precondition failed: raw={raw_size}, canonical={canonical_size}"
    )

    # Set the cap so the raw payload passes the pre-parse check (== raw_size)
    # but the canonical bytes exceed it.
    ev_sys = EvidenceSystem(
        key_resolver=resolver,
        max_payload_bytes=raw_size,
    )

    sig_b64 = _b64(priv.sign(canonical_bytes))
    proposal["evidence"] = [
        {
            "id": "approval_001",
            "type": "sig",
            "ref": "inline:attestation",
            "payload": payload,
            "alg": "ed25519",
            "signature": sig_b64,
            "key_id": "test_signer",
        }
    ]

    report = _verify(proposal, ev_sys)
    assert not report.ok
    assert any("Canonical payload too large" in r.message for r in report.results), report.results
