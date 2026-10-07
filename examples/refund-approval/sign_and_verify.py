"""Build, sign and verify a PIC Action Proposal with canonical attestation.

Fixture-local example of a signed refund approval and the proposed
mapping between the merchant decision and PIC canonical attestation.
No PIC core changes; uses the shipped pic_standard SDK as a library.

Pinned to pic_standard main at 330fdd817ef81d43461ea1787939e0d1cc87d589.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from pic_standard.canonical import canonicalize
from pic_standard.keyring import StaticKeyRingResolver, TrustedKeyRing
from pic_standard.pipeline import PipelineOptions, verify_proposal
from pic_standard.policy import PICPolicy

ATTESTATION_VERSION = "PIC-ATT/1.0"

PACK_ROOT = Path(__file__).resolve().parent
KEYS_DIR = PACK_ROOT / "keys"
FIXTURES_DIR = PACK_ROOT / "fixtures"


# ----------------------------------------------------------------------------
# Deterministic claim-text encoding.
# ----------------------------------------------------------------------------
# PIC's claims_digest is sha256 over the canonicalized claims ARRAY. It
# protects the exact `text` string in each claim entry, but it does not
# canonicalize JSON embedded inside that string. If we want the inner
# JSON to be byte-stable across reproductions, we must canonicalize it
# ourselves. canonicalize() returns PIC-CJSON/1.0 bytes; decoding as
# UTF-8 gives the deterministic text content for the `text` field.
# ----------------------------------------------------------------------------


def canonical_claim_text(payload: Dict[str, Any]) -> str:
    """Return deterministic UTF-8 text for a claim-text payload."""
    return canonicalize(payload).decode("utf-8")


def build_merchant_approval_claim(
    *, decision_id: str, approval_ref: str
) -> Dict[str, Any]:
    """Build the single claim object carrying the merchant decision + approval refs.

    PIC does NOT interpret decision_id or approval_ref. It binds the exact
    bytes of this claim via claims_digest. Our integration layer parses the
    text back out to apply the business-level checks.
    """
    inner = {"approval_ref": approval_ref, "decision_id": decision_id}
    return {
        "text": canonical_claim_text(inner),
        "evidence": ["merchant-approval"],
    }


# ----------------------------------------------------------------------------
# Proposal construction.
# ----------------------------------------------------------------------------


def build_proposal(
    *,
    decision_id: str,
    approval_ref: str,
    action_tool: str,
    action_args: Dict[str, Any],
    impact: str,
    signer_key_id: str,
) -> Dict[str, Any]:
    """Build a PIC Action Proposal shell (no evidence attached yet).

    Fields that carry the refund-approval workflow identity:
      * action.tool, action.args — the exact refund operation
      * impact                   — "money"
      * claims[0].text           — carries decision_id + approval_ref
      * provenance[0]            — the merchant provenance to be trust-upgraded
                                   by signature evidence
    """
    return {
        "protocol": "PIC/1.0",
        "intent": f"Refund {action_args.get('amount_minor')} minor units "
        f"of {action_args.get('currency')} on {action_args.get('payment_id')} "
        f"per merchant decision {decision_id}.",
        "impact": impact,
        "provenance": [
            {
                "id": "merchant-approval",
                "trust": "trusted",
                "source": f"merchant-signer:{signer_key_id}",
            }
        ],
        "claims": [build_merchant_approval_claim(
            decision_id=decision_id, approval_ref=approval_ref
        )],
        "action": {"tool": action_tool, "args": action_args},
    }


# ----------------------------------------------------------------------------
# Canonical attestation object.
# ----------------------------------------------------------------------------


def _args_digest(args: Dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize(args)).hexdigest()


def _claims_digest(claims: list) -> str:
    return hashlib.sha256(canonicalize(claims)).hexdigest()


def _intent_digest(intent: str) -> str:
    return hashlib.sha256(intent.encode("utf-8")).hexdigest()


def build_canonical_attestation(
    *,
    proposal: Dict[str, Any],
    expires_at: Optional[str],
) -> Dict[str, Any]:
    """Build a PIC-ATT/1.0 attestation object bound to the proposal.

    Binding fields (per docs/spec-evidence.md §6.4):
      * tool, impact, provenance_ids — exact-equality to proposal
      * args_digest   — sha256(canonicalize(action.args))
      * claims_digest — sha256(canonicalize(claims))
      * intent_digest — sha256(UTF-8(intent))
      * expires_at    — freshness (OMITTED when None; PIC enforces
                        expires_at freshness only when present, so
                        omitting is a legitimate PIC-verifier input
                        used by the test cases that probe the
                        workflow-level requirement for expiry)
    """
    out: Dict[str, Any] = {
        "attestation_version": ATTESTATION_VERSION,
        "tool": proposal["action"]["tool"],
        "impact": proposal["impact"],
        "provenance_ids": [p["id"] for p in proposal["provenance"]],
        "args_digest": _args_digest(proposal["action"]["args"]),
        "claims_digest": _claims_digest(proposal["claims"]),
        "intent_digest": _intent_digest(proposal["intent"]),
    }
    if expires_at is not None:
        out["expires_at"] = expires_at
    return out


# ----------------------------------------------------------------------------
# Signing.
# ----------------------------------------------------------------------------


def load_private_key_from_hex(hex_path: Path) -> ed25519.Ed25519PrivateKey:
    seed = bytes.fromhex(hex_path.read_text(encoding="utf-8").strip())
    if len(seed) != 32:
        raise ValueError(f"Expected 32-byte seed, got {len(seed)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def sign_canonical_attestation(
    *,
    attestation: Dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
) -> tuple[str, str]:
    """Sign the attestation object with Ed25519 over its canonical bytes.

    Returns (payload_string, signature_base64). The payload is the JSON
    representation of the attestation; verify-side re-canonicalizes it
    and signs/verifies over those bytes per PIC §8.4.
    """
    canonical_bytes = canonicalize(attestation)
    signature = private_key.sign(canonical_bytes)
    # The payload we store is a readable JSON form; verifier re-parses +
    # re-canonicalizes it, so byte-stability of this string is not
    # required. canonical_bytes is what the signature actually covers.
    payload_string = canonical_bytes.decode("utf-8")
    signature_b64 = base64.b64encode(signature).decode("ascii")
    return payload_string, signature_b64


def attach_canonical_sig_evidence(
    *,
    proposal: Dict[str, Any],
    payload_string: str,
    signature_b64: str,
    signer_key_id: str,
    evidence_id: str = "merchant-approval",
) -> Dict[str, Any]:
    """Attach a signature-evidence entry carrying the canonical attestation.

    The evidence `id` matches the provenance `id` so the trust-upgrade
    flows to the merchant provenance entry.
    """
    out = {**proposal}
    out["evidence"] = [
        {
            "id": evidence_id,
            "type": "sig",
            "ref": "inline:merchant_approval_canonical_attestation",
            "payload": payload_string,
            "signer": signer_key_id,
            "alg": "ed25519",
            "signature": signature_b64,
            "key_id": signer_key_id,
        }
    ]
    return out


# ----------------------------------------------------------------------------
# High-level helpers.
# ----------------------------------------------------------------------------


def sign_proposal(
    *,
    proposal: Dict[str, Any],
    signer_key_id: str,
    expires_at: Optional[str],
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
) -> Dict[str, Any]:
    """Sign ANY proposal shell with a canonical attestation. Low-level primitive.

    Caller controls proposal.action.tool, action.args, impact, claims,
    provenance. This is used by test cases that need to probe PIC
    verification over non-happy-path proposals (e.g. a signed
    attestation for the wrong tool or for impact='privacy').
    """
    if private_key is None:
        private_key = load_private_key_from_hex(KEYS_DIR / "merchant_test_private.hex")
    attestation = build_canonical_attestation(proposal=proposal, expires_at=expires_at)
    payload_string, signature_b64 = sign_canonical_attestation(
        attestation=attestation, private_key=private_key
    )
    return attach_canonical_sig_evidence(
        proposal=proposal,
        payload_string=payload_string,
        signature_b64=signature_b64,
        signer_key_id=signer_key_id,
    )


def build_signed_proposal(
    *,
    merchant_decision: Dict[str, Any],
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    attestation_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """End-to-end helper: happy-path proposal + attestation + signature.

    `attestation_overrides` can replace fields in the attestation BEFORE
    signing (used by test cases that want valid signatures over tampered
    attestations). Mutations to the proposal itself happen at the call
    site after this helper returns.
    """
    if private_key is None:
        private_key = load_private_key_from_hex(KEYS_DIR / "merchant_test_private.hex")

    proposal = build_proposal(
        decision_id=merchant_decision["decision_id"],
        approval_ref=merchant_decision["approval_ref"],
        action_tool=merchant_decision["action"]["tool"],
        action_args=merchant_decision["action"]["args"],
        impact=merchant_decision["impact"],
        signer_key_id=merchant_decision["signer_key_id"],
    )
    attestation = build_canonical_attestation(
        proposal=proposal, expires_at=merchant_decision["expires_at"]
    )
    if attestation_overrides:
        attestation = {**attestation, **attestation_overrides}

    payload_string, signature_b64 = sign_canonical_attestation(
        attestation=attestation, private_key=private_key
    )
    return attach_canonical_sig_evidence(
        proposal=proposal,
        payload_string=payload_string,
        signature_b64=signature_b64,
        signer_key_id=merchant_decision["signer_key_id"],
    )


def make_pipeline_options(
    *, keyring_path: Optional[Path] = None
) -> PipelineOptions:
    """Build PipelineOptions with evidence verification + fixture-local keyring.

    An explicit PICPolicy() is required: without one, `_required_evidence_impacts`
    returns an empty set and policy does not require evidence even for
    impact="money". The default PICPolicy requires evidence for money/privacy/
    irreversible, which is what this workflow depends on.
    """
    if keyring_path is None:
        keyring_path = KEYS_DIR / "pic_keys.example.json"
    keyring = TrustedKeyRing.from_json_file(keyring_path)
    resolver = StaticKeyRingResolver(keyring)
    return PipelineOptions(
        verify_evidence=True,
        strict_trust=True,
        policy=PICPolicy(),
        key_resolver=resolver,
        proposal_base_dir=PACK_ROOT,
    )


def pic_verify(proposal: Dict[str, Any]):
    """Call pic_standard.pipeline.verify_proposal with fixture-local keyring."""
    return verify_proposal(proposal, options=make_pipeline_options())


if __name__ == "__main__":
    # Smoke: build + sign + verify the canonical refund.
    md = json.loads((FIXTURES_DIR / "merchant_decision.json").read_text("utf-8"))
    signed = build_signed_proposal(merchant_decision=md)
    print(json.dumps(signed, indent=2, sort_keys=True))
    result = pic_verify(signed)
    print(f"\nverify_proposal: ok={result.ok} "
          f"error={result.error.code.value if result.error else None}")
