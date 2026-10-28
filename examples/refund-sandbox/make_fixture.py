"""Test-fixture signer for the refund-sandbox PIC verifier adapter.

THIS FILE SIGNS. It signs PIC refund proposals with the publicly known
test key in keys/ (RFC 8032 section 7.1 test vector 2). Anyone can make
such a signature, so a fixture made here carries no merchant authority.
pic_result.py never signs.

The CLI builds one proposal that satisfies the refund profile, from
explicit inputs, signed only with the test key. The library functions are
also used by run_cases.py to build negative cases; they accept other
throwaway keys and attestation overrides for that purpose only.

approval_ref labelling: --approval-ref-source records where the 64-hex
reference came from, inside the signed intent text. "synthetic" marks a
placeholder. "aps-receipt-id" means the value was copied from an APS
receipt. This tool verifies no APS evidence, so neither label establishes
that any APS evidence was verified.

Run in the pinned environment (requirements.txt plus constraints.txt).
pic_result.py verifies each proposal independently; a successful
verification does not establish which environment produced the signature.

Exit codes: 0 written; 2 invalid input, generation failure or output not
written. Failures do not intentionally publish a new output. An existing
output is refused and left untouched; temporary files are cleaned up on
write failure.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519
from pic_standard.canonical import canonicalize

KEYS_DIR = Path(__file__).resolve().parent / "keys"
KEY_ID = "refund-sandbox-merchant-test-v1"
PROVENANCE_ID = "merchant-approval"
ATTESTATION_VERSION = "PIC-ATT/1.0"
DEFAULT_TTL_SECONDS = 1800
MAX_SAFE_INTEGER = 2**53 - 1
WHOLE_SECOND_UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

REFERENCE_SOURCES = {
    "synthetic": "synthetic placeholder",
    "aps-receipt-id": "copied from an APS receipt_id; APS evidence not verified by this tool",
}

_HEX64 = re.compile(r"[0-9a-f]{64}")
_PAYMENT_ID = re.compile(r"[A-Za-z0-9_-]+")
_WHOLE_SECOND_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


# ----------------------------------------------------------------------------
# Library: proposal, attestation and signature.
# ----------------------------------------------------------------------------


def load_test_private_key() -> ed25519.Ed25519PrivateKey:
    """Load the publicly known test seed from KEYS_DIR/merchant_test_private.hex."""
    seed = bytes.fromhex((KEYS_DIR / "merchant_test_private.hex").read_text("utf-8").strip())
    if len(seed) != 32:
        raise ValueError(f"expected a 32-byte seed, got {len(seed)}")
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def canonical_claim_text(*, decision_id: str, approval_ref: str) -> str:
    """Canonical inner JSON for the single merchant claim."""
    return canonicalize({"approval_ref": approval_ref, "decision_id": decision_id}).decode("utf-8")


def fixture_intent(*, decision_id: str, args: Dict[str, Any], reference_source: str) -> str:
    return (
        f"Test fixture: refund {args['amount_minor']} minor units of {args['currency']} "
        f"on {args['payment_id']} per merchant decision {decision_id}; "
        f"approval_ref source: {REFERENCE_SOURCES[reference_source]}."
    )


def build_proposal(
    *, decision_id: str, approval_ref: str, args: Dict[str, Any], intent: str
) -> Dict[str, Any]:
    """PIC proposal shell without evidence."""
    return {
        "protocol": "PIC/1.0",
        "intent": intent,
        "impact": "money",
        "provenance": [
            {"id": PROVENANCE_ID, "trust": "trusted", "source": f"merchant-signer:{KEY_ID}"}
        ],
        "claims": [
            {
                "text": canonical_claim_text(decision_id=decision_id, approval_ref=approval_ref),
                "evidence": [PROVENANCE_ID],
            }
        ],
        "action": {"tool": "refund", "args": dict(args)},
    }


def build_attestation(proposal: Dict[str, Any], *, expires_at: str) -> Dict[str, Any]:
    """PIC-ATT/1.0 object bound to the proposal, with the profile's expiry and intent."""
    return {
        "attestation_version": ATTESTATION_VERSION,
        "tool": proposal["action"]["tool"],
        "impact": proposal["impact"],
        "provenance_ids": [p["id"] for p in proposal["provenance"]],
        "args_digest": hashlib.sha256(canonicalize(proposal["action"]["args"])).hexdigest(),
        "claims_digest": hashlib.sha256(canonicalize(proposal["claims"])).hexdigest(),
        "intent_digest": hashlib.sha256(proposal["intent"].encode("utf-8")).hexdigest(),
        "expires_at": expires_at,
    }


def sign_attestation(
    attestation: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey
) -> Tuple[str, str]:
    """Ed25519 over the canonical attestation bytes; returns (payload, signature_b64)."""
    payload = canonicalize(attestation)
    signature = base64.b64encode(private_key.sign(payload)).decode("ascii")
    return payload.decode("utf-8"), signature


def attach_sig_evidence(
    proposal: Dict[str, Any], *, payload: str, signature: str, key_id: str = KEY_ID
) -> Dict[str, Any]:
    """Return a copy of the proposal carrying one sig evidence entry."""
    out = dict(proposal)
    out["evidence"] = [
        {
            "id": PROVENANCE_ID,
            "type": "sig",
            "ref": "inline:merchant_approval_canonical_attestation",
            "payload": payload,
            "signer": key_id,
            "alg": "ed25519",
            "signature": signature,
            "key_id": key_id,
        }
    ]
    return out


def sign_proposal(
    proposal: Dict[str, Any],
    *,
    expires_at: str,
    private_key: Optional[ed25519.Ed25519PrivateKey] = None,
    key_id: str = KEY_ID,
    attestation_overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Sign a proposal shell. Other keys and overrides exist for negative cases only."""
    attestation = build_attestation(proposal, expires_at=expires_at)
    if attestation_overrides:
        attestation = {**attestation, **attestation_overrides}
    payload, signature = sign_attestation(attestation, private_key or load_test_private_key())
    return attach_sig_evidence(proposal, payload=payload, signature=signature, key_id=key_id)


def expiry_after(seconds: int, *, now: Optional[datetime] = None) -> str:
    """Whole-second UTC expiry at least `seconds` from now."""
    base = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    return (base + timedelta(seconds=seconds + 1)).strftime(WHOLE_SECOND_UTC_FORMAT)


def parse_whole_second_utc(value: str) -> datetime:
    """Parse YYYY-MM-DDTHH:MM:SSZ as an aware UTC instant, validating the calendar."""
    if not _WHOLE_SECOND_UTC.fullmatch(value):
        raise ValueError("must be YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, WHOLE_SECOND_UTC_FORMAT).replace(tzinfo=timezone.utc)


# ----------------------------------------------------------------------------
# CLI: one valid-profile fixture, test key only.
# ----------------------------------------------------------------------------


def _profile_inputs(args: argparse.Namespace) -> Dict[str, Any]:
    if not (args.decision_id and args.decision_id == args.decision_id.strip()):
        raise ValueError("--decision-id must be a nonempty trimmed string")
    if not _HEX64.fullmatch(args.approval_ref):
        raise ValueError("--approval-ref must be 64 lowercase hex")
    if not _PAYMENT_ID.fullmatch(args.payment_id):
        raise ValueError("--payment-id must match [A-Za-z0-9_-]+")
    if not 0 < args.amount_minor <= MAX_SAFE_INTEGER:
        raise ValueError("--amount-minor must be a positive safe integer")
    if args.currency != "EUR":
        raise ValueError("--currency must be EUR in this profile")
    if args.ttl_seconds is not None and args.ttl_seconds <= 0:
        raise ValueError("--ttl-seconds must be positive")
    return {
        "payment_id": args.payment_id,
        "amount_minor": args.amount_minor,
        "currency": args.currency,
    }


def write_new_file(out: Path, data: bytes) -> None:
    """Atomic write that refuses to replace an existing path."""
    fd, tmp = tempfile.mkstemp(prefix=".fixture-", dir=out.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        if os.path.lexists(out):
            raise FileExistsError(f"{out} appeared during the run")
        os.replace(tmp, out)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--decision-id", required=True)
    parser.add_argument("--approval-ref", required=True)
    parser.add_argument("--approval-ref-source", required=True, choices=sorted(REFERENCE_SOURCES))
    parser.add_argument("--payment-id", required=True)
    parser.add_argument("--amount-minor", required=True, type=int)
    parser.add_argument("--currency", required=True)
    expiry = parser.add_mutually_exclusive_group()
    expiry.add_argument("--expires-at", help="explicit whole-second UTC expiry")
    expiry.add_argument("--ttl-seconds", type=int, help=f"default {DEFAULT_TTL_SECONDS}")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    if os.path.lexists(args.out):
        print(f"make_fixture: refusing to overwrite existing {args.out}", file=sys.stderr)
        return 2
    try:
        refund_args = _profile_inputs(args)
        explicit_expiry = (
            parse_whole_second_utc(args.expires_at) if args.expires_at is not None else None
        )
    except ValueError as e:
        print(f"make_fixture: invalid input: {e}", file=sys.stderr)
        return 2

    try:
        if explicit_expiry is not None:
            expires_at = args.expires_at
            if explicit_expiry <= datetime.now(timezone.utc):
                print(
                    f"make_fixture: warning: {expires_at} has passed; pic_result.py will block it",
                    file=sys.stderr,
                )
        else:
            expires_at = expiry_after(args.ttl_seconds or DEFAULT_TTL_SECONDS)
        intent = fixture_intent(
            decision_id=args.decision_id,
            args=refund_args,
            reference_source=args.approval_ref_source,
        )
        proposal = build_proposal(
            decision_id=args.decision_id,
            approval_ref=args.approval_ref,
            args=refund_args,
            intent=intent,
        )
        signed = sign_proposal(proposal, expires_at=expires_at)
        data = (json.dumps(signed, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    except Exception as e:
        print(f"make_fixture: cannot generate fixture: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    try:
        write_new_file(args.out, data)
    except OSError as e:
        print(f"make_fixture: cannot write {args.out}: {e}", file=sys.stderr)
        return 2
    print(
        f"make_fixture: wrote {args.out} (test key {KEY_ID}, expires_at {expires_at}, "
        f"approval_ref source {args.approval_ref_source})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
