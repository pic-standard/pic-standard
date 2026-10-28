"""Refund-sandbox PIC verifier adapter (issue 193, review-2026-10-23 section 4).

Runs native PIC verification over one refund proposal at the pinned SDK
commit, applies the shared refund profile, and writes the closed
``refund-sandbox-pic-result/0.1`` result.

This adapter never dispatches a tool, consumes an approval, assigns an
operation_id or signs anything. A result file is not a bearer
authorization token: a consumer checks it against its own run context
and the retained input files. make_fixture.py is the only file in this
example that signs, and it signs test fixtures only.

Exit codes:
  0  allow
  1  verification or profile rejection; a complete block result is written
  2  input, environment or operational failure; a block result is written
     when possible

Verification uses the real clock. Native historical verification is not
performed, so an expired proposal blocks.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

SCHEMA = "refund-sandbox-pic-result/0.1"
CONTRACT_REVISION = "review-2026-10-23"
PIC_SDK_COMMIT = "330fdd817ef81d43461ea1787939e0d1cc87d589"
ATTESTATION_VERSION = "PIC-ATT/1.0"

EXPECTED_TOOL = "refund"
EXPECTED_IMPACT = "money"
EXPECTED_CURRENCY = "EUR"
MAX_SAFE_INTEGER = 2**53 - 1
MAX_INPUT_BYTES = 1024 * 1024

RESULT_FIELDS = (
    "schema",
    "contract_revision",
    "run_id",
    "pic_sdk_commit",
    "proposal_file_ref",
    "pic_trust_file_ref",
    "evaluated_at",
    "result",
    "tool",
    "impact",
    "args_digest",
    "claims_digest",
    "intent_digest",
    "error_code",
)

ATTESTATION_FIELDS = frozenset(
    {
        "attestation_version",
        "tool",
        "impact",
        "provenance_ids",
        "args_digest",
        "claims_digest",
        "intent_digest",
        "expires_at",
    }
)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_PAYMENT_ID = re.compile(r"[A-Za-z0-9_-]+")
_RUN_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
_KEY_EXPIRY = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z")


class BlockError(Exception):
    """A block with a stable code. exit_code is 1 for a rejection, 2 for a failure."""

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


def _reject(code: str, message: str) -> BlockError:
    return BlockError(code, message, 1)


def _fail(code: str, message: str) -> BlockError:
    return BlockError(code, message, 2)


# ----------------------------------------------------------------------------
# Strict JSON.
# ----------------------------------------------------------------------------


def _unique_object(pairs: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate member {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-JSON constant {name}")


def _reject_float(text: str) -> Any:
    raise ValueError(f"unsupported number {text}")


def _safe_int(text: str) -> int:
    value = int(text)
    if abs(value) > MAX_SAFE_INTEGER:
        raise ValueError(f"unsafe integer {text}")
    return value


def strict_loads(text: str) -> Any:
    """Parse JSON refusing duplicate members, NaN/Infinity, floats and unsafe integers."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
            parse_int=_safe_int,
        )
    except RecursionError as e:
        raise ValueError("JSON nesting too deep") from e


# ----------------------------------------------------------------------------
# Inputs, environment and keyring.
# ----------------------------------------------------------------------------


def file_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_input(path: Path, what: str) -> bytes:
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as e:
        raise _fail("SANDBOX_INPUT_MALFORMED", f"cannot read {what}: {e}") from e
    if len(data) > MAX_INPUT_BYTES:
        raise _fail("SANDBOX_INPUT_MALFORMED", f"{what} exceeds {MAX_INPUT_BYTES} bytes")
    return data


def _parse_input(data: bytes, what: str) -> Any:
    try:
        return strict_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise _fail("SANDBOX_INPUT_MALFORMED", f"{what} is not strict JSON: {e}") from e


def installed_pic_commit() -> Tuple[Optional[str], str]:
    """Return (commit, "") only for a git install of exactly the pinned commit."""
    from importlib.metadata import PackageNotFoundError, distribution

    try:
        raw = distribution("pic-standard").read_text("direct_url.json")
    except PackageNotFoundError:
        return None, "pic-standard is not installed"
    if raw is None:
        return None, "no direct_url.json: not a VCS install"
    try:
        parsed = strict_loads(raw)
    except ValueError:
        return None, "malformed direct_url.json"
    vcs = parsed.get("vcs_info") if isinstance(parsed, dict) else None
    if not isinstance(vcs, dict) or vcs.get("vcs") != "git":
        return None, "pic-standard was not installed from git"
    commit = vcs.get("commit_id")
    if commit != PIC_SDK_COMMIT:
        return None, f"installed commit {commit!r} is not the pin {PIC_SDK_COMMIT}"
    return commit, ""


def _valid_key_id(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def check_keyring_shape(keyring: Any) -> None:
    """Closed keyring shape; an adapter restriction over TrustedKeyRing.from_dict."""

    def bad(message: str) -> BlockError:
        return _fail("SANDBOX_INPUT_MALFORMED", f"keyring: {message}")

    if not isinstance(keyring, dict) or set(keyring) != {"trusted_keys", "revoked_keys"}:
        raise bad("top level must have exactly trusted_keys and revoked_keys")
    trusted = keyring["trusted_keys"]
    if not isinstance(trusted, dict) or not trusted:
        raise bad("trusted_keys must be a nonempty object")
    for key_id, entry in trusted.items():
        if not _valid_key_id(key_id):
            raise bad(f"invalid key id {key_id!r}")
        if isinstance(entry, str):
            public_key = entry
        elif isinstance(entry, dict) and "public_key" in entry:
            if not set(entry) <= {"public_key", "expires_at"}:
                raise bad(f"unexpected members in {key_id!r}")
            public_key = entry["public_key"]
            expires_at = entry.get("expires_at")
            if "expires_at" in entry and not (
                isinstance(expires_at, str) and _KEY_EXPIRY.fullmatch(expires_at)
            ):
                raise bad(f"invalid expires_at for {key_id!r}")
        else:
            raise bad(f"invalid entry for {key_id!r}")
        if not (isinstance(public_key, str) and _HEX64.fullmatch(public_key)):
            raise bad(f"public key for {key_id!r} must be 64 lowercase hex")
    revoked = keyring["revoked_keys"]
    if not isinstance(revoked, list) or not all(_valid_key_id(k) for k in revoked):
        raise bad("revoked_keys must be a list of key ids")
    if len(set(revoked)) != len(revoked):
        raise bad("revoked_keys has duplicates")


# ----------------------------------------------------------------------------
# Proposal checks.
# ----------------------------------------------------------------------------


def preflight_evidence(proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Structural evidence checks that run before any SDK verification call.

    Exactly one sig entry carrying a strictly parsed PIC-ATT/1.0 object, so
    hash or file evidence never reaches the SDK's file reader.
    """
    evidence = proposal.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 1:
        raise _reject("SANDBOX_EVIDENCE_UNSUPPORTED", "exactly one evidence entry is required")
    entry = evidence[0]
    if not isinstance(entry, dict) or entry.get("type") != "sig":
        raise _reject("SANDBOX_EVIDENCE_UNSUPPORTED", "the evidence entry must be type sig")
    payload = entry.get("payload")
    try:
        attestation = strict_loads(payload) if isinstance(payload, str) else None
    except ValueError as e:
        raise _reject("SANDBOX_ATTESTATION_REQUIRED", f"payload is not strict JSON: {e}") from e
    if not isinstance(attestation, dict) or (
        attestation.get("attestation_version") != ATTESTATION_VERSION
    ):
        raise _reject("SANDBOX_ATTESTATION_REQUIRED", "a canonical PIC-ATT/1.0 payload is required")
    if "expires_at" not in attestation:
        raise _reject("SANDBOX_EXPIRY_REQUIRED", "the attestation must carry expires_at")
    if "intent_digest" not in attestation:
        raise _reject("SANDBOX_INTENT_REQUIRED", "the attestation must carry intent_digest")
    if set(attestation) != ATTESTATION_FIELDS:
        raise _reject("SANDBOX_PROFILE_VIOLATION", "the attestation has unexpected members")
    return attestation


def native_verify(proposal: Dict[str, Any], keyring: Dict[str, Any]) -> None:
    """Native PIC verification at the pinned SDK; imported only after the pin check.

    Every SDK operation sits inside an SDK-specific boundary, so an SDK failure
    is reported as SANDBOX_VERIFIER_ERROR rather than as an adapter error.
    """
    try:
        from pic_standard import pipeline
        from pic_standard.keyring import KeyRingError, StaticKeyRingResolver, TrustedKeyRing
        from pic_standard.policy import PICPolicy
    except Exception as e:
        raise _fail("SANDBOX_VERIFIER_ERROR", f"cannot import the SDK: {e}") from e

    try:
        ring = TrustedKeyRing.from_dict(keyring)
    except KeyRingError as e:
        raise _fail("SANDBOX_INPUT_MALFORMED", f"keyring rejected by the SDK: {e}") from e
    except Exception as e:
        raise _fail("SANDBOX_VERIFIER_ERROR", f"SDK keyring raised {type(e).__name__}: {e}") from e

    try:
        options = pipeline.PipelineOptions(
            verify_evidence=True,
            strict_trust=True,
            policy=PICPolicy(),
            key_resolver=StaticKeyRingResolver(ring),
            tool_name=EXPECTED_TOOL,
            expected_tool=EXPECTED_TOOL,
        )
        result = pipeline.verify_proposal(copy.deepcopy(proposal), options=options)
    except Exception as e:
        raise _fail("SANDBOX_VERIFIER_ERROR", f"SDK raised {type(e).__name__}: {e}") from e
    if result.ok:
        return
    error = result.error
    code = getattr(getattr(error, "code", None), "value", None)
    if not (isinstance(code, str) and code.startswith("PIC_")):
        raise _fail("SANDBOX_VERIFIER_ERROR", "native rejection without a PIC error code")
    message = getattr(error, "message", "")
    if code == "PIC_INTERNAL_ERROR":
        raise _fail(code, message)
    raise _reject(code, message)


def check_profile(proposal: Dict[str, Any], attestation: Dict[str, Any]) -> Dict[str, str]:
    """Shared refund profile after native allow; returns the verified result fields."""

    def violation(message: str) -> BlockError:
        return _reject("SANDBOX_PROFILE_VIOLATION", message)

    action = proposal.get("action")
    if not isinstance(action, dict) or action.get("tool") != EXPECTED_TOOL:
        raise violation(f"action.tool must be {EXPECTED_TOOL!r}")
    if proposal.get("impact") != EXPECTED_IMPACT:
        raise violation(f"impact must be {EXPECTED_IMPACT!r}")

    args = action.get("args")
    if not isinstance(args, dict) or set(args) != {"payment_id", "amount_minor", "currency"}:
        raise violation("action.args must have exactly payment_id, amount_minor, currency")
    payment_id = args["payment_id"]
    if not (isinstance(payment_id, str) and _PAYMENT_ID.fullmatch(payment_id)):
        raise violation("payment_id must match [A-Za-z0-9_-]+")
    amount = args["amount_minor"]
    if type(amount) is not int or not 0 < amount <= MAX_SAFE_INTEGER:
        raise violation("amount_minor must be a positive safe integer")
    if args["currency"] != EXPECTED_CURRENCY:
        raise violation(f"currency must be {EXPECTED_CURRENCY!r}")

    intent = proposal.get("intent")
    if not isinstance(intent, str) or not intent:
        raise violation("intent must be a nonempty string")

    provenance = proposal.get("provenance")
    if not isinstance(provenance, list) or len(provenance) != 1:
        raise violation("exactly one provenance entry is required")
    provenance_id = provenance[0].get("id") if isinstance(provenance[0], dict) else None
    if not isinstance(provenance_id, str) or proposal["evidence"][0].get("id") != provenance_id:
        raise violation("the evidence id must equal the single provenance id")

    claims = proposal.get("claims")
    if not isinstance(claims, list) or len(claims) != 1:
        raise _reject("SANDBOX_CLAIM_INVALID", "exactly one claim is required")
    claim = claims[0]
    if not isinstance(claim, dict) or set(claim) != {"text", "evidence"}:
        raise _reject("SANDBOX_CLAIM_INVALID", "the claim must have exactly text and evidence")
    if claim["evidence"] != [provenance_id]:
        raise _reject("SANDBOX_CLAIM_INVALID", "the claim must cite the provenance entry")
    text = claim["text"]
    try:
        inner = strict_loads(text) if isinstance(text, str) else None
    except ValueError as e:
        raise _reject("SANDBOX_CLAIM_INVALID", f"claim text is not strict JSON: {e}") from e
    if not isinstance(inner, dict) or set(inner) != {"approval_ref", "decision_id"}:
        raise _reject("SANDBOX_CLAIM_INVALID", "claim must have exactly approval_ref, decision_id")
    decision_id = inner["decision_id"]
    if not _valid_key_id(decision_id):
        raise _reject("SANDBOX_CLAIM_INVALID", "decision_id must be a nonempty trimmed string")
    approval_ref = inner["approval_ref"]
    if not (isinstance(approval_ref, str) and _HEX64.fullmatch(approval_ref)):
        raise _reject("SANDBOX_CLAIM_INVALID", "approval_ref must be 64 lowercase hex")

    try:
        from pic_standard.canonical import canonicalize, intent_digest_hex, sha256_hex

        canonical_text = canonicalize(inner).decode("utf-8")
        digests = {
            "args_digest": sha256_hex(args),
            "claims_digest": sha256_hex(claims),
            "intent_digest": intent_digest_hex(intent),
        }
    except Exception as e:
        raise _fail("SANDBOX_VERIFIER_ERROR", f"SDK canonicalization raised {e}") from e
    if canonical_text != text:
        raise _reject("SANDBOX_CLAIM_INVALID", "claim text must be the canonical inner JSON")
    for name, value in digests.items():
        if attestation.get(name) != value:
            raise _fail("SANDBOX_VERIFIER_ERROR", f"verified {name} disagrees with recomputation")
    return {"tool": EXPECTED_TOOL, "impact": EXPECTED_IMPACT, **digests}


# ----------------------------------------------------------------------------
# Result.
# ----------------------------------------------------------------------------


def utc_millis_ceil(now: datetime) -> str:
    """Format a UTC instant at millisecond precision, rounding upward."""
    millis = -(-now.microsecond // 1000)
    instant = now.replace(microsecond=0) + timedelta(milliseconds=millis)
    return instant.strftime("%Y-%m-%dT%H:%M:%S.") + f"{instant.microsecond // 1000:03d}Z"


def evaluate(
    *, proposal_path: Path, keyring_path: Path, run_id: str, contract_revision: str
) -> Tuple[Dict[str, Any], int, str]:
    """Return (result, exit_code, diagnostic). Fields not established stay null."""
    result: Dict[str, Any] = dict.fromkeys(RESULT_FIELDS)
    result["schema"] = SCHEMA
    verified: Optional[Dict[str, str]] = None
    try:
        if not _RUN_ID.fullmatch(run_id):
            raise _fail("SANDBOX_INPUT_MALFORMED", "run_id must match [A-Za-z0-9._:-]{1,128}")
        result["run_id"] = run_id
        if contract_revision != CONTRACT_REVISION:
            raise _fail("SANDBOX_INPUT_MALFORMED", f"unsupported revision {contract_revision!r}")
        result["contract_revision"] = CONTRACT_REVISION

        proposal_bytes = _read_input(proposal_path, "proposal")
        result["proposal_file_ref"] = file_ref(proposal_bytes)
        keyring_bytes = _read_input(keyring_path, "keyring")
        result["pic_trust_file_ref"] = file_ref(keyring_bytes)
        proposal = _parse_input(proposal_bytes, "proposal")
        keyring = _parse_input(keyring_bytes, "keyring")
        if not isinstance(proposal, dict):
            raise _fail("SANDBOX_INPUT_MALFORMED", "proposal must be a JSON object")
        check_keyring_shape(keyring)

        commit, reason = installed_pic_commit()
        if commit is None:
            raise _fail("SANDBOX_ENVIRONMENT_UNVERIFIED", reason)
        result["pic_sdk_commit"] = commit

        attestation = preflight_evidence(proposal)
        native_verify(proposal, keyring)
        verified = check_profile(proposal, attestation)
        exit_code, diagnostic = 0, "allow"
    except BlockError as e:
        result["error_code"] = e.code
        exit_code, diagnostic = e.exit_code, f"{e.code}: {e}"
    except Exception as e:
        result["error_code"] = "SANDBOX_ADAPTER_ERROR"
        exit_code, diagnostic = 2, f"SANDBOX_ADAPTER_ERROR: {type(e).__name__}: {e}"

    result["evaluated_at"] = utc_millis_ceil(datetime.now(timezone.utc))
    if verified is not None:
        result["result"] = "allow"
        result.update(verified)
    else:
        result["result"] = "block"
    return result, exit_code, diagnostic


def serialize(result: Dict[str, Any]) -> bytes:
    """Sorted compact ASCII JSON; equal to JCS for this closed all-ASCII string/null result."""
    return json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def write_atomic(out: Path, data: bytes) -> None:
    """Write to a temporary file in the same directory, then replace into place."""
    fd, tmp = tempfile.mkstemp(prefix=".pic-result-", dir=out.parent)
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
    parser.add_argument("--proposal", required=True, type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--contract-revision", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)

    if os.path.lexists(args.out):
        print(f"pic_result: refusing to overwrite existing {args.out}", file=sys.stderr)
        return 2
    result, exit_code, diagnostic = evaluate(
        proposal_path=args.proposal,
        keyring_path=args.keyring,
        run_id=args.run_id,
        contract_revision=args.contract_revision,
    )
    print(f"pic_result: {result['result']} ({diagnostic})", file=sys.stderr)
    try:
        write_atomic(args.out, serialize(result))
    except OSError as e:
        print(f"pic_result: cannot write {args.out}: {e}", file=sys.stderr)
        return 2
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
