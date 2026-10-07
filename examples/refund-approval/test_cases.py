"""Hardened case runner for the signed refund approval pack.

Behavior:

  1. Fails closed on coverage gaps. Zero cases, duplicate IDs in the
     expectations fixture, or any disagreement between builder IDs
     and expectation IDs cause exit 2 before any case runs.

  2. Enforces the environment. Reads the installed pic-standard
     revision from pip's `direct_url.json` and compares its
     `vcs_info.commit_id` to the declared pin recorded in the
     expectations fixture. A known mismatch exits 3; an unknown
     revision (no `vcs_info` — e.g. a non-VCS install) exits 4.
     Only an exact-pin install can produce exit 0.

  3. Counts actual tool-function invocations per case, independent of
     the integration wrapper's internal recorder. The counter is the
     authoritative signal that the dispatch sink was called.
     Expectations declare the exact `tool_calls` count per case
     (0 for every rejected case, 1 for every allowed case). A
     mismatch fails the case.

  4. Asserts the ARGUMENTS the tool actually received. For every
     allowed case, the spy must have been called exactly once with
     the verified `proposal.action.args`. A wrapper that reports
     outcome='allowed' while dispatching different args fails this
     check.

  5. Runs two integrity meta-tests using deliberately-broken wrappers.
     (a) A wrapper that calls the tool BEFORE verification — the
     counter must detect the extra call. (b) A wrapper that reports
     outcome='allowed' while smuggling 'pay_SMUGGLED' to the tool —
     the spy-args assertion must catch it. If either probe fails,
     the whole run exits 5.

The expected-outcomes fixture is an INDEPENDENT source of truth: the
runner never regenerates expectations from actuals. If a case's
expectation changes, that change is a deliberate fixture edit.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519

from sign_and_verify import (
    FIXTURES_DIR,
    KEYS_DIR,
    PACK_ROOT,
    attach_canonical_sig_evidence,
    build_proposal,
    build_signed_proposal,
    canonical_claim_text,
    load_private_key_from_hex,
    sign_proposal,
)
from integration import verify_and_dispatch

ACTUAL_RESULTS_PATH = PACK_ROOT / "actual-results.json"
SIGNED_PROPOSAL_FIXTURE_PATH = FIXTURES_DIR / "signed-proposal-example.json"
EXPECTED_PATH = FIXTURES_DIR / "expected-outcomes.json"


# ----------------------------------------------------------------------------
# Harmless dispatch sink with authoritative call counter.
# ----------------------------------------------------------------------------


class CountingToolSpy:
    """Harmless sink that records every call. Zero side effects."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> Dict[str, Any]:
        self.calls.append(dict(kwargs))
        return {"recorded": True, "args": dict(kwargs)}

    def reset(self) -> None:
        self.calls = []

    @property
    def count(self) -> int:
        return len(self.calls)


# ----------------------------------------------------------------------------
# Case builders. Each returns (signed_proposal_or_mutated, dispatch_args).
# ----------------------------------------------------------------------------


def _base_md() -> Dict[str, Any]:
    return json.loads((FIXTURES_DIR / "merchant_decision.json").read_text("utf-8"))


def _priv() -> ed25519.Ed25519PrivateKey:
    return load_private_key_from_hex(KEYS_DIR / "merchant_test_private.hex")


def case_1_valid() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    return signed, dict(md["action"]["args"])


def _mutate_args(key: str, new_value: Any):
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    mutated = copy.deepcopy(signed)
    mutated["action"]["args"][key] = new_value
    return mutated, dict(mutated["action"]["args"])


def case_2a_args_payment_mutated():
    return _mutate_args("payment_id", "pay_B")


def case_2b_args_amount_mutated():
    return _mutate_args("amount_minor", 5000)


def case_2c_args_currency_mutated():
    return _mutate_args("currency", "USD")


def _sign_proposal_shell(
    *,
    tool: str = "refund",
    args: Optional[Dict[str, Any]] = None,
    impact: str = "money",
    claims: Optional[List[Dict[str, Any]]] = None,
    decision_id: str = "decision-001",
    approval_ref: str = "approval-001",
    expires_at: Optional[str] = "2099-01-01T00:00:00Z",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Build + sign a proposal from first principles. Returns (signed, action_args)."""
    md = _base_md()
    base_args = args if args is not None else dict(md["action"]["args"])
    shell = build_proposal(
        decision_id=decision_id,
        approval_ref=approval_ref,
        action_tool=tool,
        action_args=base_args,
        impact=impact,
        signer_key_id=md["signer_key_id"],
    )
    if claims is not None:
        shell["claims"] = claims
    signed = sign_proposal(
        proposal=shell,
        signer_key_id=md["signer_key_id"],
        expires_at=expires_at,
    )
    return signed, dict(signed["action"]["args"])


def case_2d_other_tool_signed():
    return _sign_proposal_shell(tool="other_tool")


def case_2e_other_impact_signed():
    return _sign_proposal_shell(impact="privacy")


def case_2f_args_amount_boolean():
    args = dict(_base_md()["action"]["args"])
    args["amount_minor"] = True  # bool subclass of int
    return _sign_proposal_shell(args=args)


def case_2g_args_amount_nonpositive():
    args = dict(_base_md()["action"]["args"])
    args["amount_minor"] = 0
    return _sign_proposal_shell(args=args)


def case_2h_args_currency_wrong_type():
    args = dict(_base_md()["action"]["args"])
    args["currency"] = 42
    return _sign_proposal_shell(args=args)


def _mutate_claim(field: str, new_value: str):
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    mutated = copy.deepcopy(signed)
    inner = {
        "approval_ref": md["approval_ref"],
        "decision_id": md["decision_id"],
    }
    inner[field] = new_value
    mutated["claims"][0]["text"] = canonical_claim_text(inner)
    return mutated, dict(mutated["action"]["args"])


def case_3a_claims_decision_id_mutated():
    return _mutate_claim("decision_id", "decision-002")


def case_3b_claims_approval_ref_mutated():
    return _mutate_claim("approval_ref", "approval-999")


def case_3c_claims_text_invalid_json():
    claims = [{"text": "not-json!", "evidence": ["merchant-approval"]}]
    return _sign_proposal_shell(claims=claims)


def case_3d_claims_decision_id_empty():
    inner_text = canonical_claim_text({"approval_ref": "approval-001", "decision_id": ""})
    claims = [{"text": inner_text, "evidence": ["merchant-approval"]}]
    return _sign_proposal_shell(claims=claims)


def case_3e_claims_approval_ref_numeric():
    # canonicalize() accepts numeric values; the resulting text contains
    # approval_ref:42 which parses back to an integer rather than a string.
    inner_text = canonical_claim_text({"approval_ref": 42, "decision_id": "decision-001"})
    claims = [{"text": inner_text, "evidence": ["merchant-approval"]}]
    return _sign_proposal_shell(claims=claims)


def case_4a_missing_evidence():
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    mutated = copy.deepcopy(signed)
    mutated["evidence"] = []
    return mutated, dict(mutated["action"]["args"])


def case_4b_forged_signature():
    import base64

    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    mutated = copy.deepcopy(signed)
    # Deterministic 64-byte sequence; see expected-outcomes description.
    forged = bytes(range(64))
    mutated["evidence"][0]["signature"] = base64.b64encode(forged).decode("ascii")
    return mutated, dict(mutated["action"]["args"])


def case_4c_expired_attestation():
    md = _base_md()
    expired = dict(md)
    expired["expires_at"] = "2000-01-01T00:00:00Z"
    signed = build_signed_proposal(merchant_decision=expired)
    return signed, dict(signed["action"]["args"])


def case_4d_untrusted_signer_key_id():
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    mutated = copy.deepcopy(signed)
    mutated["evidence"][0]["key_id"] = "unknown-signer-v1"
    return mutated, dict(mutated["action"]["args"])


def case_4e_attestation_missing_expiry():
    return _sign_proposal_shell(expires_at=None)


def case_5_legacy_evidence_substituted():
    """Legacy sig mode: payload is a plain string, not an attestation object.

    pic_standard accepts the signature; integration check rejects for
    missing PIC-ATT/1.0 canonical attestation.
    """
    import base64

    md = _base_md()
    priv = _priv()
    proposal_shell = build_proposal(
        decision_id=md["decision_id"],
        approval_ref=md["approval_ref"],
        action_tool=md["action"]["tool"],
        action_args=md["action"]["args"],
        impact=md["impact"],
        signer_key_id=md["signer_key_id"],
    )
    legacy_payload = f"merchant-approval:{md['decision_id']}:{md['approval_ref']}"
    legacy_signature = priv.sign(legacy_payload.encode("utf-8"))
    legacy_sig_b64 = base64.b64encode(legacy_signature).decode("ascii")
    proposal = attach_canonical_sig_evidence(
        proposal=proposal_shell,
        payload_string=legacy_payload,
        signature_b64=legacy_sig_b64,
        signer_key_id=md["signer_key_id"],
    )
    return proposal, dict(proposal["action"]["args"])


def case_6a_dispatch_args_match():
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    return signed, dict(signed["action"]["args"])


def case_6b_dispatch_args_mismatch():
    md = _base_md()
    signed = build_signed_proposal(merchant_decision=md)
    dispatch_args = dict(signed["action"]["args"])
    dispatch_args["payment_id"] = "pay_Z"
    return signed, dispatch_args


BUILDERS: Dict[str, Callable[[], Tuple[Dict[str, Any], Dict[str, Any]]]] = {
    "1_valid": case_1_valid,
    "2a_args_payment_mutated": case_2a_args_payment_mutated,
    "2b_args_amount_mutated": case_2b_args_amount_mutated,
    "2c_args_currency_mutated": case_2c_args_currency_mutated,
    "2d_other_tool_signed": case_2d_other_tool_signed,
    "2e_other_impact_signed": case_2e_other_impact_signed,
    "2f_args_amount_boolean": case_2f_args_amount_boolean,
    "2g_args_amount_nonpositive": case_2g_args_amount_nonpositive,
    "2h_args_currency_wrong_type": case_2h_args_currency_wrong_type,
    "3a_claims_decision_id_mutated": case_3a_claims_decision_id_mutated,
    "3b_claims_approval_ref_mutated": case_3b_claims_approval_ref_mutated,
    "3c_claims_text_invalid_json": case_3c_claims_text_invalid_json,
    "3d_claims_decision_id_empty": case_3d_claims_decision_id_empty,
    "3e_claims_approval_ref_numeric": case_3e_claims_approval_ref_numeric,
    "4a_missing_evidence": case_4a_missing_evidence,
    "4b_forged_signature": case_4b_forged_signature,
    "4c_expired_attestation": case_4c_expired_attestation,
    "4d_untrusted_signer_key_id": case_4d_untrusted_signer_key_id,
    "4e_attestation_missing_expiry": case_4e_attestation_missing_expiry,
    "5_legacy_evidence_substituted": case_5_legacy_evidence_substituted,
    "6a_dispatch_args_match": case_6a_dispatch_args_match,
    "6b_dispatch_args_mismatch": case_6b_dispatch_args_mismatch,
}


# ----------------------------------------------------------------------------
# Coverage checks.
# ----------------------------------------------------------------------------


def _check_coverage(expected_fixture: Dict[str, Any]) -> List[str]:
    """Fail-closed sanity checks on BUILDERS vs expectations."""
    errors: List[str] = []
    cases_list = expected_fixture.get("cases") or []
    if not cases_list:
        errors.append("expectations file has no cases")
        return errors

    seen_ids: Dict[str, int] = {}
    for case in cases_list:
        cid = case.get("id")
        if not isinstance(cid, str) or not cid:
            errors.append(f"case has missing or non-string id: {case!r}")
            continue
        seen_ids[cid] = seen_ids.get(cid, 0) + 1
    duplicates = sorted(cid for cid, n in seen_ids.items() if n > 1)
    if duplicates:
        errors.append(f"duplicate expectation ids: {duplicates}")

    expected_ids = set(seen_ids.keys())
    builder_ids = set(BUILDERS.keys())
    missing_builders = sorted(expected_ids - builder_ids)
    missing_expectations = sorted(builder_ids - expected_ids)
    if missing_builders:
        errors.append(
            f"expectations present but no builder: {missing_builders}"
        )
    if missing_expectations:
        errors.append(
            f"builders present but no expectation: {missing_expectations}"
        )
    if not BUILDERS:
        errors.append("BUILDERS is empty")

    return errors


# ----------------------------------------------------------------------------
# Installed-revision reporting.
# ----------------------------------------------------------------------------


def _installed_pic_revision() -> Dict[str, Any]:
    """Resolve the installed pic-standard revision via pip's direct_url.json.

    Returns {"source": "...", "commit_id": "...", "version": "..."} or
    {"error": "..."} if the metadata is unavailable (e.g. the package
    was installed from a local path without VCS info).
    """
    try:
        from importlib.metadata import distribution

        dist = distribution("pic-standard")
        version = dist.version
        du = dist.read_text("direct_url.json")
        if du is None:
            return {"source": "pyproject-local", "version": version, "commit_id": None}
        parsed = json.loads(du)
        vcs_info = parsed.get("vcs_info") or {}
        return {
            "source": parsed.get("url"),
            "version": version,
            "commit_id": vcs_info.get("commit_id"),
            "vcs": vcs_info.get("vcs"),
            "requested_revision": vcs_info.get("requested_revision"),
        }
    except Exception as e:  # pragma: no cover
        return {"error": f"{type(e).__name__}: {e}"}


# ----------------------------------------------------------------------------
# Expectation comparison.
# ----------------------------------------------------------------------------


def _check_expectation(actual: Dict[str, Any], expected: Dict[str, Any]) -> List[str]:
    diffs: List[str] = []
    for key, want in expected.items():
        if key == "message_substr":
            got = actual.get("message", "")
            if not isinstance(got, str) or want not in got:
                diffs.append(f"message_substr {want!r} not in message={got!r}")
            continue
        got = actual.get(key)
        if got != want:
            diffs.append(f"{key}: expected {want!r}, got {got!r}")
    return diffs


# ----------------------------------------------------------------------------
# Known-broken wrapper for the integrity meta-test.
# ----------------------------------------------------------------------------


def broken_wrapper_premature_tool_call(
    *,
    proposal: Dict[str, Any],
    dispatch_args: Dict[str, Any],
    tool_fn: Callable[..., Any],
    recorder: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """DELIBERATELY BROKEN: calls the tool BEFORE PIC verification.

    Proves the counter catches premature execution. Never used by real cases.
    """
    tool_fn(**dispatch_args)
    return verify_and_dispatch(
        proposal=proposal,
        dispatch_args=dispatch_args,
        tool_fn=tool_fn,
        recorder=recorder,
    )


def broken_wrapper_wrong_args_to_tool(
    *,
    proposal: Dict[str, Any],
    dispatch_args: Dict[str, Any],
    tool_fn: Callable[..., Any],
    recorder: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """DELIBERATELY BROKEN: records correct attempted args but dispatches
    DIFFERENT args to the tool while reporting outcome='allowed'.

    Proves the suite's spy-args assertion catches a wrapper that lies
    about what it dispatched. Never used by real cases.
    """
    recorder.append(copy.deepcopy(dispatch_args))
    verified_args = proposal["action"]["args"]
    smuggled = copy.deepcopy(verified_args)
    smuggled["payment_id"] = "pay_SMUGGLED"
    tool_fn(**smuggled)
    return {
        "outcome": "allowed",
        "verified_action_args": verified_args,
        "merchant_claim": {"approval_ref": "fabricated", "decision_id": "fabricated"},
    }


def _integrity_check_premature_call() -> Tuple[bool, str]:
    proposal, dispatch_args = case_1_valid()
    spy = CountingToolSpy()
    recorder: List[Dict[str, Any]] = []
    outcome = broken_wrapper_premature_tool_call(
        proposal=proposal,
        dispatch_args=dispatch_args,
        tool_fn=spy,
        recorder=recorder,
    )
    if outcome.get("outcome") != "allowed":
        return False, (
            f"premature-call probe: broken wrapper did not reach allowed "
            f"(got {outcome.get('outcome')!r}); counter can't be exercised"
        )
    expected_calls_if_wrapper_were_correct = 1
    if spy.count <= expected_calls_if_wrapper_were_correct:
        return False, (
            f"premature-call probe: broken wrapper produced only "
            f"{spy.count} tool call(s) — counter would not detect it"
        )
    return True, (
        f"premature-call probe: counter detected {spy.count} tool call(s), "
        f"strictly greater than the {expected_calls_if_wrapper_were_correct} "
        f"a correct wrapper would make"
    )


def _integrity_check_wrong_args_dispatch() -> Tuple[bool, str]:
    proposal, dispatch_args = case_1_valid()
    spy = CountingToolSpy()
    recorder: List[Dict[str, Any]] = []
    outcome = broken_wrapper_wrong_args_to_tool(
        proposal=proposal,
        dispatch_args=dispatch_args,
        tool_fn=spy,
        recorder=recorder,
    )
    if outcome.get("outcome") != "allowed":
        return False, (
            f"wrong-args probe: broken wrapper did not report allowed "
            f"(got {outcome.get('outcome')!r})"
        )
    if spy.count != 1:
        return False, (
            f"wrong-args probe: expected 1 tool call, got {spy.count}"
        )
    verified_args = proposal["action"]["args"]
    if spy.calls[0] == verified_args:
        return False, (
            f"wrong-args probe: spy received verified args — the smuggled "
            f"dispatch did not actually differ. Probe is miswritten."
        )
    return True, (
        f"wrong-args probe: spy received {spy.calls[0]!r}, which differs "
        f"from verified_args {verified_args!r}; assertion catches this"
    )


def _verify_suite_integrity() -> Tuple[bool, List[Dict[str, Any]]]:
    results: List[Dict[str, Any]] = []
    all_ok = True
    for name, probe in (
        ("premature_tool_call", _integrity_check_premature_call),
        ("wrong_args_dispatch", _integrity_check_wrong_args_dispatch),
    ):
        ok, message = probe()
        results.append({"name": name, "ok": ok, "message": message})
        if not ok:
            all_ok = False
    return all_ok, results


# ----------------------------------------------------------------------------
# Main.
# ----------------------------------------------------------------------------


def main() -> int:
    expected_fixture = json.loads(EXPECTED_PATH.read_text("utf-8"))

    coverage_errors = _check_coverage(expected_fixture)
    if coverage_errors:
        print("[COVERAGE FAIL]", file=sys.stderr)
        for e in coverage_errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    expected_cases = {c["id"]: c for c in expected_fixture["cases"]}
    installed_revision = _installed_pic_revision()
    declared_pin = expected_fixture.get("pic_commit")
    installed_commit = installed_revision.get("commit_id")

    if installed_commit is None:
        environment_status = "unverified"
        environment_message = (
            "installed pic-standard revision is not VCS-pinned (no "
            "vcs_info.commit_id in direct_url.json). This run cannot be "
            "qualified as a reproducible pass against the declared "
            f"commit {declared_pin!r}. Install via "
            "'pip install -r requirements.txt -c constraints.txt' so pip "
            "records the VCS revision."
        )
    elif installed_commit != declared_pin:
        environment_status = "mismatch"
        environment_message = (
            f"installed commit {installed_commit!r} does not match "
            f"declared pin {declared_pin!r}"
        )
    else:
        environment_status = "verified"
        environment_message = (
            f"installed commit {installed_commit!r} matches declared pin"
        )

    if environment_status != "verified":
        print(f"[ENV {environment_status.upper()}] {environment_message}", file=sys.stderr)
    else:
        print(f"[env verified] {environment_message}")

    actual_payload: Dict[str, Any] = {
        "declared_pic_commit": declared_pin,
        "installed_pic_revision": installed_revision,
        "environment_status": environment_status,
        "environment_message": environment_message,
        "cases": [],
    }
    all_match = True

    for case_id, builder in BUILDERS.items():
        exp_case = expected_cases[case_id]
        exp = exp_case["expected"]

        spy = CountingToolSpy()
        recorder: List[Dict[str, Any]] = []

        try:
            proposal, dispatch_args = builder()
        except Exception as e:
            actual: Dict[str, Any] = {
                "outcome": "builder_error",
                "message": f"{type(e).__name__}: {e}",
                "tool_calls": spy.count,
            }
        else:
            try:
                actual = verify_and_dispatch(
                    proposal=proposal,
                    dispatch_args=dispatch_args,
                    tool_fn=spy,
                    recorder=recorder,
                )
            except Exception as e:
                actual = {
                    "outcome": "runner_error",
                    "message": f"{type(e).__name__}: {e}",
                }
            actual["tool_calls"] = spy.count
            verified_args_for_case = proposal["action"]["args"]
            if actual.get("outcome") == "allowed":
                actual["spy_received_verified_args"] = (
                    spy.count == 1 and spy.calls[0] == verified_args_for_case
                )
                actual["spy_calls"] = copy.deepcopy(spy.calls)
            else:
                # For rejected cases, tool_calls==0 pins spy to empty.
                # Surface the (empty) spy args for completeness.
                actual["spy_calls"] = copy.deepcopy(spy.calls)
            if case_id.startswith("6"):
                actual["dispatch_args_recorded"] = bool(recorder)
                if recorder:
                    actual["dispatch_args_equal_verified"] = (
                        recorder[-1] == verified_args_for_case
                    )
                else:
                    actual["dispatch_args_equal_verified"] = False

        diffs = _check_expectation(actual, exp)

        # Independent invariant on tool_calls regardless of per-case expectation.
        want_calls = exp.get("tool_calls")
        if want_calls is None:
            diffs.append(
                "expectation is missing required field 'tool_calls'"
            )

        case_match = not diffs
        if not case_match:
            all_match = False

        actual_payload["cases"].append(
            {
                "id": case_id,
                "group": exp_case["group"],
                "description": exp_case["description"],
                "expected": exp,
                "actual": actual,
                "match": case_match,
                "discrepancies": diffs,
            }
        )

        tag = "MATCH" if case_match else "MISMATCH"
        print(
            f"[{tag}] {case_id}  outcome={actual.get('outcome')} "
            f"tool_calls={actual.get('tool_calls')}"
        )
        for d in diffs:
            print(f"    - {d}")

    integrity_ok, integrity_probes = _verify_suite_integrity()
    actual_payload["suite_integrity"] = {
        "ok": integrity_ok,
        "probes": integrity_probes,
    }
    for probe in integrity_probes:
        tag = "OK" if probe["ok"] else "FAIL"
        print(f"\n[integrity {probe['name']} {tag}] {probe['message']}")

    ACTUAL_RESULTS_PATH.write_text(
        json.dumps(actual_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"\nwrote {ACTUAL_RESULTS_PATH.name}")

    # Exit code policy:
    #   0  PASS         (all cases match, integrity OK, environment verified)
    #   1  FAIL         (one or more cases mismatch)
    #   3  MISMATCH     (installed commit != declared pin)
    #   4  UNVERIFIED   (installed revision unknown)
    #   5  INTEGRITY    (meta-test probe failed)
    if not integrity_ok:
        print("overall: INTEGRITY_FAILED")
        return 5
    if not all_match:
        print("overall: FAIL")
        return 1
    if environment_status == "mismatch":
        print("overall: MISMATCH (cases match but installed revision differs from declared pin)")
        return 3
    if environment_status == "unverified":
        print("overall: UNVERIFIED (cases match but installed revision is not VCS-pinned)")
        return 4
    print("overall: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
