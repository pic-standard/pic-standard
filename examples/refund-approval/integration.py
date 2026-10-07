"""Integration wrapper: PIC verify + refund-approval workflow validation + dispatch.

This wrapper implements the proposed refund-approval dispatch policy.
PIC's signature over the canonical attestation protects content
integrity. The workflow still has to decide whether that content
satisfies its own profile: the right tool, the right impact, a
well-shaped refund action, an expiry window, and a parseable merchant
claim. All of that happens BEFORE the tool is called.

The checks below are proposed patterns for a guard-style integration;
they are NOT guarantees of the shipped pic_standard.integrations.
Making any of them a built-in guard check is a separate v0.9.x
decision.

The dispatch step uses a harmless recording sink. Dispatch arguments
are a COPY of the verified proposal.action.args — never the
caller-supplied dispatch_args. The attempted-dispatch args are
recorded separately so a test can inspect dispatch INTENT even when
the integration check blocks the call.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable, Dict, List, Optional, Tuple

from pic_standard.pipeline import PipelineResult

from sign_and_verify import ATTESTATION_VERSION, pic_verify

EXPECTED_TOOL = "refund"
EXPECTED_IMPACT = "money"

ALLOWED_CURRENCIES = frozenset({"EUR"})


# ----------------------------------------------------------------------------
# Attestation-level helpers.
# ----------------------------------------------------------------------------


def _parse_canonical_sig_evidence(
    proposal: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Return (sig_evidence_entry, parsed_attestation_object) or (None, None)."""
    for ev in proposal.get("evidence", []):
        if ev.get("type") != "sig":
            continue
        payload = ev.get("payload", "")
        try:
            parsed = json.loads(payload)
        except Exception:
            continue
        if (
            isinstance(parsed, dict)
            and parsed.get("attestation_version") == ATTESTATION_VERSION
        ):
            return ev, parsed
    return None, None


# ----------------------------------------------------------------------------
# Workflow-profile validation (fail-closed, pre-dispatch).
# ----------------------------------------------------------------------------


def _validate_action_tool_impact(proposal: Dict[str, Any]) -> Optional[str]:
    tool = proposal.get("action", {}).get("tool")
    if tool != EXPECTED_TOOL:
        return f"action.tool must be {EXPECTED_TOOL!r}, got {tool!r}"
    impact = proposal.get("impact")
    if impact != EXPECTED_IMPACT:
        return f"impact must be {EXPECTED_IMPACT!r}, got {impact!r}"
    return None


def _validate_refund_args(args: Any) -> Optional[str]:
    """Validate refund action.args shape and value ranges."""
    if not isinstance(args, dict):
        return f"action.args must be an object, got {type(args).__name__}"
    required = {"payment_id", "amount_minor", "currency"}
    missing = required - set(args.keys())
    if missing:
        return f"action.args missing required fields: {sorted(missing)}"
    extra = set(args.keys()) - required
    if extra:
        return f"action.args has unexpected fields: {sorted(extra)}"

    payment_id = args["payment_id"]
    if not isinstance(payment_id, str) or not payment_id.strip():
        return f"action.args.payment_id must be a non-empty string, got {payment_id!r}"

    amount_minor = args["amount_minor"]
    # bool is a subclass of int in Python; reject booleans explicitly.
    if isinstance(amount_minor, bool) or not isinstance(amount_minor, int):
        return (
            f"action.args.amount_minor must be an integer (not bool), "
            f"got {type(amount_minor).__name__}: {amount_minor!r}"
        )
    if amount_minor <= 0:
        return (
            f"action.args.amount_minor must be a positive integer, got {amount_minor}"
        )

    currency = args["currency"]
    if not isinstance(currency, str):
        return f"action.args.currency must be a string, got {type(currency).__name__}"
    if currency not in ALLOWED_CURRENCIES:
        return (
            f"action.args.currency {currency!r} not in allowed set "
            f"{sorted(ALLOWED_CURRENCIES)}"
        )

    return None


def _validate_attestation_expiry(
    parsed_attestation: Dict[str, Any],
) -> Optional[str]:
    if "expires_at" not in parsed_attestation:
        return "canonical attestation must carry an expires_at field"
    if not isinstance(parsed_attestation["expires_at"], str) or not parsed_attestation[
        "expires_at"
    ].strip():
        return (
            f"canonical attestation expires_at must be a non-empty string, got "
            f"{parsed_attestation['expires_at']!r}"
        )
    return None


def _parse_and_validate_merchant_claim(
    proposal: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse the first claim's text as JSON and apply the workflow schema."""
    claims = proposal.get("claims") or []
    if not claims:
        return None, "proposal has no claims entry"
    text = claims[0].get("text", "")
    try:
        parsed = json.loads(text)
    except Exception as e:
        return None, f"claims[0].text is not valid JSON: {type(e).__name__}: {e}"
    if not isinstance(parsed, dict):
        return None, (
            f"claims[0].text must decode to an object, got "
            f"{type(parsed).__name__}"
        )
    extra = set(parsed.keys()) - {"decision_id", "approval_ref"}
    if extra:
        return None, (
            f"merchant claim has unexpected fields: {sorted(extra)}"
        )
    for key in ("decision_id", "approval_ref"):
        value = parsed.get(key)
        if not isinstance(value, str) or not value.strip():
            return None, (
                f"merchant claim {key!r} must be a non-empty string, got "
                f"{value!r}"
            )
    return parsed, None


# ----------------------------------------------------------------------------
# Top-level verify + dispatch.
# ----------------------------------------------------------------------------


def verify_and_dispatch(
    *,
    proposal: Dict[str, Any],
    dispatch_args: Dict[str, Any],
    tool_fn: Callable[..., Any],
    recorder: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Verify + apply workflow checks + dispatch (or reject).

    Returns a plain dict describing the outcome:
      * {"outcome": "pic_rejected", "error_code": "...", "message": "..."}
      * {"outcome": "integration_rejected", "reason": "...", "message": "..."}
      * {"outcome": "allowed", "verified_action_args": ..., "merchant_claim": ...}

    The recorder captures the caller's attempted dispatch_args at the
    point the integration pre-checks are complete; this surfaces what
    the caller TRIED to dispatch, which the test suite can inspect
    regardless of whether the integration then rejected the call.
    """
    # 1. PIC verification (schema + binding + signature + trust).
    result: PipelineResult = pic_verify(proposal)
    if not result.ok:
        err = result.error
        base_msg = err.message if err else ""
        detail_parts: List[str] = []
        details = getattr(err, "details", None) if err else None
        if isinstance(details, dict):
            failed = details.get("failed")
            if isinstance(failed, list):
                for item in failed:
                    if isinstance(item, dict) and item.get("message"):
                        detail_parts.append(str(item["message"]))
        full_msg = base_msg
        if detail_parts:
            full_msg = f"{base_msg} | " + "; ".join(detail_parts)
        return {
            "outcome": "pic_rejected",
            "error_code": err.code.value if err else "",
            "message": full_msg,
        }

    # 2. Canonical attestation present.
    sig_entry, parsed_attestation = _parse_canonical_sig_evidence(proposal)
    if sig_entry is None or parsed_attestation is None:
        return {
            "outcome": "integration_rejected",
            "reason": "canonical_attestation_required",
            "message": (
                "No PIC-ATT/1.0 canonical attestation present on verified "
                "proposal; this workflow requires canonical-mode signing."
            ),
        }

    # 3. Tool + impact profile.
    tool_impact_err = _validate_action_tool_impact(proposal)
    if tool_impact_err:
        return {
            "outcome": "integration_rejected",
            "reason": "workflow_profile_violation",
            "message": tool_impact_err,
        }

    # 4. Attestation expiry present (PIC enforces freshness WHEN present;
    # the workflow requires that it IS present).
    expiry_err = _validate_attestation_expiry(parsed_attestation)
    if expiry_err:
        return {
            "outcome": "integration_rejected",
            "reason": "workflow_profile_violation",
            "message": expiry_err,
        }

    # 5. Refund argument schema.
    args_err = _validate_refund_args(proposal.get("action", {}).get("args"))
    if args_err:
        return {
            "outcome": "integration_rejected",
            "reason": "action_args_schema_violation",
            "message": args_err,
        }

    # 6. Merchant claim schema.
    merchant_claim, claim_err = _parse_and_validate_merchant_claim(proposal)
    if claim_err or merchant_claim is None:
        return {
            "outcome": "integration_rejected",
            "reason": "merchant_claim_schema_violation",
            "message": claim_err or "merchant claim parse failure",
        }

    # 7. Record what the caller is about to dispatch (attempted-args record).
    recorder.append(copy.deepcopy(dispatch_args))

    # 8. Dispatch arguments must equal verified action.args.
    verified_args = proposal["action"]["args"]
    if dispatch_args != verified_args:
        return {
            "outcome": "integration_rejected",
            "reason": "dispatch_args_mismatch",
            "message": (
                f"Dispatch args {dispatch_args!r} differ from verified "
                f"proposal action.args {verified_args!r}."
            ),
        }

    # 9. Dispatch a COPY of the verified source of truth (defense-in-depth:
    # the tool is never called with the caller-mutated dict reference).
    tool_fn(**copy.deepcopy(verified_args))

    return {
        "outcome": "allowed",
        "verified_action_args": verified_args,
        "merchant_claim": merchant_claim,
    }
