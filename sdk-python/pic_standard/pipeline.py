"""
PIC Shared Verification Pipeline — single source of truth.

Every consumer (MCP guard, LangGraph, CLI, HTTP bridge) delegates to
``verify_proposal()`` instead of reimplementing the verification chain.

This module is the ONE function that conformance tests will target.
"""

from __future__ import annotations

import json
import logging
import time
import warnings
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from jsonschema import ValidationError as JSValidationError
from jsonschema import validate as js_validate

from pic_standard.errors import PICError, PICErrorCode, _debug_enabled
from pic_standard.policy import PICPolicy
from pic_standard.verifier import ActionProposal

# v0.3+ evidence (optional — graceful degradation when crypto not installed)
try:
    from pic_standard.evidence import (
        EvidenceSystem,
        apply_trust_upgrade_ids_to_provenance,
    )
except ImportError:  # pragma: no cover
    EvidenceSystem = None  # type: ignore[assignment,misc]
    apply_trust_upgrade_ids_to_provenance = None  # type: ignore[assignment]

log = logging.getLogger("pic_standard.pipeline")


# ------------------------------------------------------------------
# v0.8: Trust deprecation warning
# ------------------------------------------------------------------


class PICTrustFutureWarning(FutureWarning):
    """Emitted when a proposal contains self-asserted trusted provenance and
    effective evidence verification will not run for that proposal.

    In PIC/1.0, non-sanitizing mode (``strict_trust=False``) will be legacy
    and non-conformant.  This warning signals the migration path.
    """

    pass


# ------------------------------------------------------------------
# Shared helpers (moved from mcp_pic_guard.py — single copy)
# ------------------------------------------------------------------


@dataclass
class PICEvaluateLimits:
    """Hard limits to avoid abuse / resource exhaustion."""

    max_proposal_bytes: int = 64_000  # 64KB JSON
    max_provenance_items: int = 64
    max_claims: int = 64
    max_evidence_items: int = 64
    max_eval_ms: int = 500  # post-evaluation budget check (fail-closed), not a preemptive timeout


@lru_cache(maxsize=1)
def _load_packaged_schema() -> Dict[str, Any]:
    schema_text = (
        resources.files("pic_standard")
        .joinpath("schemas/proposal_schema.json")
        .read_text(encoding="utf-8")
    )
    return json.loads(schema_text)


def _proposal_size_bytes(proposal: Dict[str, Any]) -> int:
    return len(json.dumps(proposal, ensure_ascii=False).encode("utf-8"))


def _enforce_limits(proposal: Dict[str, Any], limits: PICEvaluateLimits) -> None:
    size = _proposal_size_bytes(proposal)
    if size > limits.max_proposal_bytes:
        raise PICError(
            code=PICErrorCode.LIMIT_EXCEEDED,
            message="PIC proposal exceeds max size",
            details={"max_bytes": limits.max_proposal_bytes, "actual_bytes": size},
        )

    prov = proposal.get("provenance") or []
    claims = proposal.get("claims") or []
    ev = proposal.get("evidence") or []

    if len(prov) > limits.max_provenance_items:
        raise PICError(
            PICErrorCode.LIMIT_EXCEEDED,
            "Too many provenance items",
            {"max": limits.max_provenance_items, "actual": len(prov)},
        )
    if len(claims) > limits.max_claims:
        raise PICError(
            PICErrorCode.LIMIT_EXCEEDED,
            "Too many claims",
            {"max": limits.max_claims, "actual": len(claims)},
        )
    if len(ev) > limits.max_evidence_items:
        raise PICError(
            PICErrorCode.LIMIT_EXCEEDED,
            "Too many evidence items",
            {"max": limits.max_evidence_items, "actual": len(ev)},
        )


# ------------------------------------------------------------------
# Pipeline input / output types
# ------------------------------------------------------------------


@dataclass
class PipelineOptions:
    """Configuration for a single ``verify_proposal()`` call."""

    tool_name: Optional[str] = None  # tool being invoked (used for binding + impact resolution)
    expected_tool: Optional[str] = None  # tool binding enforcement (usually == tool_name)
    policy: Optional[PICPolicy] = None
    limits: Optional[PICEvaluateLimits] = None  # None = skip limits
    verify_evidence: bool = False
    proposal_base_dir: Optional[Path] = None
    evidence_root_dir: Optional[Path] = None
    time_budget_ms: Optional[int] = None  # None = no budget; falls back to limits.max_eval_ms
    key_resolver: Any = (
        None  # Optional[KeyResolver] — Any to avoid import issues when crypto missing
    )
    strict_trust: bool = False  # v0.8: sanitize inbound trust to "untrusted"


@dataclass
class PipelineResult:
    """Outcome of ``verify_proposal()``.  Never raises — all errors captured here."""

    ok: bool
    action_proposal: Optional[ActionProposal] = None
    error: Optional[PICError] = None
    evidence_report: Any = None  # Optional[EvidenceReport] — typed as Any to avoid import issues
    impact: Optional[str] = (
        None  # resolved impact (from policy + proposal), always normalized to str
    )
    eval_ms: int = 0


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------


def _instantiate_action_proposal(
    proposal: Dict[str, Any],
) -> Tuple[Optional[ActionProposal], Optional[PICError]]:
    """Parse proposal via pydantic + verifier rules. Returns (ap, None) or (None, err)."""
    try:
        return ActionProposal(**proposal), None
    except Exception as e:
        msg = str(e) or "PIC contract violation"
        details = {"verifier_error": msg} if _debug_enabled() else None
        return None, PICError(
            code=PICErrorCode.VERIFIER_FAILED,
            message="PIC contract violation",
            details=details,
        )


def _verify_tool_binding(
    ap: ActionProposal,
    expected_tool: str,
) -> Optional[PICError]:
    """Enforce tool binding. Returns None on success, PICError on mismatch."""
    try:
        ap.verify_with_context(expected_tool=expected_tool)
        return None
    except Exception as e:
        msg = str(e) or "Tool binding mismatch"
        details = {"expected": expected_tool, "error": msg} if _debug_enabled() else None
        return PICError(
            code=PICErrorCode.TOOL_BINDING_MISMATCH,
            message="Tool binding mismatch",
            details=details,
        )


# ------------------------------------------------------------------
# v0.8: Trust resolution helpers
# ------------------------------------------------------------------


def _resolve_impact(
    proposal: Dict[str, Any],
    opts: PipelineOptions,
) -> Optional[str]:
    """Resolve effective impact using policy if available, else proposal impact."""
    tool_for_policy = opts.tool_name or opts.expected_tool
    proposal_impact = proposal.get("impact")

    if opts.policy and tool_for_policy:
        impact: Optional[str] = opts.policy.get_tool_impact(
            tool_for_policy,
            proposal_impact=proposal_impact,
        )
    else:
        impact = proposal_impact

    # Normalize enum-like impacts to strings for comparisons / serialization
    if hasattr(impact, "value"):
        impact = impact.value

    return impact


def _required_evidence_impacts(policy: Optional[PICPolicy]) -> set[str]:
    """Return normalized set of impacts for which policy requires evidence."""
    if not policy:
        return set()
    return {
        i.value if hasattr(i, "value") else str(i)
        for i in (policy.require_evidence_for_impacts or [])
    }


def _has_self_asserted_trusted_provenance(proposal: Dict[str, Any]) -> bool:
    """True if any inbound provenance entry claims trust='trusted'."""
    prov = proposal.get("provenance") or []
    return any(isinstance(p, dict) and p.get("trust") == "trusted" for p in prov)


def _sanitize_provenance_trust(proposal: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of proposal with all provenance trust rewritten to 'untrusted'.

    Does not mutate caller input.
    """
    prov = proposal.get("provenance") or []
    if not any(isinstance(p, dict) and p.get("trust") != "untrusted" for p in prov):
        return proposal

    out = dict(proposal)
    out["provenance"] = [{**p, "trust": "untrusted"} if isinstance(p, dict) else p for p in prov]
    return out


def _should_verify_evidence(
    proposal: Dict[str, Any],
    *,
    impact: Optional[str],
    opts: PipelineOptions,
) -> Tuple[bool, bool]:
    """Return (should_verify, evidence_required_by_policy).

    Evidence verification actually runs only when:
      - ``verify_evidence=True``, AND
      - evidence entries are present OR policy requires evidence for resolved impact
    """
    evidence_entries = proposal.get("evidence") or []
    require_for = _required_evidence_impacts(opts.policy)
    evidence_required_by_policy = bool(impact and impact in require_for)

    should_verify = bool(
        opts.verify_evidence and (evidence_required_by_policy or bool(evidence_entries))
    )
    return should_verify, evidence_required_by_policy


def _should_warn_on_self_asserted_trust(
    proposal: Dict[str, Any],
    *,
    opts: PipelineOptions,
    should_verify_evidence: bool,
) -> bool:
    """Warn when self-asserted trusted provenance is present and effective
    evidence verification will not run for this proposal.
    """
    if opts.strict_trust:
        return False
    if not _has_self_asserted_trusted_provenance(proposal):
        return False
    return not should_verify_evidence


def _make_evidence_system(opts: PipelineOptions) -> Any:
    """Construct EvidenceSystem or raise PICError if unavailable."""
    if EvidenceSystem is None or apply_trust_upgrade_ids_to_provenance is None:
        raise PICError(
            code=PICErrorCode.EVIDENCE_FAILED,
            message="Evidence verification requested but evidence module is unavailable",
        )

    es_kwargs: Dict[str, Any] = {}
    if opts.key_resolver is not None:
        es_kwargs["key_resolver"] = opts.key_resolver
    return EvidenceSystem(**es_kwargs)  # type: ignore[misc]


def _run_evidence_verification(
    proposal: Dict[str, Any],
    *,
    opts: PipelineOptions,
    impact: Optional[str],
    tool_for_policy: Optional[str],
) -> Tuple[Optional[Any], Optional[Dict[str, Any]], Optional[PICError]]:
    """Verify evidence and return (evidence_report, upgraded_proposal, error).

    ``upgraded_proposal`` is the trust-upgraded copy when verification succeeds.
    On error, ``upgraded_proposal`` is ``None``.
    """
    should_verify, evidence_required_by_policy = _should_verify_evidence(
        proposal,
        impact=impact,
        opts=opts,
    )

    if not should_verify:
        return None, proposal, None

    try:
        es = _make_evidence_system(opts)
    except PICError as e:
        return None, None, e

    base_dir = opts.proposal_base_dir or Path(".").resolve()
    root_dir = opts.evidence_root_dir or base_dir

    evidence_report = es.verify_all(  # type: ignore[union-attr]
        proposal,
        base_dir=base_dir,
        evidence_root_dir=root_dir,
    )

    if evidence_required_by_policy and not evidence_report.results:
        return (
            evidence_report,
            None,
            PICError(
                code=PICErrorCode.EVIDENCE_REQUIRED,
                message="Evidence required for this impact but no evidence entries were provided",
                details={"tool": tool_for_policy, "impact": impact},
            ),
        )

    if not evidence_report.ok:
        failed: List[Dict[str, Any]] = [
            {"id": r.id, "message": r.message} for r in evidence_report.results if not r.ok
        ]
        return (
            evidence_report,
            None,
            PICError(
                code=PICErrorCode.EVIDENCE_FAILED,
                message="Evidence verification failed",
                details={"failed": failed},
            ),
        )

    # Trust upgrade — returns new dict, does not mutate caller input
    upgraded = apply_trust_upgrade_ids_to_provenance(  # type: ignore[misc]
        proposal,
        evidence_report.trust_upgrade_ids,
    )
    return evidence_report, upgraded, None


# ------------------------------------------------------------------
# Core pipeline: the ONE function conformance tests target
# ------------------------------------------------------------------


def verify_proposal(
    proposal: Dict[str, Any],
    *,
    options: Optional[PipelineOptions] = None,
) -> PipelineResult:
    """
    Run the full PIC verification pipeline.

    Pipeline steps (in order):
      1.  Limits check (skip if ``options.limits`` is None)
      2.  JSON Schema validation
      3.  Resolve impact (policy + proposal, falls back to expected_tool)
      4.  Determine whether evidence verification will actually run
      5.  Emit migration warning if legacy self-asserted trust would be accepted
      6.  Build working proposal (sanitize trust when ``strict_trust=True``)
      7.  Optional evidence verification + trust upgrade
      8.  Final ``ActionProposal`` instantiation (pydantic + PIC rules)
      9.  Tool binding via ``verify_with_context`` (skip if ``expected_tool`` is None)
     10.  Time budget check

    Returns ``PipelineResult`` — **never raises**.
    """
    opts = options or PipelineOptions()
    t0 = time.perf_counter()

    def _elapsed_ms() -> int:
        return int((time.perf_counter() - t0) * 1000)

    def _fail(err: PICError, *, impact: Optional[str] = None) -> PipelineResult:
        return PipelineResult(ok=False, error=err, impact=impact, eval_ms=_elapsed_ms())

    try:
        # 1. Limits check
        if opts.limits is not None:
            _enforce_limits(proposal, opts.limits)

        # 2. JSON Schema validation
        schema = _load_packaged_schema()
        try:
            js_validate(instance=proposal, schema=schema)
        except JSValidationError as e:
            return _fail(
                PICError(
                    code=PICErrorCode.SCHEMA_INVALID,
                    message=f"PIC schema validation failed: {e.message}",
                )
            )

        # 3. Resolve impact
        impact = _resolve_impact(proposal, opts)
        tool_for_policy = opts.tool_name or opts.expected_tool

        # 4. Determine whether evidence verification will actually run
        should_verify, _ = _should_verify_evidence(
            proposal,
            impact=impact,
            opts=opts,
        )

        # 5. Migration warning for legacy trust behavior (v0.8+)
        if _should_warn_on_self_asserted_trust(
            proposal,
            opts=opts,
            should_verify_evidence=should_verify,
        ):
            warnings.warn(
                "PIC deprecation: proposal contains provenance with trust='trusted' "
                "but effective evidence verification will not run for this proposal. "
                "In PIC/1.0, trust will be verifier-derived only — self-asserted "
                "trust will be sanitized to 'untrusted'. "
                "To migrate: provide verifiable evidence (hash or signature) and "
                "enable verify_evidence=True where evidence will actually be enforced, "
                "or opt in early with strict_trust=True. "
                "See docs/migration-trust-sanitization.md for details.",
                PICTrustFutureWarning,
                stacklevel=2,
            )

        # 6. Build working proposal for this run
        working_proposal = _sanitize_provenance_trust(proposal) if opts.strict_trust else proposal

        # 7. Optional evidence verification + trust upgrade
        evidence_report = None
        final_proposal = working_proposal

        if opts.verify_evidence:
            evidence_report, upgraded, ev_err = _run_evidence_verification(
                working_proposal,
                opts=opts,
                impact=impact,
                tool_for_policy=tool_for_policy,
            )
            if ev_err is not None:
                return _fail(ev_err, impact=impact)
            if upgraded is not None:
                final_proposal = upgraded

        # 8. Final semantic validation from finalized trust state
        ap, err = _instantiate_action_proposal(final_proposal)
        if err is not None:
            return _fail(err, impact=impact)

        # 9. Tool binding
        if opts.expected_tool is not None:
            bind_err = _verify_tool_binding(ap, opts.expected_tool)  # type: ignore[arg-type]
            if bind_err is not None:
                return _fail(bind_err, impact=impact)

        # 10. Time budget check (effective budget: explicit > limits.max_eval_ms)
        eval_ms = _elapsed_ms()
        effective_budget_ms = opts.time_budget_ms
        if effective_budget_ms is None and opts.limits is not None:
            effective_budget_ms = opts.limits.max_eval_ms
        if effective_budget_ms is not None and eval_ms > effective_budget_ms:
            return _fail(
                PICError(
                    code=PICErrorCode.LIMIT_EXCEEDED,
                    message="PIC evaluation exceeded time budget",
                    details={"max_eval_ms": effective_budget_ms, "eval_ms": eval_ms},
                ),
                impact=impact,
            )

        return PipelineResult(
            ok=True,
            action_proposal=ap,
            evidence_report=evidence_report,
            impact=impact,
            eval_ms=eval_ms,
        )

    except PICError as e:
        # Limits check raises PICError — catch and wrap
        return _fail(e, impact=proposal.get("impact"))

    except Exception as e:
        # Unexpected error → fail closed
        log.exception("Unexpected error in PIC pipeline")
        details = (
            {"exception_type": type(e).__name__, "exception": str(e)} if _debug_enabled() else None
        )
        return _fail(
            PICError(
                code=PICErrorCode.INTERNAL_ERROR,
                message="Internal error in PIC verification pipeline",
                details=details,
            ),
            impact=proposal.get("impact"),
        )
