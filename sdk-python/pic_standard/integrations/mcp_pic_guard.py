from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from pic_standard.errors import PICError, PICErrorCode, _debug_enabled
from pic_standard.pipeline import (
    ActionProposal,
    PICEvaluateLimits,
    PipelineOptions,
    verify_proposal,
)
from pic_standard.policy import PICPolicy

log = logging.getLogger("pic_standard.mcp")


def _mcp_error_payload(err: PICError) -> Dict[str, Any]:
    """
    MCP-facing error envelope.
    - Always includes code + message
    - Includes details ONLY when PIC_DEBUG is enabled (prevents leakage)
    """
    payload: Dict[str, Any] = {
        "code": err.code.value if hasattr(err.code, "value") else str(err.code),
        "message": err.message,
    }
    details = getattr(err, "details", None)
    if _debug_enabled() and isinstance(details, dict) and details:
        payload["details"] = details
    return payload


def _is_pic_envelope(obj: Any) -> bool:
    """Detect if obj already looks like PIC MCP envelope."""
    return isinstance(obj, dict) and ("isError" in obj) and ("error" in obj or "result" in obj)


def _wrap_success(result: Any) -> Dict[str, Any]:
    """Return deterministic success envelope."""
    if _is_pic_envelope(result):
        return result  # already wrapped
    return {"isError": False, "result": result}


def _audit_decision(
    *,
    decision: str,
    tool_name: str,
    impact: Optional[str],
    request_id: Optional[str] = None,
    reason_code: Optional[str] = None,
    reason: Optional[str] = None,
    proposal_id: Optional[str] = None,
    verified_evidence_count: Optional[int] = None,
    eval_ms: Optional[int] = None,
) -> None:
    payload: Dict[str, Any] = {
        "event": "pic_mcp_decision",
        "decision": decision,
        "tool": tool_name,
        "impact": impact,
    }
    if request_id:
        payload["request_id"] = request_id
    if proposal_id:
        payload["proposal_id"] = proposal_id
    if verified_evidence_count is not None:
        payload["verified_evidence_count"] = verified_evidence_count
    if eval_ms is not None:
        payload["eval_ms"] = eval_ms
    if reason_code:
        payload["reason_code"] = reason_code
    if reason:
        payload["reason"] = reason

    try:
        log.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        log.info("pic_mcp_decision=%r", payload)


def evaluate_pic_for_tool_call(
    *,
    tool_name: str,
    tool_args: Dict[str, Any],
    policy: PICPolicy,
    limits: Optional[PICEvaluateLimits] = None,
    verify_evidence: bool = False,
    proposal_base_dir: Optional[Path] = None,
    evidence_root_dir: Optional[Path] = None,
    request_id: Optional[str] = None,
    strict_trust: bool = True,
    key_resolver: Any = None,
) -> Tuple[Optional[ActionProposal], Dict[str, Any]]:
    """
    Evaluate PIC for a tool call. Fail-closed via PICError.

    MCP-specific wrapper around ``pipeline.verify_proposal()``:
      - Extracts ``__pic`` from tool_args
      - Checks if PIC is required by policy (when no proposal present)
      - Delegates verification to the shared pipeline
      - Maps PipelineResult back to the (ActionProposal, tool_args) tuple

    Returns:
      (action_proposal_or_none, tool_args)
    """
    limits = limits or PICEvaluateLimits()

    t0 = time.perf_counter()

    proposal = tool_args.get("__pic")
    impact_from_policy = policy.impact_by_tool.get(tool_name)

    # MCP-specific: check if PIC proposal is required but missing
    if proposal is None:
        if impact_from_policy and impact_from_policy in policy.require_pic_for_impacts:
            raise PICError(
                code=PICErrorCode.INVALID_REQUEST,
                message="Missing required PIC proposal for high-impact tool",
                details={"tool": tool_name, "impact": impact_from_policy, "expected_arg": "__pic"},
            )
        eval_ms = int((time.perf_counter() - t0) * 1000)
        _audit_decision(
            decision="allow",
            tool_name=tool_name,
            impact=impact_from_policy,
            request_id=request_id,
            reason="no_pic_required",
            eval_ms=eval_ms,
        )
        return None, tool_args

    # MCP-specific: type check before handing to pipeline
    if not isinstance(proposal, dict):
        raise PICError(
            code=PICErrorCode.INVALID_REQUEST,
            message="PIC proposal must be an object",
        )

    # Delegate to shared pipeline
    result = verify_proposal(
        proposal,
        options=PipelineOptions(
            tool_name=tool_name,
            expected_tool=tool_name,
            policy=policy,
            limits=limits,
            verify_evidence=verify_evidence,
            proposal_base_dir=proposal_base_dir,
            evidence_root_dir=evidence_root_dir,
            strict_trust=strict_trust,
            key_resolver=key_resolver,
        ),
    )

    if not result.ok:
        # Pipeline returned an error — re-raise as PICError for MCP envelope handling
        raise result.error or PICError(
            code=PICErrorCode.INTERNAL_ERROR,
            message="Pipeline verification failed",
        )

    _audit_decision(
        decision="allow",
        tool_name=tool_name,
        impact=result.impact,
        request_id=request_id,
        proposal_id=proposal.get("id"),
        verified_evidence_count=(
            len(result.evidence_report.verified_ids)
            if result.evidence_report and hasattr(result.evidence_report, "verified_ids")
            else None
        ),
        eval_ms=result.eval_ms,
    )
    return result.action_proposal, tool_args


def _extract_request_id(kwargs: Dict[str, Any]) -> Optional[str]:
    """
    Correlation ID sources:
      - __pic_request_id: reserved safe key
      - request_id: common name in tool calls
    """
    rid = kwargs.get("__pic_request_id")
    if isinstance(rid, str) and rid.strip():
        return rid.strip()
    rid2 = kwargs.get("request_id")
    if isinstance(rid2, str) and rid2.strip():
        return rid2.strip()
    return None


def guard_mcp_tool(
    tool_name: str,
    tool_fn: Callable[..., Any],
    *,
    policy: Optional[PICPolicy] = None,
    limits: Optional[PICEvaluateLimits] = None,
    verify_evidence: bool = False,
    proposal_base_dir: Optional[Path] = None,
    evidence_root_dir: Optional[Path] = None,
    strict_trust: bool = True,
    key_resolver: Any = None,
) -> Callable[..., Any]:
    """
    Wrap a *sync* tool function with PIC enforcement.

    Returns:
      - {"isError": True, "error": {...}} on blocks
      - {"isError": False, "result": <tool_return>} on allow
    """
    policy = policy or PICPolicy()
    limits = limits or PICEvaluateLimits()
    proposal_base_dir = proposal_base_dir or Path(".").resolve()

    def wrapped(**kwargs: Any) -> Any:
        request_id = _extract_request_id(kwargs)

        try:
            evaluate_pic_for_tool_call(
                tool_name=tool_name,
                tool_args=kwargs,
                policy=policy,
                limits=limits,
                verify_evidence=verify_evidence,
                proposal_base_dir=proposal_base_dir,
                evidence_root_dir=evidence_root_dir,
                request_id=request_id,
                strict_trust=strict_trust,
                key_resolver=key_resolver,
            )
            # Remove PIC meta before calling business tool
            kwargs.pop("__pic", None)
            kwargs.pop("__pic_request_id", None)

            result = tool_fn(**kwargs)
            return _wrap_success(result)

        except PICError as e:
            _audit_decision(
                decision="block",
                tool_name=tool_name,
                impact=policy.impact_by_tool.get(tool_name),
                request_id=request_id,
                reason_code=e.code.value,
                reason=e.message,
            )
            return {"isError": True, "error": _mcp_error_payload(e)}

        except Exception as e:
            details = (
                {"exception_type": type(e).__name__, "exception": str(e)}
                if _debug_enabled()
                else None
            )
            pe = PICError(
                PICErrorCode.INTERNAL_ERROR, "Internal error while enforcing PIC", details=details
            )
            _audit_decision(
                decision="block",
                tool_name=tool_name,
                impact=policy.impact_by_tool.get(tool_name),
                request_id=request_id,
                reason_code=pe.code.value,
                reason=f"{type(e).__name__}: {e}",
            )
            return {"isError": True, "error": _mcp_error_payload(pe)}

    return wrapped


def guard_mcp_tool_async(
    tool_name: str,
    tool_fn: Callable[..., Awaitable[Any]],
    *,
    policy: Optional[PICPolicy] = None,
    limits: Optional[PICEvaluateLimits] = None,
    verify_evidence: bool = False,
    proposal_base_dir: Optional[Path] = None,
    evidence_root_dir: Optional[Path] = None,
    max_tool_ms: Optional[int] = None,
    strict_trust: bool = True,
    key_resolver: Any = None,
) -> Callable[..., Awaitable[Any]]:
    """
    Wrap an *async* tool function with PIC enforcement + optional tool timeout.

    Tool timeout is ONLY enforceable for async tools.
    For sync tools, use a subprocess/worker execution model if you need killable timeouts.
    """
    policy = policy or PICPolicy()
    limits = limits or PICEvaluateLimits()
    proposal_base_dir = proposal_base_dir or Path(".").resolve()

    async def wrapped(**kwargs: Any) -> Any:
        request_id = _extract_request_id(kwargs)

        try:
            evaluate_pic_for_tool_call(
                tool_name=tool_name,
                tool_args=kwargs,
                policy=policy,
                limits=limits,
                verify_evidence=verify_evidence,
                proposal_base_dir=proposal_base_dir,
                evidence_root_dir=evidence_root_dir,
                request_id=request_id,
                strict_trust=strict_trust,
                key_resolver=key_resolver,
            )
            kwargs.pop("__pic", None)
            kwargs.pop("__pic_request_id", None)

            if max_tool_ms is not None:
                try:
                    result = await asyncio.wait_for(
                        tool_fn(**kwargs), timeout=float(max_tool_ms) / 1000.0
                    )
                except asyncio.TimeoutError as e:
                    details = {"max_tool_ms": int(max_tool_ms)} if _debug_enabled() else None
                    raise PICError(
                        code=PICErrorCode.LIMIT_EXCEEDED,
                        message="Tool execution timed out",
                        details=details,
                    ) from e
            else:
                result = await tool_fn(**kwargs)

            return _wrap_success(result)

        except PICError as e:
            _audit_decision(
                decision="block",
                tool_name=tool_name,
                impact=policy.impact_by_tool.get(tool_name),
                request_id=request_id,
                reason_code=e.code.value,
                reason=e.message,
            )
            return {"isError": True, "error": _mcp_error_payload(e)}

        except Exception as e:
            details = (
                {"exception_type": type(e).__name__, "exception": str(e)}
                if _debug_enabled()
                else None
            )
            pe = PICError(
                PICErrorCode.INTERNAL_ERROR, "Internal error while enforcing PIC", details=details
            )
            _audit_decision(
                decision="block",
                tool_name=tool_name,
                impact=policy.impact_by_tool.get(tool_name),
                request_id=request_id,
                reason_code=pe.code.value,
                reason=f"{type(e).__name__}: {e}",
            )
            return {"isError": True, "error": _mcp_error_payload(pe)}

    return wrapped
