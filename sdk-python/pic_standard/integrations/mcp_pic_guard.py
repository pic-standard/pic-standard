from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from pic_standard.canonical import CanonicalizationError, intent_digest_hex, sha256_hex
from pic_standard.errors import PICError, PICErrorCode, _debug_enabled
from pic_standard.integrations.mcp_hooks import (
    MCPAllowDecision,
    MCPPreExecuteHook,
    MCPToolCall,
    _MCPPreExecuteHookError,
)
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


def _emit_allow_audit(decision: MCPAllowDecision) -> None:
    """Log an allow decision, byte-identical to the pre-hook audit line."""
    try:
        log.info(decision.to_audit_bytes().decode("utf-8"))
    except Exception:
        log.info("pic_mcp_decision=%r", decision.to_audit_payload())


def _audit_hook_error(*, decision: MCPAllowDecision, detail: Optional[str] = None) -> None:
    """Audit a pre-execution hook failure as a distinct integration event.

    Correlated to the preceding allow via the decision's own tool / impact /
    request_id. Never a PIC ``block`` -- PIC's decision stays ``allow``. This is
    the single place that decides whether ``detail`` (the raw exception type) may
    be emitted: only under ``PIC_DEBUG``, and never argument values.
    """
    payload: Dict[str, Any] = {
        "event": "pic_mcp_hook_error",
        "tool": decision.tool,
        "impact": decision.impact,
    }
    if decision.request_id:
        payload["request_id"] = decision.request_id
    payload["reason_code"] = PICErrorCode.INTERNAL_ERROR.value
    if _debug_enabled() and detail:
        payload["detail"] = detail
    try:
        log.info(json.dumps(payload, ensure_ascii=False))
    except Exception:
        log.info("pic_mcp_hook_error=%r", payload)


def _hook_failure_response(
    decision: MCPAllowDecision, error: _MCPPreExecuteHookError
) -> Dict[str, Any]:
    """Shared fail-closed response for a pre-execution hook failure.

    Emits the decision-correlated ``pic_mcp_hook_error`` audit and returns the
    ``PIC_INTERNAL_ERROR`` envelope. Never a PIC ``block``. Shared by both guards
    so their hook-failure semantics cannot drift. ``_audit_hook_error`` applies
    the ``PIC_DEBUG`` gate to ``detail``.
    """
    _audit_hook_error(decision=decision, detail=str(error))
    pe = PICError(code=PICErrorCode.INTERNAL_ERROR, message="PIC pre-execution hook failed")
    return {"isError": True, "error": _mcp_error_payload(pe)}


def _run_pre_execute_hook(
    on_allow: MCPPreExecuteHook,
    base_decision: MCPAllowDecision,
    action_proposal: Optional[ActionProposal],
    sanitized_args: Dict[str, Any],
) -> None:
    """Build the hook context and fire the hook inside one fail-closed boundary.

    Runs only when a hook is configured. Any failure -- a broken
    decision/proposal invariant, canonicalizing the live call, computing the
    proposal digests, the callback raising, or the callback returning anything
    other than ``None`` (e.g. an ``async def`` coroutine) -- raises
    ``_MCPPreExecuteHookError`` so the guard reports a distinct integration
    failure (never a PIC ``block``) and does not dispatch the tool.
    """
    try:
        if base_decision.proposal_present:
            if action_proposal is None:
                raise RuntimeError("proposal-backed allow is missing ActionProposal")
            decision = replace(
                base_decision,
                intent_digest=intent_digest_hex(action_proposal.intent),
                args_digest=sha256_hex(action_proposal.action["args"]),
            )
        else:
            if action_proposal is not None:
                raise RuntimeError("no-proposal allow unexpectedly has ActionProposal")
            decision = base_decision

        tool_call = MCPToolCall.build(base_decision.tool, sanitized_args)

        hook_result = on_allow(decision, tool_call)
        if hook_result is not None:
            if inspect.iscoroutine(hook_result):
                hook_result.close()
            raise TypeError("MCPPreExecuteHook must be synchronous and return None")
    except Exception as e:
        raise _MCPPreExecuteHookError(type(e).__name__) from e


_RESERVED_PIC_KEYS = ("__pic", "__pic_request_id")


def _sanitized_tool_args(tool_args: Dict[str, Any]) -> Dict[str, Any]:
    """Live tool arguments with only the reserved PIC keys removed.

    A plain ``request_id`` is intentionally retained: it is an ordinary business
    argument and participates in binding.
    """
    return {k: v for k, v in tool_args.items() if k not in _RESERVED_PIC_KEYS}


def _enforce_arg_binding(action_proposal: ActionProposal, sanitized_args: Dict[str, Any]) -> None:
    """Fail closed unless the sanitized live call matches verified ``action.args``.

    Exact RFC 8785/JCS canonical digest equality via ``sha256_hex``, completing
    tool binding (tool name and arguments) at the MCP evaluator / HTTP bridge
    boundary. A mismatch, or live arguments that cannot be canonicalized, raise
    ``PIC_ARG_BINDING_MISMATCH``. A verified proposal whose ``action.args`` is
    missing or itself non-canonicalizable is an internal invariant failure
    (``PIC_INTERNAL_ERROR``), not a caller binding mismatch. No raised error
    carries argument values or digests.

    ``sanitized_args`` is the same top-level snapshot the evaluator returns for
    hook-context construction and dispatch. Guard code does not reconstruct or
    independently re-sanitize the call after binding.
    """
    try:
        declared_args = action_proposal.action["args"]
    except (KeyError, TypeError) as e:
        raise PICError(
            code=PICErrorCode.INTERNAL_ERROR,
            message="Verified action proposal is missing canonical arguments",
        ) from e
    try:
        declared_digest = sha256_hex(declared_args)
    except CanonicalizationError as e:
        raise PICError(
            code=PICErrorCode.INTERNAL_ERROR,
            message="Verified action arguments could not be canonicalized",
        ) from e
    try:
        live_digest = sha256_hex(sanitized_args)
    except CanonicalizationError as e:
        raise PICError(
            code=PICErrorCode.ARG_BINDING_MISMATCH,
            message="Live tool arguments could not be canonicalized for binding",
        ) from e
    if live_digest != declared_digest:
        raise PICError(
            code=PICErrorCode.ARG_BINDING_MISMATCH,
            message="Tool argument binding mismatch",
        )


def _evaluate_pic_for_tool_call_with_decision(
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
) -> Tuple[Optional[ActionProposal], Dict[str, Any], MCPAllowDecision, Dict[str, Any]]:
    """Evaluate PIC for a tool call and return the structured allow decision.

    Same contract as ``evaluate_pic_for_tool_call`` (fail-closed via
    ``PICError``) plus the ``MCPAllowDecision`` it audited and the sanitized live
    arguments (the live ``tool_args`` with only ``__pic`` and ``__pic_request_id``
    removed). The same sanitized snapshot used for argument binding is
    subsequently used to construct the hook context and expand the business
    tool's keyword arguments. For a proposal-backed allow it must match the
    verified ``action.args``; the ``no_pic_required`` path returns the snapshot
    without canonicalizing or binding it, preserving non-JSON business arguments
    when no proposal is present. The allow audit is emitted here via
    ``MCPAllowDecision.to_audit_bytes()``, byte-identical to the pre-hook line.
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
        decision = MCPAllowDecision(
            tool=tool_name,
            impact=impact_from_policy,
            request_id=request_id,
            proposal_present=False,
            eval_ms=eval_ms,
            reason="no_pic_required",
        )
        _emit_allow_audit(decision)
        return None, tool_args, decision, _sanitized_tool_args(tool_args)

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

    action_proposal = result.action_proposal
    if action_proposal is None:
        # Successful verification must yield an ActionProposal. Treat its
        # absence as an internal invariant failure, not a caller binding
        # mismatch.
        raise PICError(
            code=PICErrorCode.INTERNAL_ERROR,
            message="Verification succeeded without an action proposal",
        )

    # Argument binding: the sanitized live call must equal the verified
    # proposal's action.args, enforced before the allow decision is built or
    # audited (so a mismatch is a single block, no preceding allow, no hook,
    # no dispatch). The same snapshot is returned for dispatch and the hook.
    sanitized_args = _sanitized_tool_args(tool_args)
    _enforce_arg_binding(action_proposal, sanitized_args)

    verified_evidence_count = (
        len(result.evidence_report.verified_ids)
        if result.evidence_report and hasattr(result.evidence_report, "verified_ids")
        else None
    )
    decision = MCPAllowDecision(
        tool=tool_name,
        impact=result.impact,
        request_id=request_id,
        proposal_present=True,
        proposal_id=proposal.get("id"),
        verified_evidence_count=verified_evidence_count,
        eval_ms=result.eval_ms,
    )
    _emit_allow_audit(decision)
    return action_proposal, tool_args, decision, sanitized_args


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

    The structured allow decision used by the pre-execution hook is available
    via the internal ``_evaluate_pic_for_tool_call_with_decision`` helper; this
    public function's two-item return is unchanged.
    """
    action_proposal, tool_args, _, _ = _evaluate_pic_for_tool_call_with_decision(
        tool_name=tool_name,
        tool_args=tool_args,
        policy=policy,
        limits=limits,
        verify_evidence=verify_evidence,
        proposal_base_dir=proposal_base_dir,
        evidence_root_dir=evidence_root_dir,
        request_id=request_id,
        strict_trust=strict_trust,
        key_resolver=key_resolver,
    )
    return action_proposal, tool_args


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
    on_allow: Optional[MCPPreExecuteHook] = None,
) -> Callable[..., Any]:
    """
    Wrap a *sync* tool function with PIC enforcement.

    Returns:
      - {"isError": True, "error": {...}} on blocks
      - {"isError": False, "result": <tool_return>} on allow

    ``on_allow`` is an optional, synchronous pre-execution hook (see
    ``MCPPreExecuteHook``). When set, it is called once after PIC allows and
    audits and after PIC metadata is stripped, before the tool runs. It runs
    inline in the caller's context with no PIC-applied timeout, isolation, or
    cancellation, and must return promptly. A hook failure fails closed as a
    distinct integration error (``PIC_INTERNAL_ERROR`` + ``pic_mcp_hook_error``
    audit), never a PIC block. Only per-call ordering is guaranteed; hook
    invocations across calls are not globally serialized, so stateful hooks must
    be concurrency-safe. When unset, no hook context is built and behavior is
    unchanged.
    """
    policy = policy or PICPolicy()
    limits = limits or PICEvaluateLimits()
    proposal_base_dir = proposal_base_dir or Path(".").resolve()

    def wrapped(**kwargs: Any) -> Any:
        request_id = _extract_request_id(kwargs)

        try:
            (
                action_proposal,
                _,
                decision,
                sanitized_args,
            ) = _evaluate_pic_for_tool_call_with_decision(
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

            if on_allow is not None:
                _run_pre_execute_hook(on_allow, decision, action_proposal, sanitized_args)

            result = tool_fn(**sanitized_args)
            return _wrap_success(result)

        except _MCPPreExecuteHookError as he:
            return _hook_failure_response(decision, he)

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
    on_allow: Optional[MCPPreExecuteHook] = None,
) -> Callable[..., Awaitable[Any]]:
    """
    Wrap an *async* tool function with PIC enforcement + optional tool timeout.

    Tool timeout is ONLY enforceable for async tools.
    For sync tools, use a subprocess/worker execution model if you need killable timeouts.

    ``on_allow`` is the same optional, synchronous pre-execution hook as
    ``guard_mcp_tool`` (see ``MCPPreExecuteHook``). It is invoked synchronously
    even here, before the tool is awaited, and ``max_tool_ms`` does not apply to
    it -- a blocking hook blocks the event loop, so hooks must return promptly. A
    hook failure fails closed as a distinct integration error, never a PIC block.
    Only per-call ordering is guaranteed; hook invocations across calls are not
    globally serialized, so stateful hooks must be concurrency-safe.
    """
    policy = policy or PICPolicy()
    limits = limits or PICEvaluateLimits()
    proposal_base_dir = proposal_base_dir or Path(".").resolve()

    async def wrapped(**kwargs: Any) -> Any:
        request_id = _extract_request_id(kwargs)

        try:
            (
                action_proposal,
                _,
                decision,
                sanitized_args,
            ) = _evaluate_pic_for_tool_call_with_decision(
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

            if on_allow is not None:
                _run_pre_execute_hook(on_allow, decision, action_proposal, sanitized_args)

            if max_tool_ms is not None:
                try:
                    result = await asyncio.wait_for(
                        tool_fn(**sanitized_args), timeout=float(max_tool_ms) / 1000.0
                    )
                except asyncio.TimeoutError as e:
                    details = {"max_tool_ms": int(max_tool_ms)} if _debug_enabled() else None
                    raise PICError(
                        code=PICErrorCode.LIMIT_EXCEEDED,
                        message="Tool execution timed out",
                        details=details,
                    ) from e
            else:
                result = await tool_fn(**sanitized_args)

            return _wrap_success(result)

        except _MCPPreExecuteHookError as he:
            return _hook_failure_response(decision, he)

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
