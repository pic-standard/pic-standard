"""Pre-execution hook types for the PIC MCP guard (opt-in, additive).

This module defines the optional pre-execution integration point for the MCP
guard, tracked in pic-standard/pic-standard#187. It lets an integration observe
PIC's structured allow-decision and the sanitized live tool call *before* the
business tool runs, instead of parsing the ``pic_standard.mcp`` JSON audit log.

Scope and guarantees:
    - MCP-local. These types describe one MCP integration event; they are not a
      protocol-wide lifecycle shared by the HTTP bridge, LangGraph, or other
      implementations.
    - Additive and opt-in. The existing allow audit may be represented
      internally by ``MCPAllowDecision``, but the guard does not construct
      ``MCPToolCall``, canonicalize live arguments, compute hook-only digests,
      or invoke a callback unless ``on_allow`` is configured.
    - ``allow`` is scoped to PIC evaluation only. Nothing here asserts tool
      dispatch, execution, success, or real-world effect. A hook is an
      integration gate, not a second PIC decision (see #187; the broader
      vocabulary is tracked for v1.0 in #188).

Digest representations are frozen to the ``pic_standard.canonical`` helpers:
lowercase, unprefixed, 64-character hex. Consumers that need an algorithm-
prefixed form (e.g. a TRACE bridge's ``sha256:...``) add that prefix at their
own boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Literal, Optional, Protocol, runtime_checkable

from pic_standard.canonical import canonicalize, sha256_hex

__all__ = [
    "MCPAllowDecision",
    "MCPPreExecuteHook",
    "MCPToolCall",
]


@dataclass(frozen=True, slots=True, kw_only=True)
class MCPAllowDecision:
    """PIC's structured allow decision, as surfaced to a pre-execution hook.

    ``decision`` is fixed to ``"allow"`` and is not constructible otherwise: the
    hook fires only on an allow, never on a block. ``proposal_present`` is
    ``False`` on the ``no_pic_required`` path.

    ``intent_digest``/``args_digest`` are over the *proposal's* declared
    ``intent``/``action.args`` (``canonical.intent_digest_hex`` /
    ``canonical.sha256_hex``). They are hook-only context and never enter the
    decision audit log (see ``to_audit_payload``). On an object delivered to a
    hook they are populated for a proposal-backed allow and absent for
    ``no_pic_required``; an internal audit-only instance created when no hook is
    configured may leave these hook-only fields absent.
    """

    tool: str
    impact: Optional[str]
    decision: Literal["allow"] = field(default="allow", init=False)
    request_id: Optional[str] = None
    proposal_present: bool = False
    proposal_id: Optional[str] = None
    verified_evidence_count: Optional[int] = None
    eval_ms: Optional[int] = None
    intent_digest: Optional[str] = None
    args_digest: Optional[str] = None
    reason: Optional[str] = None

    def to_audit_payload(self) -> Dict[str, Any]:
        """An ordered mapping reproducing the current allow-audit fields, order,
        and omission rules.

        Contains only the fields the current allow audit emits, in the same
        order, with the same truthy/``None`` omission rules. ``reason_code`` is
        omitted (it is a block-only field). Hook-only fields (``intent_digest``,
        ``args_digest``, ``proposal_present``) are never included.
        """
        payload: Dict[str, Any] = {
            "event": "pic_mcp_decision",
            "decision": self.decision,
            "tool": self.tool,
            "impact": self.impact,
        }
        if self.request_id:
            payload["request_id"] = self.request_id
        if self.proposal_id:
            payload["proposal_id"] = self.proposal_id
        if self.verified_evidence_count is not None:
            payload["verified_evidence_count"] = self.verified_evidence_count
        if self.eval_ms is not None:
            payload["eval_ms"] = self.eval_ms
        if self.reason:
            payload["reason"] = self.reason
        return payload

    def to_audit_bytes(self) -> bytes:
        """``to_audit_payload()`` serialized exactly as the guard logs it.

        ``json.dumps(payload, ensure_ascii=False).encode("utf-8")`` -- no newline,
        no formatter prefix. The allow-audit path logs these bytes decoded as
        UTF-8, so the logged line is identical to the pre-hook behavior. A
        consumer may hash these bytes to derive a content-addressed identifier
        for this emitted decision.
        """
        return json.dumps(self.to_audit_payload(), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True, kw_only=True)
class MCPToolCall:
    """The sanitized live tool call the guard is about to dispatch.

    Detached and immutable: ``canonical_bytes`` is the frozen RFC 8785/JCS
    preimage of the whole ``{"name", "arguments"}`` object, and ``to_dict()``
    re-parses it fresh, so a hook cannot mutate the arguments the tool receives
    or the canonical preimage. ``arguments`` are the live kwargs with ``__pic``
    and ``__pic_request_id`` already removed. ``__post_init__`` rejects an
    internally inconsistent instance.
    """

    name: str
    canonical_bytes: bytes
    arguments_digest: str
    tool_call_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.canonical_bytes, bytes):
            raise ValueError("MCPToolCall.canonical_bytes must be bytes")
        try:
            parsed = json.loads(self.canonical_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError("MCPToolCall.canonical_bytes is not valid UTF-8 JSON") from e
        if not isinstance(parsed, dict) or set(parsed) != {"name", "arguments"}:
            raise ValueError("MCPToolCall.canonical_bytes must encode exactly {name, arguments}")
        if not isinstance(self.name, str) or not isinstance(parsed["name"], str):
            raise ValueError("MCPToolCall.name must be a string")
        if not isinstance(parsed["arguments"], dict):
            raise ValueError("MCPToolCall arguments must be a JSON object")
        if parsed["name"] != self.name:
            raise ValueError("MCPToolCall.name does not match canonical_bytes")
        if canonicalize(parsed) != self.canonical_bytes:
            raise ValueError("MCPToolCall.canonical_bytes is not canonical")
        if self.arguments_digest != sha256_hex(parsed["arguments"]):
            raise ValueError("MCPToolCall.arguments_digest does not match canonical_bytes")
        if self.tool_call_digest != sha256_hex(parsed):
            raise ValueError("MCPToolCall.tool_call_digest does not match canonical_bytes")

    @classmethod
    def build(cls, name: str, arguments: Dict[str, Any]) -> "MCPToolCall":
        """Build from the sanitized live call. May raise ``CanonicalizationError``.

        ``arguments_digest = sha256_hex(arguments)`` (comparable to
        ``MCPAllowDecision.args_digest``); ``tool_call_digest = sha256_hex({"name",
        "arguments"})``; ``canonical_bytes`` is the canonicalization of that same
        object.
        """
        tool_call = {"name": name, "arguments": arguments}
        canonical_bytes = canonicalize(tool_call)
        return cls(
            name=name,
            canonical_bytes=canonical_bytes,
            arguments_digest=sha256_hex(arguments),
            tool_call_digest=sha256_hex(tool_call),
        )

    def to_dict(self) -> Dict[str, Any]:
        """A fresh parsed copy of the ``{"name", "arguments"}`` object."""
        return json.loads(self.canonical_bytes.decode("utf-8"))


@runtime_checkable
class MCPPreExecuteHook(Protocol):
    """A synchronous, fast, local pre-execution hook.

    Called once per guard allow, after PIC allows and audits and after
    ``__pic``/``__pic_request_id`` are stripped, before the tool runs. Returning
    normally continues execution; raising aborts execution fail-closed and is
    reported as an integration failure (never a PIC block). Must not perform
    network or blocking I/O.

    The hook runs inline in the caller's execution context. PIC does not apply
    ``max_tool_ms``, a separate timeout, process isolation, or cancellation to
    the hook. Hook implementations are trusted integration code and must return
    promptly; in the async guard a blocking hook blocks the event loop, and
    ``max_tool_ms`` begins only when the business tool is awaited.

    PIC guarantees ordering only within one guarded call: allow audit, hook,
    then tool dispatch. Hook invocations for different calls are not globally
    ordered or serialized. Stateful hooks must be safe for the concurrency model
    of the hosting application and should correlate state using ``request_id``.
    """

    def __call__(self, decision: MCPAllowDecision, tool_call: MCPToolCall) -> None: ...


class _MCPPreExecuteHookError(Exception):
    """Internal marker: hook-context construction or the hook callback failed.

    Routed by the guard to a fail-closed integration error (public
    ``PIC_INTERNAL_ERROR`` envelope + a distinct ``pic_mcp_hook_error`` audit
    event). Never surfaced as a PIC ``block``. Not part of the public API.
    """
