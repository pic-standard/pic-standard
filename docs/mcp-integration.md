# MCP Integration Guide

PIC Standard guard for [Model Context Protocol](https://modelcontextprotocol.io/) tool servers: enforces PIC on wrapped MCP tool calls, verifying proposals before execution when a PIC contract is provided or policy requires one.

> **Requires:** Python ≥ 3.10 · `pip install "pic-standard[mcp]"`

---

## Architecture

```
┌─────────────────────────────────────────────┐
│  MCP Tool Server (Python)                   │
│                                             │
│  ┌──────────────┐     ┌──────────────────┐  │
│  │ Tool function│     │ guard_mcp_tool() │  │
│  │ (business    │ ←── │ or               │  │
│  │  logic)      │     │ guard_mcp_tool_  │  │
│  └──────────────┘     │   async()        │  │
│                       └────────┬─────────┘  │
│                                │             │
│                       PIC verification       │
│                       (in-process, no HTTP)   │
│                                │             │
│                       ┌────────▼─────────┐  │
│                       │ PIC Pipeline     │  │
│                       │ (schema →        │  │
│                       │  verifier →      │  │
│                       │  evidence)       │  │
│                       └──────────────────┘  │
└─────────────────────────────────────────────┘
```

### How It Differs from the HTTP Bridge

The MCP guard wraps tool functions **in-process** (no bridge, no HTTP). The agent passes a PIC proposal inside tool arguments, and the guard verifies it before calling the real tool function. Use this when you control the tool server code directly.

For agent-level interception where you don't control the tool server (e.g., OpenClaw), use the [HTTP Bridge](../README.md#http-bridge-any-language) instead.

### Fail-Closed Principle

Every failure before dispatch prevents the business tool from running and returns an error envelope. PIC evaluation failures produce a `block` decision. A pre-execution hook failure occurs after PIC has allowed the call, so it produces a distinct integration error while the PIC decision remains `allow`. The system never silently fails open.

---

## Quick Start

### 1. Install

```bash
pip install "pic-standard[mcp]"
```

### 2. Load Policy

```python
from pathlib import Path
from pic_standard.config import load_policy

policy = load_policy(repo_root=Path("."))
# or: policy = load_policy(explicit_path=Path("pic_policy.json"))
```

### 3. Wrap a Tool

```python
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool


def _payments_send(amount: int) -> str:
    return f"sent ${amount}"


guarded_send = guard_mcp_tool(
    "payments_send",
    _payments_send,
    policy=policy,
    verify_evidence=True,
    proposal_base_dir=Path("."),
)
```

### 4. Expose via MCP

The low-level guard expects `__pic` and `__pic_request_id` in `tool_args`. In a real MCP server, you will usually expose normal arguments like `pic` and `request_id`, then map them to those reserved keys before calling the guard:

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-server")


@mcp.tool()
def payments_send_tool(
    amount: int,
    pic: dict | None = None,
    request_id: str | None = None,
) -> dict:
    envelope = guarded_send(
        amount=amount,
        __pic=pic,
        __pic_request_id=request_id,
    )
    return {"result": envelope}
```

The guard wrapper (`guarded_send`) returns an envelope:
- Allow: `{"isError": false, "result": "sent $500"}`
- Block: `{"isError": true, "error": {"code": "PIC_VERIFIER_FAILED", "message": "..."}}`

The MCP tool then wraps that in `{"result": envelope}` for the MCP protocol layer.

### 5. Run the Demo

```bash
python -u examples/mcp_pic_client_demo.py
```

---

## API Reference

### `guard_mcp_tool()` (Sync Tools)

```python
guarded = guard_mcp_tool(
    tool_name,  # str: must match action.tool in proposal
    tool_fn,  # Callable: your sync tool function
    policy=None,  # PICPolicy (default: empty policy)
    limits=None,  # PICEvaluateLimits (default: standard limits)
    verify_evidence=False,  # bool: enable evidence verification
    proposal_base_dir=None,  # Path: base dir for file evidence
    evidence_root_dir=None,  # Path: sandbox root for evidence files
    strict_trust=True,  # bool: enforce verifier-derived trust (default True)
    key_resolver=None,  # optional KeyResolver for signature (PIC-ATT) evidence
    on_allow=None,  # optional MCPPreExecuteHook (see Pre-Execution Hook)
)
```

The wrapper:
1. Extracts `__pic` from `tool_args`
2. Checks if PIC is required by policy
3. Runs the full verification pipeline
4. For a proposal-backed call, binds the sanitized live arguments to the verified `action.args`; any mismatch or live-argument canonicalization failure returns `PIC_ARG_BINDING_MISMATCH`
5. Uses the bound sanitized snapshot, excluding only `__pic` and `__pic_request_id`, for the hook and business tool
6. Returns `{"isError": false, "result": ...}` or `{"isError": true, "error": ...}`

A plain `request_id` is a business argument and participates in argument binding. Use the reserved `__pic_request_id` key when the value is for correlation only.

### `guard_mcp_tool_async()` (Async Tools)

```python
guarded = guard_mcp_tool_async(
    tool_name,
    async_tool_fn,
    policy=None,
    limits=None,
    verify_evidence=False,
    proposal_base_dir=None,
    evidence_root_dir=None,
    max_tool_ms=None,  # optional tool execution timeout (async only)
    strict_trust=True,
    key_resolver=None,
    on_allow=None,  # optional MCPPreExecuteHook (see Pre-Execution Hook)
)
```

Same behavior as sync, plus optional `max_tool_ms` timeout. If the tool exceeds the timeout, PIC returns `LIMIT_EXCEEDED`.

### `evaluate_pic_for_tool_call()` (Low-Level)

For custom integration patterns where you need direct access to the verification result:

```python
from pic_standard.integrations.mcp_pic_guard import evaluate_pic_for_tool_call

action_proposal, tool_args = evaluate_pic_for_tool_call(
    tool_name="payments_send",
    tool_args=kwargs,
    policy=policy,
    verify_evidence=True,
    request_id="req-abc-123",
)
# Raises PICError on block
# Returns (ActionProposal | None, tool_args)
# Note: tool_args is the original dict, not sanitized. __pic / __pic_request_id
# stripping happens in the guard wrappers.
```

---

## Request Correlation

Pass a correlation ID for audit trail linking:

```python
envelope = guarded_send(
    amount=500,
    __pic={...},
    __pic_request_id="req-abc-123",  # appears in audit logs
)
```

The guard also checks `request_id` in tool args as a fallback source.

---

## Audit Logging

Every decision (allow or block) emits a structured JSON log line via Python's `logging` module under the `pic_standard.mcp` logger:

```json
{
  "event": "pic_mcp_decision",
  "decision": "allow",
  "tool": "payments_send",
  "impact": "money",
  "request_id": "req-abc-123",
  "eval_ms": 3
}
```

Configure the logger in your application:

```python
import logging

logging.getLogger("pic_standard.mcp").setLevel(logging.INFO)
```

---

## Pre-Execution Hook (`on_allow`)

Both guards accept an optional `on_allow` hook, a structured alternative to parsing the `pic_standard.mcp` JSON audit log. It fires **once per allow**, after PIC allows and audits and after `__pic` and `__pic_request_id` are stripped, **before** the business tool runs. It fires on both a proposal-backed allow and a `no_pic_required` allow, and **never** on a block.

```python
from queue import SimpleQueue

from pic_standard.integrations import MCPAllowDecision, MCPToolCall
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool

local_records: SimpleQueue = SimpleQueue()


def on_allow(decision: MCPAllowDecision, tool_call: MCPToolCall) -> None:
    # Integration gate: returning normally permits dispatch to continue.
    # Runs inline, before tool dispatch. Keep it fast and local.
    local_records.put(
        {
            "request_id": decision.request_id,
            "tool": decision.tool,
            "impact": decision.impact,
            "proposal_present": decision.proposal_present,
            "declared_args_digest": decision.args_digest,  # over the proposal's action.args
            "live_args_digest": tool_call.arguments_digest,  # over the sanitized live call
            "tool_call_digest": tool_call.tool_call_digest,
        }
    )


guarded_send = guard_mcp_tool("payments_send", _payments_send, policy=policy, on_allow=on_allow)
```

### Contract

- **Signature:** `(decision: MCPAllowDecision, tool_call: MCPToolCall) -> None`. The hook must be **synchronous, fast, and local**: no network or blocking I/O. It runs inline in the caller's context; PIC applies no timeout, isolation, or cancellation to the hook, and in the async guard a blocking hook blocks the event loop (`max_tool_ms` begins only when the tool is awaited).
- **It is a capture/integration point, not a second authorization decision.** PIC's allow/block remains authoritative only for PIC evaluation. An allow means PIC did not block the proposed action; it does not prove dispatch or execution. The hook may prevent dispatch by raising, but that does not change PIC's allow decision into a block.
- **Fail-closed integration gate.** The hook must return `None`. If it raises, or returns anything other than `None` (returning a coroutine, including by being defined with `async def`, is rejected the same way), the call fails closed: the tool does **not** run, the envelope is `PIC_INTERNAL_ERROR` with message `"PIC pre-execution hook failed"`, and a distinct `pic_mcp_hook_error` audit event is emitted, never a `decision: "block"`. The gate validates the returned value rather than introspecting the callable.
- **Hook is a guard-wrapper feature.** The low-level `evaluate_pic_for_tool_call()` has no hook and keeps its 2-tuple return.
- **Concurrency.** Ordering is guaranteed only within one guarded call (allow audit, then hook, then tool dispatch). Hook invocations across different calls are not serialized, so stateful hooks must be concurrency-safe for the hosting application and should correlate state using `request_id`.

### `MCPAllowDecision`

PIC's structured allow decision. `decision` is always `"allow"`. Carries `tool`, `impact`, `request_id`, `proposal_present`, `proposal_id`, `verified_evidence_count`, `eval_ms`, `intent_digest`, `args_digest`, and `reason`. `intent_digest` and `args_digest` are over the **proposal's** declared `intent` and `action.args`; they are hook-only context and are **absent on a `no_pic_required` allow**.

`decision.to_audit_bytes()` returns the UTF-8 encoding of the exact `LogRecord.getMessage()` text emitted for the allow decision, without a logging formatter prefix or trailing newline, so you can hash it for a content-addressed identifier. The hook-only digests are **not** in that audit text; they are available only on the object.

### `MCPToolCall`

The sanitized live tool call the guard is about to dispatch. `arguments` are the live kwargs with `__pic` and `__pic_request_id` removed. It is immutable and detached: `canonical_bytes` is the RFC 8785/JCS preimage of the whole `{"name", "arguments"}` object and `to_dict()` returns a fresh parsed copy, so a hook cannot alter what the tool receives. It exposes `arguments_digest` (comparable to `decision.args_digest`) and `tool_call_digest`.

> `MCPToolCall` carries the actual sanitized business arguments, which may be sensitive. Do not log or export them indiscriminately; prefer the digests for audit and correlation.

> Digests are lowercase, unprefixed, 64-character SHA-256 hex (`pic_standard.canonical`). A consumer that needs an algorithm-prefixed form (for example `sha256:...`) adds that prefix at its own boundary. For a proposal-backed allow the guard enforces argument binding before the hook fires, so `decision.args_digest` and `tool_call.arguments_digest` are equal whenever the hook runs; a divergent live call is blocked with `PIC_ARG_BINDING_MISMATCH` and never reaches the hook.

---

## Debug Mode

Set `PIC_DEBUG=1` to include error details in the MCP error envelope:

```bash
PIC_DEBUG=1 python your_server.py
```

Without debug mode, error envelopes contain only `code` and `message` (no internal details leaked). Hook-failure envelopes remain limited to `code` and `message`; under `PIC_DEBUG`, the separate `pic_mcp_hook_error` audit event may additionally include only the exception type name.

---

## Policy Setup

Policy is loaded from `pic_policy.json` (see `pic_policy.example.json` in the repo root for the full schema).

```json
{
  "impact_by_tool": {
    "payments_send": "money",
    "customer_export": "privacy"
  },
  "require_pic_for_impacts": ["money", "privacy", "irreversible"],
  "require_evidence_for_impacts": ["money"]
}
```

If no PIC proposal is provided and the tool is not policy-gated as requiring PIC, the call passes through. If a PIC proposal is present, it is always verified regardless of policy.

---

## Limitations

1. **In-process only:** the guard runs inside your Python process. For cross-language or agent-level interception, use the [HTTP Bridge](../README.md#http-bridge-any-language) or [OpenClaw plugin](openclaw-integration.md).
2. **Sync verification:** `guard_mcp_tool_async` wraps an async tool, but PIC verification itself is synchronous. This is by design (verification is CPU-bound, typically <10ms).
3. **Tool timeout:** `max_tool_ms` is only available for async tools. For sync tools, use a subprocess/worker model if you need killable timeouts.
4. **No built-in auth:** the guard trusts whatever `__pic` proposal it receives. Authentication and authorization of the caller is your responsibility.
