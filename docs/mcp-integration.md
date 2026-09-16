# MCP Integration Guide

PIC Standard guard for [Model Context Protocol](https://modelcontextprotocol.io/) tool servers —
enforces PIC on wrapped MCP tool calls, verifying proposals before execution when a PIC contract is provided or policy requires one.

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

The MCP guard wraps tool functions **in-process** — no bridge, no HTTP. The agent passes a PIC proposal inside tool arguments, and the guard verifies it before calling the real tool function. Use this when you control the tool server code directly.

For agent-level interception where you don't control the tool server (e.g., OpenClaw), use the [HTTP Bridge](../README.md#http-bridge-any-language) instead.

### Fail-Closed Principle

Every error path — missing proposal, schema failure, verification failure, internal exception — results in the tool call being **blocked** and an error envelope returned. The system never fails open.

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

### `guard_mcp_tool()` — Sync Tools

```python
guarded = guard_mcp_tool(
    tool_name,  # str — must match action.tool in proposal
    tool_fn,  # Callable — your sync tool function
    policy=policy,  # PICPolicy (default: empty policy)
    limits=limits,  # PICEvaluateLimits (default: standard limits)
    verify_evidence=True,  # bool — enable evidence verification
    proposal_base_dir=Path("."),  # Path — base dir for file evidence
    evidence_root_dir=None,  # Path — sandbox root for evidence files
)
```

The wrapper:
1. Extracts `__pic` from `tool_args`
2. Checks if PIC is required by policy
3. Runs the full verification pipeline
4. Strips `__pic` and `__pic_request_id` before calling the real tool
5. Returns `{"isError": false, "result": ...}` or `{"isError": true, "error": ...}`

### `guard_mcp_tool_async()` — Async Tools

```python
guarded = guard_mcp_tool_async(
    tool_name,
    async_tool_fn,
    policy=policy,
    max_tool_ms=5000,  # optional tool execution timeout (async only)
)
```

Same behavior as sync, plus optional `max_tool_ms` timeout. If the tool exceeds the timeout, PIC returns `LIMIT_EXCEEDED`.

### `evaluate_pic_for_tool_call()` — Low-Level

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
# Note: tool_args is the original dict, not sanitized —
# __pic / __pic_request_id stripping happens in the guard wrappers.
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

## Debug Mode

Set `PIC_DEBUG=1` to include error details in the MCP error envelope:

```bash
PIC_DEBUG=1 python your_server.py
```

Without debug mode, error envelopes contain only `code` and `message` (no internal details leaked).

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

1. **In-process only** — the guard runs inside your Python process. For cross-language or agent-level interception, use the [HTTP Bridge](../README.md#http-bridge-any-language) or [OpenClaw plugin](openclaw-integration.md).
2. **Sync verification** — `guard_mcp_tool_async` wraps an async tool, but PIC verification itself is synchronous. This is by design (verification is CPU-bound, typically <10ms).
3. **Tool timeout** — `max_tool_ms` is only available for async tools. For sync tools, use a subprocess/worker model if you need killable timeouts.
4. **No built-in auth** — the guard trusts whatever `__pic` proposal it receives. Authentication and authorization of the caller is your responsibility.
