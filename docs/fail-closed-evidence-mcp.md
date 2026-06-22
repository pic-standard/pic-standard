# Fail-closed evidence for LLM tool calls (SHA-256 + MCP)

When you run agents that can call tools (payments, exports, infra changes), the nastiest failures aren’t “bad reasoning.”
They’re **causal**: untrusted inputs (prompt injection, user text, web pages) quietly influence a **high-impact side effect**.

The pattern looks like this:

1) The model reads something untrusted (“pay vendor X”, “export all users”, “rotate keys now”)  
2) The agent decides a tool call is justified  
3) The runtime executes the side effect  
4) Later you argue about it in logs

The core problem: there’s no machine-verifiable link between **what the agent claims** and **what evidence actually backs it** at the moment the side effect happens.

This note explains one approach: enforce a small **contract at the tool boundary**, add **deterministic evidence verification**, and default to **fail-closed** for high-impact actions.

---

## The obvious fixes (and why they don’t close the gap)

**“Ask the model to cite sources.”**  
Citations are more text. They aren’t enforced at runtime.

**“Log everything.”**  
Logs help audits. They don’t prevent the bad tool call.

**“Allowlist tools / add approval.”**  
Useful, but still doesn’t verify *why* a risky call is justified (and approvals don’t scale to every action).

All of these can help, but none of them creates a hard boundary where the runtime can say:

> “This specific tool call is allowed only if these specific claims are backed by verifiable evidence.”

---

## A contract at the tool boundary: PIC action proposals

PIC (Provenance & Intent Contracts) asks the agent to emit a JSON **Action Proposal** right before a tool call.

The verifier checks:

- **Tool binding**: `proposal.action.tool` must match the actual tool name being called
- **Impact class**: `money`, `privacy`, `compute`, `irreversible`, ...
- **Provenance**: which inputs influenced the decision (and their trust level)
- **Claims + evidence**: what is being asserted, and which evidence IDs support it
- **Action args**: the tool arguments the agent intends to execute

Minimal example (proposal attached under `__pic` in tool args):

```json
{
  "protocol": "PIC/1.0",
  "intent": "Send payment for invoice",
  "impact": "money",
  "provenance": [
    {"id": "invoice_123", "trust": "trusted", "source": "evidence"}
  ],
  "claims": [
    {"text": "Pay $500 to vendor ACME", "evidence": ["invoice_123"]}
  ],
  "action": {
    "tool": "payments_send",
    "args": {"amount": 500}
  }
}
```

The goal isn’t “perfect truth.” It’s enforceable consistency:

- you can’t claim “pay $500” while binding to a different tool
- you can’t claim “trusted invoice” without evidence that verifies
- you can’t sneak in extra tool args that aren’t covered by the proposal

---

## v0.3: Deterministic evidence (SHA-256)

In v0.3, evidence IDs become more than labels.

The proposal can include:

- `evidence[]` objects that point to artifacts (e.g. `file://...`)
- a `sha256` for each artifact

At runtime:

1) Evidence is resolved (e.g. a file path)  
2) SHA-256 is computed  
3) Verified evidence IDs can upgrade `provenance[].trust` to `trusted` **in-memory**  
4) For high-impact actions, enforcement can be **fail-closed** (block on verification failure)

### Why this matters

It changes “trusted” from being a **claim** to being an **output of verification**.

If the artifact changes, the SHA changes, and “trusted” disappears.

### Try it via CLI

Verify evidence only:

```bash
pic-cli evidence-verify examples/financial_hash_ok.json
```

Gate the verifier on evidence (schema → evidence verify → trust upgrade → verifier):

```bash
pic-cli verify examples/financial_hash_ok.json --verify-evidence
```

Fail-closed example (expected to fail):

```bash
pic-cli verify examples/failing/financial_hash_bad.json --verify-evidence
```

### Evidence resolution: `file://` is resolved relative to the proposal file

Example:

- `examples/financial_hash_ok.json`
- references `file://artifacts/invoice_123.txt`
- resolves to `examples/artifacts/invoice_123.txt`

This is ergonomic for local proposals, but it has server implications — which brings us to MCP.

---

## v0.3.2: Guarding MCP tool calls (production defaults)

MCP makes tool calling easy, but it also makes the boundary between “LLM output” and “side effect” extremely thin.

v0.3.2 adds a production-oriented guard you can place at the MCP tool boundary:

- `pic_standard.integrations.mcp_pic_guard.guard_mcp_tool(...)`

The guard enforces PIC **right where tools execute**, with safer defaults for real services:

- **Fail-closed** for verifier/evidence failures
- **No exception leakage by default** (debug-gated details)
- **Request correlation** in structured logs
- **Hard limits** to resist DoS-style payloads
- **Evidence sandboxing** for `file://` artifacts in server environments

### What “production defaults” means here

#### 1) Debug-gated error details (no leakage by default)

- Default (`PIC_DEBUG` unset/0): error payloads include only a `code` + minimal `message`
- Debug (`PIC_DEBUG=1): payloads may include diagnostic `details` (verifier reason, exception info)

This reduces the risk of feeding sensitive internal errors back into an LLM loop.

#### 2) Request tracing for audit logs

If the tool call includes:

- `__pic_request_id="abc123"` (recommended), or
- `request_id="abc123"`

…the guard includes that correlation ID in a single structured decision log line.

#### 3) DoS limits for the enforcement path

The guard can enforce:

- max proposal bytes
- max item counts (provenance/claims/evidence)
- evaluation time budget (`max_eval_ms`)

This protects the **policy enforcement path** from being abused as a CPU/memory sink.

#### 4) Evidence sandboxing for servers

Server-side evidence is dangerous if `file://` can escape directories.

v0.3.2 hardens resolution:

- sandbox `file://` evidence to an allowed root (`evidence_root_dir`)
- enforce `max_file_bytes` (default 5MB)

This prevents common “path escape” and “read arbitrary file” mistakes in hosted environments.

---

## What this does *not* solve

This is not a complete security story by itself:

- it doesn’t make the model truthful
- it doesn’t stop all prompt injection
- it doesn’t enforce tool execution timeouts (that’s the executor/runtime)

It does one specific thing: make the **tool boundary** deterministic and enforceable, and block high-impact side effects when the contract isn’t satisfied.

---

## A simple mental model

Most “guardrails” constrain what the model *says*.  
PIC constrains what the agent is allowed to *do*.

The contract is evaluated at the only point that matters: **right before side effects**.

---

## Open questions I’d love feedback on

If you’ve shipped tool-calling agents with real side effects:

1) What do you enforce at the tool boundary today (if anything)?
2) Do you treat “evidence” as input text, or as something the runtime verifies deterministically?
3) How do you avoid leaking internal verifier errors back into the model loop?
4) Would you keep optional integration deps installed in CI, or split “core” vs “integration” jobs?

---

## Appendix: quick links

- Repo + README + examples: https://github.com/pic-standard/pic-standard
- Evidence demos: `examples/financial_hash_ok.json` and `examples/failing/financial_hash_bad.json`
- MCP demos: `examples/mcp_pic_server_demo.py` + `examples/mcp_pic_client_demo.py`
- LangGraph demo: `examples/langgraph_pic_toolnode_demo.py`
