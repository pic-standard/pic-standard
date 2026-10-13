# PIC Standard — threat model (reference implementation)

**Scope:** PIC/1.0 pre-final specification and the reference Python guard in this
repository. This is a reviewable threat model, **not** a penetration-test result,
certification, or assurance that a third-party integration calls the guard.
Deployment-specific credentials, tenants and authentication must be assessed
separately before a production deployment.

This reference-implementation analysis expands the normative
[RFC-0001 threat-model overview](RFC-0001-pic-standard.md#threat-model);
it does not revise the RFC's protocol contract or replace an integration-specific risk review.

The [security policy](../SECURITY.md) defines private vulnerability reporting.
Do **not** post exploit details, unredacted tokens or secret evidence in a
public pull request.

## Assets and actors

**Assets:** operator intent/policy, authorized high-impact tool calls,
proposal provenance and claim identifiers, evidence bytes and reference paths,
trusted Ed25519 public-key registry (including revocations/expiry), private
signing keys outside PIC, verified decisions and evidence references.

**Actors:** user/approver, untrusted web or conversation content, model-driven
agent, integration adapter, PIC verifier, evidence/keyring operator, downstream
tool or payment system, and an adversary who may control prompt text,
proposal fields, evidence documents or an untrusted network endpoint.

**Trust is not inherited from the model.** An LLM-generated declaration such
as `provenance[].trust="trusted"` is still untrusted input. PIC is neither
identity infrastructure nor a replacement for downstream authorization.

## Data-flow and trust boundaries

```mermaid
flowchart LR
    U["Human/operator policy"] -->|configured rules| P["PIC policy/keyring"]
    X["External messages & tool output\nuntrusted"] --> A["AI agent"]
    A -->|Action Proposal: intent, provenance, claims, evidence| G["PIC integration adapter"]
    P -->|policy and allowed public keys| V["verify_proposal()"]
    G -->|bound expected tool + proposal| V
    F["Local evidence files\nseparate trust boundary"] -->|sandboxed hash/signature read| V
    V -->|allow / block + reason| G
    G -->|only after explicit ALLOW| T["Real tool / downstream service"]
    T -->|independent authorization, idempotency, settlement| R["External side effect"]
```

The integration **must not invoke** the tool before a successful gate decision;
`verify_proposal()` does not control unrelated tool-dispatch paths. External
services must independently enforce account permissions and settlement.

## Threats, controls and residual obligations

| Threat (STRIDE) | Source of attacker input | Control in reference | Important limit / owner |
|---|---|---|---|
| **Spoofing:** prompt claims an approved human source | Agent-provided provenance | `pipeline._sanitize_provenance_trust` under default `PipelineOptions.strict_trust=True` downgrades self-asserted trust; verified signature evidence may upgrade bound IDs | PIC does not authenticate a real human or identify an agent. Operator owns approval/identity channel |
| **Tampering:** evidence file altered after review | Local file bytes or reference | `evidence.EvidenceSystem` computes SHA-256 over bounded, sandboxed evidence and refuses mismatches | Hash-only integrity does **not** establish authorship/authority; evidence owner maintains file ACLs |
| **Tampering:** forged attestation or swapped claims/arguments | Evidence `sig` payload and Action Proposal | Ed25519 signature verification; **canonical attestation mode** additionally binds `tool`, `impact`, `args_digest`, `claims_digest`, optional `intent_digest`, provenance IDs and optional expiry to the proposal | **Legacy payload signing** checks the signed payload bytes but does **not** supply canonical proposal-field bindings. Signing-key custody and issuance remain external responsibilities |
| **Elevation of privilege:** proposal names a less sensitive tool | `action.tool` | `pipeline._verify_tool_binding` compares tool to integration-provided `expected_tool`; guard uses resolved impact and evidence policy | Caller must bind the **actual** tool name from its dispatch registry; unprotected paths bypass PIC |
| **Repudiation:** operator disputes who approved | Local log / proposal | Structured error codes, evidence references and deterministic verification help auditing | Without independently retained authorization receipts and immutable external logs, PIC cannot prove a human signed off |
| **Information disclosure:** evidence path or debug context leaked | Error details, file paths, HTTP body | Evidence file resolution enforces an allowed root; HTTP debug details are restricted by configuration | Host/admin must keep evidence root private, avoid exposing `PIC_DEBUG` details, scrub logs and lock down network access |
| **Denial of service:** oversized inputs or expensive evidence | Requests, evidence files, malicious payloads | `PICEvaluateLimits`, HTTP body/time limits, evidence bounds and fail-closed errors | Operators still need authentication, rate limiting, resource quotas and isolated execution for network-facing services |
| **Replay:** a previously allowed proposal is resubmitted | Captured proposal or signed attestation | Canonical bindings and optional attestation expiry can reject altered/stale signed content | **No universal replay cache, nonce ledger or exactly-once effect guarantee** is provided by a stateless verifier. The tool owner must enforce idempotency and nonce/replay policy |
| **Key compromise:** valid but stolen signing key | Attacker-controlled signature | `keyring.TrustedKeyRing` supports key expiry and revocation; verifier refuses missing/expired/revoked trusted keys | The operator must rotate/revoke compromised keys, distribute keyring updates and handle already-executed effects; PIC cannot detect a stolen yet-trusted private key |
| **Injection:** untrusted text persuades a model to call a tool | Retrieved documents or conversation | PIC checks the resulting *proposed action*, not the prose itself, under an operator-defined policy | PIC is not a general prompt-injection detector; harmless-looking actions or underspecified policies may still be allowed |

Threats with both **spoofing** and **tampering** properties (e.g., fabricated
invoice plus altered signer metadata) cross more than one row.

## Signature verification modes: different guarantees

The reference verifier has **two supported signing modes**, distinguished by
the signed evidence's payload (see
[`spec-evidence.md`](spec-evidence.md) and
[`evidence.py`](../sdk-python/pic_standard/evidence.py)):

- **Canonical attestation**: a JSON object with a recognized, string-valued
  `attestation_version` is verified over canonicalized object bytes. After
  signature verification, the verifier checks the proposal's `tool`,
  `impact`, `args_digest`, `claims_digest`, `provenance_ids` and optional
  `intent_digest` and `expires_at` bindings. Invalid or unknown versions and
  malformed canonical-looking objects fail closed; they cannot fall back to
  the legacy mode.
- **Legacy payload signing**: a payload without a canonical attestation
  version is verified against its **raw UTF-8 payload bytes**, retaining the
  original signing contract. **That signature alone does not enforce the
  canonical attestation-to-proposal field bindings**. Consumers cannot claim
  that changes to proposal arguments or destination are rejected by canonical
  binding checks in this mode. The integration must supply its own authorized,
  correctly bound policy and downstream execution controls.

Neither signing mode proves the identity or authority of the human who
approved an action, proves key custody, or prevents replay on its own.
Those remain operator/downstream responsibilities.

## Two abuse paths to test

1. **Untrusted instruction → payment attempt.** An external document asks an
   agent to transfer funds, and the agent proposes a money-impact tool call with
   `trust=trusted`. Default strict-trust sanitization must not treat that
   self-assertion as human authorization; apply the money-impact evidence
   policy and deny unless required authority-bearing evidence passes. Also
   assert the downstream payment tool has not run on denial.
2. **Signed evidence replay.** An attacker copies a previously valid proposal
   unchanged and resends it. PIC may return the same verification result;
   downstream payment/job APIs must detect duplicate intent IDs/nonces and
   avoid repeating the side effect. In **canonical attestation mode**, changing
   a signed proposal's amount or destination changes the action-argument digest
   and must fail the attestation's proposal binding. In **legacy payload mode**,
   a valid signature over unchanged raw payload bytes does **not** by itself
   prove that the proposal's amount or destination was bound to that signature;
   the operator must enforce the relevant policy and downstream authorization.

Neither scenario by itself proves the entire host application's security
boundary; each must be tested at the real tool-dispatch seam.

## Configuration that affects the security claim

- Keep `strict_trust=True` (the secure default). Setting it to `False`
  intentionally enables legacy trust handling; do not silently treat
  compatibility mode as the secure profile.
- Require evidence verification for high-impact actions. A hash-only file
  may establish integrity, but **not** authority for trust upgrade.
- Use a verified, minimal `expected_tool` and operator policy; apply the gate
  on every dispatch path that can produce a side effect.
- Isolate allowed evidence roots and keyring material. Never place private
  signing keys in proposal JSON, GitHub issues or HTTP diagnostic fields.
- Pair allowed decisions with downstream human authorization (where needed),
  per-actor rate limits, idempotency/anti-replay and durable audit receipts.
- Distinguish the HTTP bridge's `MAX_REQUEST_BYTES` / socket
  `READ_TIMEOUT_SECS` controls, which bound body size and socket reads, from
  `PICEvaluateLimits.max_eval_ms` and `PipelineOptions.time_budget_ms`.
  The evaluation-time budget is checked **after evaluation**; it can reject an
  over-budget decision but **does not preempt expensive computation** or provide
  a wall-clock kill switch. Direct `verify_proposal()` calls skip proposal
  size/item limits when `PipelineOptions.limits` is `None`, and apply an
  evaluation-time budget only when explicitly configured (or inherited from
  provided limits). Callers must opt into appropriate limits, isolation and
  resource controls for their deployment.
- An MCP integration must explicitly wrap every relevant business tool with
  `guard_mcp_tool` / `guard_mcp_tool_async`, configure its
  `PICPolicy`, trusted evidence/key resolver when required, and ensure
  policy-required proposals reach the guard in the `__pic` argument. The guard
  evaluates and strips PIC metadata before invoking the protected tool; bare
  tool registrations remain outside PIC enforcement.
- A LangGraph integration must actually use `PICToolNode` at the tool
  execution seam and configure `policy`, `verify_evidence`, `key_resolver`,
  evidence roots and `strict_trust` as appropriate. Ordinary LangGraph tool
  nodes do **not** acquire PIC protection from installing the package alone.
- Treat errors as fail-closed; the [error reference](ERRORS.md) distinguishes
  HTTP transport errors from a verification verdict.

## Evidence and verification map

| Security property | Repository source / review gate |
|---|---|
| Shared decision chain, strict trust, resource bounds and tool binding | [`sdk-python/pic_standard/pipeline.py`](../sdk-python/pic_standard/pipeline.py), [`tests/`](../tests/) |
| File-hash, canonical-signature verification and trust-upgrade rules | [`sdk-python/pic_standard/evidence.py`](../sdk-python/pic_standard/evidence.py), [evidence specification (draft)](spec-evidence.md) |
| Trusted signer revocation and expiry | [`sdk-python/pic_standard/keyring.py`](../sdk-python/pic_standard/keyring.py) |
| HTTP body/socket read limits and transport-error handling (not evaluation preemption) | [`sdk-python/pic_standard/integrations/http_bridge.py`](../sdk-python/pic_standard/integrations/http_bridge.py), [`tests/test_http_bridge.py`](../tests/test_http_bridge.py) |
| MCP synchronous/async action-boundary enforcement and optional pre-execution hook | [`sdk-python/pic_standard/integrations/mcp_pic_guard.py`](../sdk-python/pic_standard/integrations/mcp_pic_guard.py), [`sdk-python/pic_standard/integrations/mcp_hooks.py`](../sdk-python/pic_standard/integrations/mcp_hooks.py), [`tests/test_mcp_guard_hook.py`](../tests/test_mcp_guard_hook.py) |
| LangGraph tool execution after explicit PIC verification | [`sdk-python/pic_standard/integrations/langgraph_pic_toolnode.py`](../sdk-python/pic_standard/integrations/langgraph_pic_toolnode.py), [`tests/test_langgraph_integration.py`](../tests/test_langgraph_integration.py) |
| Standardized conformance fixtures | [`conformance/`](../conformance/) |
| Security disclosure and supported versions | [`SECURITY.md`](../SECURITY.md) |

**Review checklist:** verify every claimed control against the exact current
source; exercise both denial and an allowed control case; run conformance/
unit checks; inspect adapters for paths that bypass `verify_proposal()`;
separately validate human authority, replay protection, signer custody,
key-rotation latency, rate limits and evidence storage for each deployment.

**Not covered by this document:** undisclosed vulnerabilities, side-channel
resistance, external payment settlement, smart contract or wallet custody,
full malware containment, model safety, deployment compliance certification,
or claims about third-party agents and integrations not exercised.
