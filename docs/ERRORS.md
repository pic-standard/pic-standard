# PIC Error Reference

Authoritative reference for `PICErrorCode` values, their meaning,
retryability, HTTP mapping, and example wire shape.

Source of truth for the codes themselves is
[`sdk-python/pic_standard/errors.py`](../sdk-python/pic_standard/errors.py).
The shared PIC protocol error codes are mirrored in
[`integrations/openclaw/lib/types.ts`](../integrations/openclaw/lib/types.ts).
That client-side file may also define adapter-local errors that are
not emitted by the Python guard.

A regression test asserts that the level-3 headings under "Error
codes" match the current `PICErrorCode` enum members, so new codes
cannot land without documentation here.

This document records the current reference bridge behavior. More
granular HTTP status mapping, if desired later, requires an
implementation change and a corresponding OpenAPI update.

---

## Wire shape

Errors come back inside a `PICError` JSON object with two required
fields and one optional field:

```json
{
  "code": "PIC_INVALID_REQUEST",
  "message": "Content-Length header required",
  "details": { "actual_bytes": 2048576 }
}
```

- `code` is one of the values documented below.
- `message` is a short, operator-oriented string. It is not a stable
  parseable identifier; do NOT match on message text. Match on
  `code`.
- `details` is optional. In HTTP bridge responses, `details` is
  included only when `PIC_DEBUG=1` is set in the guard's environment.
  Direct Python callers may receive structured details from
  `PICError` before HTTP serialization.

For the HTTP bridge (`pic-cli serve`), a full response looks like:

```json
{
  "allowed": false,
  "error": {
    "code": "PIC_SCHEMA_INVALID",
    "message": "PIC schema validation failed: 'impact' is a required property"
  },
  "eval_ms": 3,
  "request_id": "abc123..."
}
```

## HTTP mapping in the current reference bridge

The HTTP bridge splits errors into two categories:

- **Pre-pipeline validation errors** (malformed body, non-JSON
  payload, missing / invalid `Content-Length`, over-limit body size,
  invalid `X-Request-ID`): returned as **HTTP 400** with
  `code: "PIC_INVALID_REQUEST"`.
- **Pipeline decisions** (everything else, including internal errors
  that surface through the pipeline): returned as **HTTP 200** with
  `allowed: false` and the appropriate `code`. The HTTP status is a
  transport signal, not the verdict. Read `allowed` for the verdict
  and `error.code` for why.

Non-decision transport concerns:

- Unknown path: HTTP 404.
- Wrong method (e.g. `PUT /verify`): HTTP 405.

Rationale: keeping the pipeline decision surface at HTTP 200 lets
clients treat every non-2xx response as a transport/connectivity
problem and every 2xx response as a real PIC decision. It also means
downstream logging or metrics can count decisions cleanly.

## Retryability

"Retryable" here means: retrying the identical request against the
same guard, same policy, and same evidence artifacts is expected to
succeed. It does NOT mean the caller should always retry; that is an
application-level decision.

| Code | Retryable |
|------|-----------|
| `PIC_INVALID_REQUEST` | No. Fix the request first. |
| `PIC_LIMIT_EXCEEDED` | Sometimes; depends on which limit (see per-code notes). |
| `PIC_SCHEMA_INVALID` | No. Fix the proposal. |
| `PIC_VERIFIER_FAILED` | No. Fix the causal contract, provenance, or claims. |
| `PIC_TOOL_BINDING_MISMATCH` | No. Fix the `action.tool` value or the guard's expected tool. |
| `PIC_EVIDENCE_REQUIRED` | No. Attach evidence appropriate to the impact. |
| `PIC_EVIDENCE_FAILED` | No. Fix the failing evidence artifact. |
| `PIC_POLICY_VIOLATION` | No. Fix the policy or the action scope. |
| `PIC_INTERNAL_ERROR` | Yes. Indicates a transient guard-side condition; safe to retry. |

---

## Error codes

### `PIC_INVALID_REQUEST`

**Value:** `"PIC_INVALID_REQUEST"`.

**Meaning:** the request the guard received was not well-formed
enough to enter the PIC pipeline. This is a transport / envelope
failure, not a PIC verification failure.

**Where raised:**

- HTTP bridge: malformed body, non-JSON payload, missing / invalid
  `Content-Length`, body exceeding `MAX_REQUEST_BYTES`, invalid
  `X-Request-ID` header, read-timeout on the request body.
- Direct pipeline callers: not typically raised; requests are already
  in structured form.

**HTTP status:** 400 (Bad Request).

**Retryable:** no. The caller must fix the request before retrying.

**Example:**

```json
{
  "code": "PIC_INVALID_REQUEST",
  "message": "Content-Length header required"
}
```

### `PIC_LIMIT_EXCEEDED`

**Value:** `"PIC_LIMIT_EXCEEDED"`.

**Meaning:** the proposal exceeded a configured hard limit
(`PICEvaluateLimits`): proposal byte size, provenance count, claim
count, evidence count, or per-request evaluation time budget.

**Where raised:** `pipeline._enforce_limits`, and `verify_proposal`'s
time-budget check.

**HTTP status:** returned as HTTP 200 with the pipeline decision
envelope. (`Content-Length` header limits and body-size are enforced
earlier as `PIC_INVALID_REQUEST` / HTTP 400.)

**Retryable:** situational.

- Body-size / count limits: no, unless the caller can trim the
  payload and try again.
- Time budget: yes, if the overrun was caused by external latency
  (for example a slow keyring lookup or filesystem stat). The retry
  can also raise the budget explicitly via
  `PipelineOptions(time_budget_ms=...)`.

**Example:**

```json
{
  "code": "PIC_LIMIT_EXCEEDED",
  "message": "PIC evaluation exceeded time budget",
  "details": { "max_eval_ms": 500, "eval_ms": 612 }
}
```

### `PIC_SCHEMA_INVALID`

**Value:** `"PIC_SCHEMA_INVALID"`.

**Meaning:** the proposal did not pass JSON Schema validation against
`proposal_schema.json`. Missing required field, wrong type, unknown
`impact`, unknown `provenance[].trust` enum value, etc.

**Where raised:** `pipeline.verify_proposal` step 2 (JSON Schema
validation).

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** no. The proposal itself must be corrected.

**Example:**

```json
{
  "code": "PIC_SCHEMA_INVALID",
  "message": "PIC schema validation failed: 'impact' is a required property"
}
```

### `PIC_VERIFIER_FAILED`

**Value:** `"PIC_VERIFIER_FAILED"`.

**Meaning:** semantic post-schema validation failed. The proposal
parsed successfully but violated a PIC contract rule: the
`ActionProposal` model rejected it (pydantic validation),
`verify_causal_contract` found a high-impact action without trusted
provenance evidence, or a similar structural rule violation.

**Where raised:** `pipeline._instantiate_action_proposal`, and
implicitly by any `verify_causal_contract` violation.

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** no. The causal contract must be fixed (attach the
right evidence, mark provenance appropriately, or remove the
offending action).

**Example:**

```json
{
  "code": "PIC_VERIFIER_FAILED",
  "message": "PIC contract violation"
}
```

### `PIC_TOOL_BINDING_MISMATCH`

**Value:** `"PIC_TOOL_BINDING_MISMATCH"`.

**Meaning:** the proposal's `action.tool` did not match the tool the
guard was configured to accept. Signals either a misdirected proposal
(proposal was written for a different tool) or an adapter bug (guard
was constructed with the wrong `expected_tool`).

**Where raised:** `pipeline._verify_tool_binding` (calls
`ActionProposal.verify_with_context`).

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** no. Fix the proposal's `action.tool`, or reconfigure
the guard with the correct expected tool.

**Example:**

```json
{
  "code": "PIC_TOOL_BINDING_MISMATCH",
  "message": "Tool binding mismatch"
}
```

### `PIC_EVIDENCE_REQUIRED`

**Value:** `"PIC_EVIDENCE_REQUIRED"`.

**Meaning:** the resolved impact requires evidence per policy
(`require_evidence_for_impacts`), evidence verification is enabled
(`verify_evidence=True`), but the proposal carries no evidence
entries.

**Where raised:** `pipeline._run_evidence_verification` when the
policy demands evidence and none is present.

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** no. Attach evidence appropriate to the action's impact
before retrying.

**Example:**

```json
{
  "code": "PIC_EVIDENCE_REQUIRED",
  "message": "Evidence required for this impact but no evidence entries were provided",
  "details": { "tool": "payments_send", "impact": "money" }
}
```

### `PIC_EVIDENCE_FAILED`

**Value:** `"PIC_EVIDENCE_FAILED"`.

**Meaning:** at least one evidence entry failed verification. Hash
mismatch, unresolvable file, signature verification failure,
key-resolver failure, expired key, revoked key, malformed canonical
payload, canonical binding mismatch, and similar per-entry evidence
faults all surface here.

**Where raised:** `pipeline._run_evidence_verification` when
`EvidenceSystem.verify_all` returns a report with `ok=False`.

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** no. The failing evidence artifact must be corrected,
re-signed, or replaced. `details.failed` (when `PIC_DEBUG=1`)
enumerates the failing IDs.

**Example:**

```json
{
  "code": "PIC_EVIDENCE_FAILED",
  "message": "Evidence verification failed",
  "details": {
    "failed": [
      { "id": "invoice_hash", "message": "SHA-256 mismatch: expected a1b2..." }
    ]
  }
}
```

### `PIC_POLICY_VIOLATION`

**Value:** `"PIC_POLICY_VIOLATION"`.

**Meaning:** a policy-level (operator-defined) rule blocked the
action, distinct from PIC's protocol-level verifier rules. Reserved
for future policy surfaces; the reference implementation does not
currently emit this code in the shared pipeline. Consumers should
still handle it in error switches to avoid dead branches when
adapters begin using it.

**Where raised:** reserved for adapters or downstream integrators;
not raised in the shared `pipeline.verify_proposal` today.

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** no. The action or policy must change.

**Example:**

```json
{
  "code": "PIC_POLICY_VIOLATION",
  "message": "Tool 'payments_send' disabled by operator policy",
  "details": { "policy_rule": "payments_disabled_after_hours" }
}
```

### `PIC_INTERNAL_ERROR`

**Value:** `"PIC_INTERNAL_ERROR"`.

**Meaning:** an unexpected exception occurred in the guard itself,
not in the proposal or its evidence. Bug in a helper, misconfigured
dependency, filesystem transient, etc.

**Where raised:** `pipeline.verify_proposal`'s outer `except Exception` catch and the HTTP bridge's outer exception handler.

**HTTP status:** HTTP 200 with pipeline decision envelope.

**Retryable:** yes. `PIC_INTERNAL_ERROR` is treated as a transient
guard-side condition. Callers may safely retry with the same
request. If the same request produces the same code repeatedly, the
guard is misconfigured or crashed and needs operator attention.

**Example:**

```json
{
  "code": "PIC_INTERNAL_ERROR",
  "message": "Internal error in PIC verification pipeline"
}
```

---

## Cross-language parity

TypeScript consumers get the shared PIC error codes via
[`integrations/openclaw/lib/types.ts`](../integrations/openclaw/lib/types.ts).
That client-side file additionally exports a client-side-only
`PIC_BRIDGE_UNREACHABLE` value that is NOT emitted by the Python
guard; it is set by the openclaw client when the HTTP bridge is not
reachable at all (network / socket layer). Do not treat it as a PIC
protocol error.

## Adding a new error code

1. Add the enum member to
   [`sdk-python/pic_standard/errors.py`](../sdk-python/pic_standard/errors.py)
   with a docstring.
2. Add a mirroring string literal to the TS union in
   [`integrations/openclaw/lib/types.ts`](../integrations/openclaw/lib/types.ts).
3. Add a level-3 heading under the "Error codes" section here with
   the same six fields as the sections above: Value, Meaning, Where
   raised, HTTP status, Retryable, Example.
4. If OpenAPI has landed, add the code to the `PICError.code` enum in
   [`openapi/pic-bridge.v1.yaml`](../openapi/pic-bridge.v1.yaml).
5. Append a bullet to the current `[UNRELEASED]` entry in
   [`CHANGELOG.md`](../CHANGELOG.md).

A regression test in `tests/` verifies that the count of level-3
headings under `## Error codes` matches the number of `PICErrorCode`
enum members, so this checklist is enforced mechanically.
