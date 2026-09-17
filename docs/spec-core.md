# PIC Core Verifier Semantics — DRAFT

> **Status:** DRAFT — PIC/1.0 core verifier semantics.
> Not final-normative until PIC v1.0.
> Published for community feedback per ROADMAP §1.3.
>
> **What this DRAFT does:** restates the normative core verifier
> semantics that were previously scattered across
> [RFC-0001](RFC-0001-pic-standard.md) (Core Claims, Security
> Properties, Conformance Levels, Impact Taxonomy, Verification Rule),
> [`causal_logic.md`](causal_logic.md) (causal taint formalization),
> [`migration-trust-sanitization.md`](migration-trust-sanitization.md)
> (trust axiom + sanitization timeline), and the `pic_standard.verifier`
> + `pic_standard.pipeline` reference implementations, into a single
> implementer-facing reference using BCP 14 language.
>
> **What is still open:** see Appendix C ("Open Questions Registry")
> for IDed open questions tracked through DRAFT → final cleanup. DRAFT
> text uses proposed normative language to preview intended PIC/1.0
> semantics; these requirements are not binding until the specification
> is formally adopted.
>
> **Cross-references:** This DRAFT CITES frozen normative artifacts
> ([RFC-0001](RFC-0001-pic-standard.md) anchor) and companion
> specification-track documents
> ([`spec-evidence.md`](spec-evidence.md)) rather than restating their
> normative content. Where a future PIC revision changes the cited
> contract, this DRAFT will be updated in the same release. Conflicts
> are resolved per §14 ("Normative Precedence and Conflict
> Resolution"), not by silent re-interpretation.

---

## 1. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**,
and **OPTIONAL** in this document are to be interpreted as described
in [BCP 14](https://www.rfc-editor.org/info/bcp14) ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119),
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only
when, they appear in all capitals, as shown here.

All protocol rules in this document are **Normative**. Sections,
blocks, and subsections explicitly labeled "Example", "Rationale",
"Migration Note", or "Implementation Note" are **Informative** and
do not impose conformance requirements.

---

## 2. Scope & Conformance Profiles

This specification cites
[`RFC-0001 §Conformance Levels`](RFC-0001-pic-standard.md#conformance-levels)
as the historical anchor and decouples it into three named profiles
that an implementation MUST self-declare. The profiles defined by
this specification family are:

- **`PIC-Core`** — Action Proposal parsing, impact taxonomy, trust
  sanitization, tool binding, verifier outcomes. Passes
  `conformance/core/` and `conformance/trust_sanitization/`. Defined
  normatively in this specification.
- **`PIC-Evidence`** — evidence object parsing, hash verification,
  signature verification, key lifecycle handling, trust upgrade.
  Passes `conformance/evidence/`. Defined normatively in
  [`spec-evidence.md`](spec-evidence.md).
- **`PIC-Full`** — both `PIC-Core` and `PIC-Evidence`.

An implementation MUST state which profile(s) it implements. An
implementation MUST NOT claim `PIC-Full` unless it satisfies both
`PIC-Core` and `PIC-Evidence`.

A conformance claim MUST identify both the profile name and the
specification snapshot/version being claimed, for example
`PIC-Core / DRAFT at tag v0.9.0-alpha.2`,
`PIC-Evidence / DRAFT at tag v0.9.0-alpha.2`, or `PIC-Full / v1.0`
once PIC v1.0 is finalized. A claim to a DRAFT profile MUST NOT be
represented as final PIC v1.0 conformance.

`PIC-Core` MAY be deployed independently of a standalone
`PIC-Evidence` implementation. However, this repository's
`conformance/trust_sanitization/` suite includes evidence-backed
matrix cells. An implementation claiming `PIC-Core` conformance
against this repository MUST produce the expected outcomes for
those cells, either by implementing the required
evidence-verification behavior itself or by delegating to a
`PIC-Evidence`-compatible component. `PIC-Core` does not require
a standalone evidence API or signature-evidence conformance unless
the implementation also claims `PIC-Evidence`.

A `PIC-Core` implementation that does not implement `PIC-Evidence`
MUST NOT mark evidence entries as verified and MUST NOT perform
authority-bearing evidence-driven trust upgrade itself unless it
implements the relevant `PIC-Evidence` rules or delegates to a
component that does.

---

## 3. Unknown Fields and Extensions

Unknown fields in protocol objects MUST be handled according to the
active JSON Schema and profile-specific rules. Implementations MUST
NOT silently interpret unknown fields as security-relevant
authorization, trust, policy, evidence, or tool-binding data unless
those fields are defined by a versioned PIC specification.

Future extension fields SHOULD use a reserved extension namespace
such as `x_` or `extensions`, but extension data MUST NOT affect
verifier allow/block decisions unless the implementation explicitly
opts into the corresponding extension specification.

This rule applies uniformly to Action Proposals (§4), provenance
entries (§6), claims (§4), action objects (§4), and evidence
entries (per [`spec-evidence.md §3`](spec-evidence.md#3-unknown-fields-and-extensions)).

---

## 4. Action Proposal Wire Format

An Action Proposal is a JSON object conforming to the PIC/1.0 JSON
Schema (`sdk-python/pic_standard/schemas/proposal_schema.json`). Its
required and optional fields are defined in
[`RFC-0001 §Protocol Summary`](RFC-0001-pic-standard.md#protocol-summary-pic10-action-proposal):

| Field | Type | Presence | Source of normative content |
|---|---|---|---|
| `protocol` | string (const `"PIC/1.0"`) | MUST | [RFC-0001 §Required Fields](RFC-0001-pic-standard.md#required-fields) |
| `intent` | string | MUST | RFC-0001 §Required Fields |
| `impact` | enum (see §5) | MUST | RFC-0001 §Impact Taxonomy |
| `provenance` | array of `{id, trust, source?}` | MUST | RFC-0001 §Required Fields + §6 of this DRAFT |
| `claims` | array of `{text, evidence[]}` | MUST | RFC-0001 §Required Fields |
| `action` | object `{tool, args}` | MUST | RFC-0001 §Required Fields + §7 of this DRAFT |
| `evidence` | array of evidence entries | OPTIONAL | [`spec-evidence.md §4`](spec-evidence.md#4-evidence-object-format) |

Implementations MUST validate every Action Proposal against the
PIC/1.0 JSON Schema before any other verifier rule is applied. A
schema-validation failure MUST result in the action being blocked
with `PIC_SCHEMA_INVALID` (see §9).

This specification does NOT redefine the wire-format field set; it
restates the validation discipline in BCP 14 language. For any
release snapshot, the authoritative wire format is the
`proposal_schema.json` artifact at that release tag. Historical
fingerprints in RFC-0001 anchor earlier snapshots; they do not
silently override versioned schema changes made in later release
tags.

---

## 5. Impact Taxonomy & Causal Taint

### 5.1 Impact taxonomy

The PIC/1.0 impact taxonomy is the closed enum defined in
[`RFC-0001 §Impact Taxonomy`](RFC-0001-pic-standard.md#impact-taxonomy):

| Class | Risk Level | Evidence Requirement (per RFC-0001) |
|---|---|---|
| `read` | Low | Untrusted provenance allowed |
| `write` | Low | Untrusted provenance allowed |
| `external` | Low | Untrusted provenance allowed |
| `compute` | Low | Untrusted provenance allowed |
| `money` | **High** | Trusted evidence required |
| `privacy` | **High** | Trusted evidence required |
| `irreversible` | **High** | Trusted evidence required (multi-source RECOMMENDED) |

Implementations MUST reject proposals carrying an `impact` value
outside this enum with `PIC_SCHEMA_INVALID` (the schema enforces
the closed enum).

### 5.2 Causal taint

Per [`causal_logic.md`](causal_logic.md), PIC's causal-taint axiom
is:

> Any plan generated by an LLM that relies solely on Tainted data is
> itself Tainted. Executing a High-Impact Action (money / privacy /
> irreversible) using a Tainted plan is a Violation.

Where "Tainted" data is data originating from `untrusted` provenance,
and "Untrusted" is the trust level on provenance entries before any
authority-bearing evidence-driven trust upgrade (§6.2).

Normatively, for any Action Proposal whose `impact` is in
`{money, privacy, irreversible}`:

- at least one entry in `claims[].evidence[]` MUST contain an ID
  matching a `provenance[].id` whose effective trust level (§6.4)
  is `trusted`;
- if no such causal chain exists, the verifier MUST reject the
  proposal with `PIC_VERIFIER_FAILED` (see §9).

When a matching authority-bearing `evidence[].id` is successfully
verified and is permitted by `PIC-Evidence` trust-upgrade rules, it
MAY upgrade the corresponding `provenance[].id` to effective
`trusted` status for the current verification only
(see [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules)).

The causal-taint check is an ID-binding and trust-level check. It
does NOT require the verifier to determine whether `claims[].text`
is factually true, semantically sufficient, or complete. Natural
language claim evaluation is outside the `PIC-Core` protocol
boundary unless a future profile defines machine-checkable claim
semantics.

**Rationale (Informative).** Causal taint prevents prompt-injection
attacks (T1) and hallucination-to-financial-loss attacks (T2) in
[`RFC-0001 §Threat Model`](RFC-0001-pic-standard.md#threat-model)
from triggering high-impact actions without verifiable evidence.

---

## 6. Provenance & Trust Model

### 6.1 Provenance entry format

Each `provenance[]` entry is an object with:

- `id` (string, MUST) — stable identifier, used for ID binding with
  `claims[].evidence[]` and `evidence[].id` per
  [`RFC-0001 §ID Binding Convention`](RFC-0001-pic-standard.md#id-binding-convention).
- `trust` (enum, MUST) — the only conformant PIC/1.0 trust values
  are `"trusted"` and `"untrusted"`. The legacy value
  `"semi_trusted"` was removed from the schema in v0.9.0a1;
  proposals carrying it fail JSON Schema validation with
  `PIC_SCHEMA_INVALID`. Historical migration notes are in
  Appendix A.
- `source` (string, OPTIONAL) — human-readable origin descriptor;
  Informative.

**Uniqueness (Normative).** The `provenance[].id` values in a single
proposal MUST be unique. Duplicate IDs make trust-upgrade binding,
evidence resolution, and causal-taint interpretation ambiguous.
Uniqueness is evaluated over the parsed JSON string values exactly
as provided after JSON parsing and after the lone-surrogate
rejection required by PIC-CJSON/1.0. Implementations MUST NOT trim,
case-fold, Unicode-normalize, alias, or otherwise transform
`provenance[].id` values before comparing them for uniqueness. On
duplicate IDs, the verifier MUST reject the proposal with
`PIC_DUPLICATE_ID` (see §9.1).

### 6.2 ID binding for trust upgrade

Per [`RFC-0001 §ID Binding Convention`](RFC-0001-pic-standard.md#id-binding-convention),
evidence IDs SHOULD be stable identifiers reused across `provenance`,
`claims`, and `evidence` objects. The binding works as follows:

1. `provenance[].id` identifies an input source and its initial
   trust level.
2. `claims[].evidence[]` references provenance IDs supporting the
   claim.
3. `evidence[].id` matches a provenance ID; successful verification
   of authority-bearing evidence permitted by
   [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules)
   upgrades that provenance entry's effective trust (§6.4) to
   `trusted` for the duration of the current verification.

Implementations MUST apply the trust upgrade BEFORE the causal-taint
check (§5.2) so that successful authority-bearing evidence
verification can bridge an otherwise untrusted provenance into
satisfying the gating rule.

### 6.3 Trust as output, not input

Per [`RFC-0001 §Security Properties #5`](RFC-0001-pic-standard.md#security-properties),
trust is an *output* of cryptographic verification, not an *input*
assumption. Under `strict_trust=True` (§10), self-asserted
`trust="trusted"` on inbound provenance is sanitized to `untrusted`
before any verifier rule runs; only successful authority-bearing
evidence verification permitted by `PIC-Evidence` trust-upgrade
rules can subsequently upgrade it back to `trusted`.

### 6.4 Effective trust

"Effective trust" is the trust value used by the verifier after
schema validation, trust sanitization, and authority-bearing
evidence-driven trust upgrades for the current proposal verification.

Effective trust is computed in this order:

1. parse and validate provenance trust values according to the
   active schema;
2. apply trust sanitization when `strict_trust=True` (§10);
3. apply successful authority-bearing evidence-driven trust upgrades
   permitted by `PIC-Evidence` (§6.2 and
   [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules)).

Effective trust is scoped to the current verification only. It MUST
NOT be persisted back into the proposal, cached across proposals,
or treated as a durable reputation signal.

---

## 7. Tool-Binding Integrity

Per [`RFC-0001 §Security Properties #3`](RFC-0001-pic-standard.md#security-properties),
the proposal's declared `action.tool` MUST match the actual tool
being invoked at the dispatch site. The verifier API surfaces this
via an `expected_tool` option (or equivalent integration-level
binding).

### 7.1 Exact string equality

- when the verifier is called with an `expected_tool` value, it
  MUST compare `expected_tool` against `proposal.action.tool` using
  exact string equality after JSON parsing. Implementations MUST NOT
  apply whitespace trimming, whitespace repair, case-folding,
  Unicode normalization, alias expansion, prefix matching, or
  tool-name rewriting when enforcing tool binding.
- on mismatch, the verifier MUST reject the proposal with
  `PIC_TOOL_BINDING_MISMATCH` (see §9);
- when no `expected_tool` is configured, tool-binding integrity is
  the caller's responsibility and the verifier does not enforce
  this rule.

**Rationale (Informative).** Tool-binding integrity prevents the
"agent proposed one action but attempted another" failure mode —
e.g., a proposal declaring `action.tool="docs_search"` being used
to dispatch `payments_send`. Without this check, an attacker could
craft a low-impact proposal and reuse it to authorize a high-impact
call.

### 7.2 Representation vs. normalization (Normative)

Unless a PIC specification section explicitly defines normalization,
implementations MUST NOT trim, case-fold, Unicode-normalize, alias,
repair, re-pad, or otherwise transform security-relevant protocol
values before validating requirements defined as exact.

This rule applies at least to `provenance[].id` (§6.1),
`expected_tool`, `proposal.action.tool` (§7.1), SHA-256 digest
strings ([`spec-evidence.md §4`](spec-evidence.md#4-evidence-object-format)),
and Base64-encoded signature strings
([`spec-evidence.md §4`](spec-evidence.md#4-evidence-object-format)).
Future spec fields defined as exact values inherit the principle
unless they explicitly declare their own normalization.

The rule does NOT prohibit normalization that a PIC specification
section explicitly defines — most notably, PIC Canonical JSON v1
([`canonicalization.md`](canonicalization.md)) is a defined
transformation applied to specific inputs at specific points in
verification.

---

## 8. Verifier Rules

The verifier MUST enforce the following fail-closed checks. This
section specifies required invariants, not a total execution order,
except where order is security-relevant and stated explicitly.

Implementations MAY enforce DoS-hardening limits before or during
any step below. A limit breach MUST fail closed with
`PIC_LIMIT_EXCEEDED`.

Required invariants:

- **Schema validation** (§4). Implementations MUST validate every
  Action Proposal against the PIC/1.0 JSON Schema and reject schema
  failures with `PIC_SCHEMA_INVALID`.
- **Duplicate provenance-ID rejection** (§6.1). After JSON Schema
  validation, implementations MUST reject any proposal containing
  duplicate `provenance[].id` values with `PIC_DUPLICATE_ID`.
- **Tool-binding check** (§7), when `expected_tool` is configured.
  Mismatch MUST be rejected with `PIC_TOOL_BINDING_MISMATCH`.
- **Trust sanitization** (§10), when `strict_trust=True`.
- **Authority-bearing evidence-driven trust upgrade**, delegated to
  `PIC-Evidence` (per
  [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules))
  when applicable per policy and the proposal's evidence array.
- **Causal-taint check** (§5.2). High-impact proposals lacking a
  trusted-evidence causal chain MUST be rejected with
  `PIC_VERIFIER_FAILED`.

Order constraints that are security-relevant and MUST be honored:

- Duplicate-ID detection MUST run after JSON Schema validation and
  before tool-binding, authority-bearing evidence-driven trust
  upgrade, or causal-taint evaluation.
- When `expected_tool` is configured, tool-binding MUST be checked
  before evidence verification or causal-taint evaluation for
  purposes of error-code precedence (§9.2).
- Trust sanitization MUST run before authority-bearing
  evidence-driven trust upgrade.
- Authority-bearing evidence-driven trust upgrade MUST run before
  the causal-taint check.
- Tool-binding MUST be checked before dispatching the actual tool.

Any check's failure produces a fail-closed outcome
([`RFC-0001 §Security Properties #1`](RFC-0001-pic-standard.md#security-properties));
there is no fallback to "allow anyway."

**Implementation Note (Informative).** The reference implementation
in `sdk-python/pic_standard/pipeline.py` applies these checks in a
specific order that satisfies all the above constraints. Other
implementations MAY choose a different order so long as the
security-relevant ordering constraints are preserved.

---

## 9. Verifier Outcomes

### 9.1 Error Code Stability

The error code identifiers defined by this specification family are
the **portable error-code namespace** for PIC implementations.
Reference implementations and integration mirrors, including
`sdk-python/pic_standard/errors.py` and
`integrations/openclaw/lib/types.ts`, MUST mirror the applicable
stable codes for the release snapshot they implement. When a
conforming implementation reports a failure covered by one of the
semantics below, it MUST emit the corresponding identifier and MUST
NOT substitute implementation-local or message-text-only identifiers.
Reserved identifiers are listed for compatibility but are not
required to be emitted unless their stated semantics are implemented.

Codes relevant to this specification snapshot:

- `PIC_SCHEMA_INVALID` — PIC/1.0 JSON Schema validation failure on
  the proposal envelope. Emitted by the schema-validation invariant
  in §8. Applies to any failure that could be expressed as a
  JSON Schema constraint on `proposal_schema.json` (missing required
  field, wrong type, unknown enum value, invalid string format).
  The JSON Schema is the portable contract; conforming
  implementations MUST reach this code at the same boundary
  regardless of validator library (`jsonschema` in Python, Ajv in
  TypeScript, `jsonschema` in Rust, etc.).
- `PIC_DUPLICATE_ID` — a proposal carries two or more
  `provenance[].id` values that are equal within the same proposal.
  This is a post-schema semantic validation error: JSON Schema
  validation may pass even when duplicate `provenance[].id` values
  are present, because the schema dialect used by
  `proposal_schema.json` does not express this constraint portably.
  Conforming implementations MUST emit `PIC_DUPLICATE_ID` after JSON
  Schema validation and before tool-binding, evidence, or
  causal-contract evaluation, because duplicate IDs poison the
  causal interpretation of the provenance array (§6.1). Uniqueness
  comparison follows the representation rule in §7.2 — no trimming,
  case-folding, Unicode normalization, or aliasing.
- `PIC_TOOL_BINDING_MISMATCH` — declared `action.tool` does not
  match the `expected_tool` configured at the verification call
  site. Emitted by the tool-binding invariant in §8.
- `PIC_EVIDENCE_REQUIRED` / `PIC_EVIDENCE_FAILED` — evidence-layer
  rejection codes defined normatively in
  [`spec-evidence.md`](spec-evidence.md). They participate in the
  core precedence order only after schema validation, duplicate-ID
  detection, and tool binding have passed (§9.2).
- `PIC_VERIFIER_FAILED` — fallback semantic verifier rejection after
  schema validation for PIC contract violations not covered by a more
  specific stable error code. This includes causal-rule rejection
  where a high-impact action lacks the required trusted-evidence
  causal chain. Under `strict_trust=True`, self-asserted trusted
  provenance sanitized to untrusted can cause a high-impact proposal
  to fail this rule.

  **Semantic boundary vs specific error codes (Normative):**

  - If a failure could be expressed as a JSON Schema constraint on
    `proposal_schema.json`, it MUST emit `PIC_SCHEMA_INVALID`.
  - If a post-schema semantic failure has a more specific stable
    PIC error code, the implementation MUST emit that specific code
    according to §9.2.
  - Otherwise, if it is a semantic PIC contract violation, it MUST
    emit `PIC_VERIFIER_FAILED`.

  This boundary is language-independent. An implementation whose
  parsing layer catches something the JSON Schema could have caught
  MUST still classify it as `PIC_SCHEMA_INVALID`. The prior
  "pydantic model-construction" phrasing in this DRAFT was
  descriptive of the Python reference and is not normative.

- `PIC_INVALID_REQUEST` — request shape malformed before
  verification can begin. Emitted by guard/bridge layers (MCP guard,
  HTTP bridge) when the request envelope itself is invalid (missing
  `__pic` argument when policy required it, proposal not a JSON
  object, malformed/non-JSON body). NOT emitted by the verifier
  core.
- `PIC_LIMIT_EXCEEDED` — DoS-hardening limit breached (proposal
  size cap, item-count caps on `provenance`/`claims`/`evidence`,
  evaluation time budget, tool execution timeout). Emitted by the
  DoS-hardening enforcement described in §8.
- `PIC_INTERNAL_ERROR` — unexpected exception caught at the pipeline
  or integration boundary. Defensive catch-all.
- `PIC_POLICY_VIOLATION` — **Reserved.** Defined in the enum and
  TypeScript mirror for backward compatibility with earlier PIC
  versions. The current Python reference implementation does NOT
  emit this code; policy-rule rejections are reported as
  `PIC_VERIFIER_FAILED` (see CHANGELOG v0.6.x). Implementations
  MUST NOT rely on receiving this code from the reference verifier;
  they MAY emit it themselves for distinct policy-rule rejection
  paths if their architecture separates "policy" from "verifier."

The freeform human-readable messages accompanying each error code
are **Informative**. They MAY vary across implementations, language
runtimes, and locales without affecting conformance. Programmatic
consumers (CI gates, dashboards, cross-implementation parity tests)
MUST pattern-match on the error code, NOT on the message text.

Adding a new error code is a versioned change. Removing or renaming
an existing code is a backward-incompatible change and MUST go
through the same governance as a wire-format change (see §13).
Repurposing an existing code's semantics is also a
backward-incompatible change.

### 9.2 Error Code Precedence

When multiple failures are present in a single proposal,
conforming implementations MUST emit codes in the following
precedence order (highest first):

1. `PIC_SCHEMA_INVALID`
2. `PIC_DUPLICATE_ID`
3. `PIC_TOOL_BINDING_MISMATCH`
4. `PIC_EVIDENCE_REQUIRED` / `PIC_EVIDENCE_FAILED`
   (see [`spec-evidence.md`](spec-evidence.md) for the boundary
   between these two evidence-layer codes)
5. `PIC_VERIFIER_FAILED`

Rationale: schema validation is the earliest and most objective
gate; duplicate-ID detection is next because uniqueness cannot be
expressed as a JSON Schema constraint on `proposal_schema.json` but
poisons every subsequent evaluation that binds against
`provenance[].id`; tool binding is a contract-level identity check
that should be evaluated before evidence verification or
causal-contract evaluation; the evidence-layer codes gate on the
resolved impact and evidence surface; `PIC_VERIFIER_FAILED` is the
semantic catch-all for post-schema PIC contract violations.

**Worked examples (Informative).**

- Schema violation (e.g., uppercase SHA-256 hex) + duplicate ID →
  `PIC_SCHEMA_INVALID`. The schema-layer failure fires first; the
  duplicate-ID check does not need to run.
- Valid schema + duplicate ID + tool-binding mismatch →
  `PIC_DUPLICATE_ID`. The proposal parsed and validated, but
  ambiguous provenance IDs are surfaced before tool binding.
- Valid schema + unique IDs + tool-binding mismatch →
  `PIC_TOOL_BINDING_MISMATCH`. The tool-binding invariant is the
  highest-precedence remaining failure.
- Valid schema + unique IDs + valid tool binding + missing required
  evidence → `PIC_EVIDENCE_REQUIRED`.
- Valid schema + unique IDs + valid tool binding + evidence
  verification passes + causal-taint rule rejects the high-impact
  action → `PIC_VERIFIER_FAILED`.

`PIC_LIMIT_EXCEEDED`, `PIC_INVALID_REQUEST`, `PIC_INTERNAL_ERROR`,
and `PIC_POLICY_VIOLATION` are outside this core
verification-failure ordering. `PIC_INVALID_REQUEST` is a
transport / envelope failure before the PIC pipeline begins.
`PIC_LIMIT_EXCEEDED` short-circuits at the configured guard limit
that was exceeded, whether proposal size / count limits or the
evaluation time budget. `PIC_INTERNAL_ERROR` is a defensive
catch-all; `PIC_POLICY_VIOLATION` is reserved for downstream
adapters.

This precedence resolves `OQ-CORE-001` (see Appendix C); the
`PIC_DUPLICATE_ID` position is added in v0.9.0a2 (§9.1).

---

## 10. Trust Axiom & Sanitization

### 10.1 The Trust Axiom (v0.7.5+)

Per [`RFC-0001 §Core Claims #6`](RFC-0001-pic-standard.md#core-claims)
and [`migration-trust-sanitization.md`](migration-trust-sanitization.md):

> Trust is verifier-derived, not producer-asserted. In v0.8.3,
> the only conformant path from `untrusted` to `trusted` is
> successful **signature**-evidence verification. Hash evidence
> establishes content-integrity but does not, by itself, upgrade
> trust; see [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules).

This axiom is enforced behaviorally via the `strict_trust` option.
As of v0.9.0a2, `strict_trust=True` is the secure default; the
options below describe the two callable modes:

- when `strict_trust=True` (secure default), the verifier sanitizes
  all inbound `provenance[].trust` values from `"trusted"` to
  `"untrusted"` before authority-bearing evidence-driven trust
  upgrade and before the causal-taint check.
- when `strict_trust=False` (legacy compatibility opt-in), the
  verifier accepts inbound `provenance[].trust` values at face
  value. Constructing options with `strict_trust=False` emits an
  implementation-visible legacy-mode warning; the Python reference
  implementation raises `PICLegacyTrustModeWarning` at
  `PipelineOptions` construction. Additionally, when self-asserted
  `trust="trusted"` is present and authority-bearing evidence
  verification will not derive effective trust for the proposal, an
  implementation SHOULD surface an operator-visible migration
  signal; the Python reference implementation emits
  `PICTrustFutureWarning`. Warning class names are
  implementation-specific and Informative.

### 10.2 Sanitization mechanics

Under `strict_trust=True`, implementations MUST:

1. iterate the `provenance` array;
2. for each entry whose `trust` value is `"trusted"`, replace the
   in-memory value with `"untrusted"`;
3. apply the sanitization BEFORE authority-bearing evidence-driven
   trust upgrade (§6.2), so that only evidence permitted by
   `PIC-Evidence` trust-upgrade rules can cause a provenance entry
   to reach effective `"trusted"` status (§6.4).

Sanitization is in-memory and applies only to the current
verification; the on-the-wire proposal is not modified.

### 10.3 Timeline

The trust-axiom rollout is documented normatively in
[`migration-trust-sanitization.md §Timeline`](migration-trust-sanitization.md#timeline):

| Version | Behavior |
|---|---|
| v0.7.x | Inbound trust accepted at face value; no warnings. |
| v0.8.0 | `PICTrustFutureWarning` emitted; `strict_trust` option added (default `False`). |
| v0.8.1 | `PICSemiTrustedDeprecationWarning` for `trust="semi_trusted"`; value normalized to `"untrusted"` at model-validation boundary. |
| v0.9.0a1 | `"semi_trusted"` removed from the schema enum. `PICSemiTrustedDeprecationWarning` and the v0.8.1 model-validation normalization are deleted. Proposals carrying it fail validation with `PIC_SCHEMA_INVALID`. |
| v0.9.0a2 | Secure default flipped: `strict_trust=True` becomes the default in `PipelineOptions`. `strict_trust=False` remains callable as an explicit legacy compatibility opt-in and emits `PICLegacyTrustModeWarning` at `PipelineOptions` construction. |
| v1.0 (planned) | A future major release may consider removing legacy trust mode (`strict_trust=False`), but removal is not scheduled in the v0.9.x series. |

As of v0.9.0a2 the secure default is `strict_trust=True`; conforming
implementations MUST default to secure trust mode. Implementations
that need legacy behavior for compatibility with pre-v0.9.0a2
producers MAY expose `strict_trust=False` as an explicit opt-in and
MUST surface an implementation-visible legacy-mode signal at that
opt-in.

---

## 11. Policy Boundary

Per [`RFC-0001 §Core Claims #5`](RFC-0001-pic-standard.md#core-claims):
PIC enforces protocol-level rules. Operator policy decides which
tools and impact classes require PIC proposals at all (via
configuration analogous to `require_pic_for_impacts`), and which
impact classes require evidence (via `require_evidence_for_impacts`).
Policy configuration is implementation-defined.

Policy engines MAY impose stricter requirements than this protocol.
However, a policy engine MUST NOT reinterpret PIC protocol fields
(`provenance[].trust`, `claims[].evidence[]`, `action.tool`,
`impact`, etc.) in a way that changes their normative meaning.
Policy MAY deny an action that PIC would otherwise allow; policy
MUST NOT make an invalid PIC proposal valid.

**Implementation Note (Informative).** A policy engine that wants
to require a specific provenance source for high-impact actions can
do so by adding its own pre-verifier check that inspects the
proposal and rejects when its policy is violated. It cannot do so
by treating an `untrusted` provenance as `trusted` for its own
purposes — that would be a reinterpretation of the protocol field's
meaning.

---

## 12. Conformance Assertions

The executable contract for this specification is the set of
conformance vectors listed below. An implementation claiming
conformance to this DRAFT MUST produce the same pass/fail verdicts,
expected error codes, and diagnostics for every listed vector. The
Python runner (`python -m conformance.run`) is the current reference
runner for this repository; non-Python implementations MAY use an
equivalent runner, provided the selected vectors and reported
outcomes match the reference contract.

| Vector set | Path | Modes |
|---|---|---|
| Core verifier (allow + block) | `conformance/core/` | `core` |
| Trust sanitization (strict × verify matrix) | `conformance/trust_sanitization/` | `trust_sanitization` |

Where this DRAFT's prose and the conformance vectors disagree, the
discrepancy MUST be resolved by updating EITHER the DRAFT or the
vectors before a conformance claim is asserted. The discrepancy MUST
NOT be resolved by silent re-interpretation.

See Appendix B for a per-vector cross-reference mapping conformance
vector IDs to the section of this DRAFT each one exercises.

---

## 13. Backward-Compatible Changes vs Breaking Changes

The following changes are backward-incompatible and MUST NOT occur
within the same stable protocol version:

- removing or renaming protocol fields;
- changing the meaning of an existing impact class;
- changing the trust-upgrade semantics of evidence verification;
- changing canonicalization or digest-binding rules;
- removing or renaming error-code identifiers;
- changing allow/block verdicts for existing conformance vectors
  without a versioned migration note.

The following changes MAY be backward-compatible if existing
conforming implementations remain valid:

- adding new optional fields;
- adding new conformance vectors;
- adding new stricter policy profiles;
- adding new error-code identifiers reserved for future use.

The `strict_trust=True` default flip at v1.0 (§10.3) is a
**deliberate** backward-incompatible change documented in
[`migration-trust-sanitization.md`](migration-trust-sanitization.md);
the migration path is the published timeline and an
operator-visible migration signal. The Python reference
implementation uses `PICTrustFutureWarning`; warning class names
are implementation-specific and Informative.

---

## 14. Normative Precedence and Conflict Resolution

This document is DRAFT until PIC v1.0. Where its requirements
interact with the frozen normative artifacts of PIC/1.0, the
following precedence applies:

1. [`RFC-0001-pic-standard.md`](RFC-0001-pic-standard.md) —
   defensive publication anchor for early PIC/1.0 requirements.
   Requirements that originate in RFC-0001 remain authoritative
   unless a later release-tagged specification document or schema
   artifact explicitly amends them. Later release-tagged amendments
   MUST be written down in the release snapshot and MUST NOT occur
   by silent re-interpretation.
2. [`canonicalization.md`](canonicalization.md) — PIC-CJSON/1.0.
   Byte-level serialization rules originate here. Later
   release-tagged revisions may add explicit rejection rules or
   clarifications without changing canonical bytes; such changes
   MUST be recorded in the relevant release snapshot.
3. [`spec-evidence.md`](spec-evidence.md) — companion DRAFT
   specifying `PIC-Evidence` semantics. Evidence-side requirements
   originate there; this DRAFT cites them and adds the verifier-side
   ordering (§8) and trust-upgrade application point (§6.2) that
   tie evidence verification into the core verifier flow.
4. This DRAFT — restates post-RFC normative core verifier semantics
   that were previously scattered across `causal_logic.md`,
   `migration-trust-sanitization.md`, and the reference
   implementation.

If text in this DRAFT appears to conflict with a higher-precedence
artifact, the conflict MUST be raised as an Open Question (Appendix
C) and resolved in a subsequent revision. The DRAFT MUST NOT be
treated as overriding higher-precedence artifacts by silent
re-interpretation.

---

## Appendix A. `semi_trusted` Removal (Historical Migration Note)

The `provenance[].trust` enum historically included `"semi_trusted"`.
This value was deprecated in v0.8.1 and removed in v0.9.0a1.
Starting in v0.9.0a1, proposals carrying it fail JSON Schema
validation with `PIC_SCHEMA_INVALID`.

| Version | Behavior |
|---|---|
| through v0.8.0 | `"semi_trusted"` accepted; silently sanitized to `"untrusted"` only in `strict_trust=True` mode. |
| v0.8.1 through v0.8.3 | `PICSemiTrustedDeprecationWarning` emitted on any `"semi_trusted"` observed; value normalized to `"untrusted"` at the `Provenance.trust` pydantic field validator, in ALL modes. Schema enum still accepted the string. |
| v0.9.0a1 | `"semi_trusted"` removed from the JSON Schema enum. Proposals carrying it fail validation with `PIC_SCHEMA_INVALID`. `PICSemiTrustedDeprecationWarning` and the normalization validator are deleted. |

Producers that still emit `"semi_trusted"` MUST migrate to
`"untrusted"`. If the proposal carries authority-bearing verifiable
evidence, such as signature evidence accepted by the verifier
keyring, the verifier can derive effective `"trusted"` status
through evidence verification per §6.2. See
[`migration-trust-sanitization.md §FAQ`](migration-trust-sanitization.md#faq)
for the full migration guide.

---

## Appendix B. Conformance Vector Cross-Reference (Informative)

Maps conformance vector IDs to the section(s) of this DRAFT each
one exercises.

### B.1 Core vectors (`conformance/core/`)

| Vector ID | Section(s) exercised |
|---|---|
| `core-allow-001-read-only` | §5.1 (low-impact path), §6 |
| `core-allow-002-trusted-money` | §5.2 (high-impact + trusted bridge), §6 |
| `core-block-001-untrusted-money` | §5.2 (causal-taint rejection), §9.1 (`PIC_VERIFIER_FAILED`) |
| `core-block-002-tool-binding-mismatch` | §7, §9.1 (`PIC_TOOL_BINDING_MISMATCH`) |

### B.2 Trust-sanitization vectors (`conformance/trust_sanitization/`)

The 24-vector matrix covers six `matrix_id` bases × four
`(strict_trust, verify_evidence)` cells each. All exercise §10
(trust axiom and sanitization) and §6.4 (effective trust). Block
cells additionally exercise §9.1 (`PIC_VERIFIER_FAILED`).

| `matrix_id` | Sections exercised |
|---|---|
| `compute_risk` | §5.1 (low-impact), §10 (all four cells allow) |
| `read_only_query` | §5.1 (low-impact), §10 (all four cells allow) |
| `financial_hash_ok` | §5.2 (high-impact), §6.2 (authority-bearing evidence-driven trust upgrade), §6.4 (effective trust), §10 (sanitization × verify matrix) |
| `financial_irreversible` | §5.2 (money-impact), §10 (strict-true cells block with `PIC_VERIFIER_FAILED`) |
| `privacy_risk` | §5.2 (privacy-impact), §10 (strict-true cells block) |
| `robotic_action` | §5.2 (irreversible-impact), §10 (strict-true cells block) |

See [`conformance/trust_sanitization/README.md`](../conformance/trust_sanitization/README.md)
for the full matrix expansion.

---

## Appendix C. Open Questions Registry (Informative)

The following questions are open for community feedback. Each is
identified by a stable ID so it can be cross-referenced from issues,
PRs, and future revisions. DRAFT → final cleanup tracks every ID
below; resolved items move to the changelog rather than being
silently deleted.

| ID | Summary | Resolution status |
|---|---|---|
| OQ-CORE-001 | Complete error precedence table | **Resolved in v0.9.0a1; extended in v0.9.0a2 with `PIC_DUPLICATE_ID`; see §9.2** |
| OQ-CORE-002 | Multi-source requirement for `irreversible` impact | Open |
| OQ-CORE-003 | Policy-engine surface naming + standardization | Open |

### OQ-CORE-001 — Complete error precedence table (resolved v0.9.0a1)

**Resolution:** §9.2 now defines a total ordering for multi-failure
proposals across `PIC_SCHEMA_INVALID`, `PIC_DUPLICATE_ID`,
`PIC_TOOL_BINDING_MISMATCH`, `PIC_EVIDENCE_REQUIRED` /
`PIC_EVIDENCE_FAILED`, and `PIC_VERIFIER_FAILED`. The ordering
codifies the existing reference behavior for previously defined
codes and extends it in v0.9.0a2 with `PIC_DUPLICATE_ID`. It is
normative for cross-implementation parity. `PIC_DUPLICATE_ID` was
inserted at position 2 in v0.9.0a2 to close the
duplicate-provenance-ID ambiguity surfaced by the HERMETICUM Phase
2 review; see §9.1 for the code's semantics and §9.2 for the
updated precedence and worked examples.

`PIC_LIMIT_EXCEEDED`, `PIC_INVALID_REQUEST`, `PIC_INTERNAL_ERROR`,
and `PIC_POLICY_VIOLATION` are outside this core
verification-failure ordering. `PIC_INVALID_REQUEST` is a
transport / envelope failure before the PIC pipeline begins.
`PIC_LIMIT_EXCEEDED` short-circuits at the configured guard limit
that was exceeded, whether proposal size / count limits or the
evaluation time budget. `PIC_INTERNAL_ERROR` is a defensive
catch-all; `PIC_POLICY_VIOLATION` is reserved for downstream
adapters.

Historical context (pre-resolution): before v0.9.0a1, precedence
was pinned only for the cases covered by conformance vectors; edge
cases where multiple independent rules fail simultaneously had no
normative ordering.

### OQ-CORE-002 — Multi-source requirement for `irreversible` impact

[`RFC-0001 §Impact Taxonomy`](RFC-0001-pic-standard.md#impact-taxonomy)
says `irreversible` requires "Trusted evidence required (multi-source
recommended)" — recommended, not required. A future profile may
elevate multi-source to a normative requirement for `irreversible`
impact, requiring at least two distinct trusted evidence entries
backing the proposal. Resolution requires gathering deployment
experience on whether single-source trusted evidence for hard-stops
(e.g., LIDAR-only emergency-shutdown signals) is acceptable.

### OQ-CORE-003 — Policy-engine surface naming + standardization

§11 says policy configuration is implementation-defined. A future
profile may standardize the option names
(`require_pic_for_impacts`, `require_evidence_for_impacts`,
`expected_tool`, `strict_trust`, `verify_evidence`) as a portable
configuration surface so operators can move between PIC
implementations without rewriting policy files. Resolution requires
agreement among reference implementation maintainers + the v0.9.0
TypeScript verifier author.
