# PIC Vocabulary

> **Status:** Living document. Tracks the canonical PIC-side terminology that other specs and registries cite. When PIC docs and this glossary disagree, the upstream docs and [RFC-0001](RFC-0001-pic-standard.md) are authoritative; this file is updated to match.

This is the authoritative glossary of PIC Standard terminology. External crosswalks, registries, and downstream specs should reference these definitions rather than recoining the same concepts.

Every term below is grounded in an existing PIC doc or RFC. Each entry cites its source.

---

## Table of Contents

- [Core primitives](#core-primitives)
- [Action Proposal](#action-proposal)
- [Impact taxonomy](#impact-taxonomy)
- [Provenance and trust model](#provenance-and-trust-model)
- [Evidence](#evidence)
- [Verification and decision](#verification-and-decision)
- [Attestation Object](#attestation-object)
- [Canonicalization](#canonicalization)
- [Architecture and deployment](#architecture-and-deployment)
- [Conformance and versioning](#conformance-and-versioning)

---

## Core primitives

### PIC

Provenance & Intent Contracts. A lightweight, local-first, fail-closed protocol that forces AI agents to declare intent, impact class, data provenance, claims, and cryptographic evidence before any tool call is executed. The PIC verifier intercepts proposed actions at the action boundary and blocks any action that lacks sufficient justification.

**Source:** [RFC-0001 §Abstract](RFC-0001-pic-standard.md), [README.md](../README.md)

### Action boundary

The point in an agent runtime after the agent reasons but before any side effect occurs — the boundary between reasoning and execution. PIC operates exclusively at this point.

**Source:** [RFC-0001 §Abstract](RFC-0001-pic-standard.md)

### Fail-closed

The default behavior of the PIC verifier when verification cannot complete or does not pass. Every error path — schema invalid, evidence missing, bridge unreachable, timeout exceeded, signature invalid, file not found — MUST result in the action being blocked. There is no fallback to "allow anyway."

**Source:** [RFC-0001 §Security Properties #1](RFC-0001-pic-standard.md)

### Local-first verification

A property of the PIC reference implementation: verification is deterministic and can run fully locally; the reference implementation requires no external services. Remote verification deployments are still PIC-compliant if the verifier is under the operator's control and the enforcement decision remains fail-closed.

**Source:** [RFC-0001 §Core Claims #7 and §Security Properties #4](RFC-0001-pic-standard.md)

### Operator

The party deploying and configuring PIC: the team that runs the agent runtime, owns the keyring, sets policy for which tools and impact classes require PIC proposals, and consumes the verification decisions. PIC is operator-controlled by design.

**Source:** [RFC-0001 §Core Claims #5](RFC-0001-pic-standard.md), [README.md](../README.md)

### Representation-vs-normalization boundary

The rule that security-relevant PIC protocol values are validated as represented on the wire: implementations do not trim, case-fold, Unicode-normalize, alias, repair, or re-pad these values before comparing them. Applies to fields defined as exact, including `provenance[].id`, `expected_tool` and `proposal.action.tool`, SHA-256 digest strings, and Base64-encoded signature strings. Does not prohibit normalization that a PIC specification section explicitly defines (for example, PIC Canonical JSON v1 applied to specific inputs at specific points in verification).

**Source:** [spec-core.md §7.2](spec-core.md), [spec-core.md §6.1](spec-core.md), [spec-evidence.md §4.1](spec-evidence.md)

---

## Action Proposal

### Action Proposal

The structured JSON envelope an agent submits to the PIC verifier immediately before a tool call subject to PIC enforcement. It conforms to the PIC/1.0 JSON Schema and is submitted under the `__pic` key in tool arguments.

**Source:** [RFC-0001 §Protocol Summary](RFC-0001-pic-standard.md), [README.md §The PIC Contract](../README.md)

### `__pic` metadata key

The reserved key under which an Action Proposal is carried in tool arguments for PIC verification. Whether verification *applies* to a given tool call is a separate policy decision (the policy mechanism is implementation-defined; tools and impact classes can be declared PIC-required independently of `__pic` presence).

**Source:** [RFC-0001 §Protocol Summary](RFC-0001-pic-standard.md)

### `protocol`

Required field on the Action Proposal. Constant value `"PIC/1.0"` identifying the protocol version.

**Source:** [RFC-0001 §Required Fields](RFC-0001-pic-standard.md)

### `intent`

Required field. Plain-language description of what the agent is trying to do. Bound to the signature path through `intent_digest` (see [Attestation Object](#attestation-object)) so it cannot be silently swapped without invalidating the signature.

**Source:** [RFC-0001 §Required Fields](RFC-0001-pic-standard.md), [attestation-object-draft.md §Why intent_digest is SHOULD](attestation-object-draft.md)

### `impact`

Required field. Risk classification. Enum value from the [Impact taxonomy](#impact-taxonomy) below.

**Source:** [RFC-0001 §Required Fields](RFC-0001-pic-standard.md)

### `provenance`

Required field. Array of input sources that influenced the agent's decision, each with a trust level: `[{id, trust, source?}]`. The substrate over which causal-taint rules apply.

**Source:** [RFC-0001 §Required Fields](RFC-0001-pic-standard.md), [causal_logic.md](causal_logic.md)

### `claims`

Required field. Array of agent assertions with evidence references: `[{text, evidence[]}]`. Each claim cites one or more evidence IDs that PIC verifies before allowing the action.

**Source:** [RFC-0001 §Required Fields](RFC-0001-pic-standard.md)

### `evidence`

Optional field. Array of evidence objects: hash type (`{id, type:"hash", ref, sha256}`) or sig type (`{id, type:"sig", ref, payload, alg, signature, key_id}`). See [Evidence](#evidence).

**Source:** [RFC-0001 §Optional Fields](RFC-0001-pic-standard.md), [evidence.md](evidence.md)

### `action`

Required field. The actual tool call: `{tool, args}`. The `tool` value is bound to the verification decision so the dispatched call cannot diverge from the verified proposal — see [Tool binding integrity](#tool-binding-integrity).

**Source:** [RFC-0001 §Required Fields](RFC-0001-pic-standard.md)

### ID binding convention

The three-way binding mechanism: `provenance[].id` identifies an input source and its initial trust level; `claims[].evidence[]` references provenance IDs that support the claim; `evidence[].id` matches a provenance ID, and successful verification MAY upgrade that provenance entry's trust to `trusted`. This is the mechanism by which untrusted provenance is bridged to trusted status through cryptographic evidence verification.

**Source:** [RFC-0001 §ID Binding Convention](RFC-0001-pic-standard.md)

---

## Impact taxonomy

PIC/1.0 defines seven impact classes. Three are high-impact and require trusted evidence under the verification rule below. Four are low-impact and accept untrusted provenance.

### Verification rule

For any Action Proposal where `impact` is in `{money, privacy, irreversible}`, at least one entry in `claims` MUST reference (via `evidence[]`) an evidence ID that resolves to a provenance entry with `trust == "trusted"`. If no such causal chain exists, the proposal MUST be rejected (fail-closed).

**Source:** [RFC-0001 §Verification Rule](RFC-0001-pic-standard.md)

### `read`

Low-impact. Observational data access. Untrusted provenance allowed.

**Source:** [RFC-0001 §Impact Taxonomy](RFC-0001-pic-standard.md), [causal_logic.md §3](causal_logic.md)

### `write`

Low-impact. Untrusted provenance allowed.

**Source:** [RFC-0001 §Impact Taxonomy](RFC-0001-pic-standard.md)

### `external`

Low-impact. Untrusted provenance allowed.

**Source:** [RFC-0001 §Impact Taxonomy](RFC-0001-pic-standard.md)

### `compute`

Low-impact. Untrusted provenance allowed.

**Source:** [RFC-0001 §Impact Taxonomy](RFC-0001-pic-standard.md)

### `money`

High-impact. Financial movement. Trusted evidence required.

**Source:** [RFC-0001 §Impact Taxonomy](RFC-0001-pic-standard.md), [causal_logic.md §3](causal_logic.md)

### `privacy`

High-impact. PII exposure. Trusted evidence required. Enforced as high-impact since v0.4.1.

**Source:** [RFC-0001 §Impact Taxonomy and §Implementation Timeline](RFC-0001-pic-standard.md)

### `irreversible`

High-impact. Deleting data, hard stops. Trusted evidence required (multi-source recommended).

**Source:** [RFC-0001 §Impact Taxonomy](RFC-0001-pic-standard.md), [causal_logic.md §3](causal_logic.md)

---

## Provenance and trust model

### Trusted

The trust attribution applied to provenance entries that derive from a source the operator has registered as trustworthy, or that have been upgraded to `trusted` by successful evidence verification.

**Source:** [causal_logic.md](causal_logic.md), [evidence.md](evidence.md)

### Untrusted

The default trust attribution for any input that has not been demonstrated as trusted. Plans that depend solely on untrusted data are themselves tainted.

**Source:** [causal_logic.md §1](causal_logic.md)

### Causal taint

The semantic rule that any plan generated by an LLM relying solely on tainted (untrusted-provenance) data is itself tainted, and that executing a high-impact action with a tainted plan violates the contract. Formalized in RFC-0001 as one of the protocol's core claims.

**Source:** [causal_logic.md §1](causal_logic.md), [RFC-0001 §Core Claims #6](RFC-0001-pic-standard.md)

### Trusted bridge

The process of using trusted data to validate claims made from untrusted data. Operationally, the bridge is realized through the [ID binding convention](#id-binding-convention): when an evidence entry whose `id` matches a provenance entry passes cryptographic verification, that provenance entry's trust MAY be upgraded to `trusted` (the reference implementation upgrades trust in-memory).

**Source:** [causal_logic.md §2](causal_logic.md), [RFC-0001 §Core Claims #3 and §ID Binding Convention](RFC-0001-pic-standard.md)

### Trust as an output, not an input

The protocol stance that trust is an output of cryptographic verification, not an input assumption. Provenance trust levels MAY be upgraded after evidence passes verification.

**Source:** [RFC-0001 §Security Properties #5](RFC-0001-pic-standard.md)

### Keyring

The local file (or environment-configured equivalent) that lists trusted Ed25519 public keys, optional per-key expiry, and a revoked-keys list. Loaded from `PIC_KEYS_PATH` if set, then `./pic_keys.json`, then empty. Used to verify signature evidence.

**Source:** [keyring.md](keyring.md), [RFC-0001 §Scope](RFC-0001-pic-standard.md)

### Key lifecycle

The set of states a key in the keyring can occupy: `ok` (valid and active), `expired` (`expires_at` has passed), `revoked` (listed in `revoked_keys`), or `missing` (key ID not in keyring). Evidence verification distinguishes these states for operator clarity. Trusted signing keys SHOULD support expiry timestamps and revocation lists; expired or revoked keys MUST NOT produce valid evidence.

**Source:** [keyring.md §Expiry & Revocation](keyring.md), [RFC-0001 §Security Properties #7](RFC-0001-pic-standard.md)

### `KeyResolver` protocol

The injectable trust-resolution interface introduced in v0.7. Custom resolvers plug into the verifier and pipeline directly, allowing custom trust backends or preloaded sources (HSM-backed services, Vault-managed keys, cached remote keyrings). Reference implementations include `StaticKeyRingResolver`.

**Source:** [README.md §Keyring (Trusted Signers)](../README.md)

### `strict_trust` mode

Trust-sanitization mode introduced in v0.7.5. When enabled, all inbound provenance trust is sanitized to `untrusted` and only authority-bearing evidence verification (currently signature evidence) can upgrade it. Default `True` as of v0.9.0a2 (the secure default). Legacy compatibility mode (`strict_trust=False`) remains callable and emits `PICLegacyTrustModeWarning` at construction; its removal is not scheduled in the v0.9.x series.

**Source:** [README.md §Keyring (Trusted Signers)](../README.md), [migration-trust-sanitization.md](migration-trust-sanitization.md)

---

## Evidence

### Content integrity

A property established when the SHA-256 digest of an artifact's bytes exactly matches a claimed digest. Content integrity says the bytes have not changed since the digest was computed; it does not by itself imply authority, approval, provenance trust, or truth about the content. Hash evidence establishes content integrity for the referenced bytes.

**Source:** [spec-evidence.md §5](spec-evidence.md), [spec-evidence.md §4.1](spec-evidence.md)

### Authority-bearing evidence

Evidence whose successful verification is permitted to upgrade a provenance entry's effective trust from `untrusted` to `trusted` under the trust-upgrade rules. Signature evidence accepted by the configured verifier keyring is the current main case; hash evidence is not authority-bearing on its own (see Content integrity above).

**Source:** [spec-evidence.md §8](spec-evidence.md), [spec-core.md §6.2](spec-core.md), [spec-core.md §6.4](spec-core.md)

### Hash evidence

An evidence entry of `type: "hash"` whose `id` resolves to a real artifact (typically `file://...`) and is verified by recomputing the SHA-256 digest and comparing it byte-exactly. Introduced in v0.3. File resolution is sandboxed against `evidence_root_dir`.

**Source:** [evidence.md §Evidence v0.3](evidence.md), [RFC-0001 §Implementation Timeline](RFC-0001-pic-standard.md)

### Signature evidence

An evidence entry of `type: "sig"` carrying a `payload`, an Ed25519 `signature`, and a `key_id`. Verified by resolving `key_id` against the keyring and checking the signature against the payload bytes. Introduced in v0.4; requires `pic-standard[crypto]`.

**Source:** [evidence.md §Evidence v0.4](evidence.md), [RFC-0001 §Implementation Timeline](RFC-0001-pic-standard.md)

### Evidence verification

The process of checking an evidence entry according to its type. Hash
verification establishes content integrity for the referenced bytes
but does not by itself upgrade provenance trust. Authority-bearing
evidence, such as signature evidence accepted by the configured
verifier keyring, can support trust upgrade only when permitted by
the trust-upgrade rules.

**Source:** [spec-evidence.md §5](spec-evidence.md), [spec-evidence.md §6](spec-evidence.md), [spec-evidence.md §8](spec-evidence.md)

### Sandboxed evidence resolution

The constraint that `file://` evidence references resolve only within a configured `evidence_root_dir`, preventing path traversal. Resolved artifacts are bounded in size by `max_file_bytes` (default 5 MB).

**Source:** [evidence.md §Evidence sandboxing](evidence.md), [RFC-0001 §Security Properties #6](RFC-0001-pic-standard.md)

---

## Verification and decision

### Verifier

The PIC component that consumes an Action Proposal and produces an allow/block decision. The verifier validates schema, applies tool-binding verification, runs evidence verification when enabled, applies causal-taint gating, and emits the decision. Reference implementation in Python; HTTP bridge available for non-Python consumers.

**Source:** [RFC-0001 §Abstract](RFC-0001-pic-standard.md), [architecture.md](architecture.md)

### Decision

The output of the verifier: `allowed` or `blocked`. Per-action and binary; PIC does not produce scored or graded outputs. Implementations SHOULD emit an auditable decision record (log or event) for every verification.

**Source:** [RFC-0001 §Security Properties #1 and §SHOULD #6](RFC-0001-pic-standard.md)

### Tool binding integrity

The protocol property that the proposal's declared `action.tool` MUST match the actual tool being invoked. A mismatch — indicating the agent proposed one action but attempted another — MUST be blocked.

**Source:** [RFC-0001 §Security Properties #3 and §MUST #4](RFC-0001-pic-standard.md)

### Causal taint gating

The protocol property that for high-impact actions (`money`, `privacy`, `irreversible`), the implementation MUST require at least one claim referencing evidence from trusted provenance. Proposals lacking this causal chain MUST be rejected.

**Source:** [RFC-0001 §MUST #3](RFC-0001-pic-standard.md)

### Policy-controlled enforcement boundary

The operator-configured surface that determines which tools and which impact classes require a PIC proposal. Enables incremental adoption: an operator can enable PIC gating for `money` and `irreversible` first, then expand. The policy mechanism is implementation-defined; PIC/1.0 specifies what MUST be enforced once a tool or impact class is declared PIC-required.

**Source:** [RFC-0001 §Core Claims #5 and §Protocol Summary](RFC-0001-pic-standard.md)

### Deterministic verification

The protocol property that, given the same proposal, evidence artifacts, keyring state, and policy configuration, the verifier MUST produce the same result every time.

**Source:** [RFC-0001 §Security Properties #8](RFC-0001-pic-standard.md)

---

## Attestation Object

> **Status:** The Attestation Object (`PIC-ATT/1.0`) remains draft; canonical-byte signing rules are defined (PIC-CJSON/1.0, frozen in v0.8.0), but field set, presence requirements, and freshness semantics are not yet final. Subject to Phase 1.1b review.

### Attestation Object

A minimal, stable JSON object that binds the security-relevant fields of an Action Proposal — tool, args, impact, provenance IDs, claims — by value or digest, plus freshness hooks. Once formalized, it is the verifiable record that a specific action was justified at a specific moment under a specific verifier's policy.

**Source:** [attestation-object-draft.md](attestation-object-draft.md)

### `attestation_version`

The protocol identifier on the attestation object. Currently `"PIC-ATT/1.0"`. Distinguishes attestation-object signatures from v0 legacy payload-string signatures.

**Source:** [attestation-object-draft.md §Fields](attestation-object-draft.md)

### `args_digest`

The SHA-256 hex digest of `canonicalize(action.args)` per [PIC-CJSON/1.0 §8.1](canonicalization.md). Binds the tool's execution arguments to the signed decision without copying potentially large argument structures into the signed object.

**Source:** [attestation-object-draft.md](attestation-object-draft.md), [canonicalization.md §8.1](canonicalization.md)

### `claims_digest`

The SHA-256 hex digest of `canonicalize(claims)` per [PIC-CJSON/1.0 §8.2](canonicalization.md). Binds the claims by digest to preserve audit linkage without copying claim text into signed artifacts.

**Source:** [attestation-object-draft.md](attestation-object-draft.md), [canonicalization.md §8.2](canonicalization.md)

### `intent_digest`

The SHA-256 hex digest of the raw UTF-8 bytes of the intent string per [PIC-CJSON/1.0 §8.3](canonicalization.md). Special-cased: intent is a scalar string and is not JSON-canonicalized — the digest is over its UTF-8 bytes directly.

**Source:** [attestation-object-draft.md](attestation-object-draft.md), [canonicalization.md §8.3](canonicalization.md)

### `provenance_ids`

The list of provenance entry IDs in proposal array order, included by value (not by digest). Allows the verifier to confirm that the same provenance set considered at proposal time was the set covered by the signature.

**Source:** [attestation-object-draft.md §Fields](attestation-object-draft.md)

### Freshness hooks

The attestation-object fields `issued_at` (RFC 3339 timestamp, SHOULD) and `expires_at` (RFC 3339 timestamp, OPTIONAL). When `expires_at` is present, the intended PIC/1.0 rule is reject-on-expiry. Full replay prevention (nonce caches, bounded TTL registries) is deferred to a profile-level mechanism.

**Source:** [attestation-object-draft.md §Design Principles and §Freshness Semantics](attestation-object-draft.md)

### v0 legacy mode

The compatibility rule for `sig`-type evidence entries that do not contain `attestation_version` in their payload. Verifiers continue to accept v0 signatures (where the producer is responsible for canonicalization of the payload string) until normative semantics specify otherwise.

**Source:** [attestation-object-draft.md §Backward Compatibility](attestation-object-draft.md)

---

## Canonicalization

### PIC Canonical JSON v1 (PIC-CJSON/1.0)

The byte-exact JSON serialization PIC uses for hashing and signing. Frozen as of PIC v0.8.0. Defines exact rules for whitespace, key order, number formatting, and string escaping so that two producers encoding the same semantic content produce identical bytes — and therefore identical hashes and verifiable signatures across implementations. Pure-stdlib reference implementation lives at `pic_standard.canonical` (`canonicalize()`, `sha256_hex()`, `intent_digest_hex()`).

**Source:** [canonicalization.md](canonicalization.md), [README.md §Evidence Verification](../README.md)

### Canonical bytes

The output of applying PIC-CJSON/1.0 to a JSON value. The signed bytes input to Ed25519 for an attestation-object signature are always canonical bytes, never raw payload text. Verifiers re-canonicalize on receipt to guard against lossy transport.

**Source:** [canonicalization.md](canonicalization.md), [attestation-object-draft.md §Signing Process](attestation-object-draft.md)

### Conformance vectors

The byte-exact test fixtures under [`conformance/canonicalization/`](../conformance/canonicalization/) that pin the canonical bytes for representative inputs. Any implementation claiming PIC-CJSON/1.0 conformance must produce identical bytes for every vector. Executed on every PR by the [`PIC Conformance` CI workflow](../.github/workflows/conformance.yml).

**Source:** [attestation-object-draft.md §Test Vectors](attestation-object-draft.md), [canonicalization.md](canonicalization.md)

---

## Architecture and deployment

### Interceptor pattern

PIC's deployment shape: the verifier sits between the agent and the tool executor, intercepting every tool call that falls within the operator's enforcement boundary. Verified calls pass through; failed calls are blocked and logged.

**Source:** [architecture.md](architecture.md)

### LangGraph integration

First-party PIC integration for LangGraph agents via `PICToolNode`. As of v0.7.5+, accepts `verify_evidence`, `strict_trust`, `policy`, and `key_resolver` for full pipeline configuration. Installed with `pip install "pic-standard[langgraph]"`.

**Source:** [README.md §Integrations](../README.md)

### MCP integration

In-process tool guarding for Model Context Protocol servers. The guard wraps tool functions directly via `guard_mcp_tool()` / `guard_mcp_tool_async()` — the agent passes a PIC proposal inside tool arguments, and the guard verifies it before calling the real tool function. No HTTP, no bridge. Provides fail-closed defaults, request correlation, DoS limits, and evidence sandboxing. Installed with `pip install "pic-standard[mcp]"`.

**Source:** [README.md §MCP](../README.md), [mcp-integration.md](mcp-integration.md)

### OpenClaw integration

TypeScript plugin for OpenClaw AI agents with three hooks: `pic-gate` (`before_tool_call`), `pic-init` (`before_agent_start`), and `pic-audit` (`tool_result_persist`). The plugin invokes PIC verification by calling the [HTTP bridge](#http-bridge) over localhost.

**Source:** [README.md §OpenClaw](../README.md), [openclaw-integration.md](openclaw-integration.md)

### Cordum integration

Go Pack providing PIC verification as a Cordum workflow gate step. The worker decodes the input, calls the PIC HTTP bridge `POST /verify`, and maps the result to fail-closed three-way workflow routing: `proceed`, `fail`, or `require_approval`.

**Source:** [README.md §Cordum](../README.md), [cordum-integration.md](cordum-integration.md)

### HTTP bridge

The HTTP-accessible verifier surface for non-Python consumers. Exposes `POST /verify` (verify an action proposal), `GET /health` (liveness check), and `GET /v1/version` (package + protocol version). Started with `pic-cli serve`.

**Source:** [README.md §HTTP Bridge](../README.md)

---

## Conformance and versioning

### PIC/1.0

The protocol baseline. The Action Proposal structure and wire-level schema have remained stable since the RFC anchor; post-RFC changes have not introduced wire-format breaks.

**Source:** [spec-status.md](spec-status.md), [RFC-0001](RFC-0001-pic-standard.md)

### RFC-0001

The defensive publication anchoring PIC/1.0 prior art. Apache-2.0 licensed, published with cryptographic commit hashes and an independent Zenodo DOI ([10.5281/zenodo.18725562](https://doi.org/10.5281/zenodo.18725562)) as timestamped evidence of public disclosure. Covers v0.1.0 through v0.5.5; later changes are documented in [spec-status.md](spec-status.md).

**Source:** [RFC-0001 §Defensive Publication & IP Notice](RFC-0001-pic-standard.md), [spec-status.md](spec-status.md)

### PIC/1.0 Core (conformance level)

The minimum required for PIC/1.0 conformance: schema validation, fail-closed enforcement, tool-binding verification, and the high-impact trusted-bridge rule.

**Source:** [RFC-0001 §Conformance Levels](RFC-0001-pic-standard.md)

### PIC/1.0 Evidence (conformance level)

PIC/1.0 Core plus hash and/or signature evidence verification plus keyring requirements. An implementation supporting signature evidence MUST verify Ed25519 signatures against an operator-managed trusted public key set, and MUST reject signatures from revoked or expired keys where those fields are supported.

**Source:** [RFC-0001 §Conformance Levels](RFC-0001-pic-standard.md)

### Conformance suite

The canonicalization and core test fixtures published in [`conformance/`](../conformance/) plus the [PIC Conformance Runner](../conformance/run.py). Provides the byte-exact and behavioral tests an implementation must pass to claim conformance.

**Source:** [spec-status.md](spec-status.md), [README.md](../README.md)

---

## See also

- [RFC-0001](RFC-0001-pic-standard.md) — defensive publication establishing PIC/1.0 prior art and normative protocol semantics
- [architecture.md](architecture.md) — interceptor pattern and runtime topology
- [causal_logic.md](causal_logic.md) — taint and bridging semantics
- [canonicalization.md](canonicalization.md) — PIC-CJSON/1.0 normative spec
- [attestation-object-draft.md](attestation-object-draft.md) — attestation object draft (Phase 1.1b)
- [evidence.md](evidence.md) — hash and signature evidence verification
- [keyring.md](keyring.md) — trusted-signer management
- [migration-trust-sanitization.md](migration-trust-sanitization.md) — `strict_trust` migration guide
- [spec-status.md](spec-status.md) — version and stability tracking

---

## Maintenance

External crosswalks and registries should reference entries in this glossary by anchor. When PIC docs evolve a term, update this file in the same PR; treat divergence between this file and authoritative docs as a bug.

When adding a term: ground it in an existing PIC doc or RFC. Do not coin terms here that are not already used in the upstream specs.

When deprecating a term: leave the entry, add `**Status:** Deprecated.`, link to the replacement, and explain why in one sentence.
