# PIC Standard — Enterprise-Ready Roadmap

> Living plan for standardization, interop, and enterprise adoption.
> Updated for the post-v0.8.2 repo state (2026-05-31).

---

## North Star

PIC is "standard-grade" when:

1. There are at least **2 independent implementations** (Python + TypeScript) passing the **same conformance suite**.
2. Canonicalization is **formally specified and frozen** so hashes/signatures are interoperable across languages.
3. The **core verifier**, **evidence semantics**, and **attestation-object signing semantics** are each documented in normative spec form with **MUST/SHOULD** language.
4. A single, stable guard service is deployable in **<60 seconds** (Docker) with a clear operator story.
5. Verification has **no mandatory network dependency**; trust roots remain **operator-controlled**.
6. Trust is **verifier-derived**: no field in the proposal is authoritative for trust status.
7. At least one second-language implementation proves PIC is a **protocol**, not just a Python package.

---

## Strategic Principle

There are two kinds of "improving PIC":

### 1. Standardization-grade improvement
This is improvement that makes PIC more implementable, less ambiguous, more secure, and more portable:

- clarifying semantics
- tightening trust rules
- completing conformance
- freezing canonical bytes
- reducing cross-language ambiguity
- making signer/verifier behavior explicit

This is the work on the path to standardization.

### 2. Ecosystem / product improvement
This makes PIC easier to deploy or nicer to use:

- more integrations
- deployment docs
- Docker / OpenAPI
- audit logs
- operator tooling
- profiles and registries

This matters too, but it must not get ahead of the protocol core.

**Rule of thumb:** through v1.0, PIC prioritizes improvements that reduce ambiguity and strengthen interop over improvements that merely expand surface area.

---

## How spec normative freezes are sequenced

Specifications in this project are treated as evolving drafts until cross-implementation conformance proves them stable. The sequencing is:

| Spec | Status |
|------|--------|
| `docs/canonicalization.md` (PIC-CJSON/1.0) | **Frozen at v0.8.0** — exceptional case; clean external grounding in RFC 8785 made early freeze safe |
| `docs/attestation-object-draft.md` | DRAFT throughout v0.8.x; refined under cross-impl pressure in v0.9.x; promoted to normative at v1.0 |
| `docs/spec-core.md` | Initial DRAFT in v0.8.2 (deferred from v0.8.1); evolves through v0.9.x; promoted to normative at v1.0 |
| `docs/spec-evidence.md` | Initial DRAFT in v0.8.2 (deferred from v0.8.1); evolves through v0.9.x; promoted to normative at v1.0 |

**Rationale:** A spec is genuinely frozen only when independent implementations have exposed its ambiguities. Freezing before cross-impl conformance produces specs that look authoritative but in fact have unresolved corner cases. PIC-CJSON/1.0 is the exception because RFC 8785 provided the missing external grounding before any second implementation existed.

---

## Release Ladder

| Version | Theme | What ships | Status |
|---------|-------|-----------|--------|
| v0.7.5 | Trust hardening + attestation draft | `strict_trust` pipeline option, `PICTrustFutureWarning`, attestation object draft, migration guide | ✅ Done |
| **v0.8.0** | **Canonicalization foundation + conformance skeleton** | **PIC Canonical JSON v1 spec (frozen), reference implementation (`pic_standard.canonical`), 9 canonicalization vectors, refined attestation-object draft with byte-level digests, `conformance/` suite first pass, `conformance/manifest.json`, `python -m conformance.run`, `PIC Conformance` CI job** | ✅ Done |
| **Phase 0 cleanup** | **Repo hygiene** | **`ROADMAP.md` committed, broken roadmap-link refs fixed, `semi_trusted` deprecation trajectory documented, `SECURITY.md`, `CODE_OF_CONDUCT.md`** | ✅ Done (PR #67) |
| **v0.8.1** | **`semi_trusted` deprecation** | **`PICSemiTrustedDeprecationWarning` (defined in `pic_standard.verifier`, re-exported at package root, subclasses `FutureWarning`); pydantic field validator on `Provenance.trust` as the canonical normalization boundary; bridge helper in `verify_proposal()` triggers the validator immediately after JSON Schema validation, so the deprecation warning fires regardless of `strict_trust` mode and `semi_trusted` is normalized to `"untrusted"` before strict-trust flattening or evidence verification consume the dict; full `ActionProposal` instantiation stays last so `verify_causal_contract` keeps observing post-evidence trust state; examples migrated off `semi_trusted` (trust-flip only — no hash evidence added, since hash binds bytes not authority); migration doc `docs/migration-trust-sanitization.md` updated; verdict-regression matrix codified in `tests/test_trust_deprecation_warning.py` as a permanent CI guard. **Other v0.8.1-targeted items from the post-v0.8.0 plan (conformance expansion, runner hardening, initial DRAFTs of `spec-core.md` / `spec-evidence.md`) are deferred to v0.8.2 to keep this release focused on the deprecation surface.** | ✅ Done |
| **v0.8.2** | **Conformance expansion + runner hardening + initial spec drafts + canonical runtime signing (opt-in)** | **(Deferred from v0.8.1) Evidence-mode vectors, trust-sanitization vectors, runner hardening (JSON output, run-by-id/mode, machine-readable failure reporting), initial DRAFT `docs/spec-core.md`, initial DRAFT `docs/spec-evidence.md`. (v0.8.2 native) Canonical attestation-object bytes wired into runtime signing/verification flow as an opt-in mode (default remains legacy payload-string for one release). Attestation Object v1 remains DRAFT during this stabilization phase. Legacy mode explicitly demoted to compatibility mode in docs.** | ✅ Done |
| **v0.9.0** | **Interop milestone + schema cleanup** | **First TypeScript verifier pass — minimum: canonicalization + core + trust-sanitization mode parity with Python on the same `conformance/manifest.json`, filtered to those three modes. `semi_trusted` removed from schema (was deprecated in v0.8.1). OpenAPI bridge spec, structured audit logs, Docker hardening for enterprise pilots. Spec drafts updated with cross-impl findings.** | Planned |
| v0.9.1–v0.9.2 | Ambiguity burn-down | Differential Python ↔ TS testing, fuzzing canonicalization and malformed proposals/evidence, more number/Unicode edge vectors, additional malformed-evidence cases, TS evidence-mode parity completed if not landed at v0.9.0, wording tightening from cross-impl disagreements | Planned |
| **v1.0.0** | **Production-grade protocol freeze** | **`strict_trust=True` becomes default and only conformant mode. Canonical attestation-object signing becomes default; legacy payload-string mode is non-conformant. `spec-core.md`, `spec-evidence.md`, and Attestation Object v1 all promoted to normative. PIC-CJSON/1.0 unchanged. Python + TS pass full conformance suite. Internet-Draft submission.** | Planned |

**Deferred beyond v1.0:** broader TS hardening / ecosystem tooling, trust bundle profile, discovery profile, optional CBOR profile, registry/governance machinery beyond the v1.0 minimum, additional transport bindings.

---

## Current State (post-v0.8.2)

### What exists

| Component | Status | Location |
|-----------|--------|----------|
| Core verifier (Python) | ✅ Done | `sdk-python/pic_standard/verifier.py` |
| Shared pipeline | ✅ Done | `sdk-python/pic_standard/pipeline.py` |
| JSON Schema (`PIC/1.0`) | ✅ Done | `sdk-python/pic_standard/schemas/proposal_schema.json` |
| Evidence: SHA-256 hash | ✅ Done | `sdk-python/pic_standard/evidence.py` |
| Evidence: Ed25519 sig | ✅ Done | `sdk-python/pic_standard/evidence.py` |
| Keyring (expiry + revocation) | ✅ Done | `sdk-python/pic_standard/keyring.py` |
| Policy system | ✅ Done | `sdk-python/pic_standard/policy.py`, `config.py` |
| Error codes | ✅ Done | `sdk-python/pic_standard/errors.py` |
| Guard service (`pic-cli serve`) | ✅ Done | `sdk-python/pic_standard/integrations/http_bridge.py` |
| CLI | ✅ Done | `sdk-python/pic_standard/cli.py` |
| LangGraph integration | ✅ Done | `sdk-python/pic_standard/integrations/langgraph_pic_toolnode.py` |
| MCP integration | ✅ Done | `sdk-python/pic_standard/integrations/mcp_pic_guard.py` |
| OpenClaw plugin/client (TS integration surface) | ✅ Done | `integrations/openclaw/` |
| Key resolution (`KeyResolver`, `StaticKeyRingResolver`) | ✅ Done | `sdk-python/pic_standard/keyring.py` |
| Trust sanitization option (`strict_trust`) | ✅ Done | `sdk-python/pic_standard/pipeline.py` |
| Trust migration guide | ✅ Done | `docs/migration-trust-sanitization.md` |
| Attestation object draft | ✅ Draft | `docs/attestation-object-draft.md` |
| **PIC Canonical JSON v1 spec (frozen)** | ✅ Done | `docs/canonicalization.md` |
| **Canonicalization reference implementation** | ✅ Done | `sdk-python/pic_standard/canonical.py` |
| **Canonicalization conformance vectors** | ✅ Done | `conformance/canonicalization/` |
| **Core allow/block conformance vectors** | ✅ Done | `conformance/core/` |
| **Conformance manifest** | ✅ Done | `conformance/manifest.json` |
| **Conformance runner** | ✅ Done | `conformance/run.py` |
| **Conformance CI workflow** | ✅ Done | `.github/workflows/conformance.yml` |
| Canonicalization unit tests | ✅ Done | `tests/test_canonical.py` |
| **`PICSemiTrustedDeprecationWarning` + field validator (canonical normalization boundary)** | ✅ Done (v0.8.1) | `sdk-python/pic_standard/verifier.py` |
| **Bridge helper triggering field validator after JSON Schema validation** | ✅ Done (v0.8.1) | `sdk-python/pic_standard/pipeline.py` |
| **Both deprecation-warning classes re-exported at package root** | ✅ Done (v0.8.1) | `sdk-python/pic_standard/__init__.py` |
| **Verdict-regression matrix (permanent CI guard for the dict-vs-model boundary)** | ✅ Done (v0.8.1) | `tests/test_trust_deprecation_warning.py` |
| **Project hygiene: `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff`, README pointers** | ✅ Done (Phase 0, PR #67) | repo root |

### What still blocks "standard" status

| Gap | Why it matters |
|-----|----------------|
| Canonicalization not yet wired into runtime signing paths | The byte model exists but is not yet operating in live flows; legacy payload-string mode still dominates |
| Attestation Object v1 still draft | Field set and semantics not yet frozen; awaiting cross-impl validation |
| Normative semantics still split across docs/code/tests | Interop needs `spec-core.md` and `spec-evidence.md` as clear normative anchors, not just good code behavior |
| Evidence-mode conformance missing | Portable verification of hash/sig evidence not yet part of shared vector execution |
| Trust-sanitization-mode conformance missing | The v1 trust model must be executable, not just documented |
| No second verifier implementation | Without Python + TS parity, PIC is not yet proven cross-language |
| `semi_trusted` removal still pending | Deprecation shipped in v0.8.1 (`PICSemiTrustedDeprecationWarning` + canonical normalization at the model-validation boundary). Schema-level removal scheduled for v0.9.0. |
| Structured audit logs, OpenAPI, Docker hardening incomplete | Enterprise deployment story not yet strong enough |
| Citation / external publication flow incomplete | Useful for standard-grade credibility |

---

## Guiding Technical Decisions (locked)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Trust source | Verifier-derived only | Self-asserted trust is non-authoritative and transitional only |
| Network dependency | Never mandatory at verification time | Preserves local-first/offline-capable guarantee |
| Signing target | Canonical minimal attestation object | Stable, cross-language, low-coupling, future-proof |
| Canonicalization baseline | RFC 8785 + PIC-specific rules (PIC-CJSON/1.0) | Stable byte model, frozen at v0.8.0 |
| Canonical signing rollout | Opt-in mode at v0.8.2; default at v1.0 | Mirrors `strict_trust` precedent: introduce as opt-in, side-by-side validate, flip default at the v1.0 freeze |
| `strict_trust` end state | Default and only conformant mode at v1.0 | Prevents config hazards and trust confusion |
| Trust enum semantics | Binary (`trusted` / `untrusted`) post-v0.9.0; legacy `semi_trusted` value being phased out (deprecated v0.8.1, removed v0.9.0) | The v0.7.5 Trust Axiom collapsed three trust levels into two operational categories; the schema is being reconciled accordingly |
| `semi_trusted` normalization boundary | Pydantic field validator on `Provenance.trust` (canonical) + bridge helper in `verify_proposal()` triggering it post–JSON-Schema-validation. Any construction path that bypasses the validator is non-conformant | Established in v0.8.1. Locks the boundary against future refactors and gives the eventual TS verifier a clean target ("equivalent of pydantic field validator on the equivalent of `Provenance.trust`"). Verdict-regression matrix in `tests/` codifies this contract as a permanent CI guard |
| Encoding | JSON core first | Lowest-friction adoption; optional CBOR only later |
| Standardization target | Standalone PIC spec first, transport bindings second | PIC is broader than any single framework or protocol |
| `key_id` format | Opaque string | Avoids migration friction and over-prescription |
| Trust distribution | Local-first, operator-controlled | Keeps trust roots under verifier/operator control |
| Spec normative freeze timing | At v1.0 (with PIC-CJSON/1.0 as the v0.8.0 exception) | Cross-impl validation must precede freeze |

---

## Phase 0 — Repo Hygiene (✅ shipped, PR #67)

**Status:** Shipped via PR #67. This section is preserved as historical record of the scope that landed and the decisions made within it. The state-marker work (committing this ROADMAP, removing the stale `.gitignore` entry, adding `SECURITY.md` / `CODE_OF_CONDUCT.md`, bumping `CITATION.cff` to v0.8.0 metadata, adding README pointers, documenting the `semi_trusted` deprecation trajectory in `docs/migration-trust-sanitization.md`) is all on `main`.

### Atomic PR scope (as shipped)

- [x] **Commit `ROADMAP.md` (this file) to main.** Was on local working copies only at session start; tracked references from other docs were broken.
- [x] **Fix broken `../ROADMAP.md` references** — audit determined no broken refs existed (all `../ROADMAP.md` references in `docs/` resolve correctly to repo root). Item closed without code change.
- [x] **Document `semi_trusted` deprecation trajectory.** It exists in `proposal_schema.json` with no normative semantics under the v0.7.5 Trust Axiom — a vestigial value that suggests a verifier state that doesn't operationally exist. **The decision: deprecate at v0.8.1, remove at v0.9.0.**

  **Origin context (preserved for the record):** `semi_trusted` was day-1 design (introduced January 2026, before v0.1.0) capturing a real-world distinction between "authenticated but not cryptographically signed" and "fully unauthenticated" sources. Examples in the original example proposals: a Slack-authenticated message from a manager (`slack_approval_manager` in `examples/financial_irreversible.json`), a voice-ID-recognized operator command (`operator_voice_command` in `examples/robotic_action.json`). The v0.7.5 Trust Axiom (verifier-derived trust only) made this producer-declared distinction non-authoritative — verifiers can no longer act on producer-declared trust labels regardless of nuance. The original taxonomy collapsed from three levels into two operational categories, and `semi_trusted` became vestigial.

  **Trajectory:**
  - **v0.8.1** (✅ shipped): deprecated with `PICSemiTrustedDeprecationWarning`. Schema still accepts the value (one transition release). The canonical normalization boundary is the pydantic field validator on `Provenance.trust` in `pic_standard.verifier`; `verify_proposal()` triggers that validator immediately after JSON Schema validation via a small bridge helper, so warnings fire and `semi_trusted` is normalized to `"untrusted"` regardless of `strict_trust` mode and before strict-trust flattening or evidence verification consume the dict. The `Provenance.trust` validator covers direct `Provenance(...)` / `ActionProposal(...)` construction outside the funnel as well — bypassing it is non-conformant with the v0.8.1 behavior contract. Examples migrated to `untrusted` (no semantic change since `semi_trusted` was always advisory under the Trust Axiom). Migration note added to `docs/migration-trust-sanitization.md`.
  - **v0.9.0** (planned): removed from schema. Validation rejects any proposal with `provenance[].trust = "semi_trusted"`. The field validator's deprecation branch, the bridge helper, the `PICSemiTrustedDeprecationWarning` class, and the `SEMI_TRUSTED` enum member in `verifier.py` are all deleted.
  - **v1.0**: not a concern; already removed.

  Phase 0 committed the **protocol direction** — deprecate in v0.8.1, remove in v0.9.0 — into this ROADMAP. The actual schema/code/example changes happened in v0.8.1 (deprecation + normalization, ✅ shipped) and v0.9.0 (removal, planned).
- [x] **Add `SECURITY.md`** — vulnerability reporting flow, supported versions, disclosure process.
- [x] **Add `CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1.
- [x] **Citation flow check** — `CITATION.cff` updated to v0.8.0 metadata + concept DOI + v0.8.0 version DOI; README pointer added.

**Exit criteria (all met):** the repo has the minimum credibility artifacts expected of a security-sensitive open protocol project; no internal links to nonexistent files; `semi_trusted` has a documented deprecation trajectory with a concrete v0.9.0 removal target.

---

## Phase 1 — Interop Foundation

**Goal:** remove ambiguity and make PIC implementable by others without reading Python code as the de facto spec.

### 1.1 Canonicalization — frozen
**Status:** complete in v0.8.0

Canonicalization is no longer future work; it is the byte-level foundation. PIC-CJSON/1.0 is treated as **frozen within v0.8.x** and remains unchanged through v1.0.

Future canonicalization-related work is not "design canonicalization" but:

- Expand edge-case vectors (IEEE 754 shortest-round-trip, more Unicode edges)
- Cross-language parity (TypeScript)
- Runtime wire-up into signing paths (Phase 1.5)

---

### 1.2 Conformance expansion
**Target:** v0.8.2 (deferred from v0.8.1)

Expand the suite beyond first pass:

#### Evidence mode vectors
- hash verification allow/block vectors
- signature verification allow/block vectors
- revoked key
- expired key
- bad signature
- hash mismatch
- path sandbox / escape failures

#### Trust-sanitization mode vectors
- `strict_trust=True` vectors
- self-asserted trust gets sanitized
- same proposal under default mode vs strict-trust mode yields intentionally different verdicts where expected

#### Runner hardening
- JSON output mode
- filter by mode / id
- CI-friendly machine-readable report
- stricter manifest validation
- partial-run support for debugging

**Exit criteria:** evidence and trust-sanitization behavior are executable as portable conformance, not just local test behavior.

---

### 1.3 Initial DRAFT Core spec
**Target:** v0.8.2 (deferred from v0.8.1)

**File:** `docs/spec-core.md` (DRAFT)

Initial draft — **not** intended as fully normative until v1.0. Consolidates what is currently known and decided, using BCP 14 keywords to preview intended normative language. Evolves through v0.9.x as cross-impl pressure surfaces ambiguities.

The initial draft covers:
- BCP 14 conventions
- Proposal field meanings
- Allow/block rules
- Tool-binding semantics
- Impact semantics
- Error-code meanings
- Trust Axiom (normative even in draft)
- Conformance levels for the core verifier
- Disposition of `semi_trusted` (per Phase 0 decision: trust enum is binary as of v0.9.0)

**Trust Axiom (normative):**
Conformant verifiers MUST treat inbound `provenance[].trust` values as non-authoritative. Trust status MUST be derived solely from successful evidence verification or from verifier-controlled authenticated context.

**Exit criteria:** a reviewer can understand the core verifier contract from `spec-core.md` alone, without reading Python code. The doc is labeled DRAFT and explicitly notes that field lists and rule wording may evolve until v1.0 freeze.

---

### 1.4 Initial DRAFT Evidence spec
**Target:** v0.8.2 (deferred from v0.8.1)

**File:** `docs/spec-evidence.md` (DRAFT)

Same status pattern as `spec-core.md` — initial draft, evolves through v0.9.x, frozen at v1.0.

The initial draft covers:
- Evidence object shape and field semantics
- Evidence type semantics (`hash`, `sig`)
- Hash evidence verification rules
- Signature evidence verification rules
- Trust upgrade rules (verified evidence → trust state changes)
- Keyring / resolver expectations at the protocol boundary
- Distinction between protocol behavior and implementation policy
- Evidence-related error semantics
- Relationship to attestation objects and canonicalization

**Exit criteria:** evidence verification semantics are no longer split across `docs/evidence.md`, `pipeline.py`, `evidence.py`, `migration-trust-sanitization.md`, and tests.

---

### 1.5 Canonical runtime signing
**Target:** v0.8.2

Wire canonical attestation-object bytes into the live signing/verification path.

#### Runtime work
- Signer computes signature over `canonicalize(attestation_object)`
- Verifier parses payload, re-canonicalizes, verifies signature over canonical bytes
- Raw payload bytes are no longer treated as authoritative signing bytes in the new mode

#### Rollout strategy

Canonical signing in v0.8.2 lands **behind explicit mode selection** (e.g., a `PipelineOptions` flag or producer-side opt-in), with legacy payload-string signing remaining the default for one release. This matches the `strict_trust` precedent: introduce as opt-in, exercise both modes side-by-side for one or two releases to surface rough edges, flip the default at v1.0.

- v0.8.2 producers wanting the new behavior opt in explicitly.
- Verifiers MUST handle both modes regardless (legacy + canonical), so adoption can be staggered across the producer fleet.
- **Self-describing signatures**: producer and verifier MUST be able to distinguish legacy payload-string mode from canonical attestation-object mode without out-of-band metadata or guessing. The attestation-object draft already provides the discriminator via `attestation_version: "PIC-ATT/1.0"` in the parsed payload — its presence indicates canonical-bytes mode; its absence indicates legacy payload-string mode. Verifiers MUST determine signing mode from parsed payload semantics (the presence or absence of `attestation_version`), not from transport-specific hints (HTTP headers, content types, channel metadata, producer-identity guesses, or any other out-of-band signal). This requirement is normative even while the attestation-object spec is still draft, because mixed-fleet operation depends on it: if a producer can't unambiguously signal which mode it's using, a verifier can't unambiguously verify.
- v1.0 flips the default to canonical signing, and explicitly demotes legacy payload-string mode to non-conformant.

#### Backward compatibility
- Legacy payload-string signatures remain accepted as compatibility mode through v0.8.x and v0.9.x
- The legacy mode is clearly separated from Attestation Object v1 semantics in `spec-evidence.md` and `evidence.md`
- Existing v0 signatures continue to verify until at least PIC/1.0 normative cut

#### Status of Attestation Object v1 during this phase
**Stays DRAFT.** The runtime is using a draft spec; the spec is not promoted to normative until v1.0 (after TS verifier validates it against the same vectors).

**Exit criteria:** canonical bytes are operating in the live signing/verification path as opt-in; legacy mode is documented as compatibility-only; both modes pass conformance; the mode-discriminator requirement is satisfied across all signing/verifying entry points.

---

### 1.6 Schema cleanup: `semi_trusted` deprecation
**Target:** v0.8.1 (deprecation, ✅ shipped), v0.9.0 (removal, planned)

Implements the trajectory committed in Phase 0.

#### v0.8.1 work (✅ shipped)
- ✅ New `PICSemiTrustedDeprecationWarning` warning class — defined in `pic_standard.verifier` (model-layer concern, co-located with the `Provenance` model that fires it), subclasses `FutureWarning` so it's visible in Python's default warning filters, also re-exported at the `pic_standard` package root alongside `PICTrustFutureWarning`.
- ✅ **Canonical normalization boundary** is a pydantic field validator on `Provenance.trust` (`mode='before'`). Any code path that constructs a `Provenance` (or `ActionProposal`, which cascades) sees the warning + automatic normalization to `"untrusted"`; any path that bypasses the validator is non-conformant with the v0.8.1 behavior contract. Covers direct model construction outside `verify_proposal()` (HTTP bridge, LangGraph, MCP, CLI all funnel through `verify_proposal()`, but the validator is the safety net for any future direct-construction paths).
- ✅ **Bridge helper in `pic_standard.pipeline`** (`_normalize_provenance_entries_via_model_validator`) triggers the validator on raw provenance entries immediately after JSON Schema validation in `verify_proposal()`. This ensures the warning fires regardless of `strict_trust` mode (without it, strict-trust dict-level flattening would happen first and silently mask the deprecated value). Full `ActionProposal` instantiation still happens later in the pipeline, after evidence verification, so `verify_causal_contract` continues to observe the final post-evidence trust state — the existing `untrusted → evidence verified → trusted` upgrade path is unaffected.
- ✅ Warning fires once per `Provenance` instance constructed with `semi_trusted` (per-entry, not once-per-proposal). Multiple `semi_trusted` entries in one proposal → multiple warnings.
- ✅ `examples/financial_irreversible.json` and `examples/robotic_action.json` migrated off `trust: "semi_trusted"` to `trust: "untrusted"`. **Trust-flip only — no hash evidence added.** Adding hash evidence to a Slack message or voice transcript would have been semantically misleading (hash binds bytes, not authority), so the migration is the smallest honest change. The load-bearing `"trusted"` provenance entries (`cfo_signed_invoice_hash`, `lidar_safety_trigger`) are unchanged.
- ✅ New section in `docs/migration-trust-sanitization.md`: `semi_trusted` deprecation Q&A flipped from "(planned)" to "(this release)" tense; Timeline table gained a v0.8.1 row.
- ✅ CHANGELOG v0.8.1 "Deprecated" section names the v0.9.0 removal target.
- ✅ **Verdict-regression matrix** codified in `tests/test_trust_deprecation_warning.py` — parametrized test (24 rows × 6 example proposals × the `strict_trust × verify_evidence` matrix) that pins v0.8.0 baseline `verify_proposal()` outcomes (`ok` and `error.code` only — stable fields, asserted against `PICErrorCode` enum members). Stays in the suite as a permanent CI guard against any future refactor that touches the dict-vs-model boundary.

#### v0.9.0 work (planned)
- Remove `"semi_trusted"` from the trust enum in `proposal_schema.json`. Schema validation now rejects any proposal containing it.
- Remove the `SEMI_TRUSTED` enum member from `verifier.py`.
- Remove the `Provenance.trust` field validator's `semi_trusted` branch (the validator may be removed entirely or kept for future deprecation patterns).
- Remove the `_normalize_provenance_entries_via_model_validator` bridge helper from `pipeline.py`.
- Remove the `PICSemiTrustedDeprecationWarning` class.
- CHANGELOG v0.9.0 "Removed" entry; references the v0.8.1 deprecation cycle.

**Exit criteria:** trust enum is binary (`trusted` / `untrusted`) by end of v0.9.0; legacy emitters got one full release of warning; vestigial value is gone; no ingestion path can leak it through.

---

## Phase 2 — Enterprise-Deployable Guard

**Goal:** make PIC realistically deployable as a single enforcement point.

### 2.1 Formalize errors
**File:** `docs/ERRORS.md`
**Target:** v0.8.2 / v0.9.0

Document:
- Code meaning
- Retryability
- Operator-facing meaning
- HTTP mapping
- Optional structured sub-reasons where relevant

### 2.2 Guard hardening
**Target:** v0.9.0

- Structured JSON audit logs
- Request correlation / `X-Request-ID`
- Stable `/verify` contract
- Operator-facing deployment guidance

### 2.3 OpenAPI
**File:** `openapi/pic-guard.v1.yaml`
**Target:** v0.9.0

Make the guard API formally consumable by enterprises and integrators.

### 2.4 Docker hardening
**Target:** v0.9.0

Docker artifacts already exist (added in PR #37). v0.9.0 work is to **harden and standardize the deployment contract**, not introduce Docker. Includes:
- Production base image discipline
- Non-root user
- HEALTHCHECK
- Pinned versions
- Stable port + policy mount conventions

**Exit criteria:** a service can adopt PIC enforcement operationally without reverse-engineering the Python package.

---

## Phase 3 — TypeScript Verifier (prove PIC is a protocol)

**Goal:** produce a second independent implementation.
**Target:** v0.9.0 (minimum scope) / v0.9.x (full parity)

### 3.1 `pic-standard-ts`
A standalone verifier package, not just an integration client.

Must implement:
- Proposal validation
- Core verifier rules
- Canonicalization (PIC-CJSON/1.0)
- Error codes aligned to the protocol

Evidence verification, attestation-object semantics, and TS keyring/resolver are split between v0.9.0 minimum and v0.9.x completion (see 3.3).

### 3.2 TS trust/evidence model
- TypeScript equivalent of resolver abstraction
- No mandatory network dependency
- Same trust derivation model as Python

Evidence-related TS code may complete in v0.9.x; the v0.9.0 milestone does not require it.

### 3.3 Cross-language conformance

**Minimum required for v0.9.0**: TS runs the shared `conformance/manifest.json`, **filtered to canonicalization + core + trust-sanitization modes**. The TS verifier MUST pass all vectors in those three modes against Python's reference implementation. Evidence-mode vectors in the manifest are explicitly out of scope for the v0.9.0 milestone (TS skips them via mode filter, runner reports a clean partial pass).

**May complete in v0.9.x**: Evidence-mode parity (hash + signature vector execution from TypeScript). This is more code-heavy, depends on a TS keyring/resolver implementation, and can land incrementally without holding the v0.9.0 milestone.

For whichever modes are covered: same vectors, same allow/block results, same canonicalization bytes, same expected error-code outcomes.

**Exit criteria for v0.9.0**: Python + TS pass canonicalization + core + trust-sanitization modes when running against the same `conformance/manifest.json` (mode-filtered). Evidence-mode parity is tracked separately as a v0.9.x completion item.

---

## Phase 4 — Ambiguity Burn-Down

**Goal:** eliminate the ambiguity that only appears once two implementations exist.
**Target:** v0.9.1 – v0.9.2

### Work items
- Differential Python ↔ TS testing
- Fuzzing of malformed proposals/evidence
- More number edge vectors (IEEE 754 shortest-round-trip cases, currently deferred)
- More Unicode edge vectors
- Malformed JSON / parser-boundary negative cases (raw-text vector format if added)
- More evidence corruption / key-state vectors
- TS evidence-mode parity completed if not landed at v0.9.0
- Tighter wording wherever two implementations expose ambiguity
- Spec drafts (`spec-core.md`, `spec-evidence.md`, attestation-object) updated based on findings

**Exit criteria:** very little protocol behavior remains implementation-shaped. Spec drafts are stable enough to consider freezing.

---

## Phase 5 — Production Freeze / v1.0.0

**Goal:** freeze PIC Core/Evidence/Attestation as a real standard-grade protocol.

### v1.0 means
- `strict_trust=True` is **default and only conformant mode**
- Canonical attestation-object signing is **default and only conformant signing mode**; legacy payload-string mode is **explicitly non-conformant**
- `docs/spec-core.md` is **frozen as normative**
- `docs/spec-evidence.md` is **frozen as normative**
- Attestation Object v1 spec is **frozen as normative**. The current draft document `docs/attestation-object-draft.md` is **kept at its existing filename through v1.0 launch** to avoid link churn during the highest-visibility release moment. Any rename to `docs/attestation-object.md` is deferred to a post-v1.0 maintenance release (v1.0.1 or v1.1) when external link stability is less critical.
- `docs/canonicalization.md` (PIC-CJSON/1.0) remains unchanged
- Python + TS pass full conformance suite (all modes including evidence)
- Legacy compatibility paths are clearly marked non-conformant or compatibility-only
- Extension policy is documented

### Standards-track readiness
At this point external standardization work becomes meaningful, not before:
- Internet-Draft(s)
- Media type registration
- Minimal registries
- Governance process

These do not outrun proven interop.

**Exit criteria:** PIC is no longer "the Python implementation's protocol." It is an independently implementable standard contract.

---

## Beyond v1.0 (deferred)

These are important but stay downstream of a stable core:

- Broader TS hardening and ecosystem tooling
- Trust bundle profile
- Discovery profile
- Optional CBOR profile
- Registry/governance expansion
- More transport bindings
- Richer operator tooling
- File rename `docs/attestation-object-draft.md` → `docs/attestation-object.md` (deferred from v1.0 for link-churn reasons)

---

## Next PRs (sequenced)

| # | PR | Phase | Target |
|---|----|-------|--------|
| 1 | **Phase 0 hygiene PR**: commit ROADMAP.md, fix broken roadmap-link refs, document `semi_trusted` deprecation trajectory (Path B: deprecate v0.8.1, remove v0.9.0), add SECURITY.md and CODE_OF_CONDUCT.md | 0 | ✅ Done (PR #67) |
| 2 | Conformance expansion: evidence-mode + trust-sanitization vectors | 1.2 | ✅ Done (v0.8.2) |
| 3 | Runner hardening: JSON output, filtering, machine-readable diagnostics | 1.2 | ✅ Done (v0.8.2) |
| 4 | Initial DRAFT `docs/spec-core.md` | 1.3 | ✅ Done (v0.8.2) |
| 5 | Initial DRAFT `docs/spec-evidence.md` | 1.4 | ✅ Done (v0.8.2) |
| 6 | `semi_trusted` deprecation: `PICSemiTrustedDeprecationWarning` + canonical normalization at the model-validation boundary (pydantic field validator on `Provenance.trust` + bridge helper triggering it after JSON Schema validation) + example trust-flips + migration note + verdict-regression matrix | 1.6 | ✅ Done (v0.8.1) |
| 7 | Wire canonical attestation signing into runtime as opt-in mode (against draft Attestation v1) | 1.5 | ✅ Done (v0.8.2) |
| 8 | `docs/ERRORS.md` formalization | 2.1 | v0.9.0 |
| 9 | `semi_trusted` removal: schema enum drop + code cleanup | 1.6 | v0.9.0 |
| 10 | OpenAPI + Docker hardening + structured audit logs | 2 | v0.9.0 |
| 11 | First `pic-standard-ts` verifier pass (canon + core + trust-sanitization minimum) | 3 | v0.9.0 |
| 12 | TS evidence-mode parity (if not landed at v0.9.0) | 3 | v0.9.x |
| 13 | Differential testing + fuzzing | 4 | v0.9.1–v0.9.2 |
| 14 | Promote `spec-core.md`, `spec-evidence.md`, `attestation-object-draft.md` (filename preserved) to normative; flip canonical signing default; flip strict_trust default; ship v1.0 | 5 | v1.0.0 |

---

## Final Position

PIC already has the hardest foundation work behind it:

- Verifier
- Evidence model
- Trust-hardening direction
- Canonical byte model (PIC-CJSON/1.0 frozen)
- Conformance artifacts (canonicalization + core)
- Trust-enum cleanup in motion (`semi_trusted` deprecated v0.8.1, removal scheduled v0.9.0)
- Project hygiene (SECURITY/CoC/Citation/ROADMAP all on `main` post-Phase-0)

From here, the shortest path to becoming a standard protocol is:

1. **Finish normative semantics** — `spec-core.md`, `spec-evidence.md` (both DRAFT v0.8.2 → frozen v1.0)
2. **Complete conformance** — evidence mode, trust-sanitization mode, ambiguity burn-down
3. **Make canonical bytes the real runtime signing contract** — opt-in v0.8.2, default v1.0
4. **Build a second verifier** — TypeScript (v0.9.0 minimum scope, v0.9.x full parity)
5. **Reconcile the trust enum** — `semi_trusted` deprecated v0.8.1 (✅), removed v0.9.0
6. **Freeze behavior** — v1.0.0

That is the path this roadmap follows.
