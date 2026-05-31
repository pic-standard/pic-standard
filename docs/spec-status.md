# PIC Specification Status

## RFC-0001 (Defensive Publication)

[RFC-0001](RFC-0001-pic-standard.md) is the original defensive publication for the PIC/1.0 protocol baseline. It is intentionally preserved with its original [SHA-256 fingerprint manifest](RFC-0001.SHA256) to maintain provenance integrity.

**Versions covered by the anchored artifact:** v0.1.0 through v0.5.5

### Changes since the RFC anchor

| Version | What changed | Wire format impact |
|---------|-------------|--------------------|
| v0.6.0–v0.6.1 | Shared verification pipeline, Dependabot, smoke tests, `/v1/version` endpoint | None — internal refactoring + HTTP surface |
| v0.7.0 | Injectable `KeyResolver` protocol, lazy trust resolution, evidence hot path fix | None — SDK runtime behavior only |
| v0.7.1 | Deferred integration imports, CLI import isolation, specification status note | None — packaging/docs hygiene only |
| v0.7.5 | Trust sanitization (`strict_trust`), deprecation warning for self-asserted trust, attestation object draft, migration guide | None — behavioral option only; wire format unchanged |
| v0.8.0 | PIC Canonical JSON v1 spec (`docs/canonicalization.md`) + reference implementation (`pic_standard.canonical`), initial canonicalization + core conformance suite, conformance runner (`python -m conformance.run`), `PIC Conformance` CI job, refined attestation object draft with byte-level worked example | None — new capability added; existing proposals and signature verification paths unchanged. Canonicalization is not yet wired into evidence signing in v0.8.0. |
| v0.8.1 | `PICSemiTrustedDeprecationWarning` for `provenance[].trust = "semi_trusted"`; canonical normalization at the model-validation boundary (pydantic field validator on `Provenance.trust`) with a bridge helper in `verify_proposal()` triggering it after JSON Schema validation; both deprecation-warning classes re-exported at package root; example files migrated off `semi_trusted`; verdict-regression matrix added as a permanent CI guard for the dict-vs-model boundary | None — schema enum unchanged in v0.8.1 (still accepts `"semi_trusted"`); runtime normalizes to `"untrusted"` at parse time. Wire format unchanged. Schema-level removal scheduled for v0.9.0. |
| v0.8.2 | Evidence-mode conformance vectors (35 vectors under `conformance/evidence/`: 14 hash/legacy-sig + 21 canonical/legacy-signing-mode added in V8.2-5); trust-sanitization-mode conformance vectors (24 vectors under `conformance/trust_sanitization/` covering the `strict_trust × verify_evidence` matrix lifted from `tests/test_trust_deprecation_warning.py::VERDICT_REGRESSION_MATRIX`); conformance runner hardening (`--json` output, `--filter-mode`/`--filter-id` filters, 8-token diagnostic taxonomy, manifest-error envelope, subprocess-based CLI test suite in `tests/test_conformance_runner.py`); initial DRAFT specs `docs/spec-core.md` and `docs/spec-evidence.md` defining `PIC-Core` and `PIC-Evidence` conformance profiles in BCP 14 normative language; opt-in canonical attestation-object signing wired into the SDK evidence-verification path (`pic_standard.evidence`) — legacy mode (raw UTF-8 bytes of payload string) remains the default; canonical mode triggers when payload parses as a JSON object containing a supported string-valued `attestation_version` (current allowlist: `{"PIC-ATT/1.0"}`), with three-way fail-closed discriminator for non-string, unknown-version, and duplicate-key canonical-looking payloads; post-signature binding (args/claims/intent digests, tool/impact equality, provenance_ids ordering, expires_at freshness with strict RFC 3339) enforced in canonical mode. DRAFTs not final-normative until v1.0; published for community feedback per ROADMAP §1.3/§1.4. | None — additive only. New conformance vectors, machine-readable runner output, DRAFT specs, and canonical-mode signing verification do not change the proposal wire format. Existing legacy-mode signature verification behavior remains compatible with the pre-V8.2-5 evidence vectors and tests. Canonical-mode signing is opt-in: it is selected only when a sig-evidence payload parses as a JSON object containing a supported string-valued `attestation_version` (current allowlist: `{"PIC-ATT/1.0"}`). Payloads without `attestation_version` remain legacy mode through v0.8.x/v0.9.x. During runner-hardening, the default-invocation conformance runner human output format was preserved byte-identically relative to the post-vector baseline; vector counts changed only because new conformance vectors were added. |

The PIC/1.0 proposal structure and wire-level schema have remained stable since the RFC anchor. Post-RFC changes in v0.6.x–v0.8.x primarily affected shared pipeline behavior, trust resolution, integration surface, runtime efficiency, and canonicalization/conformance tooling rather than introducing a wire-format break.

**Current Python reference implementation:** v0.8.2

---

## PIC/1.0 Specifications

This repository hosts PIC/1.0 specification-track documents in
addition to RFC-0001. Specifications cite RFC-0001 and the frozen
canonicalization spec as authoritative; they restate v0.7.5+ semantics
in BCP 14 normative language for implementer-facing reference.

| Specification | Status | Profile coverage | Source |
|---------------|--------|------------------|--------|
| [PIC Canonical JSON v1](canonicalization.md) | Stable (frozen as of v0.8.0) | Required by `PIC-Evidence` for canonical-signing mode and attestation-object digest binding | `docs/canonicalization.md` |
| [PIC Attestation Object v1 — Draft](attestation-object-draft.md) | DRAFT | Required by `PIC-Evidence` for canonical-signing mode (opt-in during v0.8.x; intended default before PIC v1.0 unless superseded by DRAFT resolution) | `docs/attestation-object-draft.md` |
| [PIC Core Verifier Semantics](spec-core.md) | DRAFT (v0.8.2) | Defines `PIC-Core` profile | `docs/spec-core.md` |
| [PIC Evidence Verification Semantics](spec-evidence.md) | DRAFT (v0.8.2) | Defines `PIC-Evidence` profile | `docs/spec-evidence.md` |

### Conformance profiles

Defined normatively in [`spec-core.md §2`](spec-core.md#2-scope--conformance-profiles)
and [`spec-evidence.md §2`](spec-evidence.md#2-scope--conformance-profiles).
Summary:

- **`PIC-Core`** — Action Proposal parsing, impact taxonomy, trust
  sanitization, tool binding, verifier outcomes. Passes
  `conformance/core/` and `conformance/trust_sanitization/`.
- **`PIC-Evidence`** — Evidence object parsing, hash verification,
  signature verification, key lifecycle, trust upgrade. Passes
  `conformance/evidence/`.
- **`PIC-Full`** — Both `PIC-Core` and `PIC-Evidence`. An
  implementation MUST NOT claim `PIC-Full` unless it satisfies both
  underlying profiles.

A conforming implementation MUST state which profile(s) it implements.

### DRAFT status discipline

DRAFT specifications are not final-normative until PIC v1.0 (per
ROADMAP §1.3/§1.4). Open questions are tracked in each spec's
Appendix C ("Open Questions Registry") with stable IDs (e.g.
`OQ-CORE-001`, `OQ-EVIDENCE-001`) so they can be cross-referenced
from issues, PRs, and future revisions. DRAFTs cite higher-precedence
artifacts (RFC-0001, `canonicalization.md`) without restating their
normative content; conflicts are resolved as Open Questions, not by
silent re-interpretation (see each spec's "Normative Precedence and
Conflict Resolution" section).

---

## Canonical PIC Vocabulary

Authoritative term definitions are maintained in [`docs/vocabulary.md`](vocabulary.md). External crosswalks and registries (e.g. `aeoess/agent-governance-vocabulary`) should reference that file rather than recoining PIC terminology. When upstream PIC docs evolve a term, `vocabulary.md` is updated in the same PR; treat divergence between the two as a bug.
