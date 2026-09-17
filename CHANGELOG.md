# Changelog

All notable changes to this project will be documented in this file.

This project follows Semantic Versioning:
https://semver.org/

## [0.9.0a2] - 2026-09-17

Alpha 2 stop in the v0.9.0a1 → v0.9.0a2 → v0.9.0 sequence.
Independent Review Hardening: normative and runtime tightenings from
an independent Protocol Stress Test on v0.8.3 (HERMETICUM Phase 1 +
Phase 2) and the PIC maintainer's independent follow-up review. Adds
one new error code, tightens schema and runtime representations of
security-relevant values, and flips `PipelineOptions.strict_trust`
default from `False` to `True` so that self-asserted trusted
provenance no longer authorizes high-impact actions by default. The
proposal envelope remains otherwise compatible with v0.9.0a1. The
schema tightens SHA-256 hex representation to lowercase only, and
the runtime rejects malformed Base64 signatures fail-closed. PRs in
this release: #144, #145, #146, #147.

### Added

- **`PIC_DUPLICATE_ID` error code** (A3-HERM.2): new
  `PICErrorCode.DUPLICATE_ID` enum member with per-code docstring in
  `sdk-python/pic_standard/errors.py`. Documented in
  `docs/ERRORS.md` with retryability, HTTP mapping, operator
  meaning, and example wire shape. Mirrored in
  `integrations/openclaw/lib/types.ts` and in the `PIC_ERROR_CODES`
  enum of `openapi/pic-bridge.v1.yaml`. Emitted by a new pipeline
  step 2c uniqueness check placed after JSON Schema validation and
  lone-surrogate rejection, and before impact resolution, tool
  binding, evidence verification, and causal-taint evaluation.
  Error-code precedence pinned as
  `SCHEMA_INVALID > DUPLICATE_ID > TOOL_BINDING_MISMATCH >
  EVIDENCE_REQUIRED/EVIDENCE_FAILED > VERIFIER_FAILED`.
- **11 new conformance vectors** (A3-HERM.2): manifest total now
  84 (was 73). New vectors cover uppercase-SHA schema rejection,
  duplicate-provenance-id rejection, URL-safe Base64 rejection,
  unpadded Base64 rejection, overpadded Base64 rejection,
  whitespace-containing Base64 rejection, wrong-decoded-length
  Base64 rejection, and PIC-authored adapted regressions for
  selected Phase 2 cases under Apache-2.0, with origin attribution
  recorded in the adapted-vector provenance table. Phase 2 cases
  that were not adapted as executable vectors are documented
  separately in the independent-review provenance notes.
- **Independent-review provenance docs** (A3-HERM.2): new
  `docs/independent-reviews/README.md` index and
  `docs/independent-reviews/hermeticum-v0.8.3.md` PIC-authored
  summary. Includes non-certification wording, attribution block,
  frozen baseline commit reference, adapted-vector provenance
  table, and a placeholder for the forthcoming canonical
  HERMETICUM case-study URL. HERMETICUM sealed reports, PDFs,
  ZIPs, and methodology documents are not redistributed and remain
  under HERMETICUM's canonical control.
- **`PICLegacyTrustModeWarning`** (A3-HERM.3): new `FutureWarning`
  subclass exported from `pic_standard.PICLegacyTrustModeWarning`.
  Fires from `PipelineOptions.__post_init__` when the caller
  explicitly passes `strict_trust=False`, so the legacy
  compatibility opt-in cannot silently reintroduce self-asserted
  trusted provenance semantics. Coexists with the existing
  `PICTrustFutureWarning`; together they form the migration signal
  surface.
- **`pic-cli verify --legacy-trust`** (A3-HERM.3): explicit CLI
  opt-in for the legacy trust mode. Sets
  `PipelineOptions.strict_trust=False` and emits
  `PICLegacyTrustModeWarning`. `pic-cli serve` is untouched in this
  release; bridge callers select trust mode through the HTTP
  bridge parameter instead.
- **HTTP bridge `strict_trust` plumbing** (A3-HERM.3):
  `handle_verify()` in
  `sdk-python/pic_standard/integrations/http_bridge.py` gains a
  `strict_trust: bool = True` parameter forwarded to the shared
  pipeline, so the secure default is preserved across all bridge
  callers unless the caller explicitly opts out.

### Changed

- **`PipelineOptions.strict_trust` default flipped `False` → `True`**
  (A3-HERM.3): secure default. Under the new default, self-asserted
  `provenance[].trust = "trusted"` no longer authorizes high-impact
  actions; only authority-bearing signature evidence anchored in the
  configured keyring can raise trust to `"trusted"` under
  `strict_trust=True`. `strict_trust=False` remains callable as a
  compatibility surface and is not scheduled for removal in the
  v0.9.x series.
- **Adapter defaults aligned with the secure default** (A3-HERM.3):
  `sdk-python/pic_standard/integrations/langgraph_pic_toolnode.py`
  (`PICToolNode`), `sdk-python/pic_standard/integrations/mcp_pic_guard.py`
  (`guard_mcp_tool`, `guard_mcp_tool_async`, and the internal shared
  entry), and `sdk-python/pic_standard/integrations/http_bridge.py`
  (`handle_verify`) all default to `strict_trust=True`.
- **Spec and docs updated for the two-warning model and legacy
  compatibility path** (A3-HERM.3):
  `docs/migration-trust-sanitization.md` rewritten around the
  flipped default, with sections on what changed, why it matters,
  the warning model, migration steps, legacy compatibility mode,
  and FAQ. `docs/spec-core.md` §10 updated with mode ordering
  (secure default first), a v0.9.0a2 timeline row, and a normative
  statement that a conformant PIC implementation MUST default to
  secure trust mode. `README.md`, `docs/vocabulary.md`, and
  `docs/spec-status.md` updated to reflect the new default.
- **`docs/spec-core.md` and `docs/spec-evidence.md` tightened**
  (A3-HERM.1): §6.1 states unique-provenance-id as a normative
  MUST; §7 reaffirms exact string equality for `expected_tool`; a
  new "Representation vs. normalization" clause requires
  implementations to preserve security-relevant protocol values
  byte-for-byte unless a specification section explicitly defines
  normalization. `docs/spec-evidence.md` records SHA-256 lowercase
  and standard-padded RFC 4648 Base64 rules with an enumerated
  non-conformant list. `docs/vocabulary.md` reinforces the
  integrity vs authority boundary and adds a normalization-boundary
  term.
- **Repo-wide ruff hygiene** (#145): full-repo `ruff check` clean;
  CI ruff scope expanded from `sdk-python/` to `.`; ruff floor
  raised to `>=0.16.8`; Python-in-markdown formatter applied to
  `docs/deploy-docker.md` and `docs/RELEASING.md`. No behavioral
  change; supports the A3-HERM.2 and A3-HERM.3 drops.

### Fixed

- **Duplicate provenance-id ambiguity** (A3-HERM.1 + A3-HERM.2):
  the JSON Schema previously permitted duplicate `provenance[].id`
  values and the runtime's causal interpretation was undefined.
  Duplicates are now rejected with the new `PIC_DUPLICATE_ID` code
  before impact resolution or tool binding. Corresponds to the
  HERMETICUM Phase 2 ADV-003 novel case, previously classified as
  AMBIGUOUS_SPEC; converted to a PIC-maintained BLOCK vector after
  the spec fix.
- **Exact tool binding whitespace normalization removed**
  (A3-HERM.1 + A3-HERM.2): the reference verifier previously
  applied `.strip()` on both sides of the `expected_tool` vs
  `tool` comparison in `verify_with_context`. Whitespace variants
  now fail closed per the normative no-normalization clause.
  Corresponds to maintainer follow-up finding MAINT-F1.
- **Strict SHA-256 lowercase representation** (A3-HERM.1 +
  A3-HERM.2): the proposal schema regex tightened from
  `^[a-fA-F0-9]{64}$` to `^[a-f0-9]{64}$`, and the runtime
  `.strip().lower()` on SHA-256 hex evidence identifiers removed.
  Uppercase and mixed-case values previously accepted by the schema
  and normalized by the runtime are now rejected fail closed at
  both boundaries. Corresponds to HERMETICUM Phase 1 finding.
- **Strict Base64 signature representation** (A3-HERM.1 +
  A3-HERM.2): the runtime Base64 decoder in
  `sdk-python/pic_standard/evidence.py` no longer rewrites
  URL-safe `-/_` to the standard alphabet or auto-restores missing
  padding. URL-safe, unpadded, overpadded, whitespace-containing,
  and wrong-decoded-length signatures are all rejected fail closed
  via `b64decode(..., validate=True)` with explicit padding and
  alphabet checks. Corresponds to maintainer follow-up finding
  MAINT-F2.
- **Hash evidence remains content-integrity only** (A3-HERM.2):
  documentation across `README.md`, `docs/evidence.md`,
  `docs/fail-closed-evidence-mcp.md`, `docs/vocabulary.md`, and
  `conformance/trust_sanitization/README.md` updated to
  consistently describe hash evidence as content-integrity and to
  remove residual wording that could be read as hash evidence
  upgrading trust. The semantic tightening itself landed in v0.8.3;
  v0.9.0a2 completes the documentation sweep.

### Security

- **Fail-closed behavior strengthened.** Under the new secure trust
  default, self-asserted `provenance[].trust = "trusted"` no longer
  authorizes high-impact actions on its own; only authority-bearing
  signature evidence anchored in the configured keyring can raise
  trust to `"trusted"` under `strict_trust=True`. In combination
  with the new `PIC_DUPLICATE_ID` uniqueness check, the tightened
  whitespace-free tool binding, and the tightened SHA-256 and
  Base64 representations, this closes several fail-open paths that
  a producer could previously reach without violating the v0.8.3
  wire format. The v0.8.3 frozen review record is not retroactively
  modified; all hardening lands forward on `main` in v0.9.0a2.
  Callers relying on self-asserted `trust: "trusted"` provenance
  for high-impact actions will now block by default; explicit
  `strict_trust=False` remains available with
  `PICLegacyTrustModeWarning`. TypeScript verifier parity is not
  shipped in v0.9.0a2 and remains a v0.9.0 final item.

---

## [0.9.0a1] - 2026-09-14

Alpha preparation for the v0.9.0 cross-implementation milestone.
Schema/spec/conformance, HTTP bridge, OpenAPI, and Docker hardening
cleanup that prepares the second-language verifier interop planned for
v0.9.0. This alpha is the first stop in the planned
v0.9.0a1 → v0.9.0a2 → v0.9.0 sequence.

### Added

- **`docs/ERRORS.md`** (A2): documents the full `PICErrorCode` taxonomy for
  v0.9.0a1 with retryability, HTTP mapping, operator meaning, and example
  wire shapes. Regression test in `tests/test_errors_md.py` enforces
  heading-to-enum parity (documented headings must match enum length and
  membership).
- Per-member Sphinx-style `#:` comments on `PICErrorCode` in
  `sdk-python/pic_standard/errors.py`; parity note added to
  `integrations/openclaw/lib/types.ts`.
- **`canonical_reject` verdict in the conformance runner** (A3): the runner
  now supports negative canonicalization vectors alongside `canonical_match`.
  First negative vector `canon-010-lone-surrogate-rejection` pins the
  canonicalizer's rejection contract for a string containing a lone UTF-16
  surrogate. Manifest total: 73 vectors (was 72).
- **Pipeline-layer lone-surrogate guard** (A3): `verify_proposal` gains a
  step 2b that scans all proposal string values and object keys after JSON
  Schema validation and rejects any lone surrogate with
  `PIC_SCHEMA_INVALID`. Regression test in `tests/test_pipeline.py`.
- **`openapi/pic-bridge.v1.yaml`** (A4): OpenAPI 3.0.3 contract for the
  reference HTTP bridge covering `POST /verify`, `GET /health`, and
  `GET /v1/version`. Enumerates the 9 v0.9.0a1 `PICErrorCode` members.
- **`.spectral.yaml`** and **`.github/workflows/openapi.yml`** (A4):
  Spectral (built-in `spectral:oas` ruleset) lints the OpenAPI file in CI
  on every PR that touches `openapi/**`, `.spectral.yaml`, or the
  workflow itself. Node 22, spectral-cli 6.16.3, `contents: read`, 10-min
  timeout.
- **OpenAPI-derived contract tests** in `tests/test_http_bridge.py` (A4):
  POST examples from the yaml exercise the live bridge without local
  patching; response shape (required fields, no unexpected fields, error
  code enum) is derived from the yaml at runtime so the tests track the
  spec automatically.
- **`PyYAML>=6.0`** dev-only dependency in `sdk-python/requirements-dev.txt`
  so the OpenAPI contract tests actually run in CI.
- **`docs/deploy-docker.md`** (A5): deployment guide for the hardened
  compose profile with per-control rationale, nine exact `docker inspect`
  verification commands, file-permission requirements
  (`uid/gid 10001:10001`), safe local-override patterns, hardening
  non-coverage list, and a Docker availability gate.

### Changed

- **`docs/spec-core.md` §9.1** (A3): reworded the
  `PIC_SCHEMA_INVALID` vs `PIC_VERIFIER_FAILED` boundary
  language-independently. Schema-layer failures MUST emit
  `SCHEMA_INVALID`; semantic post-schema PIC contract violations MUST
  emit `VERIFIER_FAILED`. Removes the pydantic-specific framing so a
  non-Python verifier (e.g., Ajv-based TS) lands the same boundary.
- **`docs/spec-core.md` §9.2** (A3): explicit error-code precedence pinned
  as `SCHEMA_INVALID > TOOL_BINDING_MISMATCH >
  EVIDENCE_REQUIRED / EVIDENCE_FAILED > VERIFIER_FAILED`. Appendix C
  moves `OQ-CORE-001` from Open to Resolved.
- **`docs/canonicalization.md` §7.13** (A3): tightens the lone-surrogate
  MUST-reject clause with "before emitting any canonical bytes" timing
  and maps the rejection to `PIC_SCHEMA_INVALID` at the verifier
  boundary. §10.1 references `canon-010`.
- **`GET /v1/version` response body** (A4): additive — adds `impl_name`
  (`"pic-standard-py"`), `impl_version`, `pic_protocol_version`
  (`"PIC/1.0"`), `conformance_manifest_ref` (`{path, sha256, commit}`),
  and `supported_modes`. Legacy fields (`pic_version`,
  `package_version`, `commit`, `policy_version`, `request_id`) preserved
  verbatim. `conformance_manifest_ref.sha256` content-addresses
  `conformance/manifest.json` as `"sha256:<64 lowercase hex>"` in a repo
  checkout and degrades to `"unknown"` in a packaged wheel that does not
  bundle the conformance suite. `commit` fields degrade to `"unknown"`
  when git is unavailable at bridge startup.
- **Centralized invalid `X-Request-ID` rejection** (A4): the bridge now
  enforces `docs/ERRORS.md`'s pre-pipeline validation contract — an
  invalid supplied header returns HTTP 400 with `PIC_INVALID_REQUEST`
  and a freshly generated `request_id` (never echoing the invalid
  supplied value). Uniform across `/verify`, `/health`, `/v1/version`,
  unknown paths, and disallowed methods. Prior silent-substitute
  behavior removed.
- **`docker-compose.yml` hardened** (A5): loopback-only host port
  binding, read-only rootfs with a bounded
  `/tmp:size=64m,noexec,nosuid,nodev` tmpfs, `cap_drop: [ALL]`,
  `security_opt: [no-new-privileges:true]`, non-root uid `10001:10001`
  pin, resource limits (`mem_limit: 512m`, `cpus: "0.5"`,
  `pids_limit: 128`) mirrored in `deploy.resources.limits`, `init: true`,
  `stop_grace_period: 10s`, and an explicit `pic-internal` user-defined
  bridge network. The dead `./sdk-python:/workspace:ro` source-code
  mount is removed; the compose `command:` override drops
  `--repo-root /workspace` so the CLI falls back to `/app`.
- Replaced `semi_trusted` warning/normalization tests with a
  schema-rejection regression guard and a package-root negative import
  test.
- Updated trust-sanitization and core-spec documentation to describe
  `semi_trusted` as removed starting in v0.9.0a1.
- Updated `docs/spec-status.md` with the missing v0.8.3 status row and
  the new v0.9.0a1 removal row.

### Removed

- Removed the legacy `provenance[].trust = "semi_trusted"` value from the
  proposal schema. Proposals carrying `"semi_trusted"` now fail JSON
  Schema validation with `PIC_SCHEMA_INVALID`.
- Removed the v0.8.1 `semi_trusted` compatibility path:
  `PICSemiTrustedDeprecationWarning`, `TrustLevel.SEMI_TRUSTED`, the
  `Provenance.trust` normalization validator, and the pipeline bridge
  helper that triggered that normalization.
- Removed the deprecated `apply_verified_ids_to_provenance` wrapper
  (introduced in v0.8.3 with a `DeprecationWarning`). Callers must use
  `apply_trust_upgrade_ids_to_provenance` fed from
  `EvidenceReport.trust_upgrade_ids`.
- Removed the redundant `./sdk-python:/workspace:ro` volume mount from
  `docker-compose.yml` (source was already installed in the image; mount
  provided no runtime value).

### Fixed

- **`docker-compose.yml` pids-limit alignment**: Docker Compose engine
  5.5.1+ rejects the project when service-level `pids_limit` is set
  without a matching `deploy.resources.limits.pids`. Both are now `128`.

### Notes

- Protocol-level breaking change for producers still emitting
  `"semi_trusted"`: replace it with `"untrusted"`; high-impact flows
  that need trusted status under strict mode should rely on
  verifier-controlled context or authority-bearing evidence such as
  signature evidence.
- Breaking change for HTTP bridge consumers that previously supplied an
  invalid `X-Request-ID` and expected silent UUID substitution; those
  callers now receive HTTP 400 / `PIC_INVALID_REQUEST`. The valid form
  is `^[A-Za-z0-9._:-]+$` up to 128 characters.
- Breaking change for the reference `docker-compose.yml` profile: host
  port bind moves from `0.0.0.0:7580` to `127.0.0.1:7580`. Callers on
  other hosts must add a narrow `docker-compose.override.yml` to
  rebind, or connect through localhost.
- No change to canonical byte output for conformant inputs. Existing
  PIC-CJSON/1.0 positive canonicalization vectors remain unchanged.
  v0.9.0a1 adds the first negative canonicalization vector
  (`canon-010-lone-surrogate-rejection`) and a `canonical_reject`
  runner verdict for inputs that must be rejected before canonical bytes
  are emitted.
- TypeScript verifier work is not included in this entry; it remains
  the final v0.9.0 interop milestone.
---

## [0.8.3] - 2026-09-07

Evidence-semantics tightening: hash evidence is content-integrity only. Reported by @keureyes in [#133](https://github.com/pic-standard/pic-standard/issues/133).

### Changed

- **Hash-evidence trust-upgrade semantics tightened.** A matching SHA-256 hash now produces a `hash_verified` result (content-integrity of the referenced file bytes) and MUST NOT upgrade `provenance[].trust` from `"untrusted"` to `"trusted"` by itself. The prior draft evidence semantics allowed a proposal author to supply both the referenced bytes and the digest, using the resulting hash match to reach trusted provenance for high-impact actions. This was integrity, not authority; it is corrected in v0.8.3. Signature evidence (Ed25519, anchored in the configured keyring) continues to upgrade trust unchanged.

### Notes

- **Proposal format unchanged.** The PIC/1.0 proposal and evidence schemas are unchanged from v0.8.2. The behavior change is verifier-side only.
- **Behavior change under `strict_trust=True`:** high-impact proposals that previously reached `trusted` via hash-only evidence now BLOCK with `PIC_VERIFIER_FAILED`. See the "hash-evidence trust-upgrade" FAQ in [`docs/migration-trust-sanitization.md`](docs/migration-trust-sanitization.md) for migration guidance.
- **Operator-visible interaction with `allow_sig_evidence`:** under `strict_trust=True`, hash-only high-impact proposals now block regardless of `allow_sig_evidence`. Deployments that previously disabled signature evidence and relied on hash-only trust upgrade must add signature evidence or accept the new BLOCK verdict.
- **Authority primitive deferred.** A future release may define an authority primitive (verifier-owned signed manifest or protected-namespace policy) that admits specific hash-verified entries into trust upgrade. Tracked as `OQ-EVIDENCE-005` in [`docs/spec-evidence.md`](docs/spec-evidence.md) Appendix C.

### Conformance vector changes

- Moved `conformance/evidence/allow/001_hash_simple.json` -> `conformance/evidence/block/027_hash_no_trust_upgrade_falsifier.json` (id `evidence-hash-allow-001-simple` -> `evidence-hash-block-027-no-trust-upgrade-falsifier`), reframed as the #133 falsifier. Expected verdict flipped `allow` -> `block` with `PIC_VERIFIER_FAILED`.
- Moved `conformance/evidence/allow/003_hash_multiple.json` -> `conformance/evidence/block/028_hash_multiple_no_trust_upgrade.json` (id `evidence-hash-allow-002-multiple-hashes` -> `evidence-hash-block-028-hash-multiple-no-trust-upgrade`). Same verdict flip.
- Renamed 4 trust-sanitization vectors `conformance/trust_sanitization/financial_hash_ok__strict-*__verify-*.json` -> `financial_hash_only__strict-*__verify-*.json` (id `trust-financial_hash_ok-*` -> `trust-financial_hash_only-*`; `matrix_id` `financial_hash_ok` -> `financial_hash_only`). The two `__verify-t` variants additionally flip `allow` -> `block` with `PIC_VERIFIER_FAILED`; the two `__verify-f` variants keep their existing block verdict.
- `conformance/evidence/allow/004_mixed_hash_and_sig.json` unchanged: signature evidence continues to upgrade trust and this vector remains a live regression guard for the signature path.

---

## [0.8.2] - 2026-05-31

Conformance + spec-drafts + opt-in canonical signing.

### Added

- **Evidence-mode conformance vectors** under `conformance/evidence/` (35 total: 14 hash/legacy-sig added in V8.2-1, plus 21 canonical/legacy-signing-mode added in V8.2-5). Covers hash + sig allow/block, sandbox + key-state, canonical-mode happy/minimal/mixed paths, three-way fail-closed discriminator (unknown `attestation_version`, non-string `attestation_version`, root/nested duplicate keys), digest binding, field binding, freshness, and digest-field shape rules.
- **Trust-sanitization conformance vectors** under `conformance/trust_sanitization/` (24 vectors covering the `strict_trust × verify_evidence` matrix over representative proposal bases, lifted from `tests/test_trust_deprecation_warning.py::VERDICT_REGRESSION_MATRIX`).
- **Conformance runner hardening**: `--json` machine-readable output, `--filter-mode <mode>` and `--filter-id <id>` filters with stable exit codes under filter, 8-token diagnostic taxonomy, manifest-error envelope, subprocess-based CLI test suite in `tests/test_conformance_runner.py`.
- **Initial DRAFT `docs/spec-core.md`** — BCP 14 normative restatement of core verifier semantics (Trust Axiom, tool-binding, impact taxonomy, error identifiers). Defines the `PIC-Core` conformance profile. Not final-normative until PIC v1.0.
- **Initial DRAFT `docs/spec-evidence.md`** — BCP 14 normative restatement of evidence verification (hash/sig modes, trust upgrade, keyring protocol, signing-mode discriminator, canonical-mode digest binding, freshness). Defines the `PIC-Evidence` conformance profile. Not final-normative until PIC v1.0.
- **Opt-in canonical attestation-object signing** in the SDK evidence-verification path (`pic_standard.evidence`). Verifier detects canonical mode from a supported string-valued `attestation_version` in the parsed `sig` evidence payload (current allowlist: `{"PIC-ATT/1.0"}`); non-string and unknown-version values fail closed (no silent legacy fallback). Canonical mode computes signature over `canonicalize(parsed_attestation_object)` bytes per `docs/canonicalization.md §8.4`. Post-signature, canonical mode enforces digest binding (`args_digest` / `claims_digest` / `intent_digest` when present), tool/impact equality binding, `provenance_ids` proposal-array ordering, and `expires_at` freshness (strict RFC 3339 with explicit timezone designator; whitespace-padded and naive timestamps rejected).
- **Persistent canonical-signing test suite** at `tests/test_evidence_canonical_signing.py` (24 scenarios), covering canonical happy/minimal paths, discriminator failures, digest/field binding, freshness, duplicate-key rejection, legacy preservation, mixed-mode verification, and post-canonical size caps. Keeps project coverage above the 80% gate.

### Changed

- **Conformance runner** human-readable output is preserved byte-identically relative to the post-vector baseline for the default invocation. `--json` mode adds machine-readable structured output; `--filter-mode`/`--filter-id` add CI-gate ergonomics. Exit codes are stable under filter (exit 2 with `no_vectors_selected` diagnostic when a filter target matches zero vectors).
- **`docs/spec-status.md`** v0.8.2 row updated to reflect new conformance vector counts and the opt-in canonical-signing landing.

### Notes

- **Wire format unchanged.** The PIC/1.0 proposal and evidence schemas are byte-compatible with v0.8.1.1. Legacy-mode signature verification behavior remains compatible with all pre-V8.2-5 evidence vectors and tests.
- **Canonical signing is opt-in.** A producer chooses canonical mode by emitting `attestation_version` in the signed payload. Producers that do not emit `attestation_version` continue to get legacy-mode (raw UTF-8 bytes of payload string) verification. Canonical-as-default is deferred to the PIC v1.0 track unless superseded by later DRAFT resolution.
- **DRAFT spec discipline.** `docs/spec-core.md` and `docs/spec-evidence.md` are DRAFT until PIC v1.0 per ROADMAP §1.3/§1.4. Open questions are tracked in each spec's Appendix C with stable IDs (`OQ-CORE-*`, `OQ-EVIDENCE-*`) for cross-referencing.
- **`docs/ERRORS.md` formalization deferred to v0.9.0.** Runner-side structured diagnostics from V8.2-3 feed into that work.
- **TypeScript verifier first pass (`pic-standard-ts`) planned for v0.9.0.** This release lays its conformance foundation; the 72-vector suite is the cross-language contract the TS verifier will gate against.
- **`semi_trusted` enum schema-level removal still scheduled for v0.9.0.** Currently deprecated since v0.8.1 with runtime normalization; this release does not change that trajectory.

---

## [0.8.1.1] - 2026-05-11

Shakedown release through the new signing infrastructure. **No protocol changes vs v0.8.1.**

This release exists to exercise the release-signing pipeline (PR #77) end-to-end and produce the first PyPI artifact bearing PEP 740 attestations + the first git tag signed with the project's dedicated Ed25519 release-signing key.

### Notes
- **No code or protocol changes vs v0.8.1.** Hygiene/infrastructure-only since v0.8.1: code-style enforcement (Ruff + ESLint/Prettier) and 80% Python statement-coverage gate (PR #73); release-signing pipeline (PR #77).
- **First signed release.** Pre-`v0.8.1.1` releases are unsigned legacy artifacts. See [`RELEASING.md`](RELEASING.md) for verification commands and the trusted public signing key fingerprint.

---

## [0.8.1] - 2026-05-07

### Added
- **`PICSemiTrustedDeprecationWarning`** (`pic_standard.verifier`) — fires at the model-validation boundary when a `Provenance` is constructed with `trust='semi_trusted'`, whether via `verify_proposal()` or via direct model construction. Replaces silent acceptance with explicit deprecation signaling. Subclasses `FutureWarning` (visible by default in Python's warning filters) to ensure producers actually see the migration signal.
- **Pydantic field validator on `Provenance.trust`** (`mode='before'`) — the canonical normalization boundary for the deprecated value. Normalizes `"semi_trusted"` → `"untrusted"` at construction time and emits the deprecation warning. Applies in all modes (not only `strict_trust=True`). Any construction path that bypasses this validator is non-conformant with the v0.8.1 behavior contract.
- **Bridge helper in `pic_standard.pipeline`** (`_normalize_provenance_entries_via_model_validator`) — triggers the canonical field validator immediately after JSON Schema validation in `verify_proposal()`, so the deprecation warning fires regardless of `strict_trust` mode and `semi_trusted` is normalized to `"untrusted"` before strict-trust flattening or evidence verification consume the dict. Full `ActionProposal` instantiation still happens later in the pipeline, after evidence verification, so `verify_causal_contract` continues to observe the final post-evidence trust state.
- **Package-root re-export** for both deprecation warning classes: `from pic_standard import PICSemiTrustedDeprecationWarning, PICTrustFutureWarning`. The existing deep-import paths (`pic_standard.verifier`, `pic_standard.pipeline`) continue to work; re-export is additive and pinned by a small public-API assertion test.
- **Test coverage** for the new warning in `tests/test_trust_deprecation_warning.py`, including:
  - Direct-construction tests (string and enum forms) on `Provenance`.
  - Cascade tests via `ActionProposal` proving per-entry warning cardinality.
  - `verify_proposal()` flow tests in both non-strict and `strict_trust=True` modes (the latter is the load-bearing Path A property).
  - Mixed-provenance and "no `semi_trusted` present" regression guards.
  - A **verdict-regression matrix** (parametrized, 24 rows across 6 example proposals × the `strict_trust × verify_evidence` matrix) that pins the v0.8.0 baseline `verify_proposal()` outcomes (`ok` and `error.code` only — stable fields, asserted against `PICErrorCode` enum members, no free-text). Stays in the suite as a permanent CI guard against any future refactor that touches the dict-vs-model boundary. Includes an explicit canary case (`financial_hash_ok.json` with `verify_evidence=True`) that would flip from `ok=True` to `ok=False` if full instantiation ever moved ahead of evidence verification.

### Deprecated
- **`provenance[].trust == "semi_trusted"`** is **deprecated** in v0.8.1. Producers MUST migrate to `"untrusted"`. The value is normalized to `"untrusted"` automatically, in all modes, by the model-validation boundary, and a `PICSemiTrustedDeprecationWarning` is emitted on every `Provenance` construction with the deprecated value. **Removal is scheduled for v0.9.0**, where the value will fail JSON Schema validation and be removed from the `TrustLevel` enum entirely. See `docs/migration-trust-sanitization.md` for the full trajectory and producer migration path.

### Changed
- **`examples/financial_irreversible.json`** and **`examples/robotic_action.json`** — migrated off `trust: "semi_trusted"` to `trust: "untrusted"`. Trust-flip only; no hash evidence added. Adding hash evidence to a Slack message or voice transcript would have been semantically misleading (hash binds bytes, not authority) and risked teaching the wrong security intuition given that PIC's evidence flow upgrades trust on successful hash verification. The existing trusted provenance entries (`cfo_signed_invoice_hash`, `lidar_safety_trigger`) remain the load-bearing sources; the migrated entries stay as honest `untrusted` corroboration.
- **`verify_proposal()`** now triggers the `Provenance.trust` field validator immediately after JSON Schema validation, so deprecated `semi_trusted` inputs warn and normalize before strict-trust flattening or evidence verification. Full `ActionProposal` instantiation still occurs later in the pipeline, after evidence verification, so contract enforcement (`verify_causal_contract`) continues to observe the final trust state and existing verdict behavior is preserved end-to-end.
- **`docs/migration-trust-sanitization.md`** — `semi_trusted` Q&A flipped from "(planned)" to "(this release)" tense; new `v0.8.1` row added to the Timeline table; example file migration noted explicitly.

### Notes
- **The proposal JSON Schema (`proposal_schema.json`) still accepts `"semi_trusted"` in v0.8.1.** Runtime normalizes the value at the model-validation boundary; the schema enum is unchanged in this release. Schema-level removal happens in v0.9.0 per the migration trajectory in `docs/migration-trust-sanitization.md`.
- **No canonicalization changes.** PIC-CJSON/1.0 remains frozen at v0.8.0.
- **No conformance manifest changes.** Existing vectors continue to pass.
- **No wire format change.** Existing v0.8.0 proposals continue to parse, verify, and produce the same allow/block verdicts under v0.8.1 (the verdict-regression matrix codifies this guarantee).

---

## [0.8.0] - 2026-04-20

### Added
- **PIC Canonical JSON v1 spec** — `docs/canonicalization.md` normatively defines PIC-CJSON/1.0: RFC 8785 (JSON Canonicalization Scheme) as the baseline, plus PIC-specific rules for object key ordering, string escaping, number serialization, Unicode handling, boolean/null serialization, lone-surrogate rejection, and the digest-byte rules for `args_digest`, `claims_digest`, `intent_digest`, and attestation-object signed bytes (§8.1–§8.4). Frozen for PIC-CJSON/1.0; edge cases discovered after release are spec-level discussions, not patch-level fixes.
- **Reference canonicalization implementation** — `pic_standard.canonical` module with:
  - `canonicalize(value) -> bytes` — PIC-CJSON/1.0 serializer, pure Python stdlib (no runtime dependencies).
  - `sha256_hex(value) -> str` — convenience for §8.1 / §8.2 digests.
  - `intent_digest_hex(intent) -> str` — §8.3 path: hashes raw UTF-8 bytes of the intent string, explicitly distinct from `sha256_hex` to prevent the common trap of canonicalizing bare strings.
  - `CanonicalizationError` — PIC's own exception class, independent of the vendored dependency.
- **Conformance suite (`conformance/`)** — new top-level directory containing:
  - 9 canonicalization vectors under `conformance/canonicalization/` covering key ordering (including UTF-16 supplementary-plane trap), array preservation, string escaping (all RFC 8785 named escapes + representative unnamed controls + solidus), number serialization (11 cases across the ECMAScript `Number::toString` branch matrix), booleans/null, and attestation-object / claims-array shapes.
  - 4 core-verifier vectors under `conformance/core/` (2 allow, 2 block) pinning `PIC_VERIFIER_FAILED` and `PIC_TOOL_BINDING_MISMATCH` outcomes.
  - `conformance/manifest.json` — versioned (`conformance/v0.1`) index of all vectors.
  - Per-directory `README.md` files documenting vector format and seeding discipline.
- **Conformance runner** — `conformance/run.py` (`python -m conformance.run`) executes every vector, validates manifest schema strictly (rejects unknown fields and mode/expected mismatches), detects manifest/vector drift, and produces a pass/fail report with CI-friendly exit codes.
- **CI workflow** — `.github/workflows/conformance.yml` runs the conformance suite on every push and pull request as a `PIC Conformance` check, separate from the main CI job.
- **Unit tests** — `tests/test_canonical.py` adds 71 tests covering the conformance vector sweep, §10.1 implementation-local rejection cases (non-finite numbers, non-string keys including the pathological `.encode()`-bearing class, circular references, tuples, non-serializable host types, lone surrogates, integers outside the ±(2^53 − 1) safe range), and the `sha256_hex` ↔ `intent_digest_hex` distinction.
- **Refined attestation object draft** — `docs/attestation-object-draft.md` updated to cite the normative canonicalization spec directly, replace placeholder digests with real byte-verifiable hex values, document the §8.4 signer/verifier contract (both re-canonicalize from the parsed attestation object; raw payload bytes are never signed or verified directly), and link to the conformance vector that pins its worked example.

### Changed
- `docs/attestation-object-draft.md` Status banner no longer says the canonicalization spec "does not yet exist"; instead it separates what's frozen in v0.8.0 (canonicalization rules, digest inputs) from what remains DRAFT (field set, freshness semantics, audience semantics).

### Vendored
- **Trail of Bits `rfc8785.py`** (v0.1.4, commit `e7bbf8987c484950edfad6cc2a29f69a18920c8e`, Apache-2.0) — vendored at `sdk-python/pic_standard/_rfc8785.py` to provide RFC 8785 number and string serialization. Upstream raw blob SHA-256 `c25bc3a046528482d53bee3487b837f31dd9c05f33e8f13288c7aab320932cec` is pinned in the file header and in `THIRD_PARTY_NOTICES.md` at the repo root. PIC-specific behavior (tuple rejection, lone-surrogate-in-key validation, circular reference detection, `canonicalize`/`sha256_hex`/`intent_digest_hex` public API, exception normalization) lives in `pic_standard.canonical` which wraps the vendored module.

### Notes
- **Runtime behavior of existing proposals is unchanged in v0.8.0.** Canonicalization is a new capability exposed through `pic_standard.canonical`; it is not wired into `verify_proposal()` or evidence signing paths. Existing payload-string signatures continue to verify as v0 legacy mode.
- **Wire-up of canonicalization into evidence signing** (attestation-object-backed signatures using `canonicalize(attestation_object)` as the signed bytes per §8.4) is deferred to a future release.
- **Evidence-mode and trust-sanitization-mode conformance vectors** are deferred to v0.8.1+ per the Out of Scope section of the v0.8.0 plan. v0.8.0's conformance suite covers canonicalization mode and core verifier mode only.
- **Cross-implementation conformance** (TypeScript/Go) arrives alongside those reference implementations in Phase 3+; the v0.8.0 conformance suite is deliberately language-neutral (JSON vectors + hex expectations + SHA-256 expectations) so any future language binding consumes the same vectors.

---

## [0.7.5] - 2026-04-03

### Added
- **`strict_trust` pipeline option**: new `PipelineOptions.strict_trust` (default `False`).
  When enabled, all inbound `provenance[].trust` values are sanitized to `"untrusted"`
  before verification. Evidence verification is the only path to trusted status.
- **Trust deprecation warning**: when a proposal declares `trust:"trusted"` but
  effective evidence verification will not run for that proposal, a
  `PICTrustFutureWarning` is emitted with migration guidance. In PIC/1.0,
  non-sanitizing mode will be legacy and non-conformant.
- **Attestation Object v1 draft**: `docs/attestation-object-draft.md` — non-normative
  design document for the canonical minimal signing target (community feedback welcome).
- **Migration guide**: `docs/migration-trust-sanitization.md` — step-by-step guide for
  migrating from self-asserted trust to evidence-backed trust.
- `strict_trust` and `key_resolver` parameters in `guard_mcp_tool()`,
  `guard_mcp_tool_async()`, and `PICToolNode` for integration-level opt-in.

### Changed
- **Pipeline refactor**: `verify_proposal()` now finalizes trust state (sanitization +
  evidence verification + trust upgrade) before `ActionProposal` instantiation. This
  removes duplicate instantiation/binding and ensures `strict_trust=True` works correctly
  with evidence-backed proposals.
- `PICToolNode` constructor now accepts `verify_evidence`, `strict_trust`, `key_resolver`,
  `policy`, `proposal_base_dir`, and `evidence_root_dir` for full pipeline configuration.

---

## [0.7.1] - 2026-03-18

### Fixed
- **Import crash on base install**: `import pic_standard.cli` no longer fails
  when optional dependencies (`langchain-core`, `mcp`) are not installed.
  `integrations/__init__.py` now uses lazy `__getattr__` loading so importing
  one integration does not pull in another's dependencies.
- CLI `serve` command import moved inside the handler — `pic-cli verify`,
  `pic-cli keys`, etc. no longer trigger any integration imports.

### Added
- `docs/spec-status.md` — companion status note for RFC-0001, explaining that
  the defensive publication is intentionally preserved with its original SHA-256
  fingerprint while the implementation has evolved through v0.7.x.
- `TYPE_CHECKING` imports and `__dir__()` in `integrations/__init__.py` for
  IDE/type-checker support.

---

## [0.7.0] - 2026-03-12

### Added
- **`KeyResolver` protocol** — injectable, sync-only interface for trust key resolution.
  `get_key(key_id) -> Optional[bytes]` and `key_status(key_id) -> KeyStatus`.
- **`StaticKeyRingResolver`** — zero-I/O resolver backed by a pre-loaded `TrustedKeyRing`.
- `PipelineOptions.key_resolver` — threads custom resolver through the shared pipeline
  into `EvidenceSystem`.
- `KeyResolver` and `StaticKeyRingResolver` exported from `pic_standard` public API.
- `tests/test_key_resolver.py` — 7 tests covering resolver protocol, injection,
  lazy default semantics, and pipeline threading.

### Changed
- **Evidence hot path fix:** `EvidenceSystem` no longer reloads the keyring per signature
  item. Default trust resolution is lazy (loaded on first signature verification only).
- `EvidenceSystem.__init__` accepts optional `key_resolver` parameter. When omitted,
  the default resolver is constructed lazily via `TrustedKeyRing.load_default()` on
  first use — hash-only evidence never triggers keyring loading.
- Deleted `_load_public_key_from_keyring()` module-level function; replaced by
  `EvidenceSystem._resolve_public_key()` instance method using the resolver protocol.

### Fixed
- Hash-only evidence verification no longer triggers unnecessary keyring file I/O.

---

## [0.6.1] - 2026-02-26

### Changed
- **Shared verification pipeline**: Extracted duplicated verification logic from
  MCP guard, LangGraph, and CLI into a single `pipeline.py` module with
  `verify_proposal()` as the one function all consumers delegate to.
- All three consumers (MCP guard, LangGraph ToolNode, CLI) now delegate to
  `pipeline.verify_proposal()` instead of reimplementing the verification chain.
- **Error code semantics**: `ActionProposal` instantiation / verifier-rule failures
  are now reported as `PIC_VERIFIER_FAILED` (instead of `PIC_POLICY_VIOLATION` in
  some MCP paths).
- `pic-cli verify` now uses the shared pipeline (`verify_proposal()`), aligning CLI
  behavior with MCP/LangGraph verification flow.
- `_debug_enabled()` moved to `errors.py` (shared location).
- `PICEvaluateLimits` canonical home moved to `pipeline.py`.
- `integrations/__init__.py` exports `PipelineOptions`, `PipelineResult`,
  `verify_proposal`, and `guard_mcp_tool_async`.

### Fixed
- Catch-all in MCP guard wrappers changed from `POLICY_VIOLATION` to
  `INTERNAL_ERROR`.
- Evidence imports narrowed from `except Exception` to `except ImportError`.
- Impact resolution now falls back to `expected_tool` when `tool_name` is None.
- Impact enum values normalized to strings before comparison.

### Added
- `pipeline.py` — shared verification pipeline with `PipelineOptions`,
  `PipelineResult`, and `verify_proposal()`.
- `tests/test_pipeline.py` — 26 tests covering schema, verifier rules, tool
  binding, limits, impact resolution, evidence gating, time budget, and result shape.
- `tests/conftest.py` — `make_proposal()` helper and reusable pytest fixtures.
- `_b64decode()` now supports a `strict` mode (default remains permissive for
  backward compatibility; strict mode will be used in future canonicalization
  tightening).
- Cross-ref comments on `VERIFIER_FAILED` and `POLICY_VIOLATION` in `errors.py`.

---

## [0.6.0] - 2026-02-19

### Added
- **Cordum integration**: Pack for workflow-level PIC verification gating
  - Worker topic: `job.pic-standard.verify`
  - Workflow routing: `proceed` / `fail` / `require_approval`
  - Fail-closed HTTP bridge client (Go)
  - Pack source: `cordum-io/cordum-packs` → `packs/pic-standard/`
- `integrations/cordum/` — README, example policy config
- `docs/cordum-integration.md` — full integration guide with architecture diagram

---

## [0.5.5] - 2026-02-18

### Fixed (OpenClaw Plugin — PR #14704 Review)
- **CRITICAL: pic-init hook API**: Changed from mutating `event.messages.push()` to returning
  `{ prependContext: string }` — the correct `before_agent_start` return type
- **CRITICAL: pic-audit event shape**: Fixed to match real `tool_result_persist` event
  `{ toolName?, toolCallId?, message, isSynthetic? }` instead of fictional
  `{ toolName, params, result, error, durationMs }`
- **CRITICAL: Config loading**: All 3 handlers now receive `pluginConfig` via closure
  from `register()` instead of reading `ctx.pluginConfig` (which doesn't exist in
  hook contexts). Config was silently falling back to defaults.
- **Type-only imports**: Split `import type` from value imports in `pic-client.ts`
- **Test exclusion**: Added `**/*.test.ts` to tsconfig `exclude` (both repos)
- **package-lock.json**: Removed from OpenClaw repo (pnpm workspace uses pnpm-lock.yaml)

### Changed
- All handlers refactored from `export default function handler()` to factory pattern:
  `export function createPicXxxHandler(pluginConfig)` returning a closure handler

---

## [0.5.4] - 2026-02-11

### Fixed (OpenClaw Plugin)
- **CRITICAL: Hook registration**: Changed from `api.registerHook()` to `api.on()` to use
  OpenClaw's typed hook system. The old method registered to the internal hooks system
  which requires a config flag and uses different trigger paths. The `api.on()` method
  registers to `typedHooks` which the hook runner actually uses for `before_tool_call`.
- **Type stub**: Added `api.on()` method and `PluginHookName` type union
- **Package name**: Changed from `@pic-standard/openclaw-plugin` to `pic-guard`

### Changed
- Hook handlers now use typed hook registration instead of internal hook system
- Removed `name` from hook options (not required for `api.on()`)

---

## [0.5.3] - 2026-02-10

### Fixed (OpenClaw Plugin)
- **Docs**: Removed fictional `openclaw plugins configure` command from integration guide
- **Import path**: Changed `openclaw` → `openclaw/plugin-sdk` for correct module resolution
- **Plugin discovery**: Added `openclaw.extensions` field to `package.json` for `openclaw plugins install`
- **HOOK.md frontmatter**: Added required `name` and `description` fields to all three hooks
  - `pic-gate`, `pic-init`, `pic-audit` now display properly in OpenClaw UI/CLI

---

## [0.5.2] - 2026-02-10

### Fixed (OpenClaw Plugin)
- **Hook discovery path**: Fixed `index.ts` to point to source `hooks/` directory
  (was loading from `dist/hooks/` which lacks `HOOK.md` files)
- **PIC_AWARENESS_MESSAGE**: Fixed schema description to match actual PIC/1.0
  - `impact`: string (not array)
  - `provenance`: array of `{ id, trust }` (not `{ source, trust_level }`)
  - `action`: `{ tool, args }` (not `{ tool, params_hash }`)
  - Added concrete JSON example for agents
- **PICVerifyResponse type**: Changed to discriminated union matching wire format
  - `allowed: true` → `error: null`
  - `allowed: false` → `error: PICError`
- **log_level type**: Removed `"error"` option (not in manifest, not used)
- **pic-audit HOOK.md**: Fixed logging description (JSON at debug, summary at info)
- **Policy docs**: Fixed example to match actual `pic_policy.example.json` schema
  - `impact_by_tool` (not `tool_impact`)
  - lowercase strings (not uppercase arrays)

### Added
- Debug logging for malformed bridge responses in `pic-client.ts`
- Debug logging for injected awareness message in `pic-init`
- TODO comments for future telemetry and i18n enhancements

---

## [0.5.1] - 2026-02-09

### Fixed (OpenClaw Conformance)
- Added required `configSchema` to plugin manifest
- Added `uiHints` for OpenClaw Control UI form rendering
- Made `pic-audit` handler synchronous (required for `tool_result_persist`)
- Updated HOOK.md frontmatter to use `metadata.openclaw.events` format
- Fixed installation paths: `~/.openclaw/plugins/` → `~/.openclaw/extensions/`
- Added `openclaw.plugin.json` to npm package files array
- Removed non-standard `hooks` array from manifest (auto-discovered)

---

## [0.5.0] - 2026-02-09
### Added
- **OpenClaw integration**: Full plugin for OpenClaw AI agent platform
  - `pic-gate` hook — verifies PIC proposals before tool execution (fail-closed)
  - `pic-init` hook — injects PIC awareness at session start
  - `pic-audit` hook — structured audit logging for tool executions
  - HTTP bridge server (`pic-cli serve`) for TypeScript/Go/etc. consumers
  - Comprehensive TypeScript types and fail-closed HTTP client

### Security / Hardening
- HTTP bridge hardening:
  - Negative Content-Length rejection with logging
  - 5-second socket read timeout (DoS protection)
  - Incomplete body detection
  - JSON object type validation
  - 1MB request body limit (MAX_REQUEST_BYTES)
- TypeScript client hardening:
  - VALID_ERROR_CODES validation (rejects unknown error codes)
  - Strict toolName validation in pic-gate
  - HTTP status check before JSON parsing
- Added `PIC_INTERNAL_ERROR` to Python error codes enum for type safety

### Tests
- Python: 20 tests for HTTP bridge (Content-Length edge cases, non-dict JSON body, etc.)
- TypeScript: 9 tests for pic-client (fail-closed behavior, error code validation, eval_ms handling)

### Docs
- `docs/openclaw-integration.md` — comprehensive guide (architecture, setup, production deployment)
- `integrations/openclaw/README.md` — plugin-specific documentation

---

## [0.4.1] - 2026-02-02
### Added
- **Privacy is enforced as high-impact** in the reference verifier (same fail-closed gating class as `money` and `irreversible`).
- **Keyring expiry + revocation**:
  - `expires_at` (optional, per key) to enforce key expiration (UTC).
  - `revoked_keys` (optional list) to hard-disable signer key IDs.
  - Key status helpers for tooling/UX (`ok | missing | revoked | expired`).
- **CLI: `pic-cli keys`**:
  - Validates and prints the active keyring used for signature evidence (v0.4+).
  - `--write-example` now emits the recommended `trusted_keys + revoked_keys` structure and shows `expires_at`.

### Tests
- Keyring parsing tests for base64/hex/PEM + errors, plus expiry/revocation.
- CLI `keys` command tests.
- Tool binding mismatch tests (LangGraph + MCP guard).
- Mixed evidence proposal tests (hash + sig entries in the same proposal).

### Docs
- README updated to document:
  - privacy as high-impact,
  - key expiry/revocation,
  - `pic-cli keys` workflow,
  - mixed evidence behavior.

---

## [0.4.0] - 2026-01-30
### Added
- **Signature evidence (Ed25519)**: `evidence[].type="sig"` verifies an Ed25519 signature over `payload` bytes using a trusted key resolved from the keyring (`key_id`).
- Keyring support for trusted public keys (base64/hex/PEM) with env-based selection via `PIC_KEYS_PATH`.
- New examples:
  - `examples/financial_sig_ok.json` (passes)
  - `examples/failing/financial_sig_bad.json` (fails)
  - `examples/_gen_sig_example.py` (regenerates demo key + examples deterministically)
- New tests for signature evidence pass/fail using `pic_keys.example.json`.

### Security / Hardening
- Signature verification is offline and deterministic; no artifact shipping required.
- Payload size is capped in EvidenceSystem (`max_payload_bytes`) to reduce DoS risk.

---

## [0.3.2] - 2026-01-19
### Added
- **MCP integration (production-grade guard)**: `pic_standard.integrations.mcp_pic_guard.guard_mcp_tool(...)` to enforce PIC at the MCP tool boundary.
- MCP demos:
  - `examples/mcp_pic_server_demo.py` (FastMCP stdio server)
  - `examples/mcp_pic_client_demo.py` (stdio client that spawns the server)
- MCP hardening features:
  - **Debug-gated error details** via `PIC_DEBUG=1` (prevents leaking exception details by default)
  - **Request tracing**: `request_id` / `__pic_request_id` included in structured decision logs
  - **DoS limits**: proposal byte limit + item count limits + evaluation time budget
  - **Evidence sandbox**: `evidence_root_dir` + `max_file_bytes` (default 5MB) for file evidence

### Changed
- Evidence resolution hardened for servers: `file://` evidence can be sandboxed to an allowed root directory.
- README updated with an MCP integration section + enterprise guidance.

### Packaging
- Version bumped to `0.3.2`
- Added optional dependency extra: `mcp`

---

## [0.3.0] - 2026-01-14
### Added
- **Evidence verification (SHA-256)**: optional `evidence[]` objects can be resolved and verified deterministically.
- New module: `pic_standard.evidence` with:
  - `file://` resolver (paths resolved relative to the proposal JSON file)
  - SHA-256 verification
  - in-memory provenance upgrade: verified evidence IDs can upgrade `provenance[].trust` to `trusted`
- CLI additions:
  - `pic-cli evidence-verify <proposal.json>`
  - `pic-cli verify <proposal.json> --verify-evidence` (fail-closed evidence gate before verifier)
- New examples:
  - `examples/financial_hash_ok.json`
  - `examples/failing/financial_hash_bad.json`
  - `examples/artifacts/invoice_123.txt`
- Tests for evidence verification and provenance upgrade.

---

## [0.2.0] - 2026-01-12
### Added
- **LangGraph anchor integration**: `pic_standard.integrations.PICToolNode` for enforcing PIC at the tool boundary (schema + verifier + tool binding) and returning `ToolMessage` outputs.
- LangGraph demo: `examples/langgraph_pic_toolnode_demo.py` demonstrating a blocked (untrusted) vs allowed (trusted) money action.
- LangGraph requirements file: `sdk-python/requirements-langgraph.txt`.

### Changed
- Integration verification errors are now raised as clean `ValueError`s (no noisy Pydantic ValidationError formatting / links).
- README updated with a dedicated **Integrations** section documenting the LangGraph anchor integration and demo.

### Packaging
- Published updated package artifacts to PyPI so `pip install pic-standard` includes the LangGraph integration module and examples/docs updates.

---

## [0.1.0] - 2026-01-09
### Added
- PIC/1.0 proposal JSON Schema (`schemas/proposal_schema.json`)
- Reference Python verifier (`pic_standard.verifier`) with minimal causal contract checks
- CLI (`pic-cli`) with `schema` and `verify` commands
- Conformance tests validating examples against the schema and verifier
- GitHub Actions CI workflow
- Contribution guidelines and issue templates
