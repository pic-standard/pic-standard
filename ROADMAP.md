# PIC Standard: Enterprise-Ready Roadmap

Review draft, revision 2, 6 November 2026. Proposed replacement for the existing ROADMAP.md. This document preserves its phase structure and settled technical decisions, updates delivered work, and specifies the remaining work packages. Proposed decisions are marked separately from existing commitments.

Reviewed baseline: Python 6856f36267a9feb56e8c3deb334e9293fc4258dd; TypeScript 9241071e80b342388ea4f823f837f118b613d1bc. Both match the attached snapshots and GitHub main at review time. TypeScript's vendored Python/corpus pin is 330fdd817ef81d43461ea1787939e0d1cc87d589.

Source paths below are relative to their named repository. Python and TypeScript package versions are both 0.9.1 at this baseline; their release histories and future version numbers are separate.

## 1. North Star

PIC reaches the existing roadmap's v1.0 target when:

1. Python and TypeScript independently implement the agreed Core and Evidence semantics and pass the same pinned release corpus for the full profile.
2. Canonical bytes, digest inputs, signing mode selection, trust derivation and error precedence are explicit enough to implement without treating Python code as the specification.
3. spec-core.md, spec-evidence.md and Attestation Object v1 are final normative specifications. PIC-CJSON/1.0 remains the frozen canonicalization foundation; any clarification or change to its supported input domain is reviewed explicitly.
4. Maintained enforcing integrations compare the action about to be dispatched with the verified proposal according to their documented contract.
5. Verification has no mandatory network dependency, and trust roots remain operator-controlled.
6. A service can deploy the reference HTTP bridge using documented policy/key configuration and verify an allow and a block. The original under-60-second startup goal remains a target to measure under stated prerequisites, not an established result.
7. An application can determine exactly which profiles, implementation revision and corpus a result claims.

PIC verifies the proposed action and supporting evidence under configured trust and policy. A PIC allow does not establish that a human approved the right business action, that downstream controls allowed dispatch, that the tool ran, or that an external effect succeeded.

## 2. Strategic Principle and Scope

Through v1.0, prioritize:

- implementation disagreements that change decisions or canonical bytes;
- integration gaps that permit dispatch inconsistent with verified arguments;
- missing native evidence verification in TypeScript;
- signing, trust, freshness and compatibility decisions needed for the freeze;
- accurate package, conformance and deployment claims.

The implementation already includes a second verifier, evidence vectors, signing examples and integrations. Remaining work extends those artifacts; it does not restart them.

Usability work may follow in parallel when it does not change the contract: supported authoring helpers, a cross-language walkthrough and clearer operator diagnostics. Replay ledgers, settlement and execution orchestration remain separate integration responsibilities.

## 3. Status Labels and Responsibility

| Label | Meaning |
|---|---|
| Delivered | Present in the reviewed repository baseline; where stated, exercised by the recorded local checks |
| Confirmed gap | Reproduced behavior that falls short of an existing requirement or integration expectation |
| Open decision | A contract or compatibility choice still requiring explicit resolution |
| Planned | Work retained from the existing roadmap, not yet delivered |
| Proposed | A new work package or change of sequencing in this review draft |
| Deferred | Excluded from the v1.0 implementation scope; its base-contract boundary must still be documented |

The lead maintainer owns scoping, specification decisions, release acceptance and assignment. No external contributor is assigned work by this draft. Existing issues remain the trackers where linked; unfiled findings need a focused tracker and triage. New labels in this roadmap are work-package IDs, not GitHub issue numbers.

## 4. Release Ladder

| Release/milestone | Scope | State |
|---|---|---|
| Python v0.7.5 | Strict-trust option, migration warning, attestation draft | Delivered |
| Python v0.8.0 | PIC-CJSON/1.0, canonicalizer, initial vectors, manifest and runner | Delivered |
| Phase 0 / PR #67 | Committed roadmap, security policy, code of conduct, citation and trust-migration direction | Delivered |
| Python v0.8.1 | semi_trusted deprecation and normalization, warning and regression matrix | Delivered; deprecated ingestion code was subsequently removed |
| Python v0.8.2 | Evidence/trust vectors, runner hardening, draft Core/Evidence specs, canonical attestation verification | Delivered |
| Python v0.8.3 | Hash verification becomes integrity-only; no hash-only trust upgrade | Delivered |
| Python v0.9.0-alpha.1 | semi_trusted removal, error reference/precedence, Unicode rejection, OpenAPI and Docker hardening | Delivered |
| Python v0.9.0-alpha.2 | Duplicate provenance-ID rejection, signature/digest wire hardening, exact tool binding and strict-trust default | Delivered |
| Python v0.9.0 | Initial cross-implementation milestone and advisory differential tooling | Delivered; TS scope was three modes, not full Evidence |
| TypeScript v0.9.0 | Native canonicalization, schema, Core and trust-sanitization verifier; published package | Delivered |
| TypeScript v0.9.1 | Bundle proposal schema for installed consumers; packed-artifact regression check | Delivered |
| Python v0.9.1 | CLI JSON output, optional MCP pre-execution hook, live-argument binding in MCP/HTTP; 91-vector corpus | Delivered |
| Subsequent main work | Refund-sandbox PIC producer; TS runner-test expectations derived from manifest | Delivered in reviewed commits; do not imply a subsequent package release |
| Next v0.9.x correction release(s) | Phase 2 integration corrections, TS Unicode/metadata corrections, demo-key maintenance | Proposed next implementation batch |
| v0.9.x interoperability completion | Numeric-boundary decision, native TS Evidence and expanded differential coverage | Planned; scope may span more than one release |
| v1.0 release candidate | Final conformance profiles, compatibility behavior, normative documents and migration checks | Planned after Phase 4 exits |
| v1.0.0 | Freeze the reviewed Core/Evidence/Attestation contract and release conformant implementations | Planned after Phase 5 checklist passes |

The existing roadmap named the ambiguity milestone v0.9.2. Retain that as the next candidate version; decide its exact contents before release. Do not assume every remaining task fits into one patch or force Python and TS package versions to move together.

The existing v1.0 ladder also lists Internet-Draft submission. Section 13 preserves that publication work and identifies the submission-versus-package-release sequencing as an explicit decision; this draft does not silently remove it.

## 5. Current State

### 5.1 What exists

| Component | State and scope | Repository location |
|---|---|---|
| Python shared pipeline | Schema, Unicode boundary, duplicate IDs, trust sanitization, tool binding, evidence and causal contract | sdk-python/pic_standard/pipeline.py |
| Core models/verifier | Binary trust enum and high-impact causal contract | sdk-python/pic_standard/verifier.py |
| Proposal schema | Versioned PIC/1.0 proposal/evidence shapes | sdk-python/pic_standard/schemas/proposal_schema.json |
| Canonicalization | PIC-CJSON/1.0 wrapper and vendored RFC 8785 implementation | canonical.py, _rfc8785.py in the Python package |
| Evidence | SHA-256 file integrity, legacy signatures and canonical Ed25519 attestations | sdk-python/pic_standard/evidence.py |
| Key lifecycle/resolution | Trusted keyring, expiry, revocation and injectable resolver | sdk-python/pic_standard/keyring.py |
| Policy | Tool impact mapping and PIC/evidence requirements | sdk-python/pic_standard/policy.py, config.py |
| Error contract | Enum and documentation with parity tests | errors.py, docs/ERRORS.md, tests/test_errors_md.py |
| CLI | Verification, structured JSON, evidence/keyring operations and bridge serving | sdk-python/pic_standard/cli.py |
| HTTP bridge | /verify, /health, /v1/version, request correlation and live-argument binding | sdk-python/pic_standard/integrations/http_bridge.py |
| MCP guards | Sync/async enforcement, live-argument binding and optional hook | sdk-python/pic_standard/integrations/mcp_pic_guard.py, mcp_hooks.py |
| LangGraph | Shared-pipeline PICToolNode; lacks live-argument comparison | sdk-python/pic_standard/integrations/langgraph_pic_toolnode.py |
| OpenClaw | Plugin and fail-closed TypeScript bridge client | integrations/openclaw/ |
| TypeScript verifier | Canonicalization, schema validation, duplicate IDs, trust sanitization, exact tool-name binding and causal contract | TS: src/canonical.ts, schema.ts, pipeline.ts, verifier.ts |
| TS package and consumer check | Bundled schema and external-working-directory packed-package smoke test | TS: scripts/copy-schema.mjs, test-packed-artifact.mjs |
| Conformance | Manifest and mode-aware runners | Python: conformance/; TS: src/run.ts, pinned vendor/pic-standard |
| Differential CI | Python/TS comparison of claimed semantic results; currently advisory and limited to three modes | .github/workflows/differential.yml; TS CI and scripts/diff_conformance.py |
| Deployment contract | OpenAPI 3.0.3 and hardened local reference container profile | openapi/pic-bridge.v1.yaml, Dockerfile, docker-compose.yml, docs/deploy-docker.md |
| Security/release documentation | Security policy, threat model, independent-review notes and release-signing process | SECURITY.md, docs/THREAT_MODEL.md, docs/independent-reviews/, RELEASING.md |
| Authoring/examples | Key generation, file signing, canonical attestation/proposal builders and signed refund cases | scripts/pic_*ed25519.py, examples/refund-approval/ |
| Bounded verifier producer | Non-dispatching PIC result for the federation refund sandbox | examples/refund-sandbox/ |

### 5.2 Conformance and review baseline

| Mode/check | Reviewed result | Boundary |
|---|---|---|
| Python canonicalization | 15/15 vectors | Corpus coverage, not all numeric/parser inputs |
| Python Core | 10/10 | Existing Core corpus |
| Python trust sanitization | 24/24 | Includes explicit compatibility configurations |
| Python Evidence | 42/42 | Includes canonical and legacy behavior at this baseline |
| TypeScript supported modes | 49/49 | Canonicalization + Core + trust sanitization only |
| Differential comparison | 49/49 semantic results agree | Evidence excluded; uncovered disagreements were reproduced separately |
| Python tests/coverage | 382 passed; 85.7% statement coverage | Linux, Python 3.12.14 in this review |
| TS tests/tooling | 149 passed; format/lint/typecheck/build/packed consumer check passed | Linux, Node 24.22.1 in this review |
| Refund approval | 22 cases and harness self-checks passed | Example SDK and dependency pins |
| Refund sandbox | 79 cases and 14 harness probes passed | Component results; no connected-workflow success claim |

MCP and HTTP already have argument-binding tests. TS already has robust canonicalizer host-input tests and manifest-derived runner tests. Do not count those as missing work.

### 5.3 What still blocks the existing v1.0 target

| ID | Blocker | Why it matters | Tracking/dependency | Done when |
|---|---|---|---|---|
| B1 | LangGraph live arguments are not bound | A signed pay_A proposal reached a harmless sink with live pay_B arguments | LG-BIND, section 9.3 | Exact-match control succeeds; divergent live arguments are rejected before dispatch |
| B2 | TS proposal pipeline accepts lone surrogates | Python and TS make opposite decisions for invalid proposal strings despite canonicalizer agreement | TS-UNICODE, section 10.2 | Both reject affected keys/values with the specified error and shared regressions |
| B3 | Numeric input boundary unresolved | Identical JSON literals can be rejected in Python and rounded/accepted in JavaScript | #155, NUMERIC | Raw input and host API rules are explicit and tested in both languages |
| B4 | Native TS Evidence incomplete | The roadmap's full-profile two-language goal is not met | #15, TS-E0 through TS-E4 | Both run the agreed Evidence corpus under identical trust, time and profile inputs |
| B5 | Conformant canonical-only signing not implemented | Existing mode discrimination still admits legacy signatures; target behavior needs migration and tests | SIGNING, section 11.3 | Conformant/compatibility paths cannot be confused and agree across implementations |
| B6 | Final normative semantics incomplete | Draft documents and open questions leave implementation choices unresolved | SPEC-FREEZE, sections 11-12 | Documents, implementations, profiles and disposition tables agree |
| B7 | Decision/execution lifecycle unresolved | Allow can be mistaken for dispatch or outcome; current audit can rewrite tool errors as blocks | #188, #185 | Meaning and audit representation are specified and implemented with compatibility tests |
| B8 | TS implementation/corpus metadata stale | getVersion() reports alpha placeholders while package is 0.9.1 | TS-META, section 10.3 | Installed API identity agrees with package and actual corpus pin |
| B9 | Release/profile claims need reconciliation | Old README/status text and mixed legacy vectors can overstate or misidentify conformance | RELEASE, section 12 | Published claims identify the exact profile, corpus and implementation; release evidence is retained |

Time-bound maintenance: #180 must be resolved before 1 January 2027 regardless of v1.0 timing. It is not a new protocol feature.

### 5.4 Items that no longer block because they are delivered

- A second verifier implementation exists and passes its declared modes.
- Canonical attestation verification is wired into the Python runtime.
- Evidence and trust-sanitization modes exist in shared conformance.
- semi_trusted is removed from the current schema and verifier enum.
- Strict trust is already the default; do not schedule another default flip.
- OpenAPI, reference Docker hardening, request correlation and structured audit surfaces exist. Specific remaining audit defects are B7.
- TypeScript schema packaging and the manifest-derived runner-test change are delivered.

## 6. Guiding Technical Decisions

### 6.1 Locked decisions retained from the existing roadmap

These remain project direction. This draft does not reopen them merely because implementation is incomplete.

| Question | Locked decision | Current implementation consequence |
|---|---|---|
| Trust source | Verifier-derived; inbound labels are non-authoritative | Preserve sanitization and evidence-derived trust; compatibility opt-outs do not become conformant authority |
| Verification network dependency | Never mandatory | Local verification must work without online discovery or a hosted account |
| Trust distribution | Operator-controlled, local-first | A proposal cannot supply its own trusted roots; external key services are optional resolver choices |
| Signing target | Minimal canonical attestation object | Bind the specified proposal fields/digests; do not sign a transport wrapper as a substitute |
| Canonicalization | RFC 8785 plus PIC-CJSON/1.0 constraints; frozen foundation | Preserve established conformant bytes; handle #155 through explicit specification/version analysis |
| Canonical rollout | Introduced in v0.8.2; canonical signing is the conformant v1.0 path | Implement a real conformant/compatibility distinction; current mode selection is payload-based, not a shipped canonical=True switch |
| Strict-trust end state | Default and only conformant mode at v1.0 | Default already delivered; decide separately whether a non-conformant compatibility API remains callable |
| Trust enum | Binary trusted / untrusted | semi_trusted removal is complete; its v0.8.1 normalizer is historical, not a current required code path |
| Digest inputs | Full canonical action.args; full canonical claims array; raw UTF-8 intent bytes | Preserve each input and ordering rule; do not quietly hash a normalized subset |
| Encoding | JSON core first | CBOR stays a future profile |
| Standardization target | Standalone PIC specification first; transport bindings second | No MCP-only field convention becomes the general protocol by accident |
| key_id format | Opaque identifier | Do not impose a new DID/URL/namespace scheme for v1.0 |
| Normative freeze | Core/Evidence/Attestation at v1.0 after cross-implementation validation | Final status must follow matched semantics, not precede them |
| Attestation filename | Preserve docs/attestation-object-draft.md through launch | Change status in place; defer filename migration to later maintenance |

The v0.8.1 semi_trusted field validator and bridge normalizer were a settled migration mechanism for that release. Retain their history in Phase 0; do not require TS to recreate deleted compatibility code.

### 6.2 Existing behavior that the freeze must preserve or explicitly migrate

| Boundary | Existing behavior | Required treatment |
|---|---|---|
| Hash evidence | Integrity-only; no independent trust elevation | Preserve; any authority-bearing hash profile is separate work |
| Signing mode | Detect from parsed payload and attestation_version; malformed canonical-looking payloads fail closed | Never retry a failed canonical attestation as legacy bytes |
| Tool name | Exact equality when a nonempty expected tool is supplied | Derive the expected tool from trusted dispatch context, not the proposal itself |
| Live arguments | MCP/HTTP compare canonical digests after reserved metadata stripping | Carry the same guarantee into LangGraph; state per-adapter metadata rules |
| Low-impact proposals | May satisfy Core without signature evidence | Canonical-only signing does not mean every read now requires a signature |
| Evidence verification option | Verification/profile configuration determines whether evidence is enforced | Do not silently equate strict_trust=True with verify_evidence=True |
| Policy configuration | Implementation-defined except specified semantic obligations | Portable naming remains an open question, not an already-frozen config schema |
| Time | Key expiry and attestation expiry use their documented checks | Specify exact equality/skew behavior before claiming matched temporal semantics |

### 6.3 New proposals requiring review

- The correction-first PR sequence in section 15.
- A common integration acceptance matrix built from existing MCP/HTTP tests.
- Supported authoring helpers promoted from examples after the freeze work is defined.
- An explicit release acceptance requirement for full pinned differential agreement; changing GitHub protection settings is a separate implementation choice.
- Decoupling Internet-Draft submission from package release, if preferred. This is not adopted by this draft.

## 7. Phase 0: Repository Hygiene and Trust Migration

State: delivered. Preserve as history; no repeat implementation task.

### 7.1 Repository hygiene, PR #67

Delivered: committed roadmap, security policy, code of conduct, citation metadata and the trust-migration trajectory. The roadmap-link audit found no broken relative references requiring a code change.

### 7.2 semi_trusted migration

| Release | Work delivered |
|---|---|
| v0.8.1 | PICSemiTrustedDeprecationWarning, model-level normalization to untrusted, pipeline bridge helper before strict-trust flattening, migrated examples and migration documentation |
| v0.9.0-alpha.1 | Removed schema value, enum member, warning class, deprecated normalizer and bridge path |
| Current baseline | Binary trust enum; proposals using semi_trusted fail schema validation |

The original Slack/voice provenance distinction was producer-declared and became non-authoritative under the Trust Axiom. The examples were changed to untrusted provenance, not supplemented with hashes pretending to establish authority. The trust verdict-regression matrix remains useful even though its historical test filename refers to deprecation.

Exit: already met. Any new regression protecting this removal belongs in ordinary maintenance, not a new migration phase.

## 8. Phase 1: Interoperability Foundation

### 8.1 Canonicalization

State: delivered in v0.8.0, with later additive vectors. Files: docs/canonicalization.md, sdk-python/pic_standard/canonical.py, _rfc8785.py, TS src/canonical.ts.

Retain the frozen canonical-byte rules, UTF-16 key ordering, shortest-round-trip number formatting, string escaping and rejection of unsupported host values. Four additional IEEE-754 vectors are already present; do not list them as entirely future work.

Remaining: #155's input-domain decision and proposal-level Unicode enforcement. Those are scoped in Phase 4. No general canonicalizer redesign is scheduled.

### 8.2 Shared conformance and runner

State: delivered. Files: conformance/manifest.json, conformance/run.py, TS src/run.ts, src/fixtures.ts and runner tests.

Existing coverage includes hash/signature success/failure, revoked/expired keys, file sandbox failures, legacy/canonical discrimination, trust-sanitization configurations, filtering and JSON diagnostics. The manifest is the inventory; the observed 91/49 counts are baseline measurements, not constants to hardcode into evolving runner tests.

Remaining: shared regressions for confirmed disagreements; explicit conformance-profile/version handling when v1.0 disallows currently tested legacy paths. See Phase 4 and section 11.3.

### 8.3 Core and Evidence draft specifications

State: initial drafts delivered in v0.8.2; still awaiting final freeze.

| Document | Existing content to retain | Remaining work |
|---|---|---|
| docs/spec-core.md | Proposal fields, trust axiom, impact/causal contract, tool binding, error precedence, profiles and unknown-field discipline | Numeric/Unicode reconciliation, lifecycle meaning, final compatibility and open-question dispositions |
| docs/spec-evidence.md | Hash/sig types, signing discriminator, signature/binding rules, key lifecycle, trust upgrade, file boundary and error semantics | Canonical-only conformant mode, temporal precision, full TS parity and explicit deferred profiles |
| docs/attestation-object-draft.md | Field table, digest inputs, canonical signing, compatibility and freshness discussion | Field-by-field enforcement matrix, audience/issued-at scope and final mode/profile decisions |

Exit: an implementer can derive the specified results without copying Python internals; the final document set agrees with the release corpus and both implementations.

### 8.4 Canonical runtime signing

State: Python verification and example-local signing delivered; v1.0 conformant-only behavior incomplete.

Current canonical evidence is selected by a supported attestation_version in parsed payload content. Verification re-canonicalizes the object, verifies its signature and then checks its proposal binding. It does not trust an HTTP header or transport hint to select the signing semantics.

Legacy noncanonical payloads remain accepted in the current compatibility behavior. Preserve that history; section 11.3 defines the remaining migration decision. Example-local signing helpers are existing code, not a newly proposed cryptographic primitive.

## 9. Phase 2: Enforcing Integrations and Operator Contract

### 9.1 Errors, HTTP and reference deployment

State: substantially delivered. Actual OpenAPI file: openapi/pic-bridge.v1.yaml, replacing the obsolete roadmap reference to pic-guard.v1.yaml.

Retain the error reference, request correlation, /verify, /health, /v1/version, fail-closed client behavior and documented local container profile. The existing deployment guide explicitly describes a reference/integration profile, not a production deployment certification.

DEPLOY work package:

| Field | Required work |
|---|---|
| Scope | Validate the documented startup/configuration path against the release candidate; correct stale version/examples and policy/key instructions |
| Checks | Health and version endpoints; one matching accepted proposal; one rejected proposal; unreachable bridge handled fail-closed by the maintained client |
| Original speed target | Record elapsed startup time only with machine, image availability, build/pull time and prerequisites specified; do not claim the under-60-second goal without a recorded measurement |
| Output | Reproducible operator instructions and bounded results; no new hosted service |

### 9.2 MCP/HTTP binding and pre-execution hook

State: delivered in v0.9.1. Files: mcp_pic_guard.py, mcp_hooks.py, http_bridge.py, tests/test_mcp_arg_binding.py, HTTP/hook tests.

Preserve:

- canonical digest equality between verified action.args and sanitized live arguments;
- only the documented reserved metadata exclusions;
- ordinary request_id as a business argument when present;
- rejection before allow audit/hook/dispatch on argument mismatch;
- opt-in hook behavior and truthful separation of hook abort from PIC rejection;
- per-call ordering only, without claiming serialization across concurrent calls.

Do not replace this with a new binding scheme. The common adapter checks in section 14 reuse these established tests and semantics.

### 9.3 LG-BIND: LangGraph live-argument binding

State: confirmed gap; tracker not yet filed in the reviewed inventory. Priority: first correction batch.

Reproduction: an unchanged canonical signed EUR 40 refund proposal for pay_A, verified with strict_trust=True, evidence verification and the example keyring, allowed PICToolNode to call a harmless sink with live pay_B arguments. MCP rejected the identical divergence.

| Field | Scope |
|---|---|
| Source | sdk-python/pic_standard/integrations/langgraph_pic_toolnode.py |
| Tests | Extend tests/test_langgraph_integration.py; reuse the established MCP binding cases where applicable |
| Dependency | Existing canonicalization helpers; no dependence on new TS Evidence or new proposal fields |
| Change | Compare the arguments that the adapter passes to the tool with verified action.args before invocation; define metadata stripping explicitly |
| Error | Use the established argument-binding error contract; preserve the integration's public error-envelope convention unless a reviewed compatibility change is required |
| Boundary | Does not establish that the tool implementation or an external provider behaves correctly after invocation |

Acceptance cases: exact canonical signed refund executes once; changed payment/amount/currency executes zero times; equivalent nested object key ordering remains accepted; missing/extra business arguments block; unsupported canonical inputs block; ordinary and reserved metadata follow the declared rule. Existing default-trust and tool-name checks remain effective.

Release evidence: tests demonstrate a red result before the fix and a pass afterwards; integration documentation states the new guarantee and compatibility tightening.

### 9.4 MCP-AUDIT: post-allow execution errors

Tracking: #185. Contract coordination: #188. Priority: correction batch; full lifecycle vocabulary can be resolved separately.

Reproduction: a synthetic tool exception after evaluation produces allow followed by PIC block; the audit contains the raw synthetic exception marker with PIC_DEBUG disabled.

Required changes: separate enforcement failure handling from tool execution handling; preserve the original PIC allow; emit the agreed non-PIC-block execution-error representation; apply the debug policy to exception text; document audit-consumer compatibility.

Acceptance matrix: sync ordinary exception; sync tool-raised PICError; async ordinary exception; async tool-raised PICError; async timeout; pre-dispatch PIC block; hook abort; successful invocation. Each must preserve the distinction between verification, dispatch and observation, and test whether the tool was reached. A timeout must not be presented as proof that no external effect occurred.

### 9.5 DEMO-TIME: durable tests and example keys

Tracking: #180. Deadline: before 1 January 2027; independent of v1.0 timing.

1. Enumerate affected tests using a controlled keyring clock after expiry.
2. Give tests whose purpose requires valid evidence explicit valid-time fixtures.
3. Keep independent expiry and revocation cases with controlled boundaries; do not globally disable time validation.
4. Agree whether maintained example keys receive a later expiry or are regenerated. Changing key material requires re-signing and checking every dependent fixture.
5. Update the root/demo keyring relationship, walkthroughs and example index consistently.

Exit: maintained examples work under the documented current baseline; test results do not change merely because the wall clock crosses 1 January; expired/revoked evidence still fails. Historical release tags and evidence vectors with self-contained keyrings are not rewritten by this task.

### 9.6 Existing operator/security backlog

| Tracker | Work | Release treatment |
|---|---|---|
| #115 | Deliberate OpenClaw npm release and repository/registry version reconciliation | Separate package decision; do not infer it from Python/TS releases |
| #86 | Triage upstream OpenClaw dependency advisories and appropriate supported-version floors | Assess the actual current inventory before changing requirements; original inventory is historical |
| #19 | Remaining scanning/configuration, cryptographic inventory and workflow proposals | Coordinate scoped changes; do not treat a badge or score as independent assurance |
| Documentation #174, #175, #177-#179 | Walkthroughs, setup, troubleshooting and example index | Track actual PR/merge state; keep historical validation baselines explicit |

An item is a release blocker only when it affects a declared release guarantee or has an explicit release disposition. Dependency updates require their normal compatibility checks; they are not automatically protocol changes.

## 10. Phase 3: TypeScript Evidence Completion

### 10.1 Delivered TypeScript baseline

Delivered: native canonicalization; bundled schema; Core verification; binary trust model with secure default; duplicate provenance-ID rejection; expected-tool equality; trust-sanitization corpus; runner JSON/filtering; advisory differential CI; Windows/Linux and Node 20/22 CI configuration; packed-package consumer check; manifest-derived runner expectations.

Current public verifyProposal() does not verify signatures, derive trust from evidence or enforce a separately supplied live argument object. The public guide states that boundary. Applications can use the Python HTTP bridge for Evidence today.

### 10.2 TS-UNICODE: proposal-string boundary

State: confirmed gap; tracker not yet filed. Files: TS src/pipeline.ts, associated verifier/schema helpers as appropriate; TS pipeline tests; shared Core regression corpus.

Implement the existing PIC proposal-string rule after schema validation and at its specified precedence, before later semantic checks. Reject invalid string values and keys recursively without repairing them. Do not merely call a different standalone canonicalizer test: that component already rejects lone surrogates.

Acceptance cases: malformed intent, claim, source, tool name, nested argument value and key all return PIC_SCHEMA_INVALID; valid surrogate pairs and ordinary Unicode remain accepted where otherwise valid; schema-invalid and multi-failure proposals preserve error precedence. Run the same shared cases in Python and TS.

### 10.3 TS-META: package/corpus identity

State: confirmed gap; tracker not yet filed. Files: TS src/index.ts, package.json, test/smoke.test.ts, metadata-related runner/consumer checks.

getVersion() currently returns implVersion: 0.0.0-alpha.0 and conformanceManifestRef: v0.9.0-alpha.2, despite package 0.9.1 and corpus commit 330fdd81. Its smoke test asserts the stale values.

Acceptance: expose the actual implementation version and pinned corpus identity; keep supported modes accurate; verify the built/packed consumer surface; replace placeholder-preserving assertions with a check against authoritative version/pin input. Review compatibility before changing the public metadata shape. No new profile is advertised by this correction.

### 10.4 Evidence work packages

Existing umbrella: Python #15. Create bounded TS trackers for the slices below; scope API decisions before code. Do not silently publish partially implemented Evidence support.

| ID | Deliverable and files | Dependencies | Acceptance |
|---|---|---|---|
| TS-E0 | Evidence API/options and verification-flow design in TS; mapping to Python PipelineOptions, result/error semantics and profiles | SIGNING-DESIGN profile decision, known numeric/input constraints | Written mapping specifies verification enabled/disabled, evidence required/optional, trust derivation and failure precedence; current Core API compatibility is addressed |
| TS-E1 | TS keyring and resolver modules, fixtures and tests | TS-E0 | Trusted/unknown/revoked/expired keys have agreed results; keyring decoding/shape rules and expiry boundaries match; no trust root is accepted from an agent-supplied proposal |
| TS-E2 | Native canonical Ed25519 verification and attestation binding in TS Evidence/pipeline modules | TS-E0, TS-E1, supported numeric rule | Correct canonical signatures verify; forged/altered evidence fails; required digests, exact tool/impact, provenance ordering, optional intent and freshness match the agreed contract |
| TS-E3 | Hash evidence and file-resolution boundary; compatibility verification if retained | TS-E0; profile decision | Raw file bytes hash correctly, path escapes are refused under the agreed sandbox rules, limits are enforced, and hashes alone do not elevate trust; legacy behavior is explicitly isolated |
| TS-E4 | Runner support, package dependencies, documentation and full-profile differential execution | TS-E1-E3 and finalized release corpus | Unsupported-mode placeholder is replaced only when acceptance passes; all claimed Evidence cases run and match Python; installed consumer and dependency failure behavior are checked |

TS-E2 should cover: canonical and legacy discriminator boundaries; unknown/non-string versions; duplicate canonical-looking members; Base64/decoded-length rules; signature before binding/freshness behavior; args/claims/intent digests; missing/malformed fields; key state; and policy-required evidence. The expected behavior comes from the agreed specification and corpus, not from copying Python error text.

TS-E3 must state path/URI resolution, evidence root, symlinks/escape handling, maximum file/payload sizes and unavailable-file results. A Node filesystem port must not silently claim browser support. Crypto/library selection is an implementation choice subject to the contract, not a new normative algorithm choice.

Phase exit: Python and TS implement the agreed full profile under the same trust, clock, policy and corpus assumptions. Native TS Evidence is publicly declared only then. Partial progress remains marked partial.

## 11. Phase 4: Ambiguity Burn-Down and Final Contract Decisions

### 11.1 NUMERIC: cross-language input domain

Tracking: #155. Dependency: informs TS-E0/E2 and the final corpus.

For raw JSON and public host-language APIs, record parsed type/value, canonical bytes or rejection, and any precision loss for:

- 9007199254740991, 9007199254740992, 9007199254740993;
- -9007199254740992, -9007199254740993;
- 1e20, 1e21, and an input exceeding finite binary64 range.

Then decide: the supported raw input domain; equivalent host API obligations; representation of precision-sensitive application values; rejection/error behavior at each boundary; and compatibility/version implications. A comparison that first converts all Python integers to floats is insufficient.

Exit: explicit specification text, independently established expectations, cross-language regressions and release guidance agree. Existing successful canonical bytes remain pinned. If resolution alters frozen normative behavior, record the versioning decision instead of treating it as an undocumented fix.

### 11.2 GENERATED: parser and malformed-input comparisons

Build on existing corpus/runners. Start with the confirmed Unicode/numeric disagreements and canonical-looking evidence parsing. Broader generated coverage should specify:

| Dimension | Minimum definition |
|---|---|
| Entry points | Raw JSON parser, host canonicalizer, public verifier or adapter; never mix them without labeling |
| Input families | Unicode values/keys, number boundaries, malformed/duplicate members, evidence wire shape and multi-failure proposals |
| Oracle | Normative result, independent expected bytes, or a declared metamorphic relation; Python alone is not the oracle for every ambiguity |
| Comparison | Canonical bytes, allow/block, required stable code/diagnostic and declared input-domain outcome |
| Reproduction | Retained failing input, seed/configuration and pinned revisions |
| Regression | Minimized failures become permanent shared or adapter cases at the appropriate boundary |

Do not replace established corpus coverage with only random comparisons. A passing generated sample is a bounded result, not a proof of all-input equivalence.

### 11.3 SIGNING and compatibility matrix

The existing roadmap already commits to canonical-only conformant signing at v1.0. What remains open is its API/profile enforcement and compatibility migration.

| Behavior | Current v0.9.x | v1.0 target retained from roadmap | Decision still needed |
|---|---|---|---|
| Core low-impact proposal without signature | Can be allowed | Remains possible under the applicable Core/policy rules | No blanket signature requirement is introduced |
| Canonical PIC-ATT/1.0 signature | Accepted with Evidence enabled and checks passing | Conformant signing path | Exact profile/API selection and producer defaults |
| Legacy raw-payload signature | Accepted by current mode discriminator | Not conformant signing | Remove support or retain an explicit compatibility path that cannot masquerade as conformant evaluation |
| Unknown/malformed canonical-looking payload | Fails closed | Remains fail-closed | No fallback to legacy verification |
| strict_trust=True | Default | Default and only conformant trust behavior | Preserve default; no repeat default flip |
| strict_trust=False | Callable with warning | Non-conformant | Remove or retain explicit compatibility API; document migration |

Required work: identify every affected CLI/API/adapter entry point; agree the selection mechanism; implement consistent behavior; add positive/negative compatibility tests; document producer and consumer migration.

Corpus rule: the current 91 vectors contain legacy-signature successes and compatibility trust configurations. Define which cases belong to v1.0 normative profiles and which remain historical/compatibility tests. Preserve historical files/results. Do not relabel a legacy success as a v1.0 conformant pass or change its expected result without version/profile context.

### 11.4 LIFECYCLE: decision, dispatch and observation

Tracking: #188, coordinated with MCP-AUDIT.

Settle these separately:

1. Normative meaning of PIC allow/block.
2. Whether PIC standardizes dispatch/observation terms or only the decision meaning.
3. Whether integration audit events need a versioned lifecycle vocabulary.
4. Correlation and ordering for retries and duplicate event delivery if such events are defined.
5. Compatibility with existing audit consumers and TRACE mapping.

The issue proposes dispatched/`aborted` and completed/`failed`/`unknown`. These are proposals until adopted. A normal tool return establishes observed completion of that invocation, not the intended external effect. #185 can correct false PIC blocks without waiting for an unbounded lifecycle design.

### 11.5 Open Questions Registry: required disposition

The status column below describes the source specifications at review time. Recommended dispositions are proposals for review, not already-locked decisions.

| Question | Source status | Required v1.0 action / proposed disposition |
|---|---|---|
| OQ-CORE-001: error precedence | Resolved in v0.9.0a1, extended in alpha.2 | Preserve and test in TS, including Unicode and Evidence additions |
| OQ-CORE-002: multiple sources for irreversible actions | Open | Proposed: retain the existing base requirement and recommendation; defer mandatory multi-source policy to a separate profile |
| OQ-CORE-003: portable policy option naming | Open | Decide names/semantics that are normative; proposed: retain implementation-defined configuration where not needed for matching profile semantics |
| OQ-EVIDENCE-001: canonical envelope shape | Open | Decide whether to retain sig plus payload discriminator; proposed: keep the existing envelope for v1.0 rather than introduce a new evidence type |
| OQ-EVIDENCE-002: clock skew | Open | Specify observable expiry equality and permitted skew behavior under a shared test clock; decide whether tolerance stays deployment-configured |
| OQ-EVIDENCE-003: digest agility | Open | Proposed: SHA-256 only in v1.0; defer agility to a versioned change/profile |
| OQ-EVIDENCE-004: replay profile | Open; full replay prevention deferred | Keep base semantics explicit: unchanged unexpired evidence may verify again; no implicit consumption guarantee. Separate any replay profile from verifier freeze |
| OQ-EVIDENCE-005: authority for hash-only evidence | Open | Proposed: retain integrity-only base behavior; defer a new authority primitive and its trust/freshness model |
| Attestation Q1: full args or normalized subset | Still listed as open in draft; canonicalization defines full args | Reconcile the stale question with the frozen digest input; do not introduce per-tool digest subsets silently |
| Attestation Q2: audience | Open | Decide representation and whether it is enforced. A signed field alone must not be described as audience restriction/replay protection without a verifier check |
| Attestation Q3: digest algorithms | Open; overlaps OQ-EVIDENCE-003 | Give one consistent v1.0 disposition in both documents |
| Optional issued_at, expires_at, intent_digest | Draft presence rules and runtime checks differ in what they establish | Publish a field matrix: required/optional, signed, semantically checked, and profile-specific requirements; distinguish timestamp metadata from enforced freshness |

Exit: each question has an explicit reviewed disposition, matching text/tests and compatibility notes. Deferred features are not prerequisites to implement before freeze; their non-guarantees must be explicit.

## 12. Phase 5: Normative Freeze and v1.0 Release

### 12.1 Specification freeze

Files: docs/spec-core.md, spec-evidence.md, attestation-object-draft.md, canonicalization.md, spec-status.md, vocabulary.md, schemas and error reference where affected.

- [ ] Resolve NUMERIC and the confirmed Unicode mismatch.
- [ ] Complete the field-by-field attestation enforcement matrix.
- [ ] Adopt and implement the conformant/compatibility matrix.
- [ ] Record every open-question disposition without deleting its history.
- [ ] Resolve allow/block semantics and reconcile maintained audit interfaces.
- [ ] Specify extension behavior and what requires a new attestation/profile/protocol version.
- [ ] Promote Core, Evidence and Attestation documents to normative only after code/corpus agreement.
- [ ] Preserve PIC-CJSON/1.0's established byte contract or explicitly document an approved versioning change.
- [ ] Keep the attestation document filename stable through launch.

### 12.2 Full-profile release evidence

- [ ] Python and TS run against the same pinned release corpus, not different moving branches.
- [ ] Each supported mode executes its expected IDs with no omissions, duplicates or unreported unsupported modes.
- [ ] Required semantic results agree, including Evidence and key lifecycle under equivalent inputs.
- [ ] Conformant and compatibility runs are identifiable and cannot be counted interchangeably.
- [ ] Package version, implementation metadata, source pin and corpus identity are consistent.
- [ ] Installed package checks run outside the source-tree working directory.
- [ ] Required tests, formatting/lint, coverage and existing release-signing checks pass.
- [ ] Maintained enforcement integrations pass their declared boundary cases, including LG-BIND and MCP-AUDIT regressions.

Advisory differential CI already exists. For release acceptance, require a recorded successful full-profile comparison of the pinned candidates. Whether that becomes a branch-protection check or a separate release job is a maintainer implementation decision.

### 12.3 Operator and migration acceptance

- [ ] The reference deployment instructions produce health/version responses and the documented allow/block outcomes.
- [ ] The expected tool, live arguments, impact policy, evidence setting and trusted keyring are sourced/configured as documented.
- [ ] Guidance covers canonical/legacy migration, explicit compatibility selection and unsupported-profile handling.
- [ ] Deadline-sensitive example/test-key work is resolved or has a valid documented maintenance state.
- [ ] README, package metadata, specification status, examples and release notes state the same supported capabilities.
- [ ] Known limitations identify replay, downstream authorization, execution observation and deployment bypass responsibility without claiming them as PIC guarantees.

### 12.4 Release output

Release the normative documents, versioned schemas/corpus, implementation packages and migration notes with their actual version/pin relationships. Retain the validation record. A v1.0 protocol freeze establishes a stable reviewed contract; it is not production certification for arbitrary deployments.

## 13. Standards-Track Readiness

Preserve the existing external-standardization track:

| ID | Deliverable | Prerequisite | Completion evidence |
|---|---|---|---|
| STD-1 | Internet-Draft text describing the agreed PIC contract and conformance profiles | Phase 4 decisions sufficiently stable to cite pinned artifacts | Draft source and submission record; external acceptance is a separate outcome |
| STD-2 | Media-type requirements and registration plan | Stable wire/profile description and a documented use case | Reviewed registration proposal or explicit deferral |
| STD-3 | Minimum registry requirements | A real extension/version namespace that needs governance | Defined entries/change process or a decision that no additional registry is yet needed |
| STD-4 | Governance/maintenance alignment | Existing GOVERNANCE.md, MAINTAINERS.md, release process and spec freeze policy | Inconsistencies corrected; ownership/change process explicit |
| STD-5 | MCP extension/binding proposal | Stable standalone semantics and transport-specific requirements | Scoped proposal under #20, not an invented replacement proposal shape |

Scheduling decision: the existing release ladder places Internet-Draft submission at v1.0. Retain that target unless the maintainer explicitly approves publishing the packages first and submitting separately. Do not confuse submission with IETF adoption or delay correctness fixes while waiting for external review.

## 14. Beyond v1.0: Detailed Adoption and Extension Backlog

These are separate from the base freeze. A task becomes scheduled only after its consumer, scope and acceptance are agreed.

### 14.1 AUTHORING: supported canonical construction/signing

Existing starting point: key-generation/file-signing scripts and examples/refund-approval/sign_and_verify.py already build proposals, canonicalize claims, construct attestations, sign and attach evidence.

Proposed deliverable: promote the reusable construction/signing operations into a supported small API. Keep key custody caller-controlled; document which operations handle private keys. Use the protocol's established canonicalization and bindings. Do not create a new attestation version solely for ergonomics.

Acceptance: an installed-package consumer can build a conformant canonical attestation, sign through the supported interface and verify it without importing example internals. Tests cover exact digest inputs, optional fields, tampering and unavailable signing dependencies. Existing example helper behavior is either reused or migrated, avoiding divergent signing implementations.

### 14.2 CROSS-LANGUAGE: one complete signed-action path

Dependencies: TS Evidence and the signing profile; supported authoring where used.

Issue in Python, verify natively in TS; then issue using a supported TS path and verify in Python. If TS issuance is not yet supported, label the reverse-direction producer as a standalone example rather than imply an SDK API exists.

Use the existing EUR 40 refund shape. Show successful verification and a guarded matching call, then altered payment/amount/currency and untrusted/expired evidence. Record implementation versions, corpus/profile, trust inputs and which component dispatches. Reuse existing fixtures and counterexamples rather than duplicate the sandbox contract.

Exit: a consumer can reproduce the portable path from installed packages; both positive and negative cases have explicit outcomes. No replay/exactly-once claim is inferred from one execution.

### 14.3 ADAPTER-MATRIX: common boundary obligations

Derive a small table from existing MCP/HTTP tests and LG-BIND. For each maintained integration, state whether it verifies only, dispatches, strips reserved metadata, compares live args, exposes hooks and observes tool completion.

Acceptance: every claimed obligation has a positive and negative boundary check at the adapter; N/A cases are explained; ordinary tool failures remain separate from PIC rejection. Do not duplicate the entire Core/Evidence corpus inside every adapter test suite.

### 14.4 LANGCHAIN: middleware integration

Proposed scope: native LangChain middleware using the existing verifier, sync/async tool interception, exact tool/live-argument binding, documented policy/key setup and an optional dependency extra.

Prerequisites: agree the target LangChain API/version, review integration demand, and settle lifecycle behavior relevant to that boundary. PICToolNode remains an existing integration; middleware is a separate adapter, not a new verifier.

Acceptance: installed-example allow/block, changed live args rejected before invocation, async parity, exceptions represented accurately, and no model call needed for PIC verification. No second policy engine or planner is added.

### 14.5 External integrations and evaluation

Delivered: AgenTrust #397 and #398; MCP retry/recovery PIC adapter #4; refund-sandbox PIC producer in this baseline. Maintain their pins and scope before proposing more adapters.

Track future outcomes separately: component run, external reproduction, connected workflow, and confirmed maintained deployment. Federation #193 and the retry/recovery collaboration do not make PIC responsible for provider execution or result disclosure policy.

A useful adoption result is a named consumer integrating the supported path and documenting setup, trust configuration, failure handling and maintenance. Downloads/stars can be recorded separately but are not deployment evidence.

### 14.6 Deferred profiles retained from the original roadmap

| Profile/work | Prerequisite before scheduling | Intended boundary |
|---|---|---|
| Trust-bundle profile | Consumers need portable distribution of trusted keys/policy | Operator-controlled trust remains; no automatic trust in a foreign bundle |
| Discovery profile | Concrete discovery/interoperability requirement | Discovery identifies candidates; it does not confer authority |
| Optional CBOR | A measured transport/device need and a JSON equivalence contract | Separate encoding profile; frozen JSON bytes do not silently change |
| Registry/governance expansion | Actual namespace or extension pressure | Minimum needed machinery rather than speculative registries |
| Additional transport bindings | Confirmed host/integrator requirement | Preserve standalone semantics; document transport-only metadata |
| Broader TS tooling/hardening | A scoped gap beyond full Evidence completion | Full Evidence itself remains a v1.0 commitment, not deferred tooling |
| Richer operator tooling | Reproduced setup/diagnostic problem | Make existing checks usable; do not expose a new source of authority |
| Attestation filename rename | Post-launch maintenance window and link plan | Redirect/update references; no semantic change |

### 14.7 Exploratory work with no implementation commitment

A portable verification bundle may package retained proposal/evidence bytes, trust/policy context, implementation identity and the evaluation result when a consumer needs offline inspection. Historical-time and historical-trust semantics must be defined before claiming historical replay. Reuse TRACE/sandbox experience; do not invent a new signed receipt merely to add surface area.

Distributed replay caches, admission ledgers, settlement, hosted approval interfaces and execution orchestration remain companion/integration work. A separate replay profile can be proposed, but it must not retroactively imply that the current stateless verifier consumes approvals.

## 15. Next PRs: Scope and Dependency Sequence

These are proposed PR-sized packages, not filed pull requests. A package may be split further after design review. Packages with no dependency can proceed independently; the row order is the recommended attention order.

| Order / ID | Repository | Concrete deliverable | Depends on | Validation / exit |
|---|---|---|---|---|
| 1 DOC-STATE | Python + TS docs as needed | Adopt corrected roadmap/state tables; distinguish locked decisions from review proposals; fix stale capability/version text | Roadmap review | Every current-state claim has source/release evidence; no pending item is marked done |
| 2 LG-BIND | Python | Pre-dispatch canonical live-argument check in PICToolNode and migration note | Existing canonical helper | Signed pay_A/live pay_B regression blocks; exact-match and existing integration tests pass |
| 3 TS-UNICODE | TS + shared corpus | Proposal-level recursive Unicode rejection at specified precedence | Existing specification; shared regression format | Both reject the six reproduced positions; valid Unicode and precedence controls pass |
| 4 TS-META | TS | Correct built/packed implementation and corpus metadata; replace stale assertions | None | Metadata agrees with package and actual corpus identity in installed consumer |
| 5 MCP-AUDIT | Python | Separate post-allow tool failure from PIC blocks; gate exception text | Narrow lifecycle agreement from #188 | Sync/async error, timeout, hook and normal cases have truthful events and debug behavior |
| 6 DEMO-TIME | Python | Controlled test clocks and maintained example keys/docs | Maintainer key-maintenance choice | Tests remain deterministic across 1 January 2027; expiry/revocation controls still work |
| 7 NUMERIC | Both + spec | #155 decision, normative input text, shared boundary cases and implementation changes if needed | Cross-language decision | Raw and host API boundary table agrees; byte/version impact explicit |
| 8 SIGNING-DESIGN | Both + spec | Conformant/compatibility API/profile matrix and attestation field enforcement decisions | Open-question review; numeric constraints known | No ambiguity about accepted signing/trust paths and advertised profile |
| 9 TS-E0 | TS | Evidence/options design and error/result mapping | SIGNING-DESIGN | Reviewed API/flow mapping; backwards compatibility explicit |
| 10 TS-E1 | TS | Keyring/resolver lifecycle implementation | TS-E0 | Key/expiry/revocation fixtures and decoding rules match |
| 11 TS-E2 | TS | Canonical Ed25519 verification, binding and trust derivation | TS-E1, NUMERIC | Canonical positive/negative and lifecycle cases pass |
| 12 TS-E3 | TS | Hash file sandbox and required legacy compatibility slice | TS-E0, SIGNING-DESIGN | File boundary and integrity-only semantics pass; compatibility labeled |
| 13 TS-E4 | TS + CI | Evidence runner/package support and full-profile differential validation | TS-E2, TS-E3 | Full claimed Evidence executes; unsupported-mode claim removed only after acceptance |
| 14 GENERATED | Both + corpus | Defined generated/parser comparisons and retained regressions | Appropriate input/profile decisions | Reproducible counterexamples and independently justified outcomes |
| 15 SPEC-FREEZE | Both + docs | Final Core/Evidence/Attestation text, extension policy and corpus/profile partition | Phase 4 decisions, TS-E4, correction packages | No unresolved normative disagreement; legacy/history preserved |
| 16 RELEASE | Both | RC packages, installed consumer/deployment checks, migration and release evidence | Section 12 checklist | All release criteria recorded against exact candidate pins |
| 17 STD-1 | Spec/publication | Internet-Draft submission from agreed pinned contract | Stable normative draft | Submission record; sequencing decision made explicitly |
| Later AUTHORING / CROSS-LANGUAGE / ADAPTER-MATRIX / LANGCHAIN | Applicable repository | Adoption deliverables in section 14 | Their stated prerequisites and agreed consumer/scope | Per-package acceptance, outside the base freeze |

Critical dependency path: NUMERIC and SIGNING-DESIGN inform TS Evidence; full TS Evidence and the correction regressions inform SPEC-FREEZE; the release checklist gates RELEASE. LG-BIND, TS-META and deadline-sensitive DEMO-TIME need not wait for TS Evidence. MCP-AUDIT needs a bounded event decision, not the entire deferred lifecycle ecosystem.

## 16. Decisions for This Review

1. Approve or adjust the correction-first order, including the reproduced LangGraph and TS pipeline gaps.
2. Confirm the original full Python/TypeScript Core-and-Evidence requirement for v1.0. This draft retains it.
3. Resolve the explicit compatibility decisions in SIGNING-DESIGN; do not reopen the already-delivered strict-trust default.
4. Adopt or revise the proposed open-question dispositions. They are not locked by appearing in the table.
5. Decide which correction packages constitute v0.9.2 and whether interoperability completion needs further v0.9.x releases.
6. Retain Internet-Draft submission with v1.0 or explicitly separate its publication schedule.
7. Keep new authoring/middleware/bundle work outside the freeze unless a reviewed release requirement justifies changing that scope.

This roadmap specifies the work and its acceptance. It does not substitute for the reviewed specification changes, implementation PRs and release records that close each item.
