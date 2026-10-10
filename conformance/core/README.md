# PIC Core Verifier — Conformance Vectors

This directory contains conformance vectors for the **PIC core verifier** — the set of rules that determine whether a given PIC Action Proposal is accepted (`allow`) or rejected (`block`) by `verify_proposal()` under default or minimal settings, without evidence verification or signature verification.

A conforming implementation of the PIC core verifier MUST, for every vector in this directory:

- If `expected` is `"allow"`: accept the proposal and return a success outcome.
- If `expected` is `"block"`: reject the proposal and return a failure outcome whose error code, reduced to its canonical string form (e.g., `"PIC_VERIFIER_FAILED"`), is byte-identical to `expected_error_code`.

In the Python reference implementation, this translates to `PipelineResult.ok == True` for allow cases and `PipelineResult.ok == False` with `PipelineResult.error.code.value == expected_error_code` for block cases. Other-language implementations are free to expose any equivalent success/failure shape; the portable contract is the canonical-string comparison above.

---

## Scope

Vectors in this directory cover the **core verifier** — the layer exercised by `pic_standard.pipeline.verify_proposal()` with default or minimal `PipelineOptions`. Specifically:

- Schema validation of the proposal (pydantic + [`proposal_schema.json`](../../proposal_schema.json)).
- The causal verifier rules (e.g., money impact with untrusted provenance and no evidence is rejected).
- Tool-binding enforcement when `expected_tool` is provided.

The following are **not covered by this directory**:

- **Evidence-mode conformance** (hash-evidence verification, file-URI resolution, signature-evidence verification): covered by [`conformance/evidence/`](../evidence/README.md).
- **Trust-sanitization mode** (the `strict_trust` matrix): covered by [`conformance/trust_sanitization/`](../trust_sanitization/README.md).
- **Policy-mode conformance** (proposal outcomes under non-default `PICPolicy`): not yet covered by portable vectors.
- **Deprecation-warning assertions**: `warnings.warn` behaviour is Python-specific and not portable; it is exercised by `tests/test_trust_deprecation_warning.py`, not by shared vectors.

These vectors are also run by the TypeScript implementation ([`pic-standard-ts`](https://github.com/pic-standard/pic-standard-ts)), and advisory differential CI compares Python and TypeScript results on PRs targeting `main`.

---

## Directory layout

```
conformance/core/
  allow/           # proposals the verifier MUST accept
    NNN_<slug>.json
  block/           # proposals the verifier MUST reject (each with an expected error code)
    NNN_<slug>.json
  README.md        # this file
```

The `allow/` and `block/` split is redundant with the `expected` field inside each vector but is intentional — the directory structure itself makes a quick `ls` sufficient to read the suite's allow/block breakdown without opening any file.

---

## Vector file format

Every vector file is a single JSON object with the following fields:

```json
{
  "id": "core-<mode>-NNN-<slug>",
  "description": "One-sentence description of the verifier behaviour this vector tests.",
  "source": "<origin>; <rule>",
  "expected": "allow" | "block",
  "expected_error_code": "PIC_VERIFIER_FAILED" (only when expected is "block"),
  "proposal": { ...full PIC Action Proposal... },
  "options": { ... } (optional; absent means default PipelineOptions())
}
```

### Field semantics

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | Stable identifier, matching the manifest entry. Format: `core-<allow\|block>-<NNN>-<slug>`, where `<NNN>` is the three-digit file prefix and `<slug>` is short kebab-case. MUST be unique across both subdirectories. |
| `description` | string | yes | One-sentence summary of what the vector covers. Not machine-interpreted. |
| `source` | string | yes | Two components separated by a semicolon: **origin** (where the proposal content came from) and **rule** (the normative verifier rule the vector pins). See **Seeding discipline** below. |
| `expected` | `"allow"` or `"block"` | yes | Whether `verify_proposal()` must accept or reject this proposal. |
| `expected_error_code` | string | yes if `expected == "block"`, forbidden if `expected == "allow"` | One of the `PICErrorCode` canonical string values defined in `sdk-python/pic_standard/errors.py` (e.g. `"PIC_VERIFIER_FAILED"`, `"PIC_TOOL_BINDING_MISMATCH"`). The runner compares the error code returned by `verify_proposal()`, reduced to its canonical string form, byte-exact to this field's value. |
| `proposal` | object | yes | The full PIC Action Proposal to feed to `verify_proposal()`. MUST be a complete, self-contained proposal — no external references outside what `options` resolves. |
| `options` | object | no | A subset of `PipelineOptions` fields encoded as JSON. Absent means default `PipelineOptions()`. In v0.8.0 only JSON-serializable options are supported (see table below); options that carry Python objects (`policy`, `limits`, `key_resolver`) are deferred to v0.8.1+. |

### Supported `options` keys (v0.8.0)

| option | type | notes |
|---|---|---|
| `expected_tool` | string | Triggers tool-binding enforcement. Absent = no binding check. |

Other `PipelineOptions` fields (`tool_name`, `policy`, `limits`, `verify_evidence`, `proposal_base_dir`, `evidence_root_dir`, `time_budget_ms`, `key_resolver`, `strict_trust`) are deferred to later conformance modes. Vectors MUST NOT depend on them in v0.8.0.

---

## Seeding discipline

Every core vector MUST pin two things in its `source` field, separated by a semicolon:

1. **Origin** — where the proposal content came from. One of:
   - An existing example proposal under `examples/` (e.g. `examples/read_only_query.json`), or
   - A named fixture in `tests/conftest.py` (e.g. the `untrusted_money_proposal` fixture), or
   - A deliberately hand-authored proposal (with a one-sentence rationale).
2. **Rule** — the normative verifier rule the vector exercises (e.g., "exercises the causal rule: money impact with untrusted provenance and no evidence is rejected", or "exercises tool-binding enforcement under `expected_tool`"). This is what stops the suite from drifting into a regression snapshot of whatever `verify_proposal()` happens to do today — each vector commits to the rule it is pinning, not merely the observed outcome.

Example `source` strings:

```
"adapted from examples/read_only_query.json; exercises the causal rule that read-impact proposals pass the verifier regardless of provenance trust"
"adapted from tests/conftest.py untrusted_money_proposal fixture; exercises the causal rule that money-impact proposals with untrusted provenance and no evidence are rejected with PIC_VERIFIER_FAILED"
```

For v0.8.0, vectors MUST be executed against the Python reference implementation (`verify_proposal()`) as a consistency check before being committed, and the `expected` / `expected_error_code` MUST match the observed outcome byte-for-byte. That consistency check does not establish conformance — conformance is established by the rule the vector cites. If the reference implementation and a vector disagree about a vector's stated rule, either the implementation is a bug or the vector is a bug, and the resolution is a spec-level review.

---

## Required coverage (v0.8.0 first pass)

The first-pass core conformance suite MUST cover at minimum:

- **At least one `read`-impact allow vector** and **at least one `money`-impact allow vector**. Other impact levels PIC defines (`privacy`, `irreversible`, and any additions in the schema) are not required to have allow vectors in this first pass; they become required as conformance modes expand in v0.8.1+.
- **At least one block vector per distinct error code the verifier can emit at the core layer in v0.8.0** — at minimum `PIC_VERIFIER_FAILED` (causal-rule failure) and `PIC_TOOL_BINDING_MISMATCH` (tool-binding failure).

Error codes exercised only by modes deferred to v0.8.1+ (`PIC_EVIDENCE_REQUIRED`, `PIC_EVIDENCE_FAILED`, `PIC_LIMIT_EXCEEDED`, `PIC_POLICY_VIOLATION`, `PIC_SCHEMA_INVALID` for non-trivial schema cases) are not required in this directory in v0.8.0.

---

## File naming and numbering

Vector files follow `NNN_<slug>.json`, where `NNN` is a zero-padded three-digit decimal counter starting at `001` within each subdirectory (`allow/001_...` and `block/001_...` are distinct vectors). Numbers are assigned in the order vectors are committed and are **never renumbered**. Gaps from removed vectors are left as-is (removal is a deliberate, documented act in the CHANGELOG).

The `id` field embeds the subdirectory and number, e.g. `allow/001_read_only.json` has `id: "core-allow-001-read-only"`. The slug portion SHOULD match between filename and id.

---

## Relationship to the manifest

This directory is indexed by [`conformance/manifest.json`](../manifest.json). Every vector file in this directory MUST have a corresponding manifest entry with `"mode": "core"`. Adding a vector file without a manifest entry is a conformance-suite bug — the runner only executes what the manifest lists.

---

## Relationship to `pic_standard.pipeline.verify_proposal()`

The Python implementation at [`sdk-python/pic_standard/pipeline.py`](../../sdk-python/pic_standard/pipeline.py) is the **current reference implementation** for the PIC core verifier in v0.8.0. The conformance vectors in this directory and the normative rules they cite define the contract; if the reference implementation diverges from any vector's stated rule, the implementation is treated as a bug.

These vectors serve two purposes:

1. **Regression gate.** Refactors of `verify_proposal()` that inadvertently change the allow/block boundary fail the suite loudly.
2. **Cross-implementation contract.** When a second-language implementation of the verifier lands (Phase 3 TypeScript or later), these vectors become the executable conformance anchor — a TypeScript `verify_proposal()` that passes the full suite is by definition consistent with the Python reference on these cases.

If `verify_proposal()` behaviour changes intentionally — a new rule is added, an existing rule is tightened — the affected vectors MUST be updated in the same commit, with a CHANGELOG entry explaining the behaviour change and citing the vector ids affected.
