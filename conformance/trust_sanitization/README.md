# Trust-sanitization conformance vectors

Portable conformance vectors that pin the verifier's `strict_trust` semantics
across the matrix of `(proposal_base × strict_trust × verify_evidence)`. Each
vector codifies one cell of the `VERDICT_REGRESSION_MATRIX` already pinned
in-tree by [`tests/test_trust_deprecation_warning.py`](../../tests/test_trust_deprecation_warning.py),
making the same behavior verifiable by any conformant implementation (e.g., the
TypeScript verifier in v0.9.0).

The matrix tests two distinct enforcement behaviors of the verifier:

- **Trust sanitization (`strict_trust=true`):** self-asserted `trust="trusted"`
  on a provenance entry is FLATTENED to `untrusted` BEFORE evidence
  verification and the verifier's causal-contract check. The only way to
  get back to `trusted` under strict mode is via verifier-derived trust
  (i.e., evidence verification that succeeds).
- **Evidence-backed upgrade (`verify_evidence=true`):** valid evidence (hash
  or signature) upgrades the matching provenance entry to `trusted` AFTER
  any sanitization step.

The 24-cell matrix exercises every combination of these two settings across
6 representative proposal bases.

## Matrix structure

| Proposal base | strict-F verify-F | strict-F verify-T | strict-T verify-F | strict-T verify-T | Behavior |
|---|---|---|---|---|---|
| `compute_risk` | allow | allow | allow | allow | low-impact always allowed |
| `read_only_query` | allow | allow | allow | allow | low-impact always allowed |
| `financial_hash_ok` | block (VERIFIER_FAILED) | allow | block (VERIFIER_FAILED) | allow | money + untrusted prov + hash evidence; `verify_evidence` flips verdict |
| `financial_irreversible` | allow | allow | block (VERIFIER_FAILED) | block (VERIFIER_FAILED) | money + self-asserted trusted; `strict_trust` flips verdict |
| `privacy_risk` | allow | allow | block (VERIFIER_FAILED) | block (VERIFIER_FAILED) | privacy + self-asserted trusted; same shape as financial_irreversible |
| `robotic_action` | allow | allow | block (VERIFIER_FAILED) | block (VERIFIER_FAILED) | irreversible + self-asserted trusted; same shape as financial_irreversible |

All 8 block cells use error code `PIC_VERIFIER_FAILED` (the verifier's
causal-contract check rejects the proposal after model instantiation).

The intended 24 trust-sanitization matrix cells do not use
`PIC_EVIDENCE_FAILED`. When they block, they block with
`PIC_VERIFIER_FAILED` because the verifier's causal-contract check rejects
the proposal after trust sanitization / evidence upgrade has completed.
Evidence-layer failures belong in the evidence-mode conformance surface;
see [`conformance/evidence/README.md`](../evidence/README.md). (A
malformed trust-sanitization vector — wrong SHA pin, missing artifact —
could still produce `PIC_EVIDENCE_FAILED` at runtime; the matrix is
designed not to, but "never" overstates runtime behavior.)

## Layout

```
conformance/trust_sanitization/
├── README.md                                            (this file)
├── compute_risk__strict-f__verify-f.json
├── compute_risk__strict-f__verify-t.json
├── ... (24 files total, one per matrix cell)
└── robotic_action__strict-t__verify-t.json
```

Files are named by matrix coordinates:
`<matrix_id>__strict-<t|f>__verify-<t|f>.json`. The double underscore
separator visually groups base / strict / verify. No `allow/` vs `block/`
subdirectory split because every cell's verdict is determined by the
coordinates, not the proposal alone.

## Vector schema

Each vector file is a JSON object with the following structure:

```json
{
  "id": "trust-financial_hash_ok-strict-f-verify-t",
  "description": "Trust-sanitization matrix cell: financial_hash_ok, strict_trust=false, verify_evidence=true.",
  "source": "Lifted from tests/test_trust_deprecation_warning.py::VERDICT_REGRESSION_MATRIX (financial_hash_ok.json, strict=F, verify=T).",
  "mode": "trust_sanitization",
  "expected": "allow",
  "options": {
    "strict_trust": false,
    "verify_evidence": true,
    "evidence_root_dir": "conformance/artifacts"
  },
  "proposal": { /* full inline PIC/1.0 proposal */ }
}
```

For `expected: "block"`, include `"expected_error_code": "PIC_VERIFIER_FAILED"`
at the top level (sibling of `expected`).

### Field reference

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable identifier. The `trust-`, `strict-*`, and `verify-*` parts are kebab-style; the embedded `matrix_id` preserves the source proposal-base identifier, including underscores. Convention: `trust-<matrix_id>-strict-<t\|f>-verify-<t\|f>`. The runner enforces consistency with `options` coordinates — see **Coordinate consistency** below. |
| `description` | yes | One-paragraph summary of the matrix cell. |
| `source` | yes | Cross-reference to `tests/test_trust_deprecation_warning.py::VERDICT_REGRESSION_MATRIX`. |
| `mode` | yes | MUST be `"trust_sanitization"`. |
| `expected` | yes | `"allow"` or `"block"`. |
| `expected_error_code` | only when `expected == "block"` | MUST be exactly `"PIC_VERIFIER_FAILED"`. Enforced at manifest validation time. |
| `options` | yes | Pipeline options as a JSON object. MUST declare `strict_trust` and `verify_evidence` as JSON booleans (not strings, not numbers). MUST NOT declare `key_resolver` or `proposal_base_dir`. For proposals with file-backed hash evidence, MUST also set `evidence_root_dir`. |
| `proposal` | yes | Full inline PIC/1.0 Action Proposal. MUST NOT contain sig evidence — use evidence mode for signature-evidence coverage. |

The vector file MUST NOT include a top-level `embedded_keyring` field. It
would be silently ignored in this mode (no sig evidence), which would
mislead reviewers into thinking keyring hermeticity is being enforced.

### Options constraints

Trust-sanitization vectors MUST declare `options` as a JSON object with
both `strict_trust` and `verify_evidence` explicitly set to JSON booleans
(`true` / `false`). String `"false"` or numeric `0` is rejected fail-closed
by the runner — the matrix coordinate must be unambiguous.

Vector JSON MUST NOT include `options.key_resolver` or
`options.proposal_base_dir`. These are runner-controlled fields and
cannot be represented portably in JSON (same convention as evidence-mode
vectors).

Vector JSON MUST NOT include sig evidence (`type: "sig"` evidence entries
in the proposal). The regression matrix excludes signature evidence; the
runner rejects sig-evidence proposals fail-closed in this mode to prevent
falling back to `PIC_KEYS_PATH` / default keyring resolution. Authors who
need sig-evidence coverage should use evidence mode.

Vector JSON MUST NOT include a top-level `embedded_keyring` field. In
this mode it would be ignored (trust-sanitization has no sig evidence),
which would mislead reviewers into thinking keyring hermeticity is being
enforced. The runner rejects it fail-closed.

For proposals that contain file-backed hash evidence (the four
`financial_hash_ok` cells), `options.evidence_root_dir` MUST be set to
`"conformance/artifacts"` (or an equivalent repo-root-relative path
inside that subtree). The runner derives `proposal_base_dir` from the
resolved `evidence_root_dir` so `file://<name>` refs resolve under the
configured artifact root. Proposals without file evidence may omit
`evidence_root_dir`.

### Coordinate consistency (LOCKED)

The runner derives the expected vector `id` and manifest `file` from the
`matrix_id` plus the boolean coordinates in `options`:

```
expected_id   = "trust-{matrix_id}-strict-{t|f}-verify-{t|f}"
expected_file = "trust_sanitization/{matrix_id}__strict-{t|f}__verify-{t|f}.json"
```

The vector's `id` MUST match `expected_id`, and the manifest entry's
`file` MUST match `expected_file`. This catches silent matrix corruption:
a file named `compute_risk__strict-f__verify-f.json` that internally
declares `strict_trust=true` would silently test the wrong cell — both
its declared cell (FF) and its actual cell (TF) produce allow for
`compute_risk`, but for `financial_irreversible` the same drift would
flip a real verdict (FF→allow vs TF→block). The runner enforces
consistency fail-closed.

## Manifest entry

Each vector has a manifest entry with a required `matrix_id` for grouping:

```json
{
  "id": "trust-financial_hash_ok-strict-f-verify-t",
  "file": "trust_sanitization/financial_hash_ok__strict-f__verify-t.json",
  "mode": "trust_sanitization",
  "expected": "allow",
  "matrix_id": "financial_hash_ok"
}
```

For `expected: "block"`, include `expected_error_code` at the manifest
entry level (same as `core` and `evidence` block entries).

Constraints (runner-enforced):

- `matrix_id` MUST be one of the 6 recognized trust-sanitization matrix
  bases: `compute_risk`, `read_only_query`, `financial_hash_ok`,
  `financial_irreversible`, `privacy_risk`, `robotic_action`. Arbitrary
  strings are rejected fail-closed at manifest validation time.
- For `expected: "block"`, `expected_error_code` MUST be exactly
  `"PIC_VERIFIER_FAILED"` — the matrix's contract is that all
  trust-sanitization blocks are verifier-layer blocks. Any other error
  code is rejected at manifest validation time.
- `file` MUST match the expected path derived from `matrix_id` plus the
  boolean coordinates in `options` (see **Coordinate consistency** above).

## Cross-references

- [`tests/test_trust_deprecation_warning.py`](../../tests/test_trust_deprecation_warning.py)
  — the in-tree regression test (`VERDICT_REGRESSION_MATRIX`) that pins the
  same behavior in Python. Every vector in this directory has a 1:1 row
  mapping; portable vectors agree with regression-matrix rows for every
  shared `(proposal_base, strict_trust, verify_evidence)` triple.
- [`conformance/run.py`](../run.py) — the runner that dispatches
  `trust_sanitization` mode vectors via `verify_proposal()`.
- [`sdk-python/pic_standard/pipeline.py`](../../sdk-python/pic_standard/pipeline.py)
  — `_sanitize_provenance_trust` + the verify_proposal pipeline that
  implements strict-trust sanitization.
- [`conformance/evidence/README.md`](../evidence/README.md) — the parallel
  evidence-mode conformance surface (different mode, different error code
  for block vectors, supports sig evidence + embedded_keyring).
- [`docs/migration-trust-sanitization.md`](../../docs/migration-trust-sanitization.md)
  — the v0.7.5 Trust Axiom migration guide that introduced `strict_trust`.
- `docs/spec-core.md` (lands in PR V8.2-4) — normative spec these vectors
  codify.
