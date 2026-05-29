# Evidence-mode conformance vectors

Portable conformance vectors that pin the verifier's evidence-verification
semantics (hash-evidence + signature-evidence) across language implementations.

Vectors in this directory exercise the **shared verification pipeline**
(`pic_standard.pipeline.verify_proposal`) with `verify_evidence=True`, asserting
that every conformant implementation produces the same allow/block verdict and
the same error code on failure.

## Layout

```
conformance/evidence/
├── README.md          (this file)
├── allow/             (vectors that MUST allow)
│   └── 001_*.json
└── block/             (vectors that MUST block, with expected error code)
    └── 001_*.json
```

Mirrors the [`conformance/core/`](../core/) layout for consistency.

## Vector schema

Each vector file is a JSON object with the following structure:

```json
{
  "id": "evidence-hash-allow-001-simple",
  "description": "Human-readable summary of what this vector tests.",
  "source": "Lifted from tests/test_evidence_hash.py::test_X or hand-authored against docs/spec-evidence.md §N.",
  "mode": "evidence",
  "expected": "allow",
  "options": {
    "verify_evidence": true,
    "evidence_root_dir": "conformance/artifacts",
    "strict_trust": false
  },
  "proposal": { /* full inline PIC/1.0 proposal */ },
  "embedded_keyring": { /* optional; see "Keyring hermeticity" below */ }
}
```

For `expected: "block"`, include an `expected_error_code` field at the top
level (sibling of `expected`) whose value is the PIC error-code enum string
(e.g., `"PIC_EVIDENCE_FAILED"`, `"PIC_EVIDENCE_REQUIRED"`,
`"PIC_VERIFIER_FAILED"`).

### Field reference

| Field | Required | Description |
|------|----------|-------------|
| `id` | yes | Stable identifier, kebab-case, matches manifest entry. Convention: `evidence-<hash\|sig\|sandbox\|mixed>-<allow\|block>-NNN-<short-slug>`. |
| `description` | yes | One-paragraph summary of the behavior being asserted. |
| `source` | yes | Where this vector was lifted from (Python test file + test name, or hand-authored citation). |
| `mode` | yes | MUST be `"evidence"`. |
| `expected` | yes | `"allow"` or `"block"`. |
| `expected_error_code` | only when `expected == "block"` | PIC error-code enum string. |
| `options` | yes | Pipeline options as a JSON object. MUST set `"verify_evidence": true`. MUST NOT declare `key_resolver` or `proposal_base_dir`; both are runner-controlled. The runner injects `key_resolver` from `embedded_keyring` and derives `proposal_base_dir` from `evidence_root_dir`. See **Options constraints** below. |
| `proposal` | yes | Full inline PIC/1.0 Action Proposal. Self-contained — no `proposal_ref` indirection. |
| `embedded_keyring` | conditional | Required as a non-null object when `proposal` contains `sig`-type evidence. Hash-only vectors SHOULD omit it; if present, it is still parsed and must be valid. |

### Options constraints

Evidence-mode vectors MUST declare `options` as a JSON object with
`"verify_evidence": true`. A vector that omits `options`, declares it as
something other than an object, or sets `verify_evidence` to anything other
than `true` is rejected fail-closed by the runner — evidence mode must
actually exercise the evidence-verification path.

Vector JSON MUST NOT include `options.key_resolver`. Key resolvers are
runner-constructed objects and cannot be represented portably in JSON.
Signature vectors MUST use `embedded_keyring`; the runner builds the
resolver from that field via
[`TrustedKeyRing.from_dict`](../../sdk-python/pic_standard/keyring.py)
wrapped in `StaticKeyRingResolver`.

Vector JSON MUST NOT include `options.proposal_base_dir`. Like `key_resolver`,
it is a runner-controlled, non-portable filesystem knob. The runner derives
`proposal_base_dir` from the resolved `evidence_root_dir`; a vector-supplied
value would break the path-resolution contract documented below.

When `options.evidence_root_dir` is present, it MUST be a non-empty string.
Explicit `null`, empty string, or non-string values are rejected fail-closed
by the runner. File-backed hash vectors MUST declare `evidence_root_dir` —
without it, the evidence system would fall back to the process CWD, breaking
portability. Sig-only vectors MAY omit `evidence_root_dir` since signature
verification does not read files.

For file-backed hash vectors, the runner derives `proposal_base_dir` from
the resolved `evidence_root_dir`, so `file://<name>` evidence refs resolve
under `conformance/artifacts/` regardless of the process CWD.

## Path resolution (LOCKED)

Evidence-mode vectors can reference filesystem artifacts (under
[`conformance/artifacts/`](../artifacts/README.md)) for hash-evidence
verification. Path resolution follows a strict layered rule:

1. **`evidence_root_dir`** in `options` is resolved relative to the
   **repository root** (NOT the manifest directory, NOT the process working
   directory, NOT the vector file's directory). Example: a vector declaring
   `"evidence_root_dir": "conformance/artifacts"` resolves to
   `<repo-root>/conformance/artifacts` regardless of where the runner is
   invoked from.

   The runner enforces three invariants on the resolved path, all
   fail-closed (each rejection surfaces as a vector-level failure with a
   reason string, not a silent bypass):

   - **Not absolute.** Absolute paths (e.g., `/etc/passwd`, `C:\Windows`)
     would encode local filesystem layout into a portable vector.
     Reason: `"evidence_root_dir must be repository-root-relative"`.
   - **Stays within repo root.** Paths that escape `<repo-root>` via `..`
     traversal would re-introduce local-filesystem coupling through the
     back door.
     Reason: `"evidence_root_dir must stay within repository root"`.
   - **Stays within `conformance/artifacts/`.** SHA-pinned artifacts live
     under that subtree by contract. A path that resolves to anywhere else
     in the repo (e.g., `"."`, `"sdk-python"`, or `"docs"`) could hash
     arbitrary repo files and weaken the artifact contract.
     Reason: `"evidence_root_dir must stay within conformance/artifacts"`.

2. **Artifact paths inside evidence entries** (`ref: "file://<name>"`) are
   resolved relative to the **configured `evidence_root_dir`**, and MUST NOT
   escape it. For normal allow/mismatch vectors, a `..` traversal that
   escapes the evidence root is a vector bug. Sandbox/block vectors may
   intentionally use escaping paths to assert that the verifier rejects
   such evidence with a path-sandbox error.

Layered model:

```
<repo-root>
  └── conformance/artifacts/         ← evidence_root_dir
        └── invoice_001.txt           ← evidence payload ref
```

This is a **portability contract**. Any conformant implementation (including
the future TypeScript verifier) MUST reproduce this resolution behavior
byte-for-byte. Implementations that resolve relative to the manifest
directory or process CWD do not conform.

## Keyring hermeticity (LOCKED)

Signature-evidence vectors carry their own keyring inline via the
`embedded_keyring` field. The runner constructs an in-memory
[`StaticKeyRingResolver`](../../sdk-python/pic_standard/keyring.py) from this
field and passes it through `PipelineOptions.key_resolver` — no environment
variables (`PIC_KEYS_PATH` is NOT consulted), no separate keyring fixture
files, and no disk I/O for key lookup at verification time.

### `embedded_keyring` schema

The schema mirrors the existing
[`TrustedKeyRing.from_dict`](../../sdk-python/pic_standard/keyring.py)
interface exactly:

```json
{
  "embedded_keyring": {
    "trusted_keys": {
      "demo_signer_v1": "<base64-encoded raw Ed25519 public key, 32 bytes>",
      "billing_key_v2": {
        "public_key": "<base64-or-hex-or-PEM>",
        "expires_at": "2026-12-31T23:59:59Z"
      }
    },
    "revoked_keys": ["old_key_v0"]
  }
}
```

Both shorthand (string value = public key) and structured (object with
`public_key` + optional `expires_at`) forms are accepted, matching
`TrustedKeyRing.from_dict` precisely. The `revoked_keys` array is optional.

### Why inline, not env-var or external file?

- **Cross-language portability.** The TypeScript verifier (v0.9.0) MUST
  consume the same vector files unchanged. An env-var-coupled keyring would
  force every implementation to invent the same setup ritual.
- **Reviewable signal.** The keyring is right next to the signature it
  validates; a reviewer can see the key, the signature, and the payload in
  a single file.
- **Determinism.** No "did we set `PIC_KEYS_PATH` correctly?" failure mode in
  CI or local runs.

## Hash-evidence vectors

Hash-evidence entries reference files under
[`conformance/artifacts/`](../artifacts/README.md) via `file://<name>` URIs.
The vector's `sha256` field pins the expected SHA-256 of the file bytes.

When adding a new hash vector:

1. Add the artifact to `conformance/artifacts/` (committing the literal
   bytes — see [`conformance/artifacts/README.md`](../artifacts/README.md)).
2. Compute its SHA-256 locally.
3. Pin that SHA-256 into the vector's `evidence[N].sha256` field.
4. For normal allow/mismatch vectors, use `"ref": "file://<artifact-name>"`
   resolved against `evidence_root_dir`. Sandbox/block vectors may intentionally
   use traversal or outside-root paths to assert fail-closed path handling.

## Signature-evidence vectors

Signature-evidence entries carry an inline UTF-8 payload string and a
base64-encoded Ed25519 signature. The matching public key lives in
`embedded_keyring.trusted_keys`.

When adding a new sig vector:

1. Generate an Ed25519 keypair (deterministically if reproducibility is
   important; see `examples/_gen_sig_example.py` for a pattern).
2. Sign the payload bytes with the private key.
3. Embed the base64 signature in `evidence[N].signature`.
4. Embed the base64 raw public key (32 bytes) in
   `embedded_keyring.trusted_keys.<key_id>` (shorthand string form).
5. The private key MUST NOT be committed anywhere.

Vectors that test revocation or expiry use the `revoked_keys` array or
the structured form with an `expires_at` in the past.

## Vector naming convention

```
evidence-<kind>-<allow|block>-NNN-<short-slug>
```

Where `<kind>` is one of: `hash`, `sig`, `sandbox`, `mixed`. Examples:

- `evidence-hash-allow-001-simple`
- `evidence-sig-block-003-revoked-key`
- `evidence-sandbox-block-001-path-traversal`
- `evidence-mixed-allow-001-hash-and-sig-both-ok`

## Cross-references

- [`conformance/artifacts/README.md`](../artifacts/README.md) — byte-stability
  contract for SHA-pinned files.
- [`conformance/run.py`](../run.py) — the runner that dispatches evidence-mode
  vectors via JSON-safe `options` mapped into `PipelineOptions`, plus any
  runner-constructed objects such as `key_resolver`, then `verify_proposal()`.
- [`sdk-python/pic_standard/evidence.py`](../../sdk-python/pic_standard/evidence.py)
  — `EvidenceSystem` implementation; hash + sig evidence verification.
- [`sdk-python/pic_standard/keyring.py`](../../sdk-python/pic_standard/keyring.py)
  — `TrustedKeyRing` and `StaticKeyRingResolver`.
- `docs/spec-evidence.md` (lands in PR V8.2-4) — normative spec these vectors
  codify.
