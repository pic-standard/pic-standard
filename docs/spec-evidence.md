# PIC Evidence Verification Semantics — DRAFT

> **Status:** DRAFT — v0.8.2 snapshot of PIC/1.0 evidence verification
> semantics. Not final-normative until PIC v1.0.
> Published for community feedback per ROADMAP §1.4.
>
> **What this DRAFT does:** restates the normative evidence verification
> semantics that were previously scattered across [RFC-0001](RFC-0001-pic-standard.md)
> (Security Properties #5, #6, #7), [`evidence.md`](evidence.md) (operator
> guide), [`keyring.md`](keyring.md) (key lifecycle), and the
> `pic_standard.evidence` reference implementation, into a single
> implementer-facing reference using BCP 14 language.
>
> **What is still open:** see Appendix C ("Open Questions Registry") for
> IDed open questions tracked through DRAFT → final cleanup. DRAFT text
> uses proposed normative language to preview intended Phase 1.4
> semantics; these requirements are not binding until the specification
> is formally adopted.
>
> **Cross-references:** This DRAFT CITES frozen normative artifacts
> ([RFC-0001](RFC-0001-pic-standard.md) anchor,
> [PIC Canonical JSON v1](canonicalization.md)) and the
> [PIC Attestation Object v1](attestation-object-draft.md) DRAFT rather
> than restating their normative content. Where a future PIC revision
> changes the cited contract, this DRAFT will be updated in the same
> release. Conflicts are resolved per §19 ("Normative Precedence and
> Conflict Resolution"), not by silent re-interpretation.

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
that an implementation MUST self-declare. The two profiles defined by
this specification family are:

- **`PIC-Core`** — Action Proposal parsing, impact taxonomy, trust
  sanitization, tool binding, verifier outcomes. Passes
  `conformance/core/` and `conformance/trust_sanitization/`. Defined
  normatively in [`spec-core.md`](spec-core.md).
- **`PIC-Evidence`** — evidence object parsing, hash verification,
  signature verification, key lifecycle handling, trust upgrade.
  Passes `conformance/evidence/`. Defined normatively in this
  specification.
- **`PIC-Full`** — both `PIC-Core` and `PIC-Evidence`.

An implementation MUST state which profile(s) it implements. An
implementation MUST NOT claim `PIC-Full` unless it satisfies both
`PIC-Core` and `PIC-Evidence`.

`PIC-Evidence` MAY be implemented independently of `PIC-Core` (e.g.,
an evidence-verification library wrapping a separate core verifier);
in that case the library's caller is responsible for satisfying
`PIC-Core` requirements.

---

## 3. Unknown Fields and Extensions

Unknown fields in protocol objects MUST be handled according to the
active JSON Schema and profile-specific rules per
[`spec-core.md §3`](spec-core.md#3-unknown-fields-and-extensions).
Implementations MUST NOT silently interpret unknown fields in
evidence objects as security-relevant authorization, trust, policy,
evidence, or tool-binding data unless those fields are defined by a
versioned PIC specification.

Future extension fields in evidence objects SHOULD use a reserved
extension namespace such as `x_` or `extensions`, but extension data
MUST NOT affect signature verification outcome, hash verification
outcome, or trust upgrade decisions unless the implementation
explicitly opts into the corresponding extension specification.

---

## 4. Evidence Object Format

Evidence entries appear in the optional `evidence` array of an Action
Proposal (see [`RFC-0001 §Optional Fields`](RFC-0001-pic-standard.md#optional-fields)).
Each entry is a JSON object with the following fields:

| Field | Type | Presence | Description |
|---|---|---|---|
| `id` | string | MUST | Stable identifier, expected to match a `provenance[].id` for trust upgrade (see §8). |
| `type` | string | MUST | One of `"hash"` or `"sig"`. The PIC/1.0 JSON Schema defines `type` as a closed enum; unknown values are schema-rejected with `PIC_SCHEMA_INVALID`. If an implementation's schema layer is more permissive, the evidence handler MUST reject the unknown type fail-closed with `PIC_EVIDENCE_FAILED`. |
| `ref` | string | MUST | URI referencing the artifact. `file://<path>` for hash evidence (see §5); `inline:attestation` or implementation-defined for sig evidence (see §6). |
| `sha256` | string | MUST when `type="hash"` | 64-character lowercase hex digest of the referenced file bytes. |
| `payload` | string | MUST when `type="sig"` | UTF-8 string carrying the bytes that were signed; in canonical-signing mode this string parses as a JSON attestation object (see §6.2). |
| `signature` | string | MUST when `type="sig"` | Base64 (standard alphabet per [RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648#section-4)) Ed25519 signature. URL-safe and unpadded variants are non-conformant per [`canonicalization.md §7.10`](canonicalization.md#710-base64-variant-pic-protocol-constraint-adjacent-to-canonicalization). |
| `alg` | string | MUST when `type="sig"` | Signature algorithm identifier. v1 supports `"ed25519"` only. Implementations MUST reject unknown algorithms fail-closed. |
| `key_id` | string | MUST when `type="sig"` | Key identifier resolved against the trusted keyring (see §9). |

**Example (Informative).** Evidence entries inside a proposal:

```json
"evidence": [
  {
    "id": "invoice_123",
    "type": "hash",
    "ref": "file://invoice_123.txt",
    "sha256": "a2e818612ae44f799be83833149cdd8a1ea750fa8d40bc8507f874f8ad488fbd"
  },
  {
    "id": "approval_123",
    "type": "sig",
    "ref": "inline:attestation",
    "payload": "{\"attestation_version\":\"PIC-ATT/1.0\", ...}",
    "alg": "ed25519",
    "signature": "<base64>",
    "key_id": "demo_signer_v1"
  }
]
```

---

## 5. Hash Evidence Verification

For each evidence entry with `type="hash"`:

1. Implementations MUST resolve `ref` per the path-resolution rule
   in §5.1 below.
2. Implementations MUST read the referenced file's bytes in binary
   mode without normalization (no newline translation, no BOM
   stripping, no transcoding) per
   [`canonicalization.md §7.11`](canonicalization.md#711-file-hash-rules-pic-protocol-constraint-adjacent-to-canonicalization).
3. Implementations MUST compute SHA-256 of the file bytes and compare,
   byte-exact, against the `sha256` field's value.
4. On match, the evidence entry is verified; the entry's `id` is
   eligible for trust upgrade (see §8).
5. On any failure (file not found, hash mismatch, sandbox violation,
   size cap breach), the evidence entry MUST NOT be marked verified.
   The verifier outcome MUST include `PIC_EVIDENCE_FAILED` (see §11).

### 5.1 Path resolution and sandboxing

`file://` references MUST be resolved relative to a configured
`evidence_root_dir`. Implementations MUST reject fail-closed:

- absolute paths in `ref`;
- relative paths that escape `evidence_root_dir` via `..` traversal;
- paths whose resolved location is outside `evidence_root_dir`;
- files larger than the configured `max_file_bytes` (default 5 MB per
  [`evidence.md`](evidence.md#evidence-sandboxing)).

Per [RFC-0001 §Security Properties #6](RFC-0001-pic-standard.md#security-properties),
file-based evidence MUST be sandboxed within `evidence_root_dir`.

---

## 6. Signature Evidence Verification

For each evidence entry with `type="sig"`:

1. Implementations MUST resolve `key_id` against the trusted keyring
   per §9 (resolver protocol) and §10 (key lifecycle). A key that is
   missing, revoked, or expired MUST NOT produce a successful evidence
   result (see §10).
2. Implementations MUST determine the signing mode per §6.2.
3. Implementations MUST compute the bytes to verify per §6.3.
4. Implementations MUST verify the Ed25519 signature against the
   computed bytes using the resolved public key.
5. In canonical-signing mode, implementations MUST additionally verify
   digest binding per §6.4 before the entry is marked verified.
6. On success, the entry's `id` is eligible for trust upgrade (see §8).
7. On any failure (unknown algorithm, key resolution failure,
   signature mismatch, payload too large, mode-detection violation,
   digest-binding failure), the verifier outcome MUST include
   `PIC_EVIDENCE_FAILED` (see §11).

### 6.2 Signing Modes — Legacy and Canonical

> **Note:** This subsection and §6.3, §6.4 are load-bearing for the
> opt-in canonical attestation-object signing implementation (PIC
> v0.8.2 PR V8.2-5).

Implementations MUST detect the signing mode of each `sig` evidence
entry from the parsed `payload`. The detection rule is a three-way
discriminator:

1. **Legacy mode.** The entry is in **legacy mode** if any of the
   following holds:
   - the `payload` string does not parse as JSON;
   - the `payload` string parses as JSON but the parsed value is not
     an object (e.g., array, string, number, boolean, or null);
   - the `payload` string parses as a JSON object that does NOT
     contain an `attestation_version` key.

   In all these cases, bytes to verify are the raw UTF-8 bytes of
   the `payload` string (see §6.3).

2. **Canonical mode (well-formed).** If the `payload` string parses as
   a JSON object containing a string-valued `attestation_version` AND
   the string value is in the implementation's supported attestation
   version allowlist, the entry is in **canonical mode**. Bytes to
   verify are computed per §6.3 (PIC Canonical JSON v1 over the
   parsed attestation object). Digest binding (§6.4) applies.

3. **Canonical-looking but malformed or unknown.** If the `payload`
   parses as a JSON object that contains `attestation_version` but
   the value is non-string (number, bool, list, object, null) OR is
   a string not in the supported allowlist, the entry MUST be
   rejected fail-closed with `PIC_EVIDENCE_FAILED`. Implementations
   MUST NOT silently fall back to legacy mode in this case;
   silent fallback would be a security footgun for malformed or
   future-version canonical-looking payloads.

For any payload that parses as a JSON object (case 2 or case 3 above),
implementations MUST detect duplicate object member names at any
nesting level — not only at the root — per
[`canonicalization.md §7.4`](canonicalization.md#74-duplicate-object-member-names).
Any duplicate detected MUST cause the evidence entry to be rejected
fail-closed with `PIC_EVIDENCE_FAILED`. A non-recursive
implementation that collapses nested duplicates silently (last-value
wins) would accept payloads that the PIC-CJSON canonicalization
rule rejects and is non-conformant; verifiers MUST recurse into
every nested object when checking duplicates.

The intended supported attestation version allowlist for `PIC-Evidence`
v0.8.2 is `{"PIC-ATT/1.0"}` — the version identifier specified by
[`attestation-object-draft.md`](attestation-object-draft.md) and used
in [`canonicalization.md §9.4`](canonicalization.md#94-attestation-object-example).
The exact allowlist constant is locked in the reference implementation
by PR V8.2-5 (opt-in canonical signing, see ROADMAP §1.5). Future PIC
revisions MAY extend the allowlist; unknown versions in current
implementations MUST fail closed per (3).

**Rationale (Informative).** A binary "is canonical?" check based on
key presence alone would let malformed canonical-looking payloads
silently downgrade to legacy mode, where less-strict byte semantics
might accept a forgery the canonical path would reject. The three-way
discriminator forces an explicit, fail-closed decision on every
`payload`.

### 6.3 Canonical-Bytes Computation

For evidence entries in **legacy mode** (§6.2.1), the bytes to
verify are the raw UTF-8 bytes of the `payload` string exactly as
they appear in the evidence entry, without canonicalization or
normalization.

For evidence entries in **canonical mode** (§6.2.2), the bytes to
verify are computed as
`canonicalize(parsed_attestation_object)` per
[`canonicalization.md §8.4`](canonicalization.md#84-attestation-object-serialization).
Implementations MUST parse the `payload` string as JSON and apply
PIC Canonical JSON v1 (PIC-CJSON/1.0) to the parsed value;
implementations MUST NOT sign or verify raw transport JSON bytes in
canonical mode.

**Rationale (Informative).** The strict re-canonicalization on the
verifier side guards against lossy transport (e.g., middleware that
re-serializes JSON, re-orders keys, normalizes whitespace, or
roundtrips through a database that strips insignificant whitespace).
The signature in canonical mode is always over canonical bytes,
never over raw payload text.

### 6.4 Digest Verification Post-Signature

For evidence entries in **canonical mode** (§6.2.2), after the
Ed25519 signature has verified successfully over the canonical bytes
(§6.3), implementations MUST verify that the attestation object's
`args_digest`, `claims_digest`, and (when present) `intent_digest`
match the corresponding canonicalized fields of the Action Proposal:

- `args_digest` MUST equal SHA-256 of `canonicalize(proposal.action.args)`
  per [`canonicalization.md §8.1`](canonicalization.md#81-args_digest).
- `claims_digest` MUST equal SHA-256 of `canonicalize(proposal.claims)`
  per [`canonicalization.md §8.2`](canonicalization.md#82-claims_digest).
- `intent_digest`, when present, MUST equal SHA-256 of the UTF-8
  bytes of `proposal.intent` per
  [`canonicalization.md §8.3`](canonicalization.md#83-intent_digest).

Implementations MUST also verify that the attestation object's
`tool` equals `proposal.action.tool`, that `impact` equals
`proposal.impact`, and that `provenance_ids` lists provenance entry
IDs in proposal-array order.

Digest fields (`args_digest`, `claims_digest`, `intent_digest`) MUST
be 64-character lowercase hexadecimal strings matching the regular
expression `^[0-9a-f]{64}$`. Implementations MUST reject fail-closed
any digest field that violates this shape, including 64-character
uppercase or mixed-case hex. Implementations MUST NOT case-fold the
digest value before comparison; the shape rule is byte-strict.

When the attestation object includes `expires_at`, the value MUST be
a strict RFC 3339 timestamp with an explicit timezone designator
(either `Z` for UTC or a numeric offset such as `+00:00` /
`-05:00`). Implementations MUST reject fail-closed any `expires_at`
value that:

- carries leading or trailing whitespace (implementations MUST NOT
  strip or normalize whitespace before parsing);
- lacks an explicit timezone designator (naive timestamps such as
  `2099-01-01T00:00:00` are non-conformant);
- otherwise fails strict RFC 3339 parsing.

Any digest mismatch, tool mismatch, impact mismatch, provenance-ids
ordering mismatch, digest-field shape violation, or `expires_at`
shape/parse failure MUST cause the evidence entry to be rejected
fail-closed with `PIC_EVIDENCE_FAILED`, even though the signature
itself verified.

**Rationale (Informative).** A valid signature over an attestation
object whose digests do NOT match the proposal it accompanies means
either (a) the signer attested to a different proposal than was
delivered, or (b) the proposal was modified after signing. Both
cases are security failures that signature verification alone does
not catch.

---

## 7. Attestation Object Signing

The producer-side construction and signing process for canonical-mode
evidence is defined in
[`attestation-object-draft.md §Signing Process`](attestation-object-draft.md#signing-process).
This specification's normative addition is the verifier-side rule
that re-canonicalization (§6.3) and digest verification (§6.4) are
mandatory, fail-closed checks after signature verification in
canonical mode.

Implementations MUST follow the verifier process specified in
[`attestation-object-draft.md §Signing Process`](attestation-object-draft.md#signing-process)
unchanged: parse → re-canonicalize → verify signature → enforce
semantics (mode allowlist, tool match, freshness, digest binding).

---

## 8. Trust Upgrade Rules

Per [RFC-0001 §ID Binding Convention](RFC-0001-pic-standard.md#id-binding-convention),
evidence verification produces trust as an *output*, not an input
assumption. When an evidence entry's verification (hash per §5 or
signature per §6) succeeds, implementations MUST upgrade the trust
level of any matching `provenance[].id` entry from `"untrusted"` to
`"trusted"` for the remainder of the verification of that proposal.

The trust upgrade MUST be applied BEFORE the core verifier's causal
gating check (high-impact actions require trusted-evidence chain) so
that a successful evidence verification can bridge an otherwise
untrusted provenance to satisfy the gating rule.

Implementations MUST NOT persist or propagate the upgraded trust
level beyond the scope of the current proposal verification. Trust
upgrades are per-verification, in-memory, and do not retroactively
affect previously-verified proposals or future proposals.

**Migration Note (Informative).** v0.7.5 introduced
`strict_trust=True` (see [`migration-trust-sanitization.md`](migration-trust-sanitization.md)
and [`spec-core.md §10`](spec-core.md#10-trust-axiom--sanitization))
which sanitizes self-asserted `trust="trusted"` provenance to
`untrusted` BEFORE evidence verification runs. Under `strict_trust`,
the only path from `untrusted` to `trusted` is successful evidence
verification — eliminating the legacy self-assertion bypass.

---

## 9. Keyring & Resolver Protocol

Implementations MUST resolve `key_id` values via an explicit
key-resolution interface. The interface MUST distinguish an active
resolved key from non-active states such as missing, revoked, or
expired (see §10). The concrete API shape MAY vary by implementation.

The reference implementation's `KeyResolver` interface is documented
in `sdk-python/pic_standard/keyring.py`; the operator-facing keyring
file format is documented in [`keyring.md`](keyring.md). Key encodings
supported in v1 are base64 (recommended), hex, and PEM (the latter
requires the `cryptography` package per [`keyring.md`](keyring.md#key-formats)).

Implementations MUST NOT silently fall back to ambient sources
(environment variables, CWD-relative files, system keychains) when
running portable conformance vectors. Per the
[`conformance/evidence/README.md`](../conformance/evidence/README.md)
hermeticity contract, sig-evidence conformance vectors carry an
explicit `embedded_keyring` field that the runner constructs into a
`StaticKeyRingResolver`; implementations claiming `PIC-Evidence`
conformance MUST honor that hermeticity rule.

---

## 10. Key Lifecycle

A `key_id` is treated as inactive if any of the conditions in the
following table holds (cf.
[`keyring.md §Expiry & Revocation`](keyring.md#expiry--revocation)):

| Condition | Status |
|---|---|
| `key_id` not in the keyring | `missing` |
| `key_id` in the keyring's `revoked_keys` list | `revoked` |
| Key carries an `expires_at` timestamp in the past | `expired` |
| Otherwise | `ok` |

Trusted keyring entries with `expires_at` in the past, or appearing
in the keyring's `revoked_keys` list, MUST NOT produce a successful
evidence result. Implementations MUST check expiry and revocation
before accepting signature evidence as valid. They MAY perform
cryptographic verification before, after, or alongside lifecycle
checks, but a revoked or expired key MUST NOT produce a successful
evidence result. (Per [RFC-0001 §Security Properties #7](RFC-0001-pic-standard.md#security-properties).)

Implementations SHOULD distinguish `missing` / `revoked` / `expired`
in their internal diagnostics for operator clarity (per
[`evidence.md §Fail-closed design`](evidence.md#fail-closed-design)),
but the externally-emitted error code is `PIC_EVIDENCE_FAILED` (see
§11) for all three.

---

## 11. Evidence Error Semantics

### 11.1 Error Code Stability

The error code identifiers defined in
`sdk-python/pic_standard/errors.py` (and mirrored in
`integrations/openclaw/lib/types.ts`) are the **portable error-code
namespace** for PIC implementations. When a conforming implementation
reports a failure covered by one of the semantics below, it MUST
emit the corresponding identifier and MUST NOT substitute
implementation-local or message-text-only identifiers. Reserved
identifiers are listed for compatibility but are not required to be
emitted unless their stated semantics are implemented.

Codes relevant to this specification, including schema-level evidence
shape failures and evidence-verification failures, with verified
emission semantics from the v0.8.2 reference implementation:

- `PIC_SCHEMA_INVALID` — schema-level failure while parsing the
  proposal or evidence object shape. For `PIC-Evidence`, this covers
  malformed evidence fields that are rejected by the PIC/1.0 JSON
  Schema before per-entry evidence verification runs, including
  invalid digest format and closed-enum violations such as unknown
  `evidence[].type` values. Distinct from `PIC_EVIDENCE_FAILED`,
  which applies after evidence is present and reaches evidence
  verification.
- `PIC_EVIDENCE_REQUIRED` — **pipeline-level** outcome: the active
  policy (`require_evidence_for_impacts`) requires the proposal's
  impact class to be backed by evidence, but the proposal contains
  no top-level `evidence` array entries to verify. Emitted before
  any per-entry evidence verification runs. Distinct from
  `PIC_EVIDENCE_FAILED`, which describes a per-entry verification
  failure (evidence was present but invalid).
- `PIC_EVIDENCE_FAILED` — evidence verification failed. Covers all
  per-entry failure modes: hash mismatch, hash file not found,
  signature invalid, signing key unknown/revoked/expired, signed
  payload exceeds size cap, sandbox path traversal, mode-detection
  violation (§6.2, including duplicate object member names at any
  nesting level), digest-binding mismatch (§6.4), digest-field
  shape violation (§6.4), `expires_at` shape/parse failure (§6.4),
  freshness failure (§15), evidence module unavailable. Pinned by
  `conformance/evidence/block/001-026` vectors.

The freeform human-readable messages accompanying each error code
are **Informative**. They MAY vary across implementations, language
runtimes, and locales without affecting conformance. Programmatic
consumers (CI gates, dashboards, cross-implementation parity tests)
MUST pattern-match on the error code, NOT on the message text.

Adding a new error code is a versioned change. Removing or renaming
an existing code is a backward-incompatible change and MUST go
through the same governance as a wire-format change (see §18).
Repurposing an existing code's semantics is also a
backward-incompatible change.

---

## 12. Attestation Object Relationship

The attestation object is the security-relevant payload carried
inside a `sig` evidence entry's `payload` field when the entry uses
canonical-signing mode (§6.2.2). Its structure, field set, and
field-presence requirements are defined in
[`attestation-object-draft.md`](attestation-object-draft.md). This
specification adds no new attestation-object fields and changes none
of those defined; it specifies only how verifiers consume the
attestation object (parse, re-canonicalize, verify, digest-bind).

Legacy-mode (§6.2.1) sig evidence entries carry an opaque `payload`
string that is not an attestation object. The attestation object
relationship applies only to canonical mode.

---

## 13. Canonicalization & Digest Binding

PIC Canonical JSON v1 ([PIC-CJSON/1.0](canonicalization.md)) is the
sole canonicalization profile recognized by this specification.
Implementations MUST use it unchanged for:

- the canonical bytes signed in canonical mode (§6.3, per
  [`canonicalization.md §8.4`](canonicalization.md#84-attestation-object-serialization));
- the digest inputs in canonical mode (§6.4, per
  [`canonicalization.md §8.1–§8.3`](canonicalization.md#81-args_digest)).

Implementations MUST NOT define an alternative canonicalization
profile, reorder canonical bytes, or normalize Unicode prior to
canonicalization. The rejection rules in
[`canonicalization.md §7.1–§7.13`](canonicalization.md#71-encoding)
apply unchanged to canonical-mode attestation objects.

File-hash digest inputs (§5) use raw file bytes per
[`canonicalization.md §7.11`](canonicalization.md#711-file-hash-rules-pic-protocol-constraint-adjacent-to-canonicalization);
no canonicalization is applied.

---

## 14. Distinction: Protocol vs. Policy

Per [RFC-0001 §Core Claims #5](RFC-0001-pic-standard.md#core-claims):
PIC enforces evidence verification semantics at the protocol level.
Operator policy decides which tools and impact classes require
evidence at all (via configuration analogous to
`require_evidence_for_impacts`).

Policy engines MAY impose stricter requirements than this protocol.
However, a policy engine MUST NOT reinterpret PIC protocol fields
(`evidence[].type`, `evidence[].sha256`, `evidence[].signature`, etc.)
in a way that changes their normative meaning. Policy MAY deny an
action that PIC would otherwise allow; policy MUST NOT make an
invalid PIC proposal valid.

---

## 15. Freshness & Replay Prevention

When the canonical-mode attestation object carries `expires_at`,
implementations MUST reject the evidence entry if the timestamp is
in the past at verification time. Clock-skew tolerance is
deployment-configured, not protocol-mandated (per
[`attestation-object-draft.md §Freshness Semantics`](attestation-object-draft.md#freshness-semantics)).

When the attestation object carries `issued_at`, implementations MAY
use it for audit and freshness assessment but MUST NOT use it alone
to gate verification outcome.

Full replay prevention (nonce caches, bounded TTL registries) is
NOT part of this specification. It is deferred to a profile-level
mechanism; see Appendix C, `OQ-EVIDENCE-004`.

---

## 16. Security Considerations

This section lists the security-relevant invariants enforced by
evidence verification. Each is normative.

### 16.1 Key Resolution

Implementations MUST resolve verification keys via an explicit
key-resolution interface (§9). They MUST NOT silently fall back to
process-wide environment variables, ambient CWD-relative keyring
files, or other implicit sources when running portable conformance
vectors. The reference runner's hermeticity contract
(`conformance/evidence/README.md`) enforces this by rejecting
evidence vectors that would otherwise reach the legacy
`PIC_KEYS_PATH` fallback.

### 16.2 Hash Root Confinement

File-backed hash evidence (§5) MUST be resolved against an
explicitly configured `evidence_root_dir`. Absolute paths, paths
escaping the configured root via `..` traversal, and paths outside
the declared artifact subtree MUST be rejected fail-closed. The
reference runner additionally confines `evidence_root_dir` itself to
`conformance/artifacts/` for portable vectors.

### 16.3 Signature Payload Canonicalization

Signers and verifiers in canonical-signing mode (§6.2.2) MUST
compute signed bytes from `canonicalize(parsed_attestation_object)`
per [`canonicalization.md §8.4`](canonicalization.md#84-attestation-object-serialization).
They MUST NOT sign or verify raw transport JSON bytes in canonical
mode. The mode discriminator (§6.2) is the presence of a
string-valued `attestation_version` in the parsed payload;
non-string and unknown string values MUST fail closed.

### 16.4 Revocation and Expiry

Per §10. Trusted keyring entries with `expires_at` in the past or
appearing in the keyring's `revoked_keys` list MUST NOT produce a
successful evidence result. Implementations MUST check expiry and
revocation before accepting signature evidence as valid. They MAY
perform cryptographic verification before, after, or alongside
lifecycle checks, but a revoked or expired key MUST NOT produce a
successful evidence result.

### 16.5 Sandboxed Evidence Resolution

`file://` URIs in evidence entries MUST resolve only within the
configured `evidence_root_dir`. Implementations MUST reject any
resolved path outside that subtree fail-closed. (Per
[RFC-0001 §Security Properties #6](RFC-0001-pic-standard.md#security-properties).)

### 16.6 No Implicit Trust Upgrade

Trust upgrade via evidence verification (§8) MUST be the result of
explicit cryptographic verification, NOT a side effect of parsing or
transport. Implementations MUST NOT mark provenance entries as
trusted on the basis of declared `trust: "trusted"` alone when
`strict_trust=True` is enabled (the v0.7.5 Trust Axiom; see
[`spec-core.md §10`](spec-core.md#10-trust-axiom--sanitization)).

---

## 17. Conformance Assertions

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
| Evidence (allow + block) | `conformance/evidence/` | `evidence` |
| Canonicalization (transitive dependency for canonical-signing mode) | `conformance/canonicalization/` | `canonicalization` |

Where this DRAFT's prose and the conformance vectors disagree, the
discrepancy MUST be resolved by updating EITHER the DRAFT or the
vectors before a conformance claim is asserted. The discrepancy MUST
NOT be resolved by silent re-interpretation.

See Appendix A for a per-vector cross-reference mapping conformance
vector IDs to the section of this DRAFT each one exercises.

---

## 18. Backward-Compatible Changes vs Breaking Changes

The following changes are backward-incompatible and MUST NOT occur
within the same stable protocol version:

- removing or renaming evidence-object fields;
- changing the meaning of an existing evidence `type` value;
- changing the trust-upgrade semantics of evidence verification;
- changing canonicalization or digest-binding rules;
- removing or renaming error-code identifiers in the evidence
  namespace;
- changing allow/block verdicts for existing conformance vectors
  without a versioned migration note;
- removing supported attestation-version values from the §6.2.2
  allowlist (adding new versions is backward-compatible; removing
  existing ones is not).

The following changes MAY be backward-compatible if existing
conforming implementations remain valid:

- adding new optional evidence-object fields;
- adding new evidence `type` values (implementations encountering
  unknown types MUST fail closed per §4);
- adding new conformance vectors;
- adding new stricter policy profiles;
- adding new attestation-version values to the supported allowlist;
- adding new error-code identifiers reserved for future use.

---

## 19. Normative Precedence and Conflict Resolution

This document is DRAFT until PIC v1.0. Where its requirements
interact with the frozen normative artifacts of PIC/1.0, the
following precedence applies:

1. [`RFC-0001-pic-standard.md`](RFC-0001-pic-standard.md) — defensive
   publication anchor, frozen for v0.1.0–v0.5.5. Wire-format and
   security-property requirements that originate in RFC-0001 are
   authoritative; this DRAFT restates them in BCP 14 form but does
   NOT override them.
2. [`canonicalization.md`](canonicalization.md) — PIC-CJSON/1.0,
   frozen as of v0.8.0. Byte-level serialization, digest
   computation, and attestation-object canonical-bytes rules
   originate here; this DRAFT cites them and MUST NOT redefine them.
3. [`attestation-object-draft.md`](attestation-object-draft.md) —
   PIC Attestation Object v1 DRAFT. Field set and signing-process
   semantics originate there; this DRAFT cites them and adds only
   the verifier-side mandatory-fail-closed rules (§6.2–§6.4) on
   top.
4. This DRAFT — restates v0.7.5–v0.8.x post-RFC normative
   evidence-verification semantics that were previously scattered
   across `evidence.md`, `keyring.md`, and the reference
   implementation.

If text in this DRAFT appears to conflict with a higher-precedence
artifact, the conflict MUST be raised as an Open Question (Appendix
C) and resolved in a subsequent revision. The DRAFT MUST NOT be
treated as overriding higher-precedence artifacts by silent
re-interpretation.

---

## Appendix A. Conformance Vector Cross-Reference (Informative)

Maps conformance vector IDs to the section(s) of this DRAFT each
one exercises.

| Vector ID | Section(s) exercised |
|---|---|
| `evidence-hash-allow-001-simple` | §5 |
| `evidence-hash-allow-002-multiple-hashes` | §5 |
| `evidence-hash-block-001-mismatch` | §5, §11 |
| `evidence-hash-block-002-file-not-found` | §5.1, §11 |
| `evidence-hash-block-003-invalid-sha256-format` | §4 (schema), §11 |
| `evidence-sandbox-block-001-path-traversal` | §5.1, §16.2, §16.5 |
| `evidence-sandbox-block-002-absolute-outside-root` | §5.1, §16.2, §16.5 |
| `evidence-sig-allow-001-simple` | §6, §9, §10 |
| `evidence-sig-block-001-payload-tampered` | §6, §11 |
| `evidence-sig-block-002-unknown-key-id` | §9, §10, §11 |
| `evidence-sig-block-003-revoked-key` | §10, §16.4, §11 |
| `evidence-sig-block-004-expired-key` | §10, §16.4, §11 |
| `evidence-sig-block-005-payload-too-large` | §6, §11 |
| `evidence-mixed-allow-001-hash-and-sig` | §5, §6, §8 |
| `evidence-sig-allow-002-canonical-happy-full` | §6.2.2, §6.3, §6.4, §15 |
| `evidence-sig-allow-003-canonical-happy-minimal` | §6.2.2, §6.3, §6.4 |
| `evidence-sig-allow-004-legacy-json-object-no-version` | §6.2.1 |
| `evidence-sig-allow-005-legacy-json-array` | §6.2.1 |
| `evidence-mixed-allow-002-legacy-and-canonical` | §6.2 (per-entry dispatch), §6.3, §6.4 |
| `evidence-sig-block-006-canonical-tampered-signature` | §6.3, §11 |
| `evidence-sig-block-007-canonical-raw-byte-sig` | §6.3, §11 |
| `evidence-sig-block-008-canonical-unknown-version` | §6.2.3, §11 |
| `evidence-sig-block-009-canonical-non-string-version` | §6.2.3, §11 |
| `evidence-sig-block-010-canonical-duplicate-key-root` | §6.2 (duplicate-keys), §11 |
| `evidence-sig-block-011-canonical-duplicate-key-nested` | §6.2 (duplicate-keys, any nesting level), §11 |
| `evidence-sig-block-012-canonical-args-digest-mismatch` | §6.4, §11 |
| `evidence-sig-block-013-canonical-claims-digest-mismatch` | §6.4, §11 |
| `evidence-sig-block-014-canonical-intent-digest-mismatch` | §6.4, §11 |
| `evidence-sig-block-015-canonical-tool-mismatch` | §6.4, §11 |
| `evidence-sig-block-016-canonical-impact-mismatch` | §6.4 (impact binding), §11 |
| `evidence-sig-block-017-canonical-provenance-ids-mismatch` | §6.4, §11 |
| `evidence-sig-block-018-canonical-expires-at-in-past` | §15, §11 |
| `evidence-sig-block-019-canonical-expires-at-whitespace-padded` | §6.4 (strict RFC 3339), §11 |
| `evidence-sig-block-020-canonical-invalid-digest-shape` | §6.4 (digest-field shape), §11 |
| `evidence-sig-block-021-canonical-expires-at-naive` | §6.4 (strict RFC 3339, timezone required), §11 |

---

## Appendix B. Backward Compat (Informative)

This DRAFT does not change the wire format of `evidence` objects.
Legacy-mode (§6.2.1) sig evidence remains valid; existing
implementations that consume only legacy-mode sig evidence retain
PIC/1.0 compatibility.

Canonical-signing mode (§6.2.2) is identified by the presence of a
supported string-valued `attestation_version` in the parsed
payload. Verifiers that do not yet implement canonical mode will
encounter such payloads as unsupported by their mode-detection
logic; per §6.2.3, they MUST fail closed rather than fall back to
legacy mode.

See [`attestation-object-draft.md §Backward Compatibility`](attestation-object-draft.md#backward-compatibility)
for the producer-side compatibility story.

---

## Appendix C. Open Questions Registry (Informative)

The following questions are open for community feedback. Each is
identified by a stable ID so it can be cross-referenced from issues,
PRs, and future revisions. DRAFT → final cleanup tracks every ID
below; resolved items move to the changelog rather than being
silently deleted.

| ID | Summary | Resolution status |
|---|---|---|
| OQ-EVIDENCE-001 | Canonical signing envelope stability | Open |
| OQ-EVIDENCE-002 | Clock-skew tolerance protocol-level vs deployment-level | Open |
| OQ-EVIDENCE-003 | Digest algorithm agility | Open |
| OQ-EVIDENCE-004 | Replay-prevention profile (nonce caches, TTL registries) | Open |

### OQ-EVIDENCE-001 — Canonical signing envelope stability

The canonical-mode signing envelope (attestation object + signature + `key_id`) is currently carried inside the existing `sig` evidence entry shape (§4). A future profile may want to split canonical-mode evidence into its own evidence `type` (e.g., `"canonical_sig"`) to make the mode-distinction visible at the schema layer rather than at parse time. Resolution requires a backward-compatibility analysis against §18 and an authoring decision on whether to deprecate the overloaded `"sig"` type.

### OQ-EVIDENCE-002 — Clock-skew tolerance protocol-level vs deployment-level

§15 leaves `expires_at` clock-skew tolerance as
deployment-configured. A protocol-level lower bound (e.g.,
"verifiers MUST tolerate at least 60 seconds of clock skew") would
improve cross-implementation interop for time-sensitive evidence but
constrains deployments. Resolution requires gathering operational
data from existing PIC deployments.

### OQ-EVIDENCE-003 — Digest algorithm agility

The attestation object's digests (§6.4) are currently SHA-256 only,
inherited from [`attestation-object-draft.md`](attestation-object-draft.md#open-questions).
A future profile may add algorithm identifiers (e.g.,
`"args_digest_alg": "sha256"`) to permit SHA-3 or BLAKE3. Resolution
requires deciding whether algorithm agility lives in the attestation
object (per-field) or in a new attestation_version (whole-payload).

### OQ-EVIDENCE-004 — Replay-prevention profile

Full replay prevention is deferred (§15). A profile-level
specification needs to define nonce shape, cache TTL bounds, and
distributed-verifier coordination. Resolution requires authoring a
separate `docs/spec-evidence-replay-profile.md`.
