# PIC Canonical JSON v1

> **Status:** Proposed — targeted for PIC v0.8.0 (will flip to "Stable" once the release is cut)
> **Version:** `PIC-CJSON/1.0`
> **Last updated:** 2026-04-18
>
> This specification defines the exact byte-level representation used when PIC hashes or signs JSON values. Once released in v0.8.0, the rules in this document are frozen and may only be revised through a new major canonicalization version (e.g., `PIC-CJSON/2.0`). Any edge case discovered after release is a spec-level discussion, not a patch-level fix.

---

## 1. Motivation

Signatures, hashes, and cross-language interop require a byte-exact representation of JSON values. Two producers that encode the same semantic content with different whitespace, key order, number formatting, or string escaping will produce different bytes — and therefore different hashes and invalid signatures across implementations.

PIC Canonical JSON v1 (PIC-CJSON/1.0) provides that byte-exact representation. It is the serialization used to compute:

- `args_digest` over `action.args`
- `claims_digest` over the `claims` array
- `intent_digest` over the `intent` string (special-cased — see §8.3)
- The attestation object bytes that are signed

---

## 2. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals, as shown here.

---

## 3. Normative References

- **[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)** — JSON Canonicalization Scheme (JCS).
- **[RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)** — The JavaScript Object Notation (JSON) Data Interchange Format.
- **[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648)** — The Base16, Base32, and Base64 Data Encodings.
- **[RFC 3629](https://www.rfc-editor.org/rfc/rfc3629)** — UTF-8, a transformation format of ISO 10646.

---

## 4. Terminology

- **Canonical form** — the unique byte sequence produced by applying PIC Canonical JSON v1 to a JSON value.
- **Producer** — the implementation that constructs and canonicalizes a JSON value (e.g., an agent that signs an attestation).
- **Verifier** — the implementation that receives canonical bytes and computes a hash or verifies a signature against them.
- **Attestation object** — the minimal signed JSON object defined in [PIC Attestation Object v1](attestation-object-draft.md).
- **Supported input** — a JSON value that is within the input surface PIC-CJSON/1.0 accepts. Non-conformant input as defined in this specification is outside the supported input surface.

---

## 5. Baseline: RFC 8785 (JCS)

PIC Canonical JSON v1 is defined as **RFC 8785 plus the PIC-specific rules and adjacent protocol constraints in §7**.

All requirements of RFC 8785 apply unchanged unless explicitly overridden or constrained in this document. Where RFC 8785 is silent on a point, its normative text governs. Where this document adds a rule (e.g., rejecting non-string object keys, defining attestation-object field types), the additional rule is normative for PIC-CJSON/1.0 but does not alter RFC 8785 itself.

Implementers SHOULD first implement RFC 8785 as written, then layer the PIC-specific rules on top.

> **⚠️ Implementation trap:** Shortcut implementations using `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` (Python) or the equivalent in other languages are **NOT sufficient**. Such shortcuts produce output that is "mostly right" but diverges from RFC 8785 on number serialization (RFC 8785 mandates the ECMAScript number serialization semantics referenced in its §3.2.2.3, not each language's default float `repr`), on string escaping (RFC 8785's minimal escape set is tighter than most language defaults), and on non-BMP code point handling. A shortcut implementation will pass trivial vectors and fail edge cases in numbers, escaping, and Unicode — which is exactly where cross-language interop breaks. Implementations MUST be validated against the conformance test vectors (§10) before claiming RFC 8785 compliance.

---

## 6. Terminology for Input Values

For the purposes of this document, the input to canonicalization is a JSON-representable value, i.e., one of: object (string-keyed map), array (ordered list), string, number (integer or finite float), boolean, or `null`.

---

## 7. PIC-Specific Rules

Sections 7.1–7.9 and 7.12–7.13 are pure canonicalization rules — they govern how a JSON value becomes canonical bytes. Sections 7.10 (Base64 Variant) and 7.11 (File Hash Rules) are **PIC protocol constraints adjacent to canonicalization**: they govern how bytes appear in or interact with PIC-canonicalized contexts without being part of the JSON canonicalization algorithm itself. They are retained here in v0.8.0 for locality of reference; future PIC revisions may migrate them into a dedicated evidence/attestation profile document once that work lands.

### 7.1 Encoding

The canonical form MUST be encoded as UTF-8 (RFC 3629). There is no Byte Order Mark (BOM). There is no trailing newline.

### 7.2 Object Key Ordering

Object keys MUST be sorted by their UTF-16 code unit sequence as defined in RFC 8785 §3.2.3.

### 7.3 Object Keys MUST Be Strings

Every object member name MUST be a JSON string. Implementations that accept input values with non-string keys (e.g., integer-keyed maps in some language runtimes) MUST reject such inputs with a canonicalization error.

### 7.4 Duplicate Object Member Names

Duplicate object member names are non-conformant input for PIC Canonical JSON v1 and MUST NOT appear in producer output or in portable canonicalization success vectors. Implementations that operate on already-parsed host-language values are not required to detect duplicate keys, because many parsers collapse them before canonicalization begins. If duplicate-key negative cases are tested in future conformance work, they MUST use a raw-text vector format rather than the parsed-value format defined for portable canonicalization vectors.

### 7.5 Array Order

Array element order MUST be preserved. Arrays MUST NOT be sorted. Sorting applies only to object member names (§7.2).

### 7.6 Whitespace

No insignificant whitespace is emitted: no spaces between tokens, no line breaks, no indentation. This matches RFC 8785.

### 7.7 String Escaping

String values MUST be serialized per RFC 8785 §3.2.2.2 (minimal escaping). Only the following characters MUST be escaped:

- `"` → `\"`
- `\` → `\\`
- U+0008 → `\b`
- U+0009 → `\t`
- U+000A → `\n`
- U+000C → `\f`
- U+000D → `\r`
- U+0000..U+001F (other control characters) → `\u00XX` (lowercase hex per RFC 8785)

All other characters, including non-ASCII characters and characters outside the Basic Multilingual Plane, MUST be emitted as their UTF-8 byte representation without escaping. In particular, the forward slash character (`/`) MUST NOT be escaped.

### 7.8 Unicode Normalization

No Unicode normalization is performed. Strings are serialized as-is with the exact UTF-8 byte representation of the input code points. Producers MUST NOT apply NFC, NFD, NFKC, or NFKD normalization before canonicalization. Verifiers MUST compare exact UTF-8 byte sequences.

### 7.9 Number Handling

Numeric values in the input are categorized into two contexts:

**Precision-critical fields in the attestation object** (digests, timestamps, version strings, and any other field defined by [PIC Attestation Object v1](attestation-object-draft.md) as string-typed): these MUST be represented as JSON strings, not JSON numbers. This eliminates IEEE 754 cross-language ambiguity in the signed core.

**General JSON numbers elsewhere** (including in `action.args` and its descendants): these MAY appear as JSON numbers. When they do, they MUST be serialized per RFC 8785 §3.2.2.3 (the ECMAScript number serialization semantics referenced by RFC 8785).

Negative zero, when representable in the host runtime, MUST be serialized according to RFC 8785 §3.2.2.3 semantics rather than preserved by host-language float stringification. In particular, canonical serialization of negative zero yields `0`, not `-0` or `-0.0`. Implementations MUST NOT rely on generic host-language formatting such as Python `repr(-0.0)`, which produces `'-0.0'`. JavaScript implementations should still follow the RFC 8785 serialization rule explicitly rather than infer correctness from ad hoc host-language conversions.

The following values are NOT representable as JSON numbers and MUST be rejected with a canonicalization error:

- `NaN`
- `+Infinity`
- `-Infinity`

Only finite numeric values are representable as JSON numbers per RFC 8259.

### 7.10 Base64 Variant *(PIC protocol constraint adjacent to canonicalization)*

> **Scope note:** This is not a JSON canonicalization rule. It governs the encoding of base64 byte strings that appear inside PIC-canonicalized JSON (e.g., Ed25519 signatures in `sig`-type evidence entries). It is colocated here in v0.8.0 because base64 variant choice directly affects byte stability of signed payloads. Future PIC revisions may migrate this rule into a dedicated evidence/attestation profile document.

Any base64-encoded bytes appearing in PIC-canonicalized contexts (e.g., Ed25519 signatures) MUST use the standard Base64 alphabet per [RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648#section-4) with `=` padding. The URL-safe variant (RFC 4648 §5) is non-conformant. Unpadded variants are non-conformant.

### 7.11 File Hash Rules *(PIC protocol constraint adjacent to canonicalization)*

> **Scope note:** This is not a JSON canonicalization rule. It governs how PIC hashes file bytes for `hash`-type evidence in `file://` references. It is colocated here in v0.8.0 because it is a byte-stability rule in the same family as the canonicalization rules. Future PIC revisions may migrate this rule into a dedicated evidence/attestation profile document.

When PIC computes a SHA-256 hash over file bytes (e.g., for `hash`-type evidence in `file://` references), the hash input MUST be the file bytes exactly as read in binary mode. No newline normalization, no BOM stripping, no transcoding. Files with a UTF-8 BOM include those BOM bytes in the hash input.

### 7.12 Booleans and Null

- `true` and `false` are serialized as the literal strings `true` and `false`.
- `null` is serialized as the literal string `null`.

No alternate representations are permitted.

### 7.13 Lone Surrogates

Strings containing lone surrogate code points (unpaired UTF-16 surrogate halves in the range U+D800..U+DFFF) are non-conformant input. Such inputs cannot be represented as well-formed UTF-8 (RFC 3629) and have no valid canonical byte sequence under RFC 8785.

Implementations MUST reject such input **before emitting any canonical bytes**, rather than attempting normalization, repair, replacement with U+FFFD, or emission of ill-formed UTF-8.

When a PIC verifier encounters such input inside a proposal, it MUST surface the rejection as `PIC_SCHEMA_INVALID` per [`spec-core.md` §9.1](spec-core.md#91-error-code-stability): the failure belongs to PIC's schema-layer boundary because the proposal contains a non-conformant string value, not a semantic post-schema contract violation. JSON Schema draft-07 cannot cleanly express this constraint, so PIC v0.9.0a1 pins it via a pipeline-layer guard that scans all proposal string values and object keys after JSON Schema validation and before ActionProposal construction. Conformance vector `canon-010-lone-surrogate-rejection` pins the canonicalizer-level rejection contract in parallel.

This is a classic cross-language trap, particularly for JavaScript and Python host strings that may carry lone surrogates through their string types without raising errors at the host layer.

---

## 8. Digest Byte Rules

PIC defines four digest computations in the attestation object. Each has a precise canonical input.

### 8.1 `args_digest`

```
args_digest = SHA-256( canonicalize(action.args) )
```

Where `canonicalize` is PIC Canonical JSON v1 (this document) applied to the `action.args` value exactly as it appears in the Action Proposal. The digest is the 64-character lowercase hex encoding of the SHA-256 output.

### 8.2 `claims_digest`

```
claims_digest = SHA-256( canonicalize(claims) )
```

Where `claims` is the full `claims` array from the Action Proposal, with array element order preserved as in the proposal. The digest is the 64-character lowercase hex encoding of the SHA-256 output.

### 8.3 `intent_digest`

```
intent_digest = SHA-256( UTF-8 bytes of intent string )
```

Unlike `args_digest` and `claims_digest`, `intent_digest` is computed directly over the UTF-8 byte representation of the `intent` string value without JSON wrapping, escaping, or canonicalization. This special case exists because the intent is a scalar string — there is no JSON structure to canonicalize, and wrapping a bare string in JSON serialization would introduce quote and escape characters that add fragility without improving byte stability. The digest is the 64-character lowercase hex encoding of the SHA-256 output.

### 8.4 Attestation Object Serialization

For attestation-object signatures, the bytes that are signed are the canonical bytes of the attestation object JSON:

```
signed_bytes = canonicalize(attestation_object)
```

The signature is computed over these bytes exactly. If the attestation object is transported inside an evidence payload string, the signer/verifier MUST parse the payload string's contents as JSON, treat the resulting value as the attestation object, and then compute:

```
signed_bytes = canonicalize(attestation_object)
```

They MUST NOT sign the surrounding evidence entry, the transport-level JSON string encoding, or the raw payload text without canonicalization.

This rule applies to attestation-object signatures identified by `attestation_version` in the payload. Legacy payload-string signatures remain governed by their legacy byte semantics; see §11.

See [PIC Attestation Object v1](attestation-object-draft.md) for the attestation object structure.

---

## 9. Worked Examples

### 9.1 Basic object — key ordering

Input:

```json
{"b": 2, "a": 1}
```

Canonical bytes (UTF-8):

```
{"a":1,"b":2}
```

Canonical bytes (hex):

```
7b2261223a312c2262223a327d
```

SHA-256 of canonical bytes:

```
43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777
```

### 9.2 Nested object with Unicode key

Input:

```json
{"z": 1, "α": 2, "a": 3}
```

Canonical bytes (UTF-8):

```
{"a":3,"z":1,"α":2}
```

(In this example, `α` (U+03B1) sorts after `z` (U+007A); this ordering is consistent with RFC 8785's UTF-16 code unit ordering rule.)

### 9.3 Array preserved, keys sorted

Input:

```json
{"items": [3, 1, 2], "meta": {"b": 1, "a": 2}}
```

Canonical bytes (UTF-8):

```
{"items":[3,1,2],"meta":{"a":2,"b":1}}
```

(Array order `[3, 1, 2]` is preserved. Object keys `a`/`b` are sorted.)

### 9.4 Attestation object example

Input:

```json
{
  "attestation_version": "PIC-ATT/1.0",
  "tool": "payments_send",
  "args_digest": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
  "impact": "money",
  "intent_digest": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
  "provenance_ids": ["invoice_123"],
  "claims_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "issued_at": "2026-04-18T12:00:00Z"
}
```

Canonical bytes (UTF-8):

```
{"args_digest":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2","attestation_version":"PIC-ATT/1.0","claims_digest":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","impact":"money","intent_digest":"7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069","issued_at":"2026-04-18T12:00:00Z","provenance_ids":["invoice_123"],"tool":"payments_send"}
```

Full byte-exact output and SHA-256 are in `conformance/canonicalization/004_attestation_object_example.json`.

---

## 10. Test Vectors

The conformance test vectors for PIC Canonical JSON v1 live at:

```
conformance/canonicalization/
```

Each vector is a JSON file with the structure:

```json
{
  "description": "Human-readable summary of what this vector tests",
  "input": "<any valid JSON value — object, array, string, number, boolean, or null>",
  "expected_canonical_bytes_hex": "7b22...",
  "expected_sha256_hex": "a1b2c3..."
}
```

The `input` field contains the JSON value itself, not a JSON-encoded string, unless a future raw-text vector format explicitly says otherwise. In concrete vectors, replace the placeholder with the actual JSON value — e.g., `"input": {"b": 2, "a": 1}` for an object vector, `"input": [3, 1, 2]` for an array vector, `"input": "hello"` for a top-level string vector, `"input": 42` for a number vector, `"input": true` for a boolean vector, or `"input": null` for a null vector.

Expected output is stored as hex-encoded bytes (not a quoted string) to avoid meta-canonicalization issues in the vector file itself.

**Seeding discipline:** At least a subset of vectors MUST be seeded from external sources — RFC 8785 appendix examples, hand-verified byte outputs, or cross-checks against an independent JCS implementation. Vectors generated solely by the PIC reference implementation prove self-consistency, not spec conformance. The externally-seeded subset provides the independent reference.

Implementations claiming PIC Canonical JSON v1 conformance MUST pass every vector under `conformance/canonicalization/`.

### 10.1 Portable vectors vs. implementation-local rejection tests

PIC Canonical JSON v1 uses two categories of test material, plus a future third category for raw-text negative cases. Keeping these separate prevents a common trap where cross-language runners assume a single vector format covers every invalid-input case the specification mentions.

**Portable conformance vectors.** These use valid JSON inputs and assert byte-exact canonical output and SHA-256 digests. They are suitable for cross-language runners and live under `conformance/canonicalization/`. Every conformant implementation MUST pass all of these.

**Implementation-local rejection tests.** Certain invalid inputs are not representable as portable JSON values and therefore MUST be tested in implementation unit tests rather than in shared JSON vectors. This includes:

- Host-language structures with non-string keys (e.g., Python dicts with integer keys, Go maps with non-string key types).
- Circular references among host-language objects.
- Non-finite numeric values (`NaN`, `+Infinity`, `-Infinity`) introduced outside a strict JSON parser.
- Host-language types with no natural JSON mapping (e.g., Python `set`, `complex`, user-defined classes without a serializer).
- Lone surrogate cases introduced through host-language strings (e.g., a Python `str` or JavaScript string carrying an unpaired U+D800..U+DFFF code unit). Per §7.13, implementations MUST reject these rather than attempting repair.

Each implementation is responsible for asserting that its canonicalizer raises a canonicalization error on these inputs. The spec MUST NOT rely on shared vectors for this class of failure, because the inputs themselves cannot be represented in a portable vector.

**Raw JSON text negative cases (future category).** Some non-conformant inputs are only detectable at the raw JSON text layer before parsing — most language parsers silently collapse, repair, or reject them before the value reaches any canonicalizer. If PIC later adds shared negative vectors for such cases, they MUST use a raw-text vector format (input stored as a JSON-escaped string, not as a parsed value) rather than the parsed-input form used for canonicalization success vectors. Examples of inputs that belong in this future category include:

- Duplicate object member names (most parsers collapse duplicates silently).
- Escaped lone surrogates in raw JSON text (e.g., `"\uD800"` appearing literally in JSON source), as distinct from lone surrogates introduced through host-language strings covered above.

PIC-CJSON/1.0 does not define raw-JSON-text negative vectors in v0.8.0. In v0.9.0a1 the runner gained a `canonical_reject` verdict and the first negative canonicalization vector, `canon-010-lone-surrogate-rejection`, pins rejection of a parsed string value containing a lone surrogate. The vector source uses the JSON escape `\uD800` to construct that value. Broader raw-JSON-text negative cases, such as duplicate object member names, malformed UTF-8 byte streams, and parser-level rejection behavior before a value reaches the canonicalizer, remain deferred to a future revision.

---

## 11. Backward Compatibility

PIC-CJSON/1.0 is introduced in PIC v0.8.0 as a new capability. It does not retroactively change the bytes signed by previously-shipped PIC versions:

- Legacy payload-string signatures (v0 mode, used in PIC v0.4 through v0.7.5) remain valid. They are identified by the absence of `attestation_version` in the evidence payload and continue to be accepted by verifiers through at least PIC/1.0.
- New attestation-object signatures (identified by `attestation_version: "PIC-ATT/1.0"` in the evidence payload) are computed over PIC-CJSON/1.0 canonical bytes as defined in §8.4.

See [`docs/attestation-object-draft.md`](attestation-object-draft.md) for the attestation object structure and [`docs/migration-trust-sanitization.md`](migration-trust-sanitization.md) for migration guidance.

---

## 12. Conformance Claims

PIC Canonical JSON v1 conformance covers §7.1–§7.9, §7.12–§7.13, and the canonical byte and digest rules in §8.1–§8.4. Sections §7.10 (Base64 Variant) and §7.11 (File Hash Rules) are PIC protocol constraints adjacent to canonicalization; they are enforced by PIC evidence/attestation behavior and should be covered by future evidence-profile conformance, not by canonicalization-only conformance. Similarly, the transport/extraction rule in §8.4 for attestation objects carried inside evidence payload strings is an attestation/evidence behavior and should be covered by future evidence-profile conformance, not by canonicalization-only conformance.

An implementation MAY claim "PIC Canonical JSON v1 conformance" if and only if:

1. It implements RFC 8785 serialization semantics for the supported input surface, plus the PIC canonicalization rules in §7.1–§7.9 and §7.12–§7.13 of this document.
2. It computes digests per §8.1–§8.3 and canonical attestation-object bytes per §8.4.
3. It passes every vector under `conformance/canonicalization/`, including externally-seeded vectors.

The reference implementation at `sdk-python/pic_standard/canonical.py` is one implementation. Protocol correctness is established by this specification plus the conformance vectors — not by any implementation alone. This specification is normative; the conformance vectors are executable artifacts derived from this specification and externally-cited normative sources (RFC 8785, RFC 4648, RFC 8259). If the reference implementation and this specification disagree, the specification wins and the implementation is a bug. If this specification and an externally-sourced vector disagree, the discrepancy MUST be resolved against the cited normative source before conformance is claimed, and either the specification text or the vector MUST be corrected.

---

## 13. Security Considerations

- **Canonicalization is a prerequisite for signature stability, not itself a security primitive.** A signature over canonical bytes is only as strong as the signing algorithm (Ed25519) and key management (see [PIC Keyring Guide](keyring.md)).
- **Reject invalid input early.** Implementations MUST reject NaN/Infinity/non-string-keyed dicts/non-serializable types/lone surrogates at canonicalization time, not silently produce partial output.
- **Do not treat "mostly correct" canonicalization as secure.** An implementation that produces different bytes from another compliant implementation on the same input is broken; signatures computed under it MUST NOT be trusted as interoperable.
- **Duplicate keys are non-conformant input.** Producers that emit duplicate keys create ambiguity that signature verification cannot detect. The burden is on producers to emit conformant JSON.

---

## 14. References

### Normative

- RFC 2119 — Key words for use in RFCs to Indicate Requirement Levels
- RFC 3629 — UTF-8, a transformation format of ISO 10646
- RFC 4648 — The Base16, Base32, and Base64 Data Encodings
- RFC 8174 — Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words
- RFC 8259 — The JavaScript Object Notation (JSON) Data Interchange Format
- RFC 8785 — JSON Canonicalization Scheme (JCS)

### Informative

- [PIC Attestation Object v1 Draft](attestation-object-draft.md)
- [PIC Migration Guide: Trust Sanitization](migration-trust-sanitization.md)
- [PIC Roadmap](../ROADMAP.md)
