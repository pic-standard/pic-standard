# Migrating to Verifier-Derived Trust

> **Applies to:** PIC v0.7.5 → v1.0 migration path
>
> This guide explains the trust model change introduced in v0.7.5 and how to
> prepare your deployment for PIC/1.0, where trust sanitization becomes the
> only conformant mode.

---

## What Is Changing

In PIC v0.7.x and earlier, the verification pipeline ultimately treats inbound `provenance[].trust` as authoritative for high-impact authorization unless evidence verification upgrades or challenges it. If a proposal declares `trust: "trusted"`, the verifier treats that provenance entry as trusted for the purpose of high-impact authorization — even when no evidence verification has occurred.

This creates a **config hazard**: a deployment that does not enable evidence verification (the current default) will accept self-asserted trust for high-impact actions like `money`, `privacy`, and `irreversible`. In that configuration, prompt injection or a misconfigured adapter can declare `trust: "trusted"` and bypass the security boundary.

Starting in v0.8.0, PIC introduces a migration path to **verifier-derived trust**, where trust is never accepted from the proposal — it is computed solely from successful evidence verification.

This migration changes verifier behavior and integration defaults over time; it does not change the PIC proposal wire format in v0.8.0. Existing proposals continue to parse and validate against the same JSON Schema.

---

## Timeline

| Version | Behavior |
|---------|----------|
| **v0.7.x** | `provenance[].trust` accepted at face value. No warnings. |
| **v0.8.0** | `PICTrustFutureWarning` emitted when self-asserted `trust="trusted"` is present and effective evidence verification will not run. New `strict_trust` pipeline option available (default `False`). Wire format unchanged. |
| **v0.8.1** | `PICSemiTrustedDeprecationWarning` emitted when `trust="semi_trusted"` is observed. The value is normalized to `"untrusted"` at the canonical model-validation boundary (the `Provenance.trust` pydantic field validator), in all modes — including strict-trust mode. Schema enum unchanged in v0.8.1. Example files migrated off `semi_trusted` (the project's own surface is clean). |
| **v0.8.3** | Hash-evidence semantics tightened. Hash verification produces `hash_verified` (content-integrity of the referenced file bytes) only and MUST NOT upgrade `provenance[].trust` from `"untrusted"` to `"trusted"` by itself. Signature evidence continues to upgrade trust via the configured keyring. Under `strict_trust=True`, high-impact proposals that previously reached `trusted` via hash-only evidence now block with `PIC_VERIFIER_FAILED`. Reported in issue #133. |
| **v0.9.0a1** | `"semi_trusted"` is **removed** from the trust enum. Proposals carrying `provenance[].trust = "semi_trusted"` are rejected at JSON Schema validation with `PIC_SCHEMA_INVALID`. The `PICSemiTrustedDeprecationWarning` class and the v0.8.1 `Provenance.trust` normalization validator are deleted; the `_normalize_provenance_entries_via_model_validator` pipeline bridge helper is removed. The only conformant trust values are `"trusted"` and `"untrusted"`. |
| **v1.0** | `strict_trust=True` is the default and the only conformant mode. Non-sanitizing mode is explicitly **legacy and non-conformant** — implementations that disable trust sanitization MUST NOT claim PIC/1.0 conformance. |

---

## The Warning

When you upgrade to v0.8.0, you may see this warning:

```
PICTrustFutureWarning: PIC deprecation: proposal contains provenance with
trust='trusted' but effective evidence verification will not run for this
proposal. In PIC/1.0, trust will be verifier-derived only — self-asserted
trust will be sanitized to 'untrusted'. To migrate: provide verifiable
evidence (hash or signature) and enable verify_evidence=True where evidence
will actually be enforced, or opt in early with strict_trust=True. See
docs/migration-trust-sanitization.md for details.
```

This warning fires when **all three** of these conditions are true:

1. `strict_trust=False` (the current default)
2. At least one provenance entry has `trust="trusted"`
3. Effective evidence verification will not run for this proposal

**Important:** The warning is based on whether evidence verification will *actually execute*, not just whether `verify_evidence=True` is set. Evidence verification only runs when both `verify_evidence=True` AND either evidence entries are present in the proposal or policy requires evidence for the resolved impact. Without either condition, the evidence step is skipped and inbound trust is still accepted at face value.

---

## Migration Steps

### Step 1: Audit

Identify deployments that rely on self-asserted trust without evidence:

- Search for proposals where `provenance[].trust == "trusted"` but no `evidence` array is present.
- Check pipeline/guard configurations for `verify_evidence=False` (the default).
- Review policy configurations: does `require_evidence_for_impacts` include the impacts your tools use?

### Step 2: Add Evidence

For each high-impact tool flow that currently relies on self-asserted trust, add verifiable evidence:

> **Note (v0.8.3):** hash evidence and signature evidence play different roles under the tightened trust semantics. Hash evidence proves content-integrity of the referenced bytes — it establishes that the bytes match the supplied digest — but does NOT, by itself, upgrade `provenance[].trust` to `"trusted"` for high-impact authorization. Signature evidence, anchored in the configured keyring, is what upgrades trust. If your high-impact flow needs to reach `trusted` provenance under `strict_trust=True`, you need signature evidence. See [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules).

**Hash evidence** (simplest — proves a file artifact exists and is unmodified):

```json
{
  "id": "invoice_evidence",
  "type": "hash",
  "ref": "file://artifacts/invoice_123.pdf",
  "sha256": "a1b2c3d4..."
}
```

**Signature evidence** (strongest — proves a trusted signer attested the payload):

```json
{
  "id": "invoice_evidence",
  "type": "sig",
  "ref": "inline:invoice-attestation",
  "payload": "invoice_123 approved by finance team",
  "alg": "ed25519",
  "signature": "<base64 signature>",
  "key_id": "org:finance-signer"
}
```

See [docs/evidence.md](evidence.md) for the full evidence guide.

### Step 3: Enable Verification

Update your pipeline or guard configuration to enable evidence verification:

**Pipeline (direct):**

```python
from pic_standard.pipeline import PipelineOptions, verify_proposal

result = verify_proposal(proposal, options=PipelineOptions(
    verify_evidence=True,
    # ... other options
))
```

**MCP guard:**

```python
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool

guarded = guard_mcp_tool(
    "payments_send", tool_fn,
    policy=policy,
    verify_evidence=True,
)
```

**LangGraph:**

```python
from pic_standard.integrations import PICToolNode

node = PICToolNode(
    tools=[payments_send],
    verify_evidence=True,
)
```

**Important caveat:** Enabling `verify_evidence=True` alone is not sufficient unless verifiable evidence entries (hash or signature) are provided in the proposal or policy requires evidence for the action's impact. Without either condition, the evidence verification step does not run, and inbound trust is still accepted at face value. For immediate v1.0-style behavior, use `strict_trust=True` (see Step 4).

**Note (v0.8.3):** in `strict_trust=True` mode, a high-impact proposal that carries only hash evidence will BLOCK, because hash verification produces `hash_verified` (content-integrity) only and does not upgrade trust. To keep such flows working under `strict_trust=True`, attach signature evidence signed by a trusted signer.

### Step 4: Opt In Early

To test v1.0 behavior now, enable `strict_trust=True`:

```python
# Pipeline
result = verify_proposal(proposal, options=PipelineOptions(
    strict_trust=True,
    verify_evidence=True,
))

# MCP guard
guarded = guard_mcp_tool(
    "payments_send", tool_fn,
    policy=policy,
    strict_trust=True,
    verify_evidence=True,
)

# LangGraph
node = PICToolNode(
    tools=[payments_send],
    strict_trust=True,
    verify_evidence=True,
)
```

When `strict_trust=True`:

- All inbound `provenance[].trust` values are sanitized to `"untrusted"` before verification.
- Evidence verification + trust upgrade is the only path to `"trusted"` status.
- High-impact proposals without valid evidence will be blocked.
- The `PICTrustFutureWarning` is not emitted (strict mode acts, it does not warn).

---

## FAQ

**Q: Will my existing low-impact tools break?**

No. Trust sanitization only affects the allow/block decision for high-impact actions (`money`, `privacy`, `irreversible`). Low-impact actions (`read`, `write`, `compute`, `external`) do not require trusted provenance, so sanitization has no effect on them.

**Q: Can I suppress the warning without migrating?**

You can filter `PICTrustFutureWarning` using Python's `warnings` module, but this only hides the symptom. The underlying config hazard remains, and your deployment will break when v1.0 makes strict trust the only conformant mode.

**Q: What if I use `verify_evidence=True` but my proposals have no evidence?**

The warning will still fire, because evidence verification will not actually run without evidence entries or a policy requirement. This is by design — `verify_evidence=True` is necessary but not sufficient.

**Q: What happens to proposals with `trust: "semi_trusted"`?**

**Starting in v0.9.0a1:** `"semi_trusted"` is removed from the trust enum. Proposals carrying `provenance[].trust = "semi_trusted"` fail JSON Schema validation with `PIC_SCHEMA_INVALID`. The `PICSemiTrustedDeprecationWarning` class no longer exists, and the v0.8.1 model-validation-boundary normalization has been removed. The only conformant trust values are `"trusted"` and `"untrusted"`. Under strict mode, high-impact authorization cannot rely on self-asserted `"trusted"` labels; trust must come from verifier-controlled context or successful evidence verification.

**Historical context:**
- **v0.7.x through v0.8.0:** `semi_trusted` was accepted at face value in non-strict mode and silently sanitized to `"untrusted"` in `strict_trust=True` mode. No warning targeted this value.
- **v0.8.1 through v0.8.3:** deprecation window. `PICSemiTrustedDeprecationWarning` fired at `Provenance` construction time and normalized the value to `"untrusted"` in all modes; the schema still accepted the string. Example files were migrated off `semi_trusted` at v0.8.1.
- **v0.9.0a1:** removed from the schema, code, and public exports.

**Migration path for any producer still emitting `trust: "semi_trusted"`:**
1. Replace `trust: "semi_trusted"` with `trust: "untrusted"`. This is forward-compatible and always correct under the trust axiom (v0.7.5).
2. If a high-impact flow needs to reach `"trusted"` under strict mode, attach signature evidence (Ed25519) signed by a trusted signer. Hash evidence alone establishes content-integrity only; see the v0.8.3 FAQ below.
3. Do not rely on producer-declared trust labels for authorization. Only verifier-controlled context or successful evidence verification can establish trusted status.

**Q: What if my proposal relies on hash evidence to upgrade untrusted provenance to trusted?**

**v0.8.3 (this release):** Hash evidence produces `hash_verified` (content-integrity of the referenced file bytes) only. It MUST NOT upgrade `provenance[].trust` from `"untrusted"` to `"trusted"` by itself, because a proposal author may supply both the referenced bytes and the digest — integrity is not authority. Under `strict_trust=True`, a high-impact proposal that previously reached `trusted` via hash-only evidence now blocks with `PIC_VERIFIER_FAILED`. Signature evidence (Ed25519, anchored in the configured keyring) continues to upgrade trust, unchanged.

**Pre-v0.8.3 baseline (v0.8.2):** Any successful hash verification added the evidence ID to `verified_ids`, which the pipeline applied to `provenance[].trust`, upgrading `untrusted` → `trusted`. This applied identically to hash and signature evidence, treating both as authority-bearing. Reported in issue #133 as unsafe: a proposal author supplying both the referenced bytes and the digest could self-authorize a high-impact action via integrity alone.

**Later releases:** A future authority primitive (tracked as `OQ-EVIDENCE-005` in [`spec-evidence.md`](spec-evidence.md) Appendix C) may admit specific hash-verified entries into trust upgrade when the digest is anchored to an independent authority — for example, a verifier-owned signed manifest or a protected-namespace policy. Until that primitive is defined, hash evidence contributes content-integrity only.

**Operator-visible interaction with `allow_sig_evidence`:** Deployments with signature evidence disabled and `strict_trust=True` will now block previously-passing hash-only high-impact proposals. This is the correct new behavior under the tightened semantics. There is no v0.8.3-conformant flag that makes hash-only evidence authority-bearing.

**Migration path for producers previously relying on hash-only trust upgrade for high-impact actions:**
1. Identify high-impact proposals that currently reach `trusted` only via hash evidence. Search for hash-only evidence entries paired with `strict_trust=True` and high-impact actions (`money`, `privacy`, `irreversible`).
2. Replace hash-only evidence with signature evidence (Ed25519) signed by a trusted signer for those flows. See [`keyring.md`](keyring.md).
3. Keep the hash evidence entry alongside signature evidence if you want content-integrity auditing — the hash still verifies and appears in `hash_verified_ids`, it just does not drive trust upgrade.
4. If a high-impact flow cannot obtain a signature yet, either (a) accept the BLOCK under strict mode until an authority primitive lands (see `OQ-EVIDENCE-005`), or (b) run outside the strict-trust / v1-style posture temporarily and document the risk. Do not claim that hash evidence upgraded provenance trust.

See the [PIC Roadmap](../ROADMAP.md) for the full trajectory and rationale.

---

## References

- [PIC Evidence Guide](evidence.md) — how to add hash and signature evidence
- [PIC Keyring Guide](keyring.md) — managing trusted signing keys
- [Attestation Object Draft](attestation-object-draft.md) — the future signing target (community feedback welcome)
