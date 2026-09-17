# Trust Sanitization: Secure Default and Legacy Compatibility

> **Applies to:** PIC v0.7.5 through current releases (v0.9.0a2+).
>
> This guide explains the trust model, the v0.9.0a2 secure-default flip,
> and how to run pre-v0.9.0a2 producers under explicit legacy
> compatibility mode when needed.

---

## 1. What Changed

Trust sanitization has been callable since v0.7.5 via the `strict_trust`
pipeline option. As of v0.9.0a2, `strict_trust=True` is the **secure
default** in `PipelineOptions`. In practice this means:

- New callers who do not pass `strict_trust` inherit the secure default.
  Inbound `provenance[].trust` values are sanitized to `"untrusted"`
  before the causal-contract check; only authority-bearing evidence
  verification (currently signature evidence) can upgrade a matching
  provenance entry back to `"trusted"`.
- Callers who explicitly pass `strict_trust=False` opt into legacy
  compatibility mode. This remains callable. Constructing options with
  `strict_trust=False` emits `PICLegacyTrustModeWarning` at
  `PipelineOptions` construction. Removal of legacy mode is **not
  scheduled in the v0.9.x series**.
- The v0.9.0a2 secure-default flip does not change the wire format.
  Proposals that were schema-valid under v0.9.0a1 remain schema-valid
  under v0.9.0a2; allow/block behavior may still change because
  self-asserted trust is sanitized by default.

---

## 2. Why This Matters

In earlier releases the default was legacy mode: inbound
`trust="trusted"` was accepted at face value unless evidence
verification actually ran. That created a config hazard for high-impact
actions like `money`, `privacy`, and `irreversible`: a deployment that
did not enable evidence verification would accept self-asserted trust,
so a prompt injection or misconfigured adapter could declare
`trust: "trusted"` and bypass the security boundary.

The v0.9.0a2 secure default closes that hazard by default. Deployments
that had not yet enabled evidence verification are now protected;
deployments that explicitly need the old behavior for compatibility
with pre-v0.9.0a2 producers can opt back in, but they must do so
explicitly and get an audit-visible warning at construction time.

### Timeline

| Version | Behavior |
|---------|----------|
| v0.7.x | `provenance[].trust` accepted at face value. No warnings. |
| v0.8.0 | `PICTrustFutureWarning` emitted when self-asserted `trust="trusted"` is present and effective evidence verification will not run. New `strict_trust` pipeline option available (default `False`). Wire format unchanged. |
| v0.8.1 | `PICSemiTrustedDeprecationWarning` emitted when `trust="semi_trusted"` is observed. The value is normalized to `"untrusted"` at the canonical model-validation boundary. |
| v0.8.3 | Hash-evidence semantics tightened. Hash verification produces `hash_verified` (content-integrity of the referenced file bytes) only and MUST NOT upgrade `provenance[].trust` from `"untrusted"` to `"trusted"` by itself. Signature evidence continues to upgrade trust via the configured keyring. Reported in issue #133. |
| v0.9.0a1 | `"semi_trusted"` is removed from the trust enum. Proposals carrying it are rejected at JSON Schema validation with `PIC_SCHEMA_INVALID`. The only conformant trust values are `"trusted"` and `"untrusted"`. |
| **v0.9.0a2** | **Secure default flipped.** `strict_trust=True` becomes the default in `PipelineOptions`. `strict_trust=False` remains callable as explicit legacy compatibility opt-in and emits `PICLegacyTrustModeWarning` at construction. |
| v1.0 (planned) | A future major release may consider removing legacy trust mode (`strict_trust=False`), but removal is not scheduled in the v0.9.x series. |

---

## 3. Warning Model

Two warnings can fire around the trust-sanitization path. They serve
different purposes and can co-fire in a single verification.

### `PICLegacyTrustModeWarning`

Fires at `PipelineOptions(strict_trust=False)` construction time. The
message is:

```
strict_trust=False enables legacy trust behavior. The secure default is
strict_trust=True.
```

This warning marks each explicit legacy opt-in. It does not imply the
proposal is unsafe; it marks that the caller has opted out of the
secure default. Every construction of
`PipelineOptions(strict_trust=False)` emits this warning, regardless of
the proposal being processed.

### `PICTrustFutureWarning`

Fires during `verify_proposal(...)` when all three of these conditions
are true:

1. `strict_trust=False` (explicit legacy opt-in)
2. At least one provenance entry has `trust="trusted"`
3. Effective evidence verification will not run for this proposal

The message includes migration guidance:

```
PIC deprecation: proposal contains provenance with trust='trusted' but
effective evidence verification will not run for this proposal. Under
the secure default (strict_trust=True), self-asserted trust is
sanitized to 'untrusted' and only authority-bearing evidence can
upgrade it. To fix: provide authority-bearing signature evidence and
enable verify_evidence=True where evidence will actually be enforced,
or drop the explicit strict_trust=False opt-in to inherit the secure
default. Hash evidence establishes content integrity only and does not
upgrade trust by itself. See docs/migration-trust-sanitization.md for
details.
```

Effective evidence verification runs when `verify_evidence=True` AND
either evidence entries are present in the proposal or policy requires
evidence for the resolved impact. Without either condition, the
evidence step is skipped and inbound trust is still accepted at face
value under legacy mode.

Neither warning fires under the secure default (`strict_trust=True`):
sanitization always runs, and the "self-asserted trust silently
accepted" migration signal does not apply.

---

## 4. Migration Steps

Under the v0.9.0a2 secure default, no migration is required for new
callers. Callers that explicitly pass `strict_trust=False` for legacy
compatibility, and callers relying on the pre-v0.9.0a2 default, should
follow the steps below.

### Step 1: Audit

Identify deployments that rely on self-asserted trust without evidence:

- Search for proposals where `provenance[].trust == "trusted"` but no
  `evidence` array is present.
- Check pipeline/guard configurations for `verify_evidence=False`.
- Review policy configurations: does `require_evidence_for_impacts`
  include the impacts your tools use?

### Step 2: Add Evidence

For each high-impact tool flow that currently relies on self-asserted
trust, add authority-bearing evidence.

> **Hash evidence establishes content integrity only, not authority.**
> Hash evidence proves the referenced bytes match the supplied digest,
> but does NOT upgrade `provenance[].trust` to `"trusted"` for
> high-impact authorization. Signature evidence, anchored in the
> configured keyring, is what upgrades trust. If your high-impact flow
> needs to reach `trusted` provenance, you need signature evidence. See
> [`spec-evidence.md §8`](spec-evidence.md#8-trust-upgrade-rules).

**Signature evidence** (Ed25519, anchored in a trusted keyring):

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

**Hash evidence** (legitimate for content-integrity auditing, but does
not on its own satisfy high-impact authorization):

```json
{
  "id": "invoice_hash",
  "type": "hash",
  "ref": "file://artifacts/invoice_123.pdf",
  "sha256": "a1b2c3d4..."
}
```

See [docs/evidence.md](evidence.md) for the full evidence guide.

### Step 3: Enable Verification

Update your pipeline or guard configuration to enable evidence
verification. Under the secure default, `strict_trust` no longer needs
to be set explicitly.

**Pipeline (direct):**

```python
from pic_standard.pipeline import PipelineOptions, verify_proposal

result = verify_proposal(
    proposal,
    options=PipelineOptions(
        verify_evidence=True,
        # strict_trust defaults to True (secure default).
    ),
)
```

**MCP guard:**

```python
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool

guarded = guard_mcp_tool(
    "payments_send",
    tool_fn,
    policy=policy,
    verify_evidence=True,
    # strict_trust defaults to True (secure default).
)
```

**LangGraph:**

```python
from pic_standard.integrations import PICToolNode

node = PICToolNode(
    tools=[payments_send],
    verify_evidence=True,
    # strict_trust defaults to True (secure default).
)
```

**Important caveat:** enabling `verify_evidence=True` alone is not
sufficient unless evidence entries are provided in the proposal or
policy requires evidence for the action's impact. Without either
condition, the evidence verification step does not run.

Under the secure default, a high-impact proposal without
authority-bearing evidence blocks with `PIC_VERIFIER_FAILED`. Hash-only
evidence establishes content integrity but does not upgrade trust, so a
high-impact flow relying on hash-only evidence must attach signature
evidence to reach `trusted` provenance.

### Step 4: Drop the Explicit Legacy Opt-In

If a call site was previously constructing options with
`strict_trust=False`, remove that explicit argument so the secure
default takes effect:

```python
# Before (legacy mode, fires PICLegacyTrustModeWarning):
options = PipelineOptions(verify_evidence=True, strict_trust=False)

# After (secure default; no warning):
options = PipelineOptions(verify_evidence=True)
```

Any adapter that previously accepted a `strict_trust=False` parameter
default should drop the explicit `False` at construction sites too,
unless the adapter or call site is deliberately preserving legacy
behavior (see Section 5).

---

## 5. Legacy Compatibility Mode

Legacy mode remains callable for deployments that need to interoperate
with pre-v0.9.0a2 producers, or to preserve existing test/example flows
that rely on self-asserted trust. To opt in explicitly:

```python
options = PipelineOptions(strict_trust=False)
# -> emits PICLegacyTrustModeWarning at construction
```

When `strict_trust=False`:

- Inbound `provenance[].trust` values are NOT sanitized.
- Self-asserted `trust="trusted"` is accepted at face value for the
  causal-contract check.
- `PICLegacyTrustModeWarning` fires once per `PipelineOptions`
  construction.
- If the proposal contains self-asserted trusted provenance and
  effective evidence verification will not run, `PICTrustFutureWarning`
  also fires during `verify_proposal(...)`.

Legacy mode is not equally recommended alongside the secure default.
Legacy mode is a compatibility surface; the secure default is the
recommended posture for new code, production deployments, and CI.

Removal of legacy mode is not scheduled in the v0.9.x series. A future
major release may consider removing it (see the timeline row for v1.0);
that is a separate release decision.

---

## 6. FAQ

**Q: Will my existing low-impact tools break?**

No. Trust sanitization only affects the allow/block decision for
high-impact actions (`money`, `privacy`, `irreversible`). Low-impact
actions (`read`, `write`, `compute`, `external`) do not require trusted
provenance, so sanitization has no effect on them.

**Q: Can I suppress the warnings without migrating?**

You can filter both warnings using Python's `warnings` module, but that
only hides the symptom. The underlying config hazard remains, and the
secure default is the correct behavior for high-impact actions.

**Q: What if I use `verify_evidence=True` but my proposals have no evidence?**

Under the secure default (`strict_trust=True`), the sanitized trust
takes effect regardless of whether evidence actually runs; high-impact
proposals without valid authority-bearing evidence block. Under legacy
mode (`strict_trust=False`), `PICTrustFutureWarning` fires because
inbound trust is still accepted at face value even though the flag is
set.

**Q: What happens to proposals with `trust: "semi_trusted"`?**

Since v0.9.0a1, `"semi_trusted"` is removed from the schema. Proposals
carrying it fail JSON Schema validation with `PIC_SCHEMA_INVALID`. The
only conformant trust values are `"trusted"` and `"untrusted"`.

Historical context:

- **v0.7.x through v0.8.0:** `semi_trusted` was accepted at face value
  in legacy mode and silently sanitized to `"untrusted"` in strict
  mode. No warning targeted this value.
- **v0.8.1 through v0.8.3:** deprecation window.
  `PICSemiTrustedDeprecationWarning` fired at `Provenance` construction
  and normalized the value to `"untrusted"` in all modes; the schema
  still accepted the string.
- **v0.9.0a1:** removed from schema, code, and public exports.

Migration path for any producer still emitting `trust: "semi_trusted"`:

1. Replace `trust: "semi_trusted"` with `trust: "untrusted"`. This is
   forward-compatible and always correct under the trust axiom.
2. If a high-impact flow needs to reach `"trusted"`, attach signature
   evidence (Ed25519) signed by a trusted signer.
3. Do not rely on producer-declared trust labels for authorization.

**Q: What if my proposal relies on hash evidence to upgrade untrusted provenance to trusted?**

Since v0.8.3, hash evidence produces `hash_verified` (content-integrity
of the referenced file bytes) only. It MUST NOT upgrade
`provenance[].trust` from `"untrusted"` to `"trusted"` by itself,
because a proposal author may supply both the referenced bytes and the
digest, so integrity does not imply authority. Under the secure default
(`strict_trust=True`), a high-impact proposal that previously reached
`trusted` via hash-only evidence blocks with `PIC_VERIFIER_FAILED`.
Signature evidence (Ed25519, anchored in the configured keyring) is
what upgrades trust.

**Operator-visible interaction with `allow_sig_evidence`:** deployments
with signature evidence disabled will block previously-passing hash-only
high-impact proposals. This is the correct behavior under the tightened
semantics; there is no conformant flag that makes hash-only evidence
authority-bearing.

Migration path for producers previously relying on hash-only trust
upgrade for high-impact actions:

1. Identify high-impact proposals that reach `trusted` only via hash
   evidence.
2. Replace hash-only evidence with signature evidence (Ed25519) signed
   by a trusted signer for those flows. See [`keyring.md`](keyring.md).
3. Keep the hash evidence entry alongside signature evidence if you
   want content-integrity auditing; the hash still verifies and appears
   in `hash_verified_ids`, it just does not drive trust upgrade.
4. If a high-impact flow cannot obtain a signature yet, either (a)
   accept the block under the secure default until an authority
   primitive lands (see `OQ-EVIDENCE-005` in
   [`spec-evidence.md`](spec-evidence.md) Appendix C), or (b) run under
   explicit legacy mode (`strict_trust=False`) and document the risk.

**Q: Are `strict_trust=True` and legacy compatibility mode equally recommended?**

No. `strict_trust=True` is the secure default and the recommended mode
for new code, production deployments, and CI. Legacy mode is a
compatibility surface for existing integrations that have not yet
migrated; every explicit legacy opt-in emits
`PICLegacyTrustModeWarning` so operator tooling can surface remaining
legacy sites for follow-up work.

See the [PIC Roadmap](../ROADMAP.md) for the full trajectory and
rationale.

---

## References

- [PIC Evidence Guide](evidence.md): how to add hash and signature evidence
- [PIC Keyring Guide](keyring.md): managing trusted signing keys
- [Attestation Object Draft](attestation-object-draft.md): the future signing target (community feedback welcome)
