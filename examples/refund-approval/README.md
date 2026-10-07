# Signed refund approval: verification before dispatch

A standalone, reproducible PIC example. The merchant signs an exact
refund action under a canonical PIC-ATT/1.0 attestation; an integration
wrapper runs PIC verification and a documented workflow profile
(tool, impact, argument schema, expiry, merchant claim), then
dispatches the verified arguments to a harmless sink. A 22-case suite
exercises each binding and each pre-dispatch workflow check, with
tool-call accounting, two integrity meta-tests, and environment
enforcement against a pinned PIC commit.

Developed as PIC's standalone contribution to the bounded refund
workflow experiment discussed in
[aeoess/agent-governance-vocabulary#193](https://github.com/aeoess/agent-governance-vocabulary/issues/193).

No `pic_standard` core change. The pack consumes the shipped SDK as a
library.

The exact refund action is: `payment_id="pay_A"`, `amount_minor=4000`,
`currency="EUR"`, `impact="money"`, `tool="refund"`.

## Mapping

PIC's canonical attestation (PIC-ATT/1.0) binds a fixed set of
proposal fields via digests signed with the merchant key. PIC does not
interpret decision or approval identifiers; it protects the exact
bytes that carry them.

| Information                     | Proposed PIC representation                                                                                                       |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Refund operation                | `action.tool = "refund"`                                                                                                          |
| Exact refund arguments          | `action.args` containing `payment_id`, `amount_minor`, `currency`                                                                 |
| Impact                          | `impact = "money"`                                                                                                                |
| Merchant decision + approval    | `claims[0].text` is the canonicalized JSON of `{"approval_ref": "...", "decision_id": "..."}`; `claims[0].evidence` lists the merchant provenance id |
| Approval validity window        | Attestation `expires_at` (RFC 3339, timezone-aware)                                                                               |
| Signer identity                 | Dedicated merchant `key_id` entered into a fixture-local trusted keyring                                                          |

PIC binds the following over the signed payload: `tool`, `impact`,
`provenance_ids`, `args_digest`, `claims_digest`, `intent_digest`,
`expires_at` (when present). `claims_digest` protects the exact `text`
string in each claim. The inner JSON that `text` carries is
canonicalized before storage so reviewers can regenerate the fixtures
byte-stably. PIC's freshness check runs only when `expires_at` is
present; this workflow REQUIRES it to be present (see case 4e).

PIC does NOT:

* interpret `decision_id` or `approval_ref` — those are integration-layer identifiers;
* enforce that the attestation targets the right tool, the right impact, or well-shaped refund args — the integration layer enforces its own profile;
* convert a signed attestation into a dispatch decision — the dispatch step is the integration's responsibility (see case 6).

This is a proposed convention, not a new PIC field or capability.

### Interoperability contract vs diagnostic text

The expected-outcomes fixture asserts a mix of:

* **Structured** outcome fields: `outcome`, `error_code`, `reason`, `tool_calls`, `spy_received_verified_args`, `dispatch_args_recorded`, `dispatch_args_equal_verified`.
* **Diagnostic substrings** in `message` (`message_substr`).

Only the structured fields are a stable contract. The substring
matches are specific to `pic_standard` at the pinned commit — they
help the suite catch regressions in THIS example and should not be
relied on by independent implementations.

## PIC version

Pinned to `pic-standard/pic-standard` main at commit
`330fdd817ef81d43461ea1787939e0d1cc87d589`. The `v0.9.0` tag points
at a different commit (`f745b1cd`), although both declare package
version `0.9.0` in `pyproject.toml`. The runner reads the installed
revision from `direct_url.json` and fails closed if it does not match
the declared pin.

## Install and run

```
python -m venv .venv
. .venv/Scripts/activate            # Windows (POSIX: . .venv/bin/activate)
pip install -r requirements.txt -c constraints.txt
python test_cases.py
```

Expected exit code 0, overall PASS. The suite checks:

* **Coverage gates**: nonempty case set, no duplicate IDs, exact set agreement between builders and expectations. Any gap exits 2 before any case runs.
* **Environment enforcement**: reads `direct_url.json` from the installed `pic-standard` dist-info and compares the recorded `vcs_info.commit_id` to the declared pin. Mismatch exits 3. Unverified (no `vcs_info`, e.g. a non-VCS install) exits 4. Only an exact-pin install passes.
* **Per-case match**: structured outcome fields and (where asserted) `message_substr`.
* **Tool-call accounting**: exactly 1 call for allowed cases, 0 for every rejected case. The counter is independent of the integration wrapper's internal recorder.
* **Spy args assertion**: for every allowed case, the args the tool actually received must equal the verified `proposal.action.args`. A wrapper that reports allowed while dispatching different args fails this check.
* **Integrity meta-tests**: two deliberately-broken wrappers probe the invariants. (a) A wrapper that calls the tool before PIC verification — the counter must detect the extra call. (b) A wrapper that preserves its reported outcome but dispatches `pay_SMUGGLED` to the spy — the spy-args assertion must catch it.

Exit code policy:

| code | meaning |
|-----:|---------|
| 0    | PASS: cases match, integrity meta-tests OK, environment verified |
| 1    | FAIL: one or more cases mismatch |
| 2    | COVERAGE: builders ↔ expectations disagree before any case runs |
| 3    | MISMATCH: installed `pic-standard` commit differs from declared pin |
| 4    | UNVERIFIED: installed `pic-standard` revision is not VCS-pinned |
| 5    | INTEGRITY: an integrity meta-test probe failed |

To prove the coverage, environment and integrity gates themselves fire:

```
python self_check.py
```

Deliberately-broken configurations (empty cases, dropped expectation,
duplicate ID, fake wrong commit id, missing `direct_url.json`, local
`dir_info` install) each must exit with the specific code the policy
assigns. A final normal run must exit zero. Expected result:
`[self-check summary]` all OK, exit 0.

The pack also emits:

* `actual-results.json` — generated by the runner each run.
* `fixtures/signed-proposal-example.json` — static wire-form happy-path proposal for inspection without running the signer.

See `environment.txt` for Python version, resolved deps, and the
installed `pic-standard` revision.

## Cases

Six groups, 22 cases total. Mutations and workflow-profile violations
are reported separately within each group.

### 1. Valid approval (`1_valid`)

A single valid case: the merchant signs the exact refund action with
the test key, the fixture-local keyring trusts that key, PIC
verification succeeds, workflow profile checks pass, dispatch args
match verified `action.args`, the harmless sink is called exactly
once with those args.

### 2. Payment, amount, currency or tool changed without new evidence

Three post-signing mutations rejected by PIC digest binding:

* `2a` — `payment_id` → `pay_B`                          (PIC: `args_digest mismatch`)
* `2b` — `amount_minor` → `5000`                         (PIC: `args_digest mismatch`)
* `2c` — `currency` → `USD`                              (PIC: `args_digest mismatch`)

Two workflow-profile violations caught before dispatch (signatures valid):

* `2d` — signed canonical attestation for `tool="other_tool"`                 (integration: `workflow_profile_violation`)
* `2e` — signed canonical attestation for `impact="privacy"`                  (integration: `workflow_profile_violation`)

Three refund argument-schema violations caught before dispatch:

* `2f` — `amount_minor = True` (boolean subclass of int)                       (integration: `action_args_schema_violation`)
* `2g` — `amount_minor = 0`                                                    (integration: `action_args_schema_violation`)
* `2h` — `currency = 42` (number)                                              (integration: `action_args_schema_violation`)

### 3. decision_id or approval_ref changed, missing or malformed

Two post-signing mutations rejected by PIC digest binding:

* `3a` — inner `decision_id` → `decision-002`            (PIC: `claims_digest mismatch`)
* `3b` — inner `approval_ref` → `approval-999`           (PIC: `claims_digest mismatch`)

Three claim-schema violations caught before dispatch (signatures valid):

* `3c` — `claims[0].text` is a non-JSON string                                 (integration: `merchant_claim_schema_violation`)
* `3d` — `decision_id` is the empty string                                     (integration: `merchant_claim_schema_violation`)
* `3e` — `approval_ref` is a number                                            (integration: `merchant_claim_schema_violation`)

### 4. Missing, forged, expired, untrusted or expiry-absent evidence

* `4a` — `evidence: []` with `impact="money"`                                  (PIC: `PIC_EVIDENCE_REQUIRED`)
* `4b` — signature replaced with the deterministic 64-byte sequence `bytes(range(64))` (PIC: `signature invalid`)
* `4c` — `expires_at` in the past; signature verifies, freshness check fails   (PIC: `attestation expired`)
* `4d` — evidence `key_id = "unknown-signer-v1"` absent from the keyring       (PIC: `not present in trusted keyring`)
* `4e` — canonical attestation signed WITHOUT `expires_at`; PIC accepts (freshness only enforced when present), workflow check requires presence (integration: `workflow_profile_violation`)

### 5. Legacy evidence substituted for the required canonical attestation (`5_legacy_evidence_substituted`)

Merchant signs the plain string `"merchant-approval:<decision_id>:<approval_ref>"` with the test key and attaches it as signature evidence. PIC's reference verifier accepts it in legacy mode (bytes-to-verify = raw UTF-8 payload). The integration post-check rejects because PIC-ATT/1.0 canonical attestation is required.

### 6. Separate call arguments vs the verified proposal

* `6a` — control: dispatch args equal verified `action.args`; integration allows, records the dispatch, tool invoked once with the verified args.
* `6b` — mutation: dispatch args have a different `payment_id`; integration records the dispatch intent and rejects (`dispatch_args_mismatch`); tool not invoked.

**Pattern not guarantee.** The shipped `pic_standard.integrations.mcp_pic_guard`
does NOT today compare dispatch args against the verified proposal.
Making this a built-in guard check is a separate v0.9.x decision; see
`integration.py` for the pattern as implemented here.

## Trust configuration

* Fixture-local keyring: `keys/pic_keys.example.json` (named `.example.json` so the repo-root `.gitignore` rule for real keyrings — `pic_keys.json` — still applies), with `merchant-test-v1` bound to the public key from RFC 8032 §7.1 test vector 1.
* `PipelineOptions(verify_evidence=True, strict_trust=True, policy=PICPolicy(), key_resolver=StaticKeyRingResolver(...))`.
* `PICPolicy()` is explicit; without it `_required_evidence_impacts` returns an empty set and `impact="money"` would not require evidence. The default `PICPolicy` requires evidence for money/privacy/irreversible, which is what this workflow relies on.
* Private key is RFC 8032 §7.1 test vector 1, intentionally publicly known so reviewers can regenerate signatures. See `keys/README.md`.

## Layout

```
examples/refund-approval/
├── README.md                        # This file.
├── requirements.txt                 # Pinned pic-standard source.
├── constraints.txt                  # Transitive dependency lock.
├── environment.txt                  # Author's Python + resolved deps + installed revision.
├── sign_and_verify.py               # Build proposal + attestation + sign + verify.
├── integration.py                   # Post-verify workflow validation + dispatch.
├── test_cases.py                    # 22-case runner + tool-call counter + spy-args + integrity meta-tests.
├── self_check.py                    # Proves the runner's coverage, environment and integrity gates fire.
├── actual-results.json              # Generated by test_cases.py.
├── fixtures/
│   ├── merchant_decision.json       # Input: merchant decision + approval + action.
│   ├── expected-outcomes.json       # Independent expected results (never regenerated).
│   └── signed-proposal-example.json # Static wire-form happy-path signed proposal.
└── keys/
    ├── README.md                    # TEST-ONLY banner + key provenance.
    ├── merchant_test_private.hex    # Test-only Ed25519 seed (RFC 8032 §7.1 vector 1).
    ├── merchant_test_public.hex     # Test-only Ed25519 public key.
    └── pic_keys.example.json        # PIC trusted keyring.
```
