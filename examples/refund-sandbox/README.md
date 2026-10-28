# Refund sandbox: PIC verifier adapter

PIC producer for the bounded refund sandbox in
[aeoess/agent-governance-vocabulary#193](https://github.com/aeoess/agent-governance-vocabulary/issues/193).
It verifies one refund proposal natively with the PIC SDK at a pinned
commit, applies the shared refund profile, and writes the closed
`refund-sandbox-pic-result/0.1` result defined in section 4 of contract
revision `review-2026-10-23`.

## Status

Component checks only. The adapter (`pic_result.py`), the fixture maker
(`make_fixture.py`) and the case harness (`run_cases.py`, `self_check.py`)
have been exercised in isolation in the pinned environment. **Success of
the connected workflow (APS, PIC, Horizon Shield, Probity, Default
Settlement) has not been established.** Specifically:

- **The APS-linked fixture is pending.** `make_fixture.py` supports
  `--approval-ref-source aps-receipt-id`, but the reported checks have not
  yet exercised a fixture built from an actual APS receipt. All exercised
  fixtures use a synthetic `approval_ref`. This example verifies no APS
  evidence under either label.
- Normal fixtures are signed with a publicly known test key; negative
  cases also use a throwaway key (see
  [Test key limitations](#test-key-limitations)).
- Native historical verification was not performed. The adapter verifies
  against the live clock only (see [Clocks](#clocks)).
- Admission, handoff, resolution signing, execution and settlement are
  outside this example.

## Files

| File | Role |
|---|---|
| `pic_result.py` | The adapter. Verifies and writes a result. **Never signs**, dispatches, consumes an approval or assigns an `operation_id`. |
| `make_fixture.py` | **Signs** test proposals with the public test key. Dedicated fixture-signing CLI; its signing helpers are also used by the case harness. |
| `keys/` | Public test key pair and the example keyring. See `keys/README.md`. |
| `requirements.txt`, `constraints.txt` | The SDK pin and the transitive pins. |
| `environment.txt` | Captured description of the environment the checks ran in. |
| `run_cases.py` | Case harness: 79 registered component cases. |
| `fixtures/expected-outcomes.json` | Expected outcome for every registered case. |
| `actual-results.json` | Generated report of the last `run_cases.py` invocation, which may be a subset or `not-run`; check its `status` and `subset` fields. Not an input. |
| `self_check.py` | Harness probes: checks that `run_cases.py` detects specific faults and malformed inputs. |

## Environment and pins

Run every setup and example command in this README from
`examples/refund-sandbox/`.

Create the venv:

```bash
python -m venv .venv
```

Activate it with the line for your shell. POSIX shells:

```bash
. .venv/bin/activate
```

Git Bash on Windows:

```bash
. .venv/Scripts/activate
```

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Then install:

```bash
python -m pip install -r requirements.txt -c constraints.txt
```

`requirements.txt` installs `pic-standard[crypto]` from git at commit
`330fdd817ef81d43461ea1787939e0d1cc87d589`. `constraints.txt` pins the
transitive versions. `environment.txt` records the Python version,
`pip freeze` and the installed `direct_url.json` of the environment the
recorded checks ran in.

Before any verification, the adapter reads the installed `pic-standard`
metadata (`direct_url.json`). It requires `vcs_info.vcs == "git"` and
`commit_id` equal to the pin. If pic-standard is missing, is not a VCS
install, has malformed metadata, is a local-directory install or reports a
different commit, the result blocks with `SANDBOX_ENVIRONMENT_UNVERIFIED`.

This check reads install metadata. It does not prove that the code on
disk matches the commit, so an installation with the correct metadata
and modified code would pass it. The integrity of the venv belongs to the
runner that creates and owns it.

## Producer command

```bash
python pic_result.py --proposal PROPOSAL.json --keyring KEYRING.json --run-id RUN_ID --contract-revision review-2026-10-23 --out RESULT.json
```

- `--proposal`: one PIC refund proposal, at most 1 MiB, UTF-8, strict
  JSON.
- `--keyring`: the PIC trusted keyring, same limits. It must come from
  the consumer's trust policy, never from the agent or the caller (see the
  consumer contract).
- `--run-id`: supplied by the runner, matching `[A-Za-z0-9._:-]{1,128}`.
- `--contract-revision`: must be exactly `review-2026-10-23`. Any other
  value fails, and is never echoed into a result.
- `--out`: a path that must not exist yet (see [Output](#output)).

Each input file is read exactly once. `proposal_file_ref` and
`pic_trust_file_ref` are `sha256:` over those raw bytes. The adapter never
rereads, rewrites or normalizes an input. A one-line diagnostic goes to
stderr for the transcript and is not part of any contract.

"Strict JSON" means duplicate members, `NaN`/`Infinity`, floats and
integers outside ±(2^53 − 1) are all refused. The same parser checks the
outer files, the attestation `payload` string and the claim `text` string.
`verify_proposal` receives the unmodified proposal; the strict parses of
embedded strings are checks only.

## Verification order

1. `--run-id` and `--contract-revision`.
2. Read, hash and strictly parse both files; check the keyring's closed
   shape.
3. SDK metadata pin check.
4. Evidence preflight, before any SDK verification call: exactly one
   evidence entry, of type `sig`, whose payload strictly parses to a
   PIC-ATT/1.0 attestation with `expires_at`, `intent_digest` and no other
   members beyond the closed set. Hash and file evidence therefore never
   reach the SDK's file reader.
5. Keyring construction with `TrustedKeyRing.from_dict`, then native
   verification with `verify_proposal` and
   `PipelineOptions(verify_evidence=True, strict_trust=True, policy=PICPolicy(), key_resolver=StaticKeyRingResolver(ring), tool_name="refund", expected_tool="refund")`.
6. Refund profile checks, then the three digests are recomputed with the
   pinned SDK and must equal the verified attestation.

## Result

Exactly these 14 fields, written as sorted, compact ASCII JSON (equal to
JCS for this all-string-or-null object):

| Field | Allow | Block |
|---|---|---|
| `schema` | `refund-sandbox-pic-result/0.1` | same |
| `contract_revision` | `review-2026-10-23` | null if the run id or revision was rejected |
| `run_id` | the supplied run id | null if the run id was rejected |
| `pic_sdk_commit` | the pin | null unless the metadata pin check passed; failures before that check leave it null, failures afterwards retain the pin |
| `proposal_file_ref` | `sha256:` of the proposal bytes | null if not reached or the proposal could not be read |
| `pic_trust_file_ref` | `sha256:` of the keyring bytes | null if not reached or the keyring could not be read |
| `evaluated_at` | completion time | same |
| `result` | `allow` | `block` |
| `tool`, `impact` | `refund`, `money` | null |
| `args_digest`, `claims_digest`, `intent_digest` | lowercase hex | null |
| `error_code` | null | a code (see below) |

Digests are bare lowercase hex. `args_digest` and `claims_digest` are
SHA-256 over the PIC canonical (RFC 8785 JCS based) bytes of
`action.args` and `claims`. `intent_digest` is SHA-256 over the raw UTF-8
intent. A block never carries a fabricated value: anything not established
is null.

## Exit codes and error codes

| Exit | Meaning | Result file |
|---|---|---|
| 0 | allow | written |
| 1 | rejection of the proposal's content | complete block written |
| 2 | input, environment or operational failure | block written when possible |

The split follows the source of the failure:

- **Exit 2: outer inputs and the environment.**
  - `SANDBOX_INPUT_MALFORMED`: invalid run id or revision; a proposal or
    keyring file that is unreadable, larger than 1 MiB, not UTF-8 or not
    strict JSON; a proposal that is not an object; a keyring outside the
    closed shape or rejected by the SDK.
  - `SANDBOX_ENVIRONMENT_UNVERIFIED`: the metadata pin check failed.
  - `SANDBOX_VERIFIER_ERROR`: the SDK could not be imported, raised, or
    produced digests that disagree with the verified attestation.
  - `PIC_INTERNAL_ERROR`: returned by the SDK.
  - `SANDBOX_ADAPTER_ERROR`: an unexpected exception in the adapter.
- **Exit 1: content of the proposal**, including strictness failures
  inside embedded strings.
  - `SANDBOX_EVIDENCE_UNSUPPORTED`: not exactly one `sig` evidence entry.
  - `SANDBOX_ATTESTATION_REQUIRED`: payload is not strict JSON or not
    PIC-ATT/1.0.
  - `SANDBOX_EXPIRY_REQUIRED`, `SANDBOX_INTENT_REQUIRED`: attestation lacks
    `expires_at` or `intent_digest`.
  - `SANDBOX_PROFILE_VIOLATION`: attestation members, tool, impact, args,
    intent or provenance outside the profile.
  - `SANDBOX_CLAIM_INVALID`: claim count, shape, citation, strictness,
    canonical form, `decision_id` or `approval_ref` format.
  - Any other `PIC_*` code that the pinned SDK returns for a native
    rejection, for example `PIC_EVIDENCE_FAILED` or
    `PIC_TOOL_BINDING_MISMATCH`. Native codes appear only when the SDK
    actually returned them.

`SANDBOX_*` codes belong to this experiment only. SDK diagnostic messages
are not a protocol error contract.

## Output

- **Existing output is refused.** If `--out` already exists, the adapter
  exits 2, writes nothing and leaves the existing file untouched. That
  file may be an allow from an earlier run, so safety depends on the
  consumer rejecting the failed invocation (see the consumer contract).
- **Atomic write.** The result goes to a temporary file in the same
  directory, is flushed and fsynced, and is moved into place with
  `os.replace`. A write failure exits 2; removal of the temporary file is
  attempted, but cleanup errors are suppressed, so a stray temporary file
  can remain.
- **Private output directory assumed.** The existence check at start and
  the check just before `os.replace` are not atomic against another
  process writing to the same directory. Use a fresh `--out` per
  invocation, in a directory only the runner can write.

## Clocks

Verification uses the real clock. The SDK checks the attestation's
`expires_at` and any key `expires_at` against the current time, so an
expired proposal or key blocks. There is no clock injection, and native
historical verification was not performed. `evaluated_at` is the
completion time, taken after the verification checks finish (UTC,
millisecond precision, rounded up); the individual checks ran at or before
that instant, not exactly at it.

`make_fixture.py` sets a whole-second UTC `expires_at`, by default at
least 1800 seconds ahead, so a fixture must be verified within its
lifetime and regenerated afterwards. In `run_cases.py`, ordinary valid
proposals receive relative expiry at runtime; deliberately expired cases
and key-expiry cases also use fixed past/future timestamps.

## Consumer contract

**Authentication boundary.** The proposal contains signed PIC evidence.
This adapter's result is unsigned. Consumers must obtain it through a
trusted runner-controlled channel; matching hashes and a claimed SDK
commit alone do not authenticate who performed verification.

What a consumer such as Probity must do before treating a PIC result as
an allow. These are requirements on the consumer; this repository does
not claim any consumer has implemented or passed them.

1. **Invocation.** Require exit code 0 from this invocation. On any
   other exit, or a missing or unreadable output, reject, and do not read
   whatever is at the output path.
2. **Shape.** Strictly parse the result. Require exactly the 14 fields,
   `schema == "refund-sandbox-pic-result/0.1"`,
   `contract_revision == "review-2026-10-23"`, `result == "allow"`,
   `error_code == null`, `tool == "refund"` and `impact == "money"`.
3. **Run context.** Require `run_id` to equal the consumer's own run id
   for this run, and `pic_sdk_commit` to equal the pin the consumer
   declares (for Probity, `components.lock.json`). Optionally, also
   require `evaluated_at` to fall within the invocation window on the
   consumer's clock; this is useful additional validation, but it does not
   authenticate the result or replace the other context checks.
4. **Retained inputs and trust.** Hash the retained proposal bytes and
   the retained keyring bytes exactly as stored, and require equality with
   `proposal_file_ref` and `pic_trust_file_ref`. The keyring must match
   the consumer's independently configured trust policy. It is not enough
   that the runner selected it if the runner accepts a caller-selected
   keyring.
5. **Arguments.** Take `action.args` from the retained proposal, never
   from the result or the agent, then:
   - validate both the retained `action.args` and the admitted/executed
     arguments against the closed refund schema: exactly `payment_id`
     (`[A-Za-z0-9_-]+`), `amount_minor` (positive safe integer, rejecting
     booleans) and `currency == "EUR"`;
   - require exact typed equality between those two argument objects;
   - recompute SHA-256 over their PIC canonical bytes and require
     equality with the result's `args_digest`;
   - keep the trusted result channel.
6. **No reuse.** One result per run id and invocation. Never accept an
   allow file from an earlier run, and never reuse an output path.
7. **Retire the stand-in.** Remove the stand-in `pic-arguments` check once
   these checks are in place.

Checking that `approval_ref` equals the APS `receipt_id` belongs to
admission. The adapter checks only its format.

Ownership: this repository owns the adapter, its cases, fixtures, pins
and these instructions. The runner invokes the pinned producer and
retains its inputs and output. Tests for fake or reused results, wrong run
context, caller-selected trust and consumption of the result belong to
the consumers (Probity and Horizon Shield); this repository writes none
of them.

## Profile restrictions

These are restrictions of this example's refund profile. They are not
PIC protocol requirements, and other PIC deployments need not follow
them:

- exactly one evidence entry, of type `sig`, with a strict PIC-ATT/1.0
  payload carrying `expires_at` and `intent_digest`;
- a closed attestation field set: `attestation_version`, `tool`,
  `impact`, `provenance_ids`, `args_digest`, `claims_digest`,
  `intent_digest`, `expires_at`;
- exactly one provenance entry, and the evidence id equals it;
- `tool == "refund"`, `impact == "money"`;
- `action.args` exactly `payment_id` (`[A-Za-z0-9_-]+`), `amount_minor`
  (positive safe integer, not a boolean) and `currency == "EUR"`;
- exactly one claim, citing the provenance entry, whose `text` is the
  canonical JSON of exactly `decision_id` (nonempty, trimmed) and
  `approval_ref` (64 lowercase hex);
- a closed keyring shape: exactly `trusted_keys` (nonempty; each entry a
  64-hex public key or `{public_key, optional expires_at}`) and
  `revoked_keys` (unique key ids);
- 1 MiB per input file and strict JSON throughout.

## Signing and fixtures

`pic_result.py` never signs and never reads the private key.
`make_fixture.py` signs on purpose:

```bash
python make_fixture.py --decision-id DECISION_ID --approval-ref HEX64 --approval-ref-source synthetic --payment-id pay_A --amount-minor 4000 --currency EUR --out proposal.json
```

`--approval-ref-source` is `synthetic` or `aps-receipt-id`, and the label
is written into the signed intent. Neither label means that any APS
evidence was verified. `--expires-at` (whole-second UTC) and
`--ttl-seconds` are mutually exclusive. Existing output is refused.

## Test key limitations

Normal fixtures are signed with RFC 8032 section 7.1 test vector 2. Its
private key is public, so anyone can produce a proposal that verifies
under `keys/pic_keys.example.json`. An allow under that keyring shows only
that the proposal passed the adapter's checks under a key anyone can use.
It carries no merchant authority, identity or approval, and the key must
never be trusted outside this experiment. Negative cases in `run_cases.py`
also sign with a throwaway key that the example keyring does not trust.
Separation from `examples/refund-approval` comes from each example's
keyring trusting only its own key. See `keys/README.md`.

## Running the checks

In the pinned environment, from `examples/refund-sandbox/`:

```bash
python run_cases.py
```

```bash
python self_check.py
```

`run_cases.py` runs the 79 registered component cases (or the cases
selected with `--case`) against `fixtures/expected-outcomes.json` and
writes `actual-results.json`. Exit codes:
- 0: every selected case matched.
- 1: at least one case mismatched, failed validation or raised.
- 2: unsafe report path; report cleanup or write failure; unloadable
  adapter; expectations failing the coverage gate; unknown or repeated
  `--case` ids.
- 3: not the pinned environment, or the SDK-dependent helpers could not
  be loaded; no case runs.

`self_check.py` runs 14 probes. They are:
- a baseline;
- adapter faults injected through restored patches (a corrupted file
  reference, bad timestamps, a bypassed preflight, an unexpected file
  read);
- malformed or incomplete expectations;
- report-path checks.

Probes check the expected exit code and diagnostic, plus report status or
preservation of the protected file, as applicable. The probes show that
the harness catches those specific problems, not every possible fault.

Neither file is named `test_*.py`, so the repository's root `pytest` run
does not collect them and does not need the pinned SDK.
