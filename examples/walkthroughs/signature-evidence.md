# Signature evidence walkthrough

This walkthrough is pinned to PIC Standard v0.9.0 at commit `f745b1cd`, Python 3.11.9, and the `crypto` extra. The demo keys `demo_signer_v1` and `demo_hash_signer_v1` expire at `2027-01-01T00:00:00Z`. After that instant, verification fails because the key is expired; that is different from a bad signature. Never disable lifecycle checks, change the system clock, or use legacy-trust mode to make an example pass.

Run every command from the repository root. Use the root `pic_keys.example.json` keyring—**not** `examples/pic_keys.demo.json`.

## Set up an isolated environment

Clone and check out the version used for this walkthrough before installing anything:

```bash
git clone https://github.com/pic-standard/pic-standard.git
cd pic-standard
git checkout v0.9.0
python -m venv .venv
```

Activate the environment with `source .venv/bin/activate` on Linux/macOS, or `source .venv/Scripts/activate` in Windows Git Bash. Then, in the same Bash session:

```bash
python --version
python -m pip install -e ".[crypto]"
export PIC_KEYS_PATH="$(pwd)/pic_keys.example.json"
```

The commands were verified with Python 3.11.9; PIC v0.9.0 supports Python 3.10 or later. `PIC_KEYS_PATH` is explicit so the verifier resolves `demo_signer_v1` from the release-pinned root keyring rather than from an ambient or example keyring.

## Verify the valid signed proposal

```bash
pic-cli verify examples/financial_sig_ok.json --verify-evidence
echo "exit code: $?"
```

Literal output:

```text
PASS: Schema valid
PASS: Verifier passed
exit code: 0
```

The proposal claims **Pay 500 USD** (the fixture renders this as `Pay $500`), and `action.args.amount` is `500`. Its legacy signed evidence payload is the exact UTF-8 string:

```text
amount=500;currency=USD;invoice=123
```

The `approval_123` provenance entry starts as `untrusted`. Because this is a money-impact action, it cannot rely on self-asserted trust. Successful Ed25519 verification against `demo_signer_v1` in the trusted keyring verifies the matching signature evidence and upgrades `approval_123` to `trusted` in memory before the verifier evaluates the action. See the [trust upgrade rules](https://github.com/pic-standard/pic-standard/blob/v0.9.0/docs/spec-evidence.md#8-trust-upgrade-rules) and [key lifecycle rules](https://github.com/pic-standard/pic-standard/blob/v0.9.0/docs/spec-evidence.md#10-key-lifecycle).

## Verify the tampered proposal

```bash
pic-cli verify examples/failing/financial_sig_bad.json --verify-evidence
echo "exit code: $?"
```

Literal output:

```text
PASS: Schema valid
FAIL: Evidence verification failed
Evidence verification failed
exit code: 4
```

The bad file changes the claim to **Pay 600 USD (tampered)** (rendered as `Pay $600 (tampered)`), changes `action.args.amount` to `600`, and changes the legacy signed payload to:

```text
amount=600;currency=USD;invoice=123
```

It leaves both the Ed25519 `signature` and `key_id` unchanged. The retained signature was made for different payload bytes, so it cannot verify the modified payload. Consequently, `approval_123` receives no trust upgrade and the pipeline fails closed.

Exit code `4` means evidence verification failed; it does not identify the precise underlying cause. An invalid signature, an unknown or expired key, a revoked key, and other evidence failures can share this exit code. By contrast, exit code `3` means the evidence stage completed but the verifier rejected the proposal; that CLI distinction is tracked by issue #174.

## What the signature does—and does not—cover

**Strong warning:** this fixture uses legacy Ed25519 signing. Its signature covers **only** the exact inline `evidence.payload` bytes. It does **not** cover the entire action, `action.args`, the human-readable claim, or the proposal. Keeping the payload consistent with those fields is therefore an application responsibility in legacy mode. See [legacy and canonical signing modes](https://github.com/pic-standard/pic-standard/blob/v0.9.0/docs/spec-evidence.md#62-signing-modes--legacy-and-canonical).

Canonical signing is more robust: it signs a canonical attestation and then verifies digests that bind security-relevant proposal content, including the proposal/action context defined by the canonical mode. Prefer canonical signing for new integrations; its post-signature binding checks are specified under [digest verification](https://github.com/pic-standard/pic-standard/blob/v0.9.0/docs/spec-evidence.md#64-digest-verification-post-signature).
