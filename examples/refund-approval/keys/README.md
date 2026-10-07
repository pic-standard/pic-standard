# TEST-ONLY KEY MATERIAL

**DO NOT USE THIS KEY FOR ANYTHING OUTSIDE THIS FIXTURE.**

The Ed25519 key pair in this directory is a well-known public test vector
(RFC 8032 §7.1 test vector 1). It is intentionally published here so any
reviewer can regenerate the signed fixtures byte-for-byte without
contacting the author.

Its signature establishes fixture behavior under a dedicated test
`key_id`. It carries no real merchant authority and no claim about any
real-world identity.

## Files

- `merchant_test_private.hex` — Ed25519 private key seed (32 bytes hex).
  Matches RFC 8032 §7.1 test vector 1 private key.
- `merchant_test_public.hex` — Ed25519 public key (32 bytes hex).
  Matches RFC 8032 §7.1 test vector 1 public key.
- `pic_keys.example.json` — PIC trusted keyring binding
  `merchant-test-v1` → this public key. Named `.example.json` so the
  repo-root `.gitignore` rule for real keyrings (`pic_keys.json`) still
  applies, and this test-only file is clearly labeled.

## key_id

- `merchant-test-v1`

Scoped to this fixture only. A production merchant signer would use a
production key under a production `key_id`, with production keyring
hygiene (HSM, rotation, revocation list).

## How the keyring is loaded

The example wires the keyring explicitly through
`PipelineOptions(key_resolver=StaticKeyRingResolver(TrustedKeyRing.from_json_file(...)))`.
It does NOT rely on the `PIC_KEYS_PATH` environment variable or on
the default keyring loader. See `sign_and_verify.py:make_pipeline_options`.
