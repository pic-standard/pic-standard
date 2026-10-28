# TEST-ONLY KEY MATERIAL

**DO NOT USE THIS KEY FOR ANYTHING OUTSIDE THIS EXPERIMENT.**

The private key in this directory is publicly known. It is the Ed25519
key pair from RFC 8032 §7.1 test vector 2, published here so any
reviewer can regenerate the signed fixtures byte-for-byte. Anyone can
sign with it, so a signature under this key is unsuitable as evidence of
a real approval and carries no merchant authority or real-world identity.

## Files

- `merchant_test_private.hex`: Ed25519 private key seed (32 bytes hex),
  RFC 8032 §7.1 test vector 2. Used only by `make_fixture.py`, which
  deliberately signs fixtures. `pic_result.py` never reads it and never
  signs.
- `merchant_test_public.hex`: the matching Ed25519 public key (32 bytes
  hex).
- `pic_keys.example.json`: the PIC trusted keyring for this example. It
  trusts exactly one key, `refund-sandbox-merchant-test-v1`, bound to
  this public key, and revokes none. Named `.example.json` so the
  repo-root `.gitignore` rule for real keyrings (`pic_keys.json`) still
  applies.

## Separation from other examples

`examples/refund-approval` uses a different key (RFC 8032 test vector 1)
under a different `key_id`. Separation comes from the keyrings, not from
the keys: each example's keyring trusts only its own key, so a proposal
signed for one example does not verify under the other's keyring. A
keyring that trusted both keys would remove that separation.

## How the keyring is loaded

`pic_result.py` reads the keyring file's bytes once, hashes those bytes
for `pic_trust_file_ref`, strictly parses them, and builds the keyring
with `TrustedKeyRing.from_dict(...)` wrapped in `StaticKeyRingResolver`.
It does not use `PIC_KEYS_PATH`, the default keyring loader or
`TrustedKeyRing.from_json_file`, which would read the file a second time.
In a connected run the runner selects the keyring file; the agent cannot.
