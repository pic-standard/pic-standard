from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"
FAILING = EXAMPLES / "failing"

OK_PATH = EXAMPLES / "financial_sig_ok.json"
BAD_PATH = FAILING / "financial_sig_bad.json"
KEYS_EXAMPLE_PATH = REPO_ROOT / "pic_keys.example.json"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def main() -> None:
    # Generate a fresh keypair
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    key_id = "demo_signer_v1"
    payload_ok = "amount=500;currency=USD;invoice=123"
    payload_bad = "amount=600;currency=USD;invoice=123"

    sig_ok = priv.sign(payload_ok.encode("utf-8"))
    # IMPORTANT: We intentionally reuse the OK signature for the tampered payload example
    # so it fails deterministically.
    sig_bad = sig_ok

    # Write keyring example at repo root (public key only)
    KEYS_EXAMPLE_PATH.write_text(
        json.dumps({"trusted_keys": {key_id: _b64(pub_raw)}}, indent=2),
        encoding="utf-8",
    )

    # Load + rewrite the OK example
    ok = json.loads(OK_PATH.read_text(encoding="utf-8"))
    ok["evidence"][0]["key_id"] = key_id
    ok["evidence"][0]["signer"] = key_id
    ok["evidence"][0]["payload"] = payload_ok
    ok["evidence"][0]["signature"] = _b64(sig_ok)
    OK_PATH.write_text(json.dumps(ok, indent=4), encoding="utf-8")

    # Load + rewrite the BAD example
    bad = json.loads(BAD_PATH.read_text(encoding="utf-8"))
    bad["evidence"][0]["key_id"] = key_id
    bad["evidence"][0]["signer"] = key_id
    bad["evidence"][0]["payload"] = payload_bad
    bad["evidence"][0]["signature"] = _b64(sig_bad)
    BAD_PATH.write_text(json.dumps(bad, indent=4), encoding="utf-8")

    print("PASS: Wrote:")
    print(f" - {KEYS_EXAMPLE_PATH.relative_to(REPO_ROOT)}")
    print(f" - {OK_PATH.relative_to(REPO_ROOT)}")
    print(f" - {BAD_PATH.relative_to(REPO_ROOT)}")
    print()
    print("Next:")
    print("  PIC_KEYS_PATH=pic_keys.example.json pic-cli evidence-verify examples/financial_sig_ok.json")
    print("  PIC_KEYS_PATH=pic_keys.example.json pic-cli evidence-verify examples/failing/financial_sig_bad.json")


if __name__ == "__main__":
    main()
