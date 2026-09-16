from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def main() -> None:
    """
    Generates a new Ed25519 keypair and prints:
      - base64 public key (to paste into pic_keys.json)
      - base64 private key (KEEP SECRET; do NOT commit)
      - a ready-to-paste pic_keys.json snippet
    """
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()

    # Raw bytes are easiest for Ed25519
    pk_raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_raw = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    key_id = "demo_signer_v1"

    print("=== PIC Ed25519 Keygen ===")
    print(f"key_id: {key_id}")
    print("")
    print("PUBLIC_KEY_BASE64:")
    print(b64(pk_raw))
    print("")
    print("PRIVATE_KEY_BASE64 (KEEP SECRET; DO NOT COMMIT):")
    print(b64(sk_raw))
    print("")
    print("pic_keys.json snippet:")
    print(json.dumps({"trusted_keys": {key_id: b64(pk_raw)}}, indent=2))


if __name__ == "__main__":
    main()
