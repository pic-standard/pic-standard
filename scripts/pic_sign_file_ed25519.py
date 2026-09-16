from __future__ import annotations

import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def main() -> int:
    """
    Usage:
      python scripts/pic_sign_file_ed25519.py <PRIVATE_KEY_BASE64> <FILE_PATH>

    Prints:
      signature_base64
    """
    if len(sys.argv) != 3:
        print("Usage: python scripts/pic_sign_file_ed25519.py <PRIVATE_KEY_BASE64> <FILE_PATH>")
        return 2

    sk_b64 = sys.argv[1].strip()
    file_path = Path(sys.argv[2])

    sk_raw = base64.b64decode(sk_b64)
    if len(sk_raw) != 32:
        print("Invalid Ed25519 private key length (expected 32 raw bytes base64)")
        return 3

    data = file_path.read_bytes()
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_raw)
    sig = sk.sign(data)
    print(b64(sig))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
