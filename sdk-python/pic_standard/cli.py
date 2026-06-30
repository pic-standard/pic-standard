from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from jsonschema import ValidationError
from jsonschema import validate as js_validate

from .config import dump_policy, load_policy
from .errors import PICErrorCode
from .evidence import EvidenceSystem

# NEW: keys command
from .keyring import KeyRingError, TrustedKeyRing
from .pipeline import PipelineOptions, _load_packaged_schema, verify_proposal


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"File not found: {path}") from None
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in {path}: {e}") from None


def cmd_schema(proposal_path: Path) -> int:
    proposal = load_json(proposal_path)
    schema = _load_packaged_schema()

    try:
        js_validate(instance=proposal, schema=schema)
        print("PASS: Schema valid")
        return 0
    except ValidationError as e:
        print("FAIL: Schema invalid")
        print(str(e))
        return 2


def cmd_evidence_verify(proposal_path: Path) -> int:
    # Always validate schema first (consistent UX)
    code = cmd_schema(proposal_path)
    if code != 0:
        return code

    proposal = load_json(proposal_path)

    es = EvidenceSystem()
    report = es.verify_all(proposal, base_dir=proposal_path.parent)

    if not report.results:
        print("FAIL: Evidence verification failed")
        print("No evidence entries found in proposal (expected 'evidence': [...]).")
        return 4

    for r in report.results:
        if r.ok:
            print(f"PASS: Evidence {r.id}: {r.message}")
        else:
            print(f"FAIL: Evidence {r.id}: {r.message}")

    if report.ok:
        print("PASS: Evidence verification passed")
        return 0

    print("FAIL: Evidence verification failed")
    return 4


def cmd_verify(proposal_path: Path, *, verify_evidence: bool = False) -> int:
    # Intentionally run schema command first for stable CLI UX / exit-code messaging.
    # verify_proposal() validates schema again internally (shared pipeline path).
    code = cmd_schema(proposal_path)
    if code != 0:
        return code

    proposal = load_json(proposal_path)

    result = verify_proposal(
        proposal,
        options=PipelineOptions(
            verify_evidence=verify_evidence,
            proposal_base_dir=proposal_path.parent,
            evidence_root_dir=proposal_path.parent,
        ),
    )

    if result.ok:
        print("PASS: Verifier passed")
        return 0

    err = result.error
    if err and err.code == PICErrorCode.SCHEMA_INVALID:
        print("FAIL: Schema invalid")
        print(err.message)
        return 2
    if err and err.code in (PICErrorCode.EVIDENCE_REQUIRED, PICErrorCode.EVIDENCE_FAILED):
        print("FAIL: Evidence verification failed")
        print(err.message)
        return 4
    print("FAIL: Verifier failed")
    print(err.message if err else "Unknown error")
    return 3


def _find_policy_source(repo_root: Path) -> str:
    """
    Best-effort: explain where policy came from.
    This mirrors load_policy() priority:
      explicit_path (not used by CLI)
      PIC_POLICY_PATH env var
      repo_root/pic_policy.json or repo_root/pic_policy.local.json
      default policy
    """
    env_path = os.getenv("PIC_POLICY_PATH")
    if env_path:
        return f"PIC_POLICY_PATH={env_path}"

    for name in ("pic_policy.json", "pic_policy.local.json"):
        candidate = repo_root / name
        if candidate.exists():
            return str(candidate)

    return "default (no policy file found)"


def cmd_policy(*, repo_root: Path, write_example: bool = False) -> int:
    """
    Show the effective policy (and where it was loaded from).
    """
    if write_example:
        example = {
            "impact_by_tool": {
                "payments_send": "money",
                "customer_export": "privacy",
                "aws_batch_run": "compute",
            },
            "require_pic_for_impacts": ["money", "privacy", "irreversible"],
            "require_evidence_for_impacts": ["money", "privacy", "irreversible"],
        }
        print(json.dumps(example, indent=2, ensure_ascii=True))
        return 0

    policy = load_policy(repo_root=repo_root)
    source = _find_policy_source(repo_root)

    print("PASS: Policy loaded")
    print(f"Source: {source}")
    print(json.dumps(dump_policy(policy), indent=2, ensure_ascii=True))
    return 0


# ------------------------------
# Keyring helpers + command
# ------------------------------
def _find_keys_source(repo_root: Path) -> str:
    """
    Best-effort: explain where keys came from.
    This mirrors TrustedKeyRing.load_default() priority:
      PIC_KEYS_PATH env var
      ./pic_keys.json in current working directory
      none
    """
    env_path = (os.getenv("PIC_KEYS_PATH") or "").strip()
    if env_path:
        return f"PIC_KEYS_PATH={env_path}"

    # By design, TrustedKeyRing.load_default() looks in CWD.
    # For CLI ergonomics, we also tell the user if repo_root/pic_keys.json exists.
    # (But we don't change load_default() behavior here.)
    cwd_candidate = Path("pic_keys.json")
    if cwd_candidate.exists():
        return str(cwd_candidate.resolve())

    repo_candidate = repo_root / "pic_keys.json"
    if repo_candidate.exists():
        return f"{repo_candidate} (note: loader uses CWD unless PIC_KEYS_PATH is set)"

    return "none (no PIC_KEYS_PATH and no pic_keys.json found)"


def cmd_keys(*, repo_root: Path, write_example: bool = False) -> int:
    """
    Validate and print the trusted keyring used for signature-based evidence (v0.4+).

    - Loads from PIC_KEYS_PATH if set, otherwise from ./pic_keys.json if present.
    - Prints loaded key IDs.
    """
    if write_example:
        example = {
            "trusted_keys": {
                "demo_signer_v1": "<base64-ed25519-public-key-32-bytes>",
                "cfo_key_v2": {
                    "public_key": "<base64-or-hex-or-pem>",
                    "expires_at": "2026-12-31T23:59:59Z",
                },
            },
            "revoked_keys": ["cfo_key_v1"],
        }
        print(json.dumps(example, indent=2, ensure_ascii=True))
        return 0

    source = _find_keys_source(repo_root)

    try:
        ring = TrustedKeyRing.load_default()
    except KeyRingError as e:
        print("FAIL: Keyring invalid")
        print(f"Source: {source}")
        print(str(e))
        return 6
    except Exception as e:
        print("FAIL: Keyring failed to load")
        print(f"Source: {source}")
        print(str(e))
        return 6

    key_ids = sorted(list(ring.keys.keys()))

    print("PASS: Keyring loaded")
    print(f"Source: {source}")

    if not key_ids:
        print("No trusted keys configured (0 keys).")
        print("To add keys:")
        print("  1) Run: pic-cli keys --write-example > pic_keys.json")
        print("  2) Edit pic_keys.json and paste your public keys")
        print("  3) Re-run: pic-cli keys")
        return 0

    print(f"Trusted keys ({len(key_ids)}):")
    for kid in key_ids:
        print(f"- {kid}")

    return 0


# ------------------------------
# HTTP bridge command
# ------------------------------
def cmd_serve(*, host: str, port: int, repo_root: Path, verify_evidence: bool = False) -> int:
    """Start the PIC HTTP bridge server."""
    from .integrations.http_bridge import start_bridge

    policy = load_policy(repo_root=repo_root)
    source = _find_policy_source(repo_root)
    print(f"Starting PIC HTTP bridge on {host}:{port}")
    print(f"Policy: {source}")
    start_bridge(
        host=host,
        port=port,
        policy=policy,
        verify_evidence=verify_evidence,
        proposal_base_dir=repo_root,
        evidence_root_dir=repo_root,
    )
    return 0  # unreachable unless KeyboardInterrupt


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pic-cli", description="PIC Standard CLI utilities")
    sub = p.add_subparsers(dest="command", required=True)

    s1 = sub.add_parser("schema", help="Validate proposal against JSON Schema")
    s1.add_argument("proposal", type=Path)

    s2 = sub.add_parser("verify", help="Validate proposal against schema + verifier")
    s2.add_argument("proposal", type=Path)
    s2.add_argument(
        "--verify-evidence",
        action="store_true",
        help=(
            "Verify evidence (v0.3: sha256) and upgrade provenance to TRUSTED "
            "based on verified IDs before running verifier."
        ),
    )

    s3 = sub.add_parser("evidence-verify", help="Verify evidence only (v0.3: sha256)")
    s3.add_argument("proposal", type=Path)

    s4 = sub.add_parser(
        "policy", help="Show the effective policy loaded from pic_policy.json / PIC_POLICY_PATH"
    )
    s4.add_argument(
        "--repo-root",
        type=Path,
        default=Path(".").resolve(),
        help="Repo root to search for pic_policy.json (default: current working directory).",
    )
    s4.add_argument(
        "--write-example",
        action="store_true",
        help="Print an example policy JSON you can save as pic_policy.json.",
    )

    s5 = sub.add_parser(
        "keys", help="Validate and print trusted signer keys (for signature evidence v0.4+)"
    )
    s5.add_argument(
        "--repo-root",
        type=Path,
        default=Path(".").resolve(),
        help="Repo root (used for nicer source hints; loader uses PIC_KEYS_PATH or CWD).",
    )
    s5.add_argument(
        "--write-example",
        action="store_true",
        help="Print an example pic_keys.json you can save and edit.",
    )

    s6 = sub.add_parser(
        "serve", help="Start the PIC HTTP bridge server for non-Python integrations"
    )
    s6.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1).",
    )
    s6.add_argument(
        "--port",
        type=int,
        default=7580,
        help="Listen port (default: 7580).",
    )
    s6.add_argument(
        "--repo-root",
        type=Path,
        default=Path(".").resolve(),
        help="Repo root for policy and evidence files (default: current working directory).",
    )
    s6.add_argument(
        "--verify-evidence",
        action="store_true",
        help="Enable evidence verification for incoming proposals.",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "schema":
        return cmd_schema(args.proposal)
    if args.command == "evidence-verify":
        return cmd_evidence_verify(args.proposal)
    if args.command == "verify":
        return cmd_verify(args.proposal, verify_evidence=getattr(args, "verify_evidence", False))
    if args.command == "policy":
        return cmd_policy(
            repo_root=args.repo_root,
            write_example=getattr(args, "write_example", False),
        )
    if args.command == "keys":
        return cmd_keys(
            repo_root=args.repo_root,
            write_example=getattr(args, "write_example", False),
        )
    if args.command == "serve":
        return cmd_serve(
            host=args.host,
            port=args.port,
            repo_root=args.repo_root,
            verify_evidence=getattr(args, "verify_evidence", False),
        )

    raise SystemExit("Unknown command")


if __name__ == "__main__":
    raise SystemExit(main())
