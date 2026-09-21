#!/usr/bin/env python3
"""Authoritative differential conformance diff for PIC envelopes.

Compares two conformance-runner JSON envelopes (from any conformant
implementation of the PIC Standard: the Python reference implementation
in this repository, a TypeScript or other-language port, etc.) by
projecting each to the semantic subset that defines cross-language
conformance parity, canonicalizing with sorted keys, and byte-comparing.

Included in the semantic subset:
  - summary: total, passed, failed, all_passed, diagnostic
  - exit_code
  - results[]: preserved in emitted order; each projected to
    {id, passed, reason_code}

Excluded:
  - summary.message (freeform, expected to differ across languages)
  - results[].message (freeform)
  - results[].mode (not part of the semantic diff contract)
  - selection (input reflection, not a conformance signal)
  - manifest_version (not part of the semantic diff contract)
  - any timing or wall-clock field

Usage:
    python scripts/diff_conformance.py <a.json> <b.json>

Exit codes:
    0 - semantic subsets match
    1 - subsets differ; a unified diff of the projected form is
        written to stderr
    2 - usage error (bad argument count, unreadable file,
        malformed JSON, missing required field)
"""

from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path
from typing import Any


class InputError(Exception):
    """Bad diff input or malformed envelope."""


def _load(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as err:
        raise InputError(f"could not read {path}: {err}") from err
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        raise InputError(f"malformed JSON in {path}: {err}") from err
    if not isinstance(parsed, dict):
        raise InputError(f"{path} root must be a JSON object")
    return parsed


def _project(envelope: dict[str, Any], label: str) -> dict[str, Any]:
    """Project an envelope to the semantic subset."""
    if "summary" not in envelope or not isinstance(envelope["summary"], dict):
        raise InputError(f"{label} missing summary object")
    if "exit_code" not in envelope:
        raise InputError(f"{label} missing exit_code")
    if "results" not in envelope or not isinstance(envelope["results"], list):
        raise InputError(f"{label} missing results array")
    summary = envelope["summary"]
    for field in ("total", "passed", "failed", "all_passed", "diagnostic"):
        if field not in summary:
            raise InputError(f"{label}.summary missing {field}")
    projected_results: list[dict[str, Any]] = []
    for i, r in enumerate(envelope["results"]):
        if not isinstance(r, dict):
            raise InputError(f"{label}.results[{i}] is not an object")
        for field in ("id", "passed", "reason_code"):
            if field not in r:
                raise InputError(f"{label}.results[{i}] missing {field}")
        projected_results.append(
            {
                "id": r["id"],
                "passed": r["passed"],
                "reason_code": r["reason_code"],
            }
        )
    return {
        "summary": {
            "total": summary["total"],
            "passed": summary["passed"],
            "failed": summary["failed"],
            "all_passed": summary["all_passed"],
            "diagnostic": summary["diagnostic"],
        },
        "exit_code": envelope["exit_code"],
        "results": projected_results,
    }


def _canonicalize(projection: dict[str, Any]) -> str:
    """Deterministic JSON: sorted keys, LF, indented for diff readability."""
    return json.dumps(projection, sort_keys=True, indent=2) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <a.json> <b.json>", file=sys.stderr)
        return 2

    try:
        a_env = _load(Path(argv[1]))
        b_env = _load(Path(argv[2]))
        a_proj = _project(a_env, argv[1])
        b_proj = _project(b_env, argv[2])
    except InputError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    a_canon = _canonicalize(a_proj)
    b_canon = _canonicalize(b_proj)
    if a_canon == b_canon:
        return 0
    diff_lines = difflib.unified_diff(
        a_canon.splitlines(keepends=True),
        b_canon.splitlines(keepends=True),
        fromfile=argv[1],
        tofile=argv[2],
        n=3,
    )
    sys.stderr.writelines(diff_lines)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
