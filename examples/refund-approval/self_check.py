"""Self-check: prove the coverage gates, environment enforcement and
integrity meta-tests actually fire.

Runs test_cases.py under a series of deliberately-broken configurations
and asserts each one exits with the specific nonzero code the policy
assigns to that failure mode:

  * exit 2: coverage gap (empty / mismatched / duplicate expectations)
  * exit 3: environment mismatch (installed revision != declared pin)
  * exit 4: environment unverified (installed revision not VCS-pinned)

Also verifies a clean normal run exits 0.

Exit 0 iff every expected outcome is observed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parent
EXPECTED = PACK_ROOT / "fixtures" / "expected-outcomes.json"
RUNNER = PACK_ROOT / "test_cases.py"


def _direct_url_path() -> Path:
    """Resolve the pic-standard dist-info direct_url.json path for monkey-probes."""
    dist = distribution("pic-standard")
    files = dist.files or []
    for f in files:
        if f.name == "direct_url.json":
            return Path(dist.locate_file(f))
    # Fallback: derive from dist-info location.
    dist_info_file = next(iter(dist.files or []), None)
    if dist_info_file is None:
        raise RuntimeError("cannot locate pic-standard dist-info")
    dist_info_dir = Path(dist.locate_file(dist_info_file)).parent
    return dist_info_dir / "direct_url.json"


def _run_runner() -> int:
    result = subprocess.run(
        [sys.executable, str(RUNNER)],
        cwd=str(PACK_ROOT),
        capture_output=True,
        text=True,
    )
    return result.returncode


def _run_with_substitute_expectations(substitute: dict) -> int:
    original = EXPECTED.read_text(encoding="utf-8")
    try:
        EXPECTED.write_text(json.dumps(substitute, indent=2) + "\n", encoding="utf-8")
        return _run_runner()
    finally:
        EXPECTED.write_text(original, encoding="utf-8")


def _run_with_substitute_direct_url(substitute: object) -> int:
    """Run with a swapped direct_url.json. `substitute` is a dict (JSON) or
    None (temporarily remove the file). Always restored."""
    du_path = _direct_url_path()
    original = du_path.read_text(encoding="utf-8") if du_path.exists() else None
    try:
        if substitute is None:
            if du_path.exists():
                du_path.unlink()
        else:
            du_path.write_text(json.dumps(substitute) + "\n", encoding="utf-8")
        return _run_runner()
    finally:
        if original is None:
            if du_path.exists():
                du_path.unlink()
        else:
            du_path.write_text(original, encoding="utf-8")


def main() -> int:
    checks = []

    # Coverage gates: all expected exit 2.
    original = json.loads(EXPECTED.read_text(encoding="utf-8"))

    empty = {**original, "cases": []}
    rc = _run_with_substitute_expectations(empty)
    checks.append(("coverage: empty cases list", rc, 2, rc == 2))

    truncated = {**original, "cases": original["cases"][:-1]}
    rc = _run_with_substitute_expectations(truncated)
    checks.append(("coverage: dropped last expectation", rc, 2, rc == 2))

    dup = {**original, "cases": original["cases"] + [original["cases"][0]]}
    rc = _run_with_substitute_expectations(dup)
    checks.append(("coverage: duplicate id", rc, 2, rc == 2))

    # Environment: mismatch -> 3.
    fake_mismatch = {
        "url": "https://github.com/pic-standard/pic-standard.git",
        "vcs_info": {
            "commit_id": "0000000000000000000000000000000000000000",
            "requested_revision": "0000000000000000000000000000000000000000",
            "vcs": "git",
        },
    }
    rc = _run_with_substitute_direct_url(fake_mismatch)
    checks.append(("environment: wrong commit_id", rc, 3, rc == 3))

    # Environment: unverified -> 4.
    rc = _run_with_substitute_direct_url(None)
    checks.append(("environment: direct_url.json missing", rc, 4, rc == 4))

    # Environment: local-dir install (dir_info, no vcs_info) -> 4.
    rc = _run_with_substitute_direct_url(
        {"dir_info": {}, "url": "file:///C:/projects/pic-standard"}
    )
    checks.append(("environment: dir_info (no vcs_info)", rc, 4, rc == 4))

    # Normal: everything restored, must exit 0.
    rc = _run_runner()
    checks.append(("normal run after self-check", rc, 0, rc == 0))

    print("[self-check summary]")
    all_ok = True
    for name, rc, want, ok in checks:
        tag = "OK" if ok else "FAIL"
        print(f"  [{tag}] {name} exit={rc} (expected {want})")
        if not ok:
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
