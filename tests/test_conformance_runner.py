"""Subprocess-based CLI tests for ``conformance/run.py`` (v0.8.2 PR V8.2-3 commit 4).

The 10 cases below are locked by the PR V8.2-3 design checkpoint §6. Each
test invokes ``python -m conformance.run`` via :mod:`subprocess` so the
real CLI surface (argparse, exit codes, stdout/stderr routing) is
exercised rather than the in-process Python API.

Counts are derived dynamically from the manifest where possible so the
suite tolerates future vector additions — tests assert the right SET is
selected, not hardcoded counts. The single exception is the default
human-mode test, which pins ``Vectors: {total}`` and
``Summary: {total}/{total} passed`` explicitly to catch a runner that
silently selects a partial manifest while still emitting a passing
summary.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Repo root — used both for cwd of subprocess invocations and for reading
# the canonical manifest in count-derivation helpers. tests/ is one level
# under the repo root, so parent.parent resolves correctly.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST_PATH = _REPO_ROOT / "conformance" / "manifest.json"

# Subprocess timeout (seconds). A broken runner should fail fast rather
# than hang CI. 60s is generous — the full 51-vector run takes <1s
# locally and the temp-manifest tests are even smaller.
_SUBPROCESS_TIMEOUT_SECONDS = 60


def _run_runner(args: list[str]) -> tuple[int, bytes, bytes]:
    """Invoke ``python -m conformance.run <args>`` and return (rc, stdout_bytes, stderr_bytes).

    Subprocess-based per design checkpoint §6 — tests exercise the real
    CLI surface (argparse, exit codes, output streams) rather than
    ``conformance.run.main`` in-process. ``text=False`` captures raw
    bytes so JSON parsing is unaffected by the test host's stdout
    encoding (Windows PowerShell vs POSIX shells write different
    encodings for redirected stdout — subprocess.run sidesteps that).

    Subprocess has a hard timeout to keep a hung runner from hanging CI.
    """
    r = subprocess.run(
        [sys.executable, "-m", "conformance.run", *args],
        capture_output=True,
        text=False,
        cwd=str(_REPO_ROOT),
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    return r.returncode, r.stdout, r.stderr


def _run_json(args: list[str], *, expected_rc: int = 0) -> dict:
    """Invoke ``python -m conformance.run --json <args>``, assert contract, return parsed envelope.

    Centralizes the ``--json`` no-mixed-output contract: every JSON
    invocation MUST exit with the expected code AND write nothing to
    stderr (per PR V8.2-3 design checkpoint §2 — JSON consumers parse
    a single stream). The helper asserts both invariants before
    returning, so callers don't need to repeat the boilerplate.
    """
    rc, out, err = _run_runner(["--json", *args])
    assert rc == expected_rc, f"expected exit {expected_rc}, got {rc}; stderr={err!r}"
    assert err == b"", f"--json must not write stderr, got {err!r}"
    return json.loads(out)


def _load_manifest() -> dict:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _count_by_mode(mode: str) -> int:
    return sum(1 for e in _load_manifest()["vectors"] if e["mode"] == mode)


# ---------------------------------------------------------------------------
# §6 case 1: default no-arg run → exits 0, full manifest selected and passed
# ---------------------------------------------------------------------------


def test_default_invocation_all_pass():
    """Default invocation: full manifest selected, all selected vectors
    pass, exit 0, stderr empty.

    The Summary line is pinned to ``{total}/{total} passed`` explicitly
    so a runner that accidentally selected a partial manifest (e.g. a
    filter regression that defaulted to non-empty filter set) couldn't
    pass this test by emitting a smaller but still-all-pass summary.
    """
    total = len(_load_manifest()["vectors"])

    rc, out, err = _run_runner([])
    assert rc == 0, f"expected exit 0, got {rc}; stderr={err!r}"
    assert err == b"", f"expected empty stderr, got {err!r}"
    text = out.decode("utf-8")

    # Header pins the count of vectors the runner actually iterated.
    assert f"Vectors:          {total}" in text, (
        f"expected header 'Vectors:          {total}' in output; got:\n{text}"
    )
    # Final summary pins the exact pass count.
    assert f"Summary: {total}/{total} passed" in text, (
        f"expected 'Summary: {total}/{total} passed' in output; got:\n{text}"
    )
    # All-pass form has no '(N failed)' suffix per HumanRenderer's
    # contract — defensively check the runner doesn't emit '(0 failed)'.
    assert "(0 failed)" not in text


# ---------------------------------------------------------------------------
# §6 case 2: --json no filter → valid JSON envelope, all fields per §2 lock
# ---------------------------------------------------------------------------


def test_json_no_filter_envelope_shape():
    d = _run_json([])

    manifest = _load_manifest()
    total = len(manifest["vectors"])

    # Top-level envelope.
    assert d["manifest_version"] == manifest["version"]
    assert d["exit_code"] == 0

    # Selection block: no filters set → all manifest entries selected.
    assert d["selection"]["total_in_manifest"] == total
    assert d["selection"]["selected"] == total
    assert d["selection"]["filter_modes"] == []
    assert d["selection"]["filter_ids"] == []

    # Results: one per selected vector; all-pass run → reason_code/message
    # are None per the "iff passed" contract.
    assert len(d["results"]) == total
    for r in d["results"]:
        assert set(r.keys()) == {"id", "mode", "passed", "reason_code", "message"}
        assert r["passed"] is True
        assert r["reason_code"] is None
        assert r["message"] is None

    # Summary block.
    assert d["summary"]["total"] == total
    assert d["summary"]["passed"] == total
    assert d["summary"]["failed"] == 0
    assert d["summary"]["all_passed"] is True
    assert d["summary"]["diagnostic"] is None
    assert d["summary"]["message"] is None


# ---------------------------------------------------------------------------
# §6 case 3: --filter-mode evidence → selects only evidence vectors
# ---------------------------------------------------------------------------


def test_filter_mode_evidence_selects_only_evidence():
    d = _run_json(["--filter-mode", "evidence"])

    expected_count = _count_by_mode("evidence")
    assert expected_count > 0, "manifest has no evidence vectors; test is vacuous"

    assert d["selection"]["filter_modes"] == ["evidence"]
    assert d["selection"]["selected"] == expected_count
    assert len(d["results"]) == expected_count
    assert all(r["mode"] == "evidence" for r in d["results"])
    assert all(r["passed"] for r in d["results"])


# ---------------------------------------------------------------------------
# §6 case 4: same-kind union via two --filter-mode flags
# ---------------------------------------------------------------------------


def test_filter_mode_union_canonicalization_core():
    d = _run_json(["--filter-mode", "canonicalization", "--filter-mode", "core"])

    expected_count = _count_by_mode("canonicalization") + _count_by_mode("core")
    assert d["selection"]["filter_modes"] == ["canonicalization", "core"]
    assert d["selection"]["selected"] == expected_count
    assert len(d["results"]) == expected_count
    modes = {r["mode"] for r in d["results"]}
    assert modes == {"canonicalization", "core"}


# ---------------------------------------------------------------------------
# §6 case 5: --filter-id <single existing> → selects exactly that vector
# ---------------------------------------------------------------------------


def test_filter_id_single_known():
    target_id = "canon-001-basic-object"
    d = _run_json(["--filter-id", target_id])

    assert d["selection"]["filter_ids"] == [target_id]
    assert d["selection"]["selected"] == 1
    assert len(d["results"]) == 1
    assert d["results"][0]["id"] == target_id
    assert d["results"][0]["passed"] is True


# ---------------------------------------------------------------------------
# §6 case 6: --filter-id <unknown> → exit 2 + no_vectors_selected
# ---------------------------------------------------------------------------


def test_filter_id_unknown_no_vectors_selected():
    d = _run_json(["--filter-id", "DOES_NOT_EXIST"], expected_rc=2)

    assert d["summary"]["diagnostic"] == "no_vectors_selected"
    assert d["summary"]["all_passed"] is False
    assert d["results"] == []
    assert d["selection"]["filter_ids"] == ["DOES_NOT_EXIST"]
    assert d["selection"]["selected"] == 0
    assert d["exit_code"] == 2
    assert isinstance(d["summary"]["message"], str)
    assert "DOES_NOT_EXIST" in d["summary"]["message"]


# ---------------------------------------------------------------------------
# §6 case 7: --filter-mode <unknown> (typo case) → exit 2 + no_vectors_selected
# ---------------------------------------------------------------------------


def test_filter_mode_unknown_no_vectors_selected():
    """A typo'd mode name like 'evidance' must trip exit 2 — silent green
    on misspelled CI filters would be dangerous."""
    d = _run_json(["--filter-mode", "evidance"], expected_rc=2)

    assert d["summary"]["diagnostic"] == "no_vectors_selected"
    assert d["selection"]["filter_modes"] == ["evidance"]
    assert d["selection"]["selected"] == 0
    assert d["exit_code"] == 2


# ---------------------------------------------------------------------------
# §6 case 8: cross-kind union (--filter-mode + --filter-id together)
# ---------------------------------------------------------------------------


def test_filter_cross_kind_union():
    d = _run_json(
        [
            "--filter-mode",
            "evidence",
            "--filter-id",
            "canon-001-basic-object",
        ]
    )

    selected_ids = {r["id"] for r in d["results"]}

    # Union must include the explicit canon-001 id.
    assert "canon-001-basic-object" in selected_ids

    # Union must include every evidence-mode vector currently in the manifest.
    manifest = _load_manifest()
    expected_evidence_ids = {v["id"] for v in manifest["vectors"] if v["mode"] == "evidence"}
    assert expected_evidence_ids, "manifest has no evidence vectors; test is vacuous"
    assert expected_evidence_ids.issubset(selected_ids)

    # And the union should be exactly evidence-mode | {canon-001-basic-object}.
    assert selected_ids == expected_evidence_ids | {"canon-001-basic-object"}


# ---------------------------------------------------------------------------
# §6 case 9: failure path via temp manifest → reason_code populated under --json
# ---------------------------------------------------------------------------


def test_failing_vector_populates_reason_code(tmp_path: Path):
    """Lock the §3 taxonomy population: a failing vector exposes a
    non-null ``reason_code`` and ``message`` per the JsonRenderer
    contract.

    Constructed scenario: vector expects allow but the proposal will be
    blocked by the verifier (untrusted-only provenance on money impact),
    so the runner emits ``reason_code='verdict_mismatch'``.
    """
    vec = {
        "id": "test-verdict-mismatch",
        "mode": "core",
        "expected": "allow",
        "proposal": {
            "protocol": "PIC/1.0",
            "intent": "force a verdict mismatch",
            "impact": "money",
            "provenance": [{"id": "untrusted_only", "trust": "untrusted"}],
            "claims": [{"text": "x", "evidence": ["untrusted_only"]}],
            "action": {"tool": "test.tool", "args": {}},
        },
    }
    (tmp_path / "test_vector.json").write_text(json.dumps(vec), encoding="utf-8")
    manifest = {
        "version": "conformance/v0.1",
        "vectors": [
            {
                "id": "test-verdict-mismatch",
                "file": "test_vector.json",
                "mode": "core",
                "expected": "allow",
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    d = _run_json(["--manifest", str(manifest_path)], expected_rc=1)

    assert len(d["results"]) == 1
    r0 = d["results"][0]
    assert r0["passed"] is False
    assert r0["reason_code"] == "verdict_mismatch"
    assert isinstance(r0["message"], str)
    assert len(r0["message"]) > 0


# ---------------------------------------------------------------------------
# §6 case 10: exit-code stability under filter (temp manifest, 1 pass + 1 fail)
# ---------------------------------------------------------------------------


def test_filter_isolates_passing_vector_from_unselected_failure(tmp_path: Path):
    """Lock the §5 exit-code stability contract: a filter that selects
    only passing vectors exits 0 even when other (unselected) vectors
    in the manifest would have failed.

    Constructed scenario: a temp manifest with one passing vector and
    one intentionally failing vector. Baseline full run exits 1 (the
    failure counts); filtered run targeting only the passing id exits 0.
    """
    passing_vec = {
        "id": "test-passing",
        "mode": "core",
        "expected": "allow",
        "proposal": {
            "protocol": "PIC/1.0",
            "intent": "read only",
            "impact": "read",
            "provenance": [{"id": "src", "trust": "trusted"}],
            "claims": [{"text": "x", "evidence": ["src"]}],
            "action": {"tool": "docs_search", "args": {}},
        },
    }
    failing_vec = {
        "id": "test-failing",
        "mode": "core",
        "expected": "allow",
        "proposal": {
            "protocol": "PIC/1.0",
            "intent": "will fail",
            "impact": "money",
            "provenance": [{"id": "untrusted_only", "trust": "untrusted"}],
            "claims": [{"text": "x", "evidence": ["untrusted_only"]}],
            "action": {"tool": "test.tool", "args": {}},
        },
    }
    (tmp_path / "passing.json").write_text(json.dumps(passing_vec), encoding="utf-8")
    (tmp_path / "failing.json").write_text(json.dumps(failing_vec), encoding="utf-8")
    manifest = {
        "version": "conformance/v0.1",
        "vectors": [
            {"id": "test-passing", "file": "passing.json", "mode": "core", "expected": "allow"},
            {"id": "test-failing", "file": "failing.json", "mode": "core", "expected": "allow"},
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    # Baseline: running ALL vectors must fail (proves the failing vector
    # really does fail, so the filtered-pass result is meaningful). We
    # don't inspect the envelope here; just confirm the exit code.
    _run_json(["--manifest", str(manifest_path)], expected_rc=1)

    # Filtered run: only the passing vector → exit 0.
    d = _run_json(
        [
            "--manifest",
            str(manifest_path),
            "--filter-id",
            "test-passing",
        ]
    )

    assert d["selection"]["selected"] == 1
    assert len(d["results"]) == 1
    assert d["results"][0]["id"] == "test-passing"
    assert d["results"][0]["passed"] is True
    assert d["summary"]["all_passed"] is True
    assert d["exit_code"] == 0
