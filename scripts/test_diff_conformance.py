"""Self-tests for scripts/diff_conformance.py.

Constructs minimal envelope pairs in a temp dir, calls the imported
`main()` directly, and asserts exit codes. Pins the projection
contract independently of real runner output so a subtle projection
mistake cannot hide behind a passing integration diff.

Usage:
    python scripts/test_diff_conformance.py

Or from repo root:
    python -m unittest scripts.test_diff_conformance
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

# Ensure the diff script is importable regardless of cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from diff_conformance import main as diff_main


def _envelope(*, results, summary_overrides=None, exit_code=0):
    """Build a minimal valid envelope around the given results list."""
    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.get("passed")),
        "failed": sum(1 for r in results if not r.get("passed")),
        "all_passed": (all(r.get("passed") for r in results) if results else True),
        "diagnostic": None,
        "message": None,
    }
    if summary_overrides:
        summary.update(summary_overrides)
    return {
        "manifest_version": "conformance/v0.1",
        "selection": {
            "total_in_manifest": len(results),
            "selected": len(results),
            "filter_modes": [],
            "filter_ids": [],
        },
        "results": results,
        "summary": summary,
        "exit_code": exit_code,
    }


def _result(*, vector_id, passed=True, reason_code=None, message=None, mode="core"):
    return {
        "id": vector_id,
        "mode": mode,
        "passed": passed,
        "reason_code": reason_code,
        "message": message,
    }


class DiffConformanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, data):
        p = self.tmp_path / name
        p.write_text(json.dumps(data), encoding="utf-8")
        return str(p)

    def _run_argv(self, argv):
        """Call diff_main with stderr captured; return exit code."""
        buf = io.StringIO()
        with redirect_stderr(buf):
            return diff_main(argv)

    def _run_diff(self, a, b):
        return self._run_argv(["prog", a, b])

    # --- 1. Same semantic subset -> exit 0 -------------------------------

    def test_identical_envelopes_match(self):
        env = _envelope(
            results=[
                _result(vector_id="canon-001", passed=True),
                _result(vector_id="core-001", passed=True),
            ]
        )
        a = self._write("a.json", env)
        b = self._write("b.json", env)
        self.assertEqual(0, self._run_diff(a, b))

    def test_different_message_only_still_matches(self):
        """Freeform message differences are excluded from the projection."""
        a_env = _envelope(
            results=[
                _result(
                    vector_id="c1",
                    passed=False,
                    reason_code="verdict_mismatch",
                    message="py phrasing",
                ),
            ]
        )
        b_env = _envelope(
            results=[
                _result(
                    vector_id="c1",
                    passed=False,
                    reason_code="verdict_mismatch",
                    message="ts phrasing",
                ),
            ]
        )
        a_env["summary"]["message"] = "py summary text"
        b_env["summary"]["message"] = "ts summary text"
        a = self._write("a.json", a_env)
        b = self._write("b.json", b_env)
        self.assertEqual(0, self._run_diff(a, b))

    def test_different_selection_and_manifest_version_still_matches(self):
        """selection and manifest_version are outside the projection."""
        a_env = _envelope(results=[_result(vector_id="c1", passed=True)])
        b_env = _envelope(results=[_result(vector_id="c1", passed=True)])
        a_env["manifest_version"] = "conformance/v0.1"
        b_env["manifest_version"] = "conformance/v0.2"
        a_env["selection"]["filter_modes"] = ["canonicalization"]
        b_env["selection"]["filter_modes"] = []
        a = self._write("a.json", a_env)
        b = self._write("b.json", b_env)
        self.assertEqual(0, self._run_diff(a, b))

    def test_different_result_mode_still_matches(self):
        """results[].mode is not part of the semantic diff contract."""
        a_env = _envelope(results=[_result(vector_id="c1", passed=True, mode="core")])
        b_env = _envelope(results=[_result(vector_id="c1", passed=True, mode="trust_sanitization")])
        a = self._write("a.json", a_env)
        b = self._write("b.json", b_env)
        self.assertEqual(0, self._run_diff(a, b))

    # --- 2. Projected differences -> exit 1 ------------------------------

    def test_different_reason_code_diffs(self):
        a_env = _envelope(
            results=[
                _result(
                    vector_id="c1", passed=False, reason_code="verdict_mismatch", message="text a"
                ),
            ]
        )
        b_env = _envelope(
            results=[
                _result(
                    vector_id="c1",
                    passed=False,
                    reason_code="error_code_mismatch",
                    message="text b",
                ),
            ]
        )
        a = self._write("a.json", a_env)
        b = self._write("b.json", b_env)
        self.assertEqual(1, self._run_diff(a, b))

    def test_different_result_order_diffs(self):
        r1 = _result(vector_id="c1", passed=True)
        r2 = _result(vector_id="c2", passed=True)
        a = self._write("a.json", _envelope(results=[r1, r2]))
        b = self._write("b.json", _envelope(results=[r2, r1]))
        self.assertEqual(1, self._run_diff(a, b))

    def test_different_passed_diffs(self):
        a = self._write("a.json", _envelope(results=[_result(vector_id="c1", passed=True)]))
        b = self._write(
            "b.json",
            _envelope(
                results=[
                    _result(
                        vector_id="c1",
                        passed=False,
                        reason_code="verdict_mismatch",
                        message="failed",
                    )
                ]
            ),
        )
        self.assertEqual(1, self._run_diff(a, b))

    def test_different_exit_code_diffs(self):
        r = [_result(vector_id="c1", passed=True)]
        a = self._write("a.json", _envelope(results=r, exit_code=0))
        b = self._write("b.json", _envelope(results=r, exit_code=1))
        self.assertEqual(1, self._run_diff(a, b))

    def test_different_summary_diagnostic_diffs(self):
        a_env = _envelope(results=[], exit_code=2)
        a_env["summary"]["diagnostic"] = "no_vectors_selected"
        b_env = _envelope(results=[], exit_code=2)
        b_env["summary"]["diagnostic"] = "manifest_invalid"
        a = self._write("a.json", a_env)
        b = self._write("b.json", b_env)
        self.assertEqual(1, self._run_diff(a, b))

    # --- 3. Malformed / missing input -> exit 2 --------------------------

    def test_missing_summary_returns_2(self):
        bad = {"exit_code": 0, "results": []}
        a = self._write("bad.json", bad)
        b = self._write("good.json", _envelope(results=[]))
        self.assertEqual(2, self._run_diff(a, b))

    def test_missing_summary_field_returns_2(self):
        env = _envelope(results=[])
        del env["summary"]["diagnostic"]
        a = self._write("a.json", env)
        b = self._write("b.json", _envelope(results=[]))
        self.assertEqual(2, self._run_diff(a, b))

    def test_missing_result_field_returns_2(self):
        env = _envelope(
            results=[
                {"id": "c1", "mode": "core", "passed": True, "message": None}
                # reason_code missing
            ]
        )
        a = self._write("a.json", env)
        b = self._write("b.json", _envelope(results=[]))
        self.assertEqual(2, self._run_diff(a, b))

    def test_malformed_json_returns_2(self):
        p = self.tmp_path / "bad.json"
        p.write_text("{ not valid", encoding="utf-8")
        b = self._write("b.json", _envelope(results=[]))
        self.assertEqual(2, self._run_diff(str(p), b))

    def test_missing_file_returns_2(self):
        missing = str(self.tmp_path / "does-not-exist.json")
        b = self._write("b.json", _envelope(results=[]))
        self.assertEqual(2, self._run_diff(missing, b))

    def test_wrong_arg_count_returns_2(self):
        self.assertEqual(2, self._run_argv(["prog"]))
        self.assertEqual(2, self._run_argv(["prog", "a.json"]))
        self.assertEqual(2, self._run_argv(["prog", "a.json", "b.json", "extra"]))


if __name__ == "__main__":
    unittest.main()
