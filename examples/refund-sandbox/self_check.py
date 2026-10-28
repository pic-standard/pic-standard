"""Self-check: proves run_cases.py detects deliberately broken behavior.

Run in the pinned environment:
    python self_check.py

Each probe runs run_cases.main() in-process with a temporary report path
and, where needed, temporary expectations, after injecting one deliberate
fault into pic_result.py through a patch that is restored afterwards. A
probe passes only when the runner returns the expected exit code, leaves
the expected report status and names the expected problem. A green
run_cases.py result shows the adapter passes; these probes show the
harness would catch these specific faults. They do not prove that every
possible fault is detected.

Exit codes: 0 every declared probe ran and behaved as expected; 1 a probe
misbehaved, the probe registry did not match the declared list, or
run_cases.py could not be loaded.

Probes read the committed expectations and work on temporary copies; no
source, expectation, key or installed file is modified.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
EXPECTED_PATH = HERE / "fixtures" / "expected-outcomes.json"

# Declared independently of the registry, so a lost or renamed probe fails the run.
EXPECTED_PROBES = (
    "baseline",
    "corrupted_file_ref",
    "malformed_timestamp",
    "out_of_bounds_timestamp",
    "unexpected_native_call",
    "unexpected_file_read",
    "missing_expectation",
    "duplicate_expectation",
    "root_not_object",
    "cases_null",
    "case_entry_empty",
    "boolean_exit_code",
    "report_aliases_expectations",
    "stale_pass_replaced",
)

MODULES: Dict[str, Any] = {}
PROBES: Dict[str, Callable[[Path], List[str]]] = {}


def probe(name: str) -> Callable[[Callable[[Path], List[str]]], Callable[[Path], List[str]]]:
    def register(fn: Callable[[Path], List[str]]) -> Callable[[Path], List[str]]:
        if name in PROBES:
            raise ValueError(f"duplicate probe name {name}")
        PROBES[name] = fn
        return fn

    return register


def _load() -> None:
    """Import pic_result first so run_cases patches and uses the same module object."""
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import pic_result
    import run_cases

    MODULES["pr"], MODULES["rc"] = pic_result, run_cases


def run(
    tmp: Path,
    *,
    cases: Optional[List[str]] = None,
    expectations: Optional[Path] = None,
    report: Optional[Path] = None,
    patches: tuple = (),
) -> Dict[str, Any]:
    report = report or tmp / "report.json"
    argv = ["--report", str(report)]
    if expectations is not None:
        argv += ["--expectations", str(expectations)]
    for case_id in cases or []:
        argv += ["--case", case_id]
    output = io.StringIO()
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = MODULES["rc"].main(argv)
    try:
        written = json.loads(report.read_text("utf-8"))
    except (OSError, ValueError):
        written = None
    return {"exit": code, "report": written, "text": output.getvalue()}


def check(result: Dict[str, Any], exit_code: int, status: Optional[str], needle: str) -> List[str]:
    failures = []
    if result["exit"] != exit_code:
        failures.append(f"exit {result['exit']}, expected {exit_code}")
    got_status = result["report"].get("status") if isinstance(result["report"], dict) else None
    if got_status != status:
        failures.append(f"report status {got_status!r}, expected {status!r}")
    if needle not in result["text"]:
        failures.append(f"output does not mention {needle!r}")
    return failures


def expectations_with(tmp: Path, edit: Callable[[Any], Any]) -> Path:
    """Copy of the committed expectations after one deliberate edit.

    An editor may change the data in place and return None, or return a
    replacement value; any non-None replacement is used, including [] or {}.
    """
    data = json.loads(EXPECTED_PATH.read_text("utf-8"))
    edited = edit(data)
    if edited is not None:
        data = edited
    path = tmp / "expectations.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _drop_a01(data: Dict[str, Any]) -> None:
    data["cases"] = [c for c in data["cases"] if c["id"] != "a01_valid_allow"]


def _duplicate_a01(data: Dict[str, Any]) -> None:
    data["cases"].append(dict(data["cases"][0]))


def _boolean_exit_code(data: Dict[str, Any]) -> None:
    data["cases"][0]["exit_code"] = False


# ----------------------------------------------------------------------------
# Probes.
# ----------------------------------------------------------------------------


@probe("baseline")
def _baseline(tmp: Path) -> List[str]:
    return check(run(tmp, cases=["a01_valid_allow"]), 0, "passed", "PASS a01_valid_allow")


@probe("corrupted_file_ref")
def _corrupted_file_ref(tmp: Path) -> List[str]:
    patch = MODULES["rc"].patched(MODULES["pr"], "file_ref", lambda data: "sha256:" + "0" * 64)
    result = run(tmp, cases=["a01_valid_allow"], patches=(patch,))
    return check(result, 1, "failed", "file-refs-wrong")


@probe("malformed_timestamp")
def _malformed_timestamp(tmp: Path) -> List[str]:
    patch = MODULES["rc"].patched(
        MODULES["pr"], "utc_millis_ceil", lambda now: "2026-13-45T99:99:99.999Z"
    )
    result = run(tmp, cases=["a01_valid_allow"], patches=(patch,))
    return check(result, 1, "failed", "evaluated-at")


@probe("out_of_bounds_timestamp")
def _out_of_bounds_timestamp(tmp: Path) -> List[str]:
    patch = MODULES["rc"].patched(
        MODULES["pr"], "utc_millis_ceil", lambda now: "2000-01-01T00:00:00.000Z"
    )
    result = run(tmp, cases=["a01_valid_allow"], patches=(patch,))
    return check(result, 1, "failed", "evaluated-at")


@probe("unexpected_native_call")
def _unexpected_native_call(tmp: Path) -> List[str]:
    patch = MODULES["rc"].patched(MODULES["pr"], "preflight_evidence", lambda proposal: {})
    result = run(tmp, cases=["d01_missing_evidence"], patches=(patch,))
    return check(result, 1, "failed", "native_calls: expected 0, got 1")


@probe("unexpected_file_read")
def _unexpected_file_read(tmp: Path) -> List[str]:
    original = MODULES["pr"].native_verify
    (tmp / "probe-evidence.bin").write_bytes(b"probe")

    def reading_verify(proposal: Any, keyring: Any) -> Any:
        evidence = sys.modules["pic_standard.evidence"]
        evidence._read_sandboxed_file(
            "file://probe-evidence.bin", base_dir=tmp, evidence_root_dir=tmp, max_file_bytes=64
        )
        return original(proposal, keyring)

    patch = MODULES["rc"].patched(MODULES["pr"], "native_verify", reading_verify)
    result = run(tmp, cases=["a01_valid_allow"], patches=(patch,))
    return check(result, 1, "failed", "file_reads: expected 0, got 1")


@probe("missing_expectation")
def _missing_expectation(tmp: Path) -> List[str]:
    result = run(tmp, expectations=expectations_with(tmp, _drop_a01))
    return check(result, 2, "not-run", "registered cases without expectations")


@probe("duplicate_expectation")
def _duplicate_expectation(tmp: Path) -> List[str]:
    result = run(tmp, expectations=expectations_with(tmp, _duplicate_a01))
    return check(result, 2, "not-run", "duplicate ids")


@probe("root_not_object")
def _root_not_object(tmp: Path) -> List[str]:
    result = run(tmp, expectations=expectations_with(tmp, lambda data: []))
    return check(result, 2, "not-run", "expectations must be an object")


@probe("cases_null")
def _cases_null(tmp: Path) -> List[str]:
    result = run(tmp, expectations=expectations_with(tmp, lambda data: {**data, "cases": None}))
    return check(result, 2, "not-run", "cases must be a nonempty list")


@probe("case_entry_empty")
def _case_entry_empty(tmp: Path) -> List[str]:
    result = run(tmp, expectations=expectations_with(tmp, lambda data: {**data, "cases": [{}]}))
    return check(result, 2, "not-run", "invalid id None")


@probe("boolean_exit_code")
def _boolean_exit_code_probe(tmp: Path) -> List[str]:
    result = run(tmp, expectations=expectations_with(tmp, _boolean_exit_code))
    return check(result, 2, "not-run", "exit_code must be the integer")


@probe("report_aliases_expectations")
def _report_aliases_expectations(tmp: Path) -> List[str]:
    """Aliasing is exercised on a temporary copy, never on the committed file."""
    committed_before = _sha256(EXPECTED_PATH)
    copy = tmp / "expectations-copy.json"
    shutil.copyfile(EXPECTED_PATH, copy)
    copy_before = _sha256(copy)
    result = run(tmp, expectations=copy, report=copy)
    failures = []
    if result["exit"] != 2:
        failures.append(f"exit {result['exit']}, expected 2")
    if "report path is the expectations file" not in result["text"]:
        failures.append("output does not name the aliasing")
    if not copy.exists() or _sha256(copy) != copy_before:
        failures.append("temporary expectations copy was deleted or changed")
    if _sha256(EXPECTED_PATH) != committed_before:
        failures.append("committed expectations changed")
    return failures


@probe("stale_pass_replaced")
def _stale_pass_replaced(tmp: Path) -> List[str]:
    report = tmp / "report.json"
    stale = {"report_format": MODULES["rc"].REPORT_FORMAT, "status": "passed"}
    report.write_text(json.dumps(stale) + "\n", encoding="utf-8")
    result = run(tmp, expectations=expectations_with(tmp, _drop_a01), report=report)
    return check(result, 2, "not-run", "registered cases without expectations")


# ----------------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------------


def registry_problems() -> List[str]:
    if not PROBES:
        return ["no probes are registered"]
    problems = []
    missing = sorted(set(EXPECTED_PROBES) - set(PROBES))
    unexpected = sorted(set(PROBES) - set(EXPECTED_PROBES))
    if missing:
        problems.append(f"declared probes not registered: {missing}")
    if unexpected:
        problems.append(f"registered probes not declared: {unexpected}")
    return problems


def main() -> int:
    problems = registry_problems()
    if problems:
        for problem in problems:
            print(f"self_check: {problem}", file=sys.stderr)
        return 1
    try:
        _load()
    except Exception as e:
        print(f"self_check: cannot load run_cases.py: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    failed = 0
    for name in EXPECTED_PROBES:
        with tempfile.TemporaryDirectory(prefix="refund-sandbox-self-check-") as tmp:
            try:
                failures = PROBES[name](Path(tmp))
            except Exception as e:
                failures = [f"probe raised {type(e).__name__}: {e}"]
        print(f"{'OK  ' if not failures else 'FAIL'} {name}")
        for failure in failures:
            print(f"     {failure}")
        failed += bool(failures)
    print(
        f"self_check: {len(EXPECTED_PROBES) - failed}/{len(EXPECTED_PROBES)} "
        "probes behaved as expected"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
