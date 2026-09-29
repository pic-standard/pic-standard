"""Smoke test for the MCP PIC demo.

Runs examples/mcp_pic_client_demo.py end-to-end as a subprocess and
asserts the three demo cases produce their labeled outcomes:

    1) untrusted money                                       -> BLOCKED
    2) self-declared trusted money with hash evidence        -> BLOCKED
    3) signature-backed trusted money                        -> ALLOWED

Regression guard for the strict-trust doctrine landed in v0.9.0a2
and for hash-evidence content-integrity semantics landed in v0.8.3
(#133/#134). If a future change to pipeline, evidence, keyring, or
the demo itself reintroduces the "self-declared trust + hash evidence
-> ALLOWED" pattern, or breaks the signature-backed ALLOW path, this
smoke test fails.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_CLIENT = REPO_ROOT / "examples" / "mcp_pic_client_demo.py"


@pytest.mark.skipif(
    importlib.util.find_spec("mcp") is None,
    reason="mcp package not installed",
)
@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography not installed (required for signature evidence)",
)
def test_mcp_demo_three_cases_produce_expected_labels() -> None:
    result = subprocess.run(
        [sys.executable, str(DEMO_CLIENT)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    stdout = result.stdout

    assert result.returncode == 0, (
        f"demo exited non-zero: {result.returncode}\nstdout:\n{stdout}\nstderr:\n{result.stderr}"
    )

    assert "FAIL:" not in stdout, (
        f"MCP demo reported at least one FAIL. stdout:\n{stdout}\nstderr:\n{result.stderr}"
    )

    for expected_label in (
        "1) untrusted money -> should be BLOCKED",
        "2) self-declared trusted money with hash evidence -> should be BLOCKED",
        "3) signature-backed trusted money -> should be ALLOWED",
    ):
        assert expected_label in stdout, (
            f"expected demo section not found: {expected_label!r}\nstdout:\n{stdout}"
        )

    blocked_count = stdout.count("PASS: blocked as expected")
    allowed_count = stdout.count("PASS: allowed as expected")
    assert blocked_count == 2, (
        f"expected exactly 2 blocked-PASS lines, got {blocked_count}. stdout:\n{stdout}"
    )
    assert allowed_count == 1, (
        f"expected exactly 1 allowed-PASS line, got {allowed_count}. stdout:\n{stdout}"
    )


def test_mcp_demo_main_exits_1_when_print_pic_returns_false() -> None:
    """Regression: main() exits with code 1 when _print_pic reports FAIL.

    Stubs demo.run to call _print_pic once with an unparseable response
    and return its result. Asserts subprocess exit code is 1 and FAIL:
    appears in stdout.

    Scope: proves the _print_pic-returns-False and main-translates-False-
    to-sys.exit(1) links. Does NOT prove that the real three-case run()
    aggregates results across cases; the aggregation test below covers
    that.
    """
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("mcp package not installed")

    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "REPO_ROOT = Path.cwd()\n"
        'sys.path.insert(0, str(REPO_ROOT / "examples"))\n'
        'sys.path.insert(0, str(REPO_ROOT / "sdk-python"))\n'
        "import mcp_pic_client_demo as demo\n"
        "class UnparseableResp:\n"
        "    structuredContent = None\n"
        "    content = []\n"
        "async def stub_run():\n"
        "    return demo._print_pic(UnparseableResp(), expect_block=True)\n"
        "demo.run = stub_run\n"
        "demo.main()\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1, (
        f"expected exit code 1 when _print_pic reports FAIL, got {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "FAIL:" in result.stdout, f"expected FAIL: in stdout, got:\n{result.stdout}"


def test_mcp_demo_real_run_aggregates_first_case_failure_across_all_three() -> None:
    """Regression: real run() aggregates a case-1 failure and still executes
    cases 2 and 3, then main() exits 1.

    Patches _extract_pic_envelope to return None for its first invocation
    (forcing case 1 to print FAIL:), then delegates normally for the
    remaining invocations. Verifies:
      - All three case labels appear in stdout (no short-circuit).
      - Case 1 printed the unparseable-envelope FAIL: line.
      - Cases 2 and 3 still produced their expected PASS lines.
      - The process exited with code 1.

    Directly protects the aggregation contract: one real failing case
    aggregates into a non-zero shell exit without swallowing the rest.
    """
    if importlib.util.find_spec("mcp") is None:
        pytest.skip("mcp package not installed")
    if importlib.util.find_spec("cryptography") is None:
        pytest.skip("cryptography not installed (required for signature evidence)")

    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "REPO_ROOT = Path.cwd()\n"
        'sys.path.insert(0, str(REPO_ROOT / "examples"))\n'
        'sys.path.insert(0, str(REPO_ROOT / "sdk-python"))\n'
        "import mcp_pic_client_demo as demo\n"
        "_orig = demo._extract_pic_envelope\n"
        "_state = {'calls': 0}\n"
        "def _patched(resp):\n"
        "    _state['calls'] += 1\n"
        "    if _state['calls'] == 1:\n"
        "        return None\n"
        "    return _orig(resp)\n"
        "demo._extract_pic_envelope = _patched\n"
        "demo.main()\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    stdout = result.stdout

    assert result.returncode == 1, (
        f"expected exit code 1 for a real-run first-case FAIL, got {result.returncode}\nstdout:\n{stdout}\nstderr:\n{result.stderr}"
    )

    for expected_label in (
        "1) untrusted money -> should be BLOCKED",
        "2) self-declared trusted money with hash evidence -> should be BLOCKED",
        "3) signature-backed trusted money -> should be ALLOWED",
    ):
        assert expected_label in stdout, (
            f"expected case label {expected_label!r} missing: cases 2/3 must still run after case 1 fails.\nstdout:\n{stdout}"
        )

    assert "FAIL: could not parse PIC envelope from MCP response" in stdout, (
        f"expected patched case 1 FAIL: line in stdout:\n{stdout}"
    )

    assert stdout.count("PASS: blocked as expected") == 1, (
        f"expected exactly 1 blocked-PASS (case 2 only, since case 1 was patched to fail), got {stdout.count('PASS: blocked as expected')}. stdout:\n{stdout}"
    )
    assert stdout.count("PASS: allowed as expected") == 1, (
        f"expected exactly 1 allowed-PASS (case 3), got {stdout.count('PASS: allowed as expected')}. stdout:\n{stdout}"
    )
