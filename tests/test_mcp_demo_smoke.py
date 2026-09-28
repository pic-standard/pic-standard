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
