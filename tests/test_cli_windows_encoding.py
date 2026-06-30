"""Regression test: CLI/demo runtime output must be ASCII-only.

cp1252 (the default Windows console encoding) cannot encode common Unicode
characters such as the check mark, cross mark, right arrow, em dash, en dash,
curly quotes, or ellipsis. Until issue #120, the pic-cli emitted such
characters and crashed on Windows consoles with UnicodeEncodeError.

This test asserts that representative CLI subcommands produce ASCII-only
stdout and stderr, with the expected exit code. encode("ascii") is
intentionally stricter than encode("cp1252") because cp1252 happens to
encode em dash, en dash, curly quotes, and ellipsis - so a cp1252-passing
test would still let those slip through.

Coverage: PASS path, FAIL path, and JSON-stdout path. Each asserts both
ASCII safety AND the expected exit code so a malformed invocation cannot
silently produce empty (and therefore trivially ASCII-safe) output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pic_standard.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


def assert_ascii_safe(text: str, label: str) -> None:
    """Assert that text encodes as ASCII (and therefore as cp1252 too)."""
    try:
        text.encode("ascii")
    except UnicodeEncodeError as e:
        pytest.fail(
            f"{label} contains non-ASCII characters that would crash on "
            f"cp1252 Windows consoles: {e}\n--- output ---\n{text}\n"
            f"--- end ---"
        )


def run_cli_ascii_safe(monkeypatch, capsys, tmp_path, argv, expected_exit=0):
    """Run a CLI invocation; assert ASCII safety on stdout+stderr AND exit code.

    cli_main(...) returns an int directly under normal operation. argparse
    may raise SystemExit for --help or bad flags; handle that defensively.
    Non-int SystemExit codes are a contract violation and fail the test
    rather than silently coerce, so a wrong invocation cannot pass merely
    by producing empty output before failing.
    """
    monkeypatch.chdir(tmp_path)
    try:
        result = cli_main(argv)
        if result is None:
            exit_code = 0
        elif isinstance(result, int):
            exit_code = result
        else:
            pytest.fail(
                f"argv={argv}: non-integer cli_main return: {result!r}"
            )
    except SystemExit as e:
        if e.code is None:
            exit_code = 0
        elif isinstance(e.code, int):
            exit_code = e.code
        else:
            pytest.fail(
                f"argv={argv}: non-integer SystemExit code: {e.code!r}"
            )

    captured = capsys.readouterr()
    assert_ascii_safe(captured.out, f"stdout for argv={argv}")
    assert_ascii_safe(captured.err, f"stderr for argv={argv}")
    assert exit_code == expected_exit, (
        f"argv={argv}: expected exit {expected_exit}, got {exit_code}"
    )


# PASS-path invocations + JSON-stdout invocations
PASS_INVOCATIONS = [
    pytest.param(
        ["schema", str(EXAMPLES / "read_only_query.json")], 0,
        id="schema-valid",
    ),
    pytest.param(
        ["verify", str(EXAMPLES / "read_only_query.json")], 0,
        id="verify-low-impact-allow",
    ),
    # JSON-stdout paths (cli.py L144 / L152 / L203 use ensure_ascii=True
    # after the issue #120 fix; these invocations exercise that path).
    pytest.param(
        ["policy", "--write-example"], 0,
        id="policy-write-example-json-stdout",
    ),
    pytest.param(
        ["keys", "--write-example"], 0,
        id="keys-write-example-json-stdout",
    ),
]


@pytest.mark.parametrize("argv,expected_exit", PASS_INVOCATIONS)
def test_cli_pass_and_json_paths_ascii_safe(
    monkeypatch, capsys, tmp_path, argv, expected_exit,
):
    """PASS-path and JSON-stdout CLI output must be ASCII-only with correct exit."""
    run_cli_ascii_safe(monkeypatch, capsys, tmp_path, argv, expected_exit)


def test_cli_schema_fail_path_ascii_safe(monkeypatch, capsys, tmp_path):
    """FAIL-path CLI output must also be ASCII-only with non-zero exit.

    Uses a runtime-generated invalid proposal (not a committed fixture);
    same isolation pattern as tests/test_cli_keys_command.py uses for
    keyring fixtures.

    Exit code 2 is the verified contract: cmd_schema returns 2 on
    jsonschema.ValidationError (sdk-python/pic_standard/cli.py
    cmd_schema, "return 2" on the ValidationError branch).
    """
    invalid = tmp_path / "invalid_proposal.json"
    # Structurally invalid: missing required fields ("impact", "provenance",
    # "claims", "action") per the PIC/1.0 JSON Schema. jsonschema raises
    # ValidationError; cmd_schema returns 2.
    invalid.write_text(
        '{"protocol": "PIC/1.0", "intent": "incomplete proposal"}',
        encoding="utf-8",
    )
    run_cli_ascii_safe(
        monkeypatch, capsys, tmp_path,
        ["schema", str(invalid)],
        expected_exit=2,
    )
