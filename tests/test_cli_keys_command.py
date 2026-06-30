from __future__ import annotations

import json
from pathlib import Path

from pic_standard.cli import main as cli_main


def _write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def test_cli_keys_success_loads_from_pic_keys_path(monkeypatch, capsys, tmp_path: Path):
    """
    Ensure: `pic-cli keys` loads from PIC_KEYS_PATH and prints key IDs.

    This is hermetic (does not depend on repo files or CWD).
    """
    keyring_path = tmp_path / "pic_keys.test.json"
    _write_json(
        keyring_path,
        {
            "trusted_keys": {
                # 32 bytes pubkey (base64). Same one you use in examples.
                "demo_signer_v1": "u1esUbs/ZYS3PTPMIxiwsh47pyCUAv5VgzrmjEKbw6k="
            },
            "revoked_keys": [],
        },
    )

    monkeypatch.setenv("PIC_KEYS_PATH", str(keyring_path))

    rc = cli_main(["keys", "--repo-root", str(tmp_path)])
    assert rc == 0

    out = capsys.readouterr().out
    assert "PASS: Keyring loaded" in out
    assert "PIC_KEYS_PATH=" in out  # source hint should mention env
    assert "Trusted keys" in out
    assert "- demo_signer_v1" in out


def test_cli_keys_invalid_keyring_reports_error(monkeypatch, capsys, tmp_path: Path):
    """
    Ensure: invalid keyring file produces a non-zero exit code + clear error output.
    """
    keyring_path = tmp_path / "pic_keys.bad.json"

    # Invalid base64 -> should be rejected by keyring parsing
    _write_json(
        keyring_path,
        {
            "trusted_keys": {"demo_signer_v1": "NOT_BASE64!!"},
        },
    )

    monkeypatch.setenv("PIC_KEYS_PATH", str(keyring_path))

    rc = cli_main(["keys", "--repo-root", str(tmp_path)])
    assert rc != 0

    out = capsys.readouterr().out
    assert "FAIL: Keyring" in out
    assert "Source:" in out
    # message should include why (not too brittle)
    assert "base64" in out.lower() or "invalid" in out.lower()


def test_cli_keys_write_example_prints_json(capsys, tmp_path: Path):
    """
    Ensure: `pic-cli keys --write-example` prints JSON and exits 0.
    """
    rc = cli_main(["keys", "--repo-root", str(tmp_path), "--write-example"])
    assert rc == 0

    out = capsys.readouterr().out.strip()
    # Must be valid JSON
    obj = json.loads(out)
    assert "trusted_keys" in obj
    assert isinstance(obj["trusted_keys"], dict)
