from __future__ import annotations

import json
from pathlib import Path

from pic_standard.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples"


def test_verify_json_success_is_single_structured_object(capsys) -> None:
    code = cli_main(["verify", str(EXAMPLES / "read_only_query.json"), "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 0
    assert captured.err == ""
    assert payload["ok"] is True
    assert payload["impact"] == "read"
    assert isinstance(payload["eval_ms"], int)
    assert payload["eval_ms"] >= 0
    assert payload["error"] is None
    assert "PASS:" not in captured.out


def test_verify_json_schema_failure_is_structured(tmp_path, capsys) -> None:
    proposal = tmp_path / "invalid.json"
    proposal.write_text(
        '{"protocol": "PIC/1.0", "intent": "incomplete proposal"}',
        encoding="utf-8",
    )

    code = cli_main(["verify", str(proposal), "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 2
    assert captured.err == ""
    assert payload["ok"] is False
    assert payload["impact"] is None
    assert isinstance(payload["eval_ms"], int)
    assert payload["error"]["code"] == "PIC_SCHEMA_INVALID"
    assert "PASS:" not in captured.out
    assert "FAIL:" not in captured.out


def test_verify_json_verifier_failure_preserves_exit_code_3(tmp_path, capsys) -> None:
    proposal = tmp_path / "untrusted-money.json"
    proposal.write_text(
        json.dumps(
            {
                "protocol": "PIC/1.0",
                "intent": "Send $50 to vendor for invoice #1234",
                "impact": "money",
                "provenance": [{"id": "invoice", "trust": "untrusted"}],
                "claims": [
                    {
                        "text": "Send $50 to vendor for invoice #1234",
                        "evidence": ["invoice"],
                    }
                ],
                "action": {"tool": "payments_send", "args": {}},
            }
        ),
        encoding="utf-8",
    )

    code = cli_main(["verify", str(proposal), "--json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 3
    assert captured.err == ""
    assert payload["ok"] is False
    assert payload["impact"] == "money"
    assert payload["error"]["code"] == "PIC_VERIFIER_FAILED"
    assert "PASS:" not in captured.out
    assert "FAIL:" not in captured.out


def test_verify_json_evidence_failure_preserves_exit_code_4(tmp_path, capsys) -> None:
    proposal = tmp_path / "bad-evidence.json"
    proposal.write_text(
        json.dumps(
            {
                "protocol": "PIC/1.0",
                "intent": "Send payment for approved invoice",
                "impact": "money",
                "provenance": [
                    {
                        "id": "invoice",
                        "trust": "untrusted",
                        "source": "file://missing-invoice.txt",
                    }
                ],
                "claims": [
                    {
                        "text": "Invoice is approved for payment",
                        "evidence": ["invoice"],
                    }
                ],
                "action": {"tool": "payments_send", "args": {"amount": 50}},
                "evidence": [
                    {
                        "id": "invoice",
                        "type": "hash",
                        "ref": "file://missing-invoice.txt",
                        "sha256": "0" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    code = cli_main(["verify", str(proposal), "--json", "--verify-evidence"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert code == 4
    assert captured.err == ""
    assert payload["ok"] is False
    assert payload["impact"] == "money"
    assert payload["error"]["code"] == "PIC_EVIDENCE_FAILED"
    assert "PASS:" not in captured.out
    assert "FAIL:" not in captured.out


def test_verify_default_human_output_is_preserved(capsys) -> None:
    code = cli_main(["verify", str(EXAMPLES / "read_only_query.json")])

    captured = capsys.readouterr()

    assert code == 0
    assert "PASS: Schema valid" in captured.out
    assert "PASS: Verifier passed" in captured.out
