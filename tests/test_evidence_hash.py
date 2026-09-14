import hashlib
import json
from pathlib import Path

from pic_standard.evidence import (
    EvidenceSystem,
    apply_trust_upgrade_ids_to_provenance,
)

ROOT = Path(__file__).resolve().parents[1]


def verify_multiple_evidences(proposal: dict, base_dir: Path) -> dict:
    """Helper function to verify multiple pieces of evidence in a proposal.

    Processes all evidence items and returns a summary with verification results.
    """
    system = EvidenceSystem()
    report = system.verify_all(proposal, base_dir=base_dir)
    return {
        "ok": report.ok,
        "total_evidence": len(report.results),
        "verified_count": len(report.verified_ids),
        "verified_ids": report.verified_ids,
        "results": report.results,
    }


def test_evidence_hash_ok_verifies_content_integrity_only(tmp_path):
    """Hash verification is content-integrity only, not trust-upgrading (v0.8.3).

    Under v0.8.3 evidence semantics, a matching SHA-256 hash proves
    content-integrity of the referenced file bytes but MUST NOT populate
    ``trust_upgrade_ids``. Applying ``apply_trust_upgrade_ids_to_provenance``
    with the report's ``trust_upgrade_ids`` therefore leaves any hash-only
    provenance entry untrusted. See ``docs/spec-evidence.md`` §8.

    Uses an inline hash-only fixture under ``tmp_path`` rather than
    ``examples/financial_hash_ok.json``, because that example becomes a
    signed ALLOW example later in the same PR and a signature-driven trust
    upgrade would mask the hash-only invariant this test protects.
    """
    # Inline artifact + real digest
    artifact = tmp_path / "invoice.txt"
    artifact.write_bytes(b"invoice body bytes")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

    # Proposal: provenance id == evidence id, hash-only, initially untrusted
    proposal = {
        "protocol": "PIC/1.0",
        "intent": "test hash content-integrity",
        "impact": "money",
        "provenance": [
            {"id": "inline_hash_id", "trust": "untrusted"},
        ],
        "claims": [
            {"text": "hash evidence attached", "evidence": ["inline_hash_id"]},
        ],
        "action": {"tool": "test_tool", "args": {}},
        "evidence": [
            {
                "id": "inline_hash_id",
                "type": "hash",
                "ref": f"file://{artifact.name}",
                "sha256": digest,
            }
        ],
    }

    report = EvidenceSystem().verify_all(proposal, base_dir=tmp_path)
    assert report.ok
    # Hash verifies content-integrity: present in hash_verified_ids and the audit union.
    assert "inline_hash_id" in report.hash_verified_ids
    assert "inline_hash_id" in report.verified_ids
    # But NOT signature-verified, NOT authority-bearing.
    assert "inline_hash_id" not in report.signature_verified_ids
    assert "inline_hash_id" not in report.trust_upgrade_ids

    # Applying trust upgrade with the (non-authority-bearing) set must leave
    # the hash-only provenance entry untrusted.
    upgraded = apply_trust_upgrade_ids_to_provenance(proposal, report.trust_upgrade_ids)
    invoice_prov = next(
        (p for p in upgraded.get("provenance", []) if p.get("id") == "inline_hash_id"),
        None,
    )
    assert invoice_prov is not None
    assert invoice_prov.get("trust") == "untrusted", (
        "hash-verified provenance MUST stay untrusted in v0.8.3"
    )


def test_evidence_hash_bad_fails():
    proposal_path = ROOT / "examples" / "failing" / "financial_hash_bad.json"
    proposal = json.loads(proposal_path.read_text(encoding="utf-8"))

    report = EvidenceSystem().verify_all(proposal, base_dir=proposal_path.parent)
    assert not report.ok
    assert report.results
    assert any((not r.ok) for r in report.results)


def test_evidence_invalid_file_path_raises_error():
    """Verify that verify_evidence handles FileNotFoundError for non-existent files."""
    proposal = {
        "evidence": [
            {
                "id": "missing_file",
                "type": "hash",
                "ref": "file://missing.txt",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            }
        ]
    }

    report = EvidenceSystem().verify_all(proposal, base_dir=ROOT)
    assert not report.ok
    assert len(report.results) == 1
    result = report.results[0]
    assert result.id == "missing_file"
    assert not result.ok


def test_evidence_invalid_hash_string_fails():
    """Verify that evidence verification fails when hash string is malformed."""
    # Create a proposal with an existing file but an invalid hash
    proposal_path = ROOT / "examples" / "artifacts" / "invoice_123.txt"
    proposal = {
        "evidence": [
            {
                "id": "invoice_bad_hash",
                "type": "hash",
                "ref": f"file://{proposal_path.name}",
                "sha256": "not_a_valid_hash_string",
            }
        ]
    }

    report = EvidenceSystem().verify_all(proposal, base_dir=proposal_path.parent)
    assert not report.ok
    assert len(report.results) == 1
    result = report.results[0]
    assert result.id == "invoice_bad_hash"
    assert not result.ok
    # Accept either invalid format or mismatch error
    error_msg = result.message.lower()
    assert "invalid" in error_msg or "mismatch" in error_msg


def test_evidence_large_file_verification(tmp_path):
    """Verify that evidence verification handles large files (>1 MB) correctly."""
    # Create a large file in pytest's temporary directory
    large_file_path = tmp_path / "test_large_evidence.bin"

    # Create a file larger than 1 MB (2 MB in this case)
    file_size = 2 * 1024 * 1024  # 2 MB
    with open(large_file_path, "wb") as f:
        f.write(b"x" * file_size)

    # Compute the SHA256 hash
    with open(large_file_path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()

    # Create a proposal with the large file evidence
    proposal = {
        "evidence": [
            {
                "id": "large_file_evidence",
                "type": "hash",
                "ref": f"file://{large_file_path.name}",
                "sha256": file_hash,
            }
        ]
    }

    # Verify the large file evidence
    report = EvidenceSystem().verify_all(proposal, base_dir=tmp_path)
    assert report.ok
    assert len(report.results) == 1
    result = report.results[0]
    assert result.id == "large_file_evidence"
    assert result.ok
    assert "large_file_evidence" in report.verified_ids


def test_evidence_multiple_pieces_verification(tmp_path):
    """Verify that multiple pieces of evidence are validated correctly."""
    file1_path = tmp_path / "evidence_file1.txt"
    file2_path = tmp_path / "evidence_file2.txt"
    file3_path = tmp_path / "evidence_file3.txt"

    # Create three test files with different content
    file1_path.write_text("First evidence file")
    file2_path.write_text("Second evidence file with different content")
    file3_path.write_text("Third evidence file")

    # Compute SHA256 hashes for each file
    hash1 = hashlib.sha256(file1_path.read_bytes()).hexdigest()
    hash2 = hashlib.sha256(file2_path.read_bytes()).hexdigest()
    hash3 = hashlib.sha256(file3_path.read_bytes()).hexdigest()

    # Create a proposal with multiple evidence items
    proposal = {
        "evidence": [
            {
                "id": "evidence_1",
                "type": "hash",
                "ref": f"file://{file1_path.name}",
                "sha256": hash1,
            },
            {
                "id": "evidence_2",
                "type": "hash",
                "ref": f"file://{file2_path.name}",
                "sha256": hash2,
            },
            {
                "id": "evidence_3",
                "type": "hash",
                "ref": f"file://{file3_path.name}",
                "sha256": hash3,
            },
        ]
    }

    # Verify multiple evidences using the helper function
    summary = verify_multiple_evidences(proposal, tmp_path)

    # Assertions
    assert summary["ok"], "All evidence should be verified successfully"
    assert summary["total_evidence"] == 3, "Should have 3 evidence items"
    assert summary["verified_count"] == 3, "All 3 evidence items should be verified"
    assert "evidence_1" in summary["verified_ids"]
    assert "evidence_2" in summary["verified_ids"]
    assert "evidence_3" in summary["verified_ids"]

    # Verify each result is successful
    for result in summary["results"]:
        assert result.ok, f"Evidence {result.id} should be verified"
