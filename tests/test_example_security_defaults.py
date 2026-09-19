from __future__ import annotations

import json
from pathlib import Path

import pytest
from pic_standard.errors import PICErrorCode
from pic_standard.pipeline import verify_proposal

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "example_name",
    [
        "api_key_rotation.json",
        "multi_step_workflow.json",
        "pii_export.json",
        "resource_deletion.json",
    ],
)
def test_default_pipeline_blocks_unsigned_high_impact_examples(example_name: str) -> None:
    proposal = json.loads((ROOT / "examples" / example_name).read_text(encoding="utf-8"))

    result = verify_proposal(proposal)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == PICErrorCode.VERIFIER_FAILED
