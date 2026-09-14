from __future__ import annotations

from conftest import make_proposal
from pic_standard.errors import PICErrorCode
from pic_standard.pipeline import (
    PICEvaluateLimits,
    PipelineOptions,
    PipelineResult,
    verify_proposal,
)
from pic_standard.policy import PICPolicy

# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestPipelineSchemaValidation:
    def test_valid_proposal_passes(self, money_proposal: dict) -> None:
        result = verify_proposal(money_proposal)
        assert result.ok
        assert result.error is None

    def test_missing_protocol_fails(self) -> None:
        bad = make_proposal()
        del bad["protocol"]
        result = verify_proposal(bad)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == PICErrorCode.SCHEMA_INVALID

    def test_missing_intent_fails(self) -> None:
        bad = make_proposal()
        del bad["intent"]
        result = verify_proposal(bad)
        assert not result.ok
        assert result.error.code == PICErrorCode.SCHEMA_INVALID

    def test_missing_impact_fails(self) -> None:
        bad = make_proposal()
        del bad["impact"]
        result = verify_proposal(bad)
        assert not result.ok
        assert result.error.code == PICErrorCode.SCHEMA_INVALID

    def test_missing_provenance_fails(self) -> None:
        bad = make_proposal()
        del bad["provenance"]
        result = verify_proposal(bad)
        assert not result.ok
        assert result.error.code == PICErrorCode.SCHEMA_INVALID

    def test_missing_claims_fails(self) -> None:
        bad = make_proposal()
        del bad["claims"]
        result = verify_proposal(bad)
        assert not result.ok
        assert result.error.code == PICErrorCode.SCHEMA_INVALID

    def test_missing_action_fails(self) -> None:
        bad = make_proposal()
        del bad["action"]
        result = verify_proposal(bad)
        assert not result.ok
        assert result.error.code == PICErrorCode.SCHEMA_INVALID

    def test_lone_surrogate_in_claim_text_rejected_as_schema_invalid(self) -> None:
        """Strings with lone UTF-16 surrogates must fail with PIC_SCHEMA_INVALID.

        Per docs/canonicalization.md §7.13 and docs/spec-core.md §9.1, lone
        surrogates are non-conformant input at the schema-layer boundary.
        A low-impact proposal that would otherwise pass MUST still be
        rejected purely on the lone-surrogate rule.
        """
        proposal = make_proposal(
            impact="read",
            trust="untrusted",
            tool="docs_search",
            intent="Search docs",
            claim_text="\ud800",
        )
        result = verify_proposal(proposal)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == PICErrorCode.SCHEMA_INVALID


# ---------------------------------------------------------------------------
# Verifier rules (ActionProposal instantiation)
# ---------------------------------------------------------------------------


class TestPipelineVerifierRules:
    def test_trusted_money_passes(self, money_proposal: dict) -> None:
        result = verify_proposal(money_proposal)
        assert result.ok
        assert result.action_proposal is not None

    def test_untrusted_money_blocked(self, untrusted_money_proposal: dict) -> None:
        result = verify_proposal(untrusted_money_proposal)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == PICErrorCode.VERIFIER_FAILED

    def test_read_impact_any_trust_passes(self, read_proposal: dict) -> None:
        result = verify_proposal(read_proposal)
        assert result.ok


# ---------------------------------------------------------------------------
# Tool binding
# ---------------------------------------------------------------------------


class TestPipelineToolBinding:
    def test_matching_tool_passes(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                expected_tool="payments_send",
            ),
        )
        assert result.ok

    def test_mismatched_tool_fails(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                expected_tool="wrong_tool",
            ),
        )
        assert not result.ok
        assert result.error.code == PICErrorCode.TOOL_BINDING_MISMATCH

    def test_no_expected_tool_skips_binding(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                expected_tool=None,
            ),
        )
        assert result.ok


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


class TestPipelineLimits:
    def test_oversize_proposal_blocked(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                limits=PICEvaluateLimits(max_proposal_bytes=10),
            ),
        )
        assert not result.ok
        assert result.error.code == PICErrorCode.LIMIT_EXCEEDED

    def test_normal_size_passes(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                limits=PICEvaluateLimits(),
            ),
        )
        assert result.ok

    def test_no_limits_skips_check(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                limits=None,
            ),
        )
        assert result.ok

    def test_too_many_provenance_blocked(self) -> None:
        prov = [{"id": f"p{i}", "trust": "trusted"} for i in range(100)]
        proposal = make_proposal()
        proposal["provenance"] = prov
        result = verify_proposal(
            proposal,
            options=PipelineOptions(
                limits=PICEvaluateLimits(max_provenance_items=5),
            ),
        )
        assert not result.ok
        assert result.error.code == PICErrorCode.LIMIT_EXCEEDED


# ---------------------------------------------------------------------------
# Impact resolution
# ---------------------------------------------------------------------------


class TestPipelineImpactResolution:
    def test_impact_from_proposal(self, money_proposal: dict) -> None:
        result = verify_proposal(money_proposal)
        assert result.impact == "money"

    def test_impact_from_policy_via_tool_name(self) -> None:
        proposal = make_proposal(impact="read", tool="docs_search")
        policy = PICPolicy(impact_by_tool={"payments_send": "money"})
        result = verify_proposal(
            proposal,
            options=PipelineOptions(
                tool_name="payments_send",
                policy=policy,
            ),
        )
        assert result.impact == "money"

    def test_impact_falls_back_to_expected_tool(self) -> None:
        proposal = make_proposal(impact="read", tool="docs_search")
        policy = PICPolicy(impact_by_tool={"payments_send": "money"})
        result = verify_proposal(
            proposal,
            options=PipelineOptions(
                expected_tool="payments_send",
                policy=policy,
            ),
        )
        assert result.impact == "money"


# ---------------------------------------------------------------------------
# Evidence (basic — no crypto fixtures needed for pipeline-level tests)
# ---------------------------------------------------------------------------


class TestPipelineEvidence:
    def test_evidence_skipped_when_false(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                verify_evidence=False,
            ),
        )
        assert result.ok
        assert result.evidence_report is None

    def test_evidence_required_but_missing(self) -> None:
        policy = PICPolicy(
            impact_by_tool={"payments_send": "money"},
            require_evidence_for_impacts=["money"],
        )
        proposal = make_proposal()  # no evidence entries
        result = verify_proposal(
            proposal,
            options=PipelineOptions(
                tool_name="payments_send",
                verify_evidence=True,
                policy=policy,
            ),
        )
        assert not result.ok
        assert result.error.code == PICErrorCode.EVIDENCE_REQUIRED


# ---------------------------------------------------------------------------
# Time budget
# ---------------------------------------------------------------------------


class TestPipelineTimeBudget:
    def test_no_budget_skips_check(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                limits=None,
                time_budget_ms=None,
            ),
        )
        assert result.ok

    def test_generous_budget_passes(self, money_proposal: dict) -> None:
        result = verify_proposal(
            money_proposal,
            options=PipelineOptions(
                time_budget_ms=10_000,
            ),
        )
        assert result.ok


# ---------------------------------------------------------------------------
# PipelineResult shape
# ---------------------------------------------------------------------------


class TestPipelineResult:
    def test_ok_result_shape(self, money_proposal: dict) -> None:
        result = verify_proposal(money_proposal)
        assert isinstance(result, PipelineResult)
        assert result.ok is True
        assert result.action_proposal is not None
        assert result.error is None
        assert result.eval_ms >= 0

    def test_error_result_shape(self) -> None:
        bad = make_proposal()
        del bad["protocol"]
        result = verify_proposal(bad)
        assert isinstance(result, PipelineResult)
        assert result.ok is False
        assert result.action_proposal is None
        assert result.error is not None
        assert result.eval_ms >= 0
