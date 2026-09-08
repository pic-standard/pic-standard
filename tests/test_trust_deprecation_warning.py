"""Tests for PIC trust deprecation warnings.

Covers:

- ``PICTrustFutureWarning`` (v0.7.5): self-asserted ``trust='trusted'``
  under non-strict mode where evidence verification will not actually run.

Plus:
- A schema-rejection regression guard for the removed ``semi_trusted``
  provenance trust value (removed in v0.9.0a1 completing the v0.8.1
  deprecation cycle).
- A verdict-regression matrix that pins baseline outcomes for representative
  example proposals, so any future refactor that touches pipeline verdict
  behavior surfaces immediately as a CI failure.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest
from conftest import make_proposal
from pic_standard.errors import PICErrorCode
from pic_standard.pipeline import (
    PICTrustFutureWarning,
    PipelineOptions,
    verify_proposal,
)


class TestTrustFutureWarning:
    """PICTrustFutureWarning fires when self-asserted trust is present and
    effective evidence verification will not run for the proposal."""

    def test_warning_fires_on_self_asserted_trust_without_evidence(self) -> None:
        """trust='trusted' + verify_evidence=False -> warning emitted, result still ok."""
        proposal = make_proposal(trust="trusted", impact="money")
        with pytest.warns(PICTrustFutureWarning):
            result = verify_proposal(
                proposal,
                options=PipelineOptions(verify_evidence=False, strict_trust=False),
            )
        assert result.ok

    def test_no_warning_when_evidence_will_actually_run(self) -> None:
        """trust='trusted' + verify_evidence=True + evidence entries present -> no warning.

        Evidence will actually run, so no migration warning is needed.
        We use a deliberately invalid evidence entry to prove the evidence path
        was taken (the pipeline should fail with EVIDENCE_FAILED).
        """
        proposal = make_proposal(
            trust="trusted",
            impact="money",
            extra_evidence=[
                {
                    "id": "approved_invoice",
                    "type": "hash",
                    "ref": "file://nonexistent.txt",
                    "sha256": "0" * 64,
                }
            ],
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = verify_proposal(
                proposal,
                options=PipelineOptions(verify_evidence=True, strict_trust=False),
            )
        pic_warnings = [w for w in caught if issubclass(w.category, PICTrustFutureWarning)]
        assert not pic_warnings
        # Prove the evidence path was actually taken
        assert not result.ok
        assert result.error is not None
        assert result.error.code == PICErrorCode.EVIDENCE_FAILED

    def test_no_warning_when_strict_trust_enabled(self) -> None:
        """strict_trust=True -> blocks, does not warn."""
        proposal = make_proposal(trust="trusted", impact="money")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = verify_proposal(
                proposal,
                options=PipelineOptions(strict_trust=True),
            )
        pic_warnings = [w for w in caught if issubclass(w.category, PICTrustFutureWarning)]
        assert not pic_warnings
        assert not result.ok  # blocked by sanitization

    def test_no_warning_when_trust_is_untrusted(self) -> None:
        """trust='untrusted' -> no warning (nothing to warn about)."""
        proposal = make_proposal(
            trust="untrusted",
            impact="read",
            tool="docs_search",
            intent="Search docs",
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            verify_proposal(
                proposal,
                options=PipelineOptions(verify_evidence=False),
            )
        pic_warnings = [w for w in caught if issubclass(w.category, PICTrustFutureWarning)]
        assert not pic_warnings

    def test_warning_fires_when_verify_evidence_true_but_evidence_will_not_run(self) -> None:
        """verify_evidence=True but NO evidence entries and NO policy -> warning fires.

        This is the nuance case: the flag is set but evidence won't actually execute
        because there are no evidence entries and no policy requiring evidence.
        """
        proposal = make_proposal(trust="trusted", impact="money")
        with pytest.warns(PICTrustFutureWarning):
            result = verify_proposal(
                proposal,
                options=PipelineOptions(verify_evidence=True, strict_trust=False),
            )
        assert result.ok

    def test_warning_message_contains_migration_guidance(self) -> None:
        """Warning text must mention key migration concepts."""
        proposal = make_proposal(trust="trusted", impact="money")
        with pytest.warns(PICTrustFutureWarning) as record:
            verify_proposal(
                proposal,
                options=PipelineOptions(verify_evidence=False, strict_trust=False),
            )
        assert len(record) == 1
        msg = str(record[0].message)
        assert "verifiable evidence" in msg
        assert "strict_trust=True" in msg
        assert "migration-trust-sanitization.md" in msg


# ============================================================================
# v0.9.0a1: semi_trusted removal, schema-rejection regression guard
# ============================================================================


class TestSemiTrustedRemoved:
    """The 'semi_trusted' provenance trust value was deprecated in v0.8.1 and
    removed from the schema in v0.9.0a1. A proposal carrying it MUST be rejected
    by schema validation with PIC_SCHEMA_INVALID.

    This test is the permanent regression guard against anyone accidentally
    re-adding the enum value to proposal_schema.json.
    """

    def test_semi_trusted_is_schema_invalid(self) -> None:
        """Proposal with provenance[].trust='semi_trusted' -> PIC_SCHEMA_INVALID.

        Build a valid proposal first, then inject the removed value directly
        into the raw dict. Avoids depending on make_proposal accepting the
        deprecated value (which may become stricter over time).
        """
        proposal = make_proposal(
            trust="untrusted",
            impact="read",
            tool="docs_search",
            intent="search",
        )
        proposal["provenance"][0]["trust"] = "semi_trusted"
        result = verify_proposal(proposal, options=PipelineOptions(strict_trust=False))
        assert not result.ok
        assert result.error is not None
        assert result.error.code == PICErrorCode.SCHEMA_INVALID


# ============================================================================
# Verdict-regression matrix (codified, parametrized)
# ============================================================================
#
# Permanent CI guard against any future refactor that touches pipeline verdict
# behavior. Asserts only the STABLE verdict-bearing fields of PipelineResult:
# `ok` (bool) and, when ok=False, `error.code` compared against a PICErrorCode
# enum member. Does NOT assert on `error.message`, `impact`, `eval_ms`, or
# other unstable fields. Does NOT compare against the enum's `.value` string;
# the enum member is the stable API, `.value` is an implementation detail.
#
# Expected baseline values are HARDCODED LITERALS (enum members for error
# codes; bool / None for verdicts) captured from prior baseline behavior.
# They are NOT derived at test time by calling verify_proposal() or any helper
# that shares a code path with the system under test; that would defeat the
# guard's purpose (the test would just assert that the current behavior matches
# the current behavior).
#
# Excluded: financial_sig_ok.json. Its verify_evidence=True path requires
# keyring environment setup (PIC_KEYS_PATH or explicit key_resolver) and would
# make the regression matrix brittle. Sig-flow regression is covered by
# dedicated sig tests elsewhere in the suite.

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


# (filename, strict_trust, verify_evidence, expected_ok, expected_error_code_or_None)
VERDICT_REGRESSION_MATRIX: list[tuple[str, bool, bool, bool, PICErrorCode | None]] = [
    # Low-impact: always allowed regardless of trust
    ("compute_risk.json", False, False, True, None),
    ("compute_risk.json", False, True, True, None),
    ("compute_risk.json", True, False, True, None),
    ("compute_risk.json", True, True, True, None),
    ("read_only_query.json", False, False, True, None),
    ("read_only_query.json", False, True, True, None),
    ("read_only_query.json", True, False, True, None),
    ("read_only_query.json", True, True, True, None),
    # CANARY for evidence verification happening before contract validation.
    # financial_hash_ok.json is a high-impact (money) proposal whose provenance
    # starts untrusted. In the final v0.8.3 fixture, hash evidence proves
    # content-integrity only, while signature evidence populates trust_upgrade_ids
    # via the configured keyring. With verify_evidence=True, signature evidence
    # must verify and upgrade trust before the causal-contract check sees the
    # model. If a future refactor moves full ActionProposal instantiation ahead
    # of evidence verification, the two ok=True rows below flip to ok=False and
    # this test points at the regression.
    ("financial_hash_ok.json", False, False, False, PICErrorCode.VERIFIER_FAILED),
    ("financial_hash_ok.json", False, True, True, None),  # canary
    ("financial_hash_ok.json", True, False, False, PICErrorCode.VERIFIER_FAILED),
    ("financial_hash_ok.json", True, True, True, None),  # canary (strict mode)
    # High-impact (money). Has cfo_signed_invoice_hash:trusted as load-bearing
    # entry. Non-strict: contract satisfied. Strict: all flattened to untrusted,
    # contract fails.
    ("financial_irreversible.json", False, False, True, None),
    ("financial_irreversible.json", False, True, True, None),
    ("financial_irreversible.json", True, False, False, PICErrorCode.VERIFIER_FAILED),
    ("financial_irreversible.json", True, True, False, PICErrorCode.VERIFIER_FAILED),
    # High-impact (privacy) with user_email_consent:trusted.
    ("privacy_risk.json", False, False, True, None),
    ("privacy_risk.json", False, True, True, None),
    ("privacy_risk.json", True, False, False, PICErrorCode.VERIFIER_FAILED),
    ("privacy_risk.json", True, True, False, PICErrorCode.VERIFIER_FAILED),
    # High-impact (irreversible) with lidar_safety_trigger:trusted as load-bearing.
    ("robotic_action.json", False, False, True, None),
    ("robotic_action.json", False, True, True, None),
    ("robotic_action.json", True, False, False, PICErrorCode.VERIFIER_FAILED),
    ("robotic_action.json", True, True, False, PICErrorCode.VERIFIER_FAILED),
]


@pytest.mark.parametrize(
    "filename,strict_trust,verify_evidence,expected_ok,expected_error_code",
    VERDICT_REGRESSION_MATRIX,
)
def test_verdict_regression_matrix(
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
    strict_trust: bool,
    verify_evidence: bool,
    expected_ok: bool,
    expected_error_code: PICErrorCode | None,
) -> None:
    """Pins baseline outcomes for representative example proposals.

    Asserts only the stable verdict-bearing fields. See module-level matrix
    comment for the design rationale.
    """
    # Since v0.8.3, financial_hash_ok.json carries signature evidence that must
    # verify against the demo keyring for its ALLOW rows to hold. Point the
    # verifier at examples/../pic_keys.example.json so the demo keys are found
    # without depending on the caller's environment.
    monkeypatch.setenv("PIC_KEYS_PATH", str(EXAMPLES_DIR.parent / "pic_keys.example.json"))

    proposal = json.loads((EXAMPLES_DIR / filename).read_text(encoding="utf-8"))

    # Suppress PICTrustFutureWarning: it fires for examples carrying self-asserted
    # trusted entries. The matrix asserts verdicts, not warning emission. Warning
    # emission is covered by the dedicated TestTrustFutureWarning tests above.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        result = verify_proposal(
            proposal,
            options=PipelineOptions(
                strict_trust=strict_trust,
                verify_evidence=verify_evidence,
                proposal_base_dir=EXAMPLES_DIR,
                evidence_root_dir=EXAMPLES_DIR,
            ),
        )

    assert result.ok is expected_ok, (
        f"verdict regression: {filename} "
        f"(strict_trust={strict_trust}, verify_evidence={verify_evidence}) "
        f"returned ok={result.ok}, expected ok={expected_ok}"
    )
    if not expected_ok:
        assert result.error is not None
        assert result.error.code == expected_error_code, (
            f"error.code regression: {filename} returned "
            f"{result.error.code!r}, expected {expected_error_code!r}"
        )


# ============================================================================
# Public API surface, package-root re-export pin
# ============================================================================


class TestPublicAPISurface:
    """Pins package-root warning exports after the semi_trusted removal."""

    def test_pic_trust_future_warning_importable_at_package_root(self) -> None:
        from pic_standard import PICTrustFutureWarning as PicTrust

        assert issubclass(PicTrust, FutureWarning)

    def test_semi_trusted_deprecation_warning_not_importable_at_package_root(self) -> None:
        with pytest.raises(ImportError):
            from pic_standard import PICSemiTrustedDeprecationWarning  # noqa: F401
