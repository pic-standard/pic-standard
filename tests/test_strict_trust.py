"""Tests for PIC v0.8 strict_trust pipeline option."""

from __future__ import annotations

import copy
import warnings

import pytest
from conftest import make_proposal
from pic_standard.errors import PICErrorCode
from pic_standard.pipeline import (
    PICLegacyTrustModeWarning,
    PipelineOptions,
    verify_proposal,
)


class TestStrictTrust:
    """strict_trust sanitizes inbound provenance trust to 'untrusted'."""

    def test_strict_trust_sanitizes_trusted_to_untrusted(self) -> None:
        """High-impact + strict_trust=True + no evidence → blocked."""
        proposal = make_proposal(trust="trusted", impact="money")
        result = verify_proposal(
            proposal,
            options=PipelineOptions(strict_trust=True),
        )
        assert not result.ok
        assert result.error is not None
        assert result.error.code == PICErrorCode.VERIFIER_FAILED

    def test_strict_trust_with_evidence_verification_allows(self) -> None:
        """strict_trust=True + valid signature evidence → trust upgraded → allowed.

        Uses signature evidence as one concrete path; hash evidence is equally valid.
        This test requires the crypto extra (Ed25519).
        """
        import base64

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from pic_standard.keyring import StaticKeyRingResolver, TrustedKey, TrustedKeyRing

        # Generate a test keypair
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        # Build keyring with the test key
        keyring = TrustedKeyRing(
            keys={"test-key": TrustedKey(public_key=public_key_bytes)},
            revoked_keys=set(),
        )
        resolver = StaticKeyRingResolver(keyring)

        # Sign a payload
        payload = "test-payment-evidence"
        signature = private_key.sign(payload.encode("utf-8"))
        sig_b64 = base64.b64encode(signature).decode("ascii")

        proposal = make_proposal(
            trust="trusted",
            impact="money",
            prov_id="invoice_evidence",
            extra_evidence=[
                {
                    "id": "invoice_evidence",
                    "type": "sig",
                    "ref": "inline:payment",
                    "payload": payload,
                    "alg": "ed25519",
                    "signature": sig_b64,
                    "key_id": "test-key",
                }
            ],
        )

        result = verify_proposal(
            proposal,
            options=PipelineOptions(
                strict_trust=True,
                verify_evidence=True,
                key_resolver=resolver,
            ),
        )
        assert result.ok, f"Expected allow, got: {result.error}"

    def test_strict_trust_low_impact_passes(self) -> None:
        """Low-impact (read) + strict_trust=True → allowed (no trusted provenance required)."""
        proposal = make_proposal(
            tool="docs_search",
            impact="read",
            intent="Search docs",
            trust="trusted",
        )
        result = verify_proposal(
            proposal,
            options=PipelineOptions(strict_trust=True),
        )
        assert result.ok

    def test_strict_trust_untrusted_input_unchanged(self) -> None:
        """Already untrusted + strict_trust=True → no-op, still allowed for low-impact."""
        proposal = make_proposal(
            tool="docs_search",
            impact="read",
            intent="Search docs",
            trust="untrusted",
        )
        result = verify_proposal(
            proposal,
            options=PipelineOptions(strict_trust=True),
        )
        assert result.ok

    def test_strict_trust_false_preserves_existing_behavior(self) -> None:
        """strict_trust=False (legacy explicit opt-in) preserves self-asserted trust acceptance."""
        proposal = make_proposal(trust="trusted", impact="money")
        with pytest.warns(
            PICLegacyTrustModeWarning,
            match="strict_trust=False enables legacy trust behavior",
        ):
            result = verify_proposal(
                proposal,
                options=PipelineOptions(strict_trust=False),
            )
        assert result.ok

    def test_verify_evidence_true_without_evidence_or_policy_still_accepts_trust(self) -> None:
        """verify_evidence=True but no evidence entries and no policy → evidence doesn't run.

        Documents the nuance: verify_evidence=True alone is not sufficient without
        evidence entries or policy requiring evidence for the resolved impact.
        Exercises legacy explicit opt-in (strict_trust=False) so trust is not
        sanitized; the caller-visible warning is asserted alongside.
        """
        proposal = make_proposal(trust="trusted", impact="money")
        with pytest.warns(
            PICLegacyTrustModeWarning,
            match="strict_trust=False enables legacy trust behavior",
        ):
            result = verify_proposal(
                proposal,
                options=PipelineOptions(verify_evidence=True, strict_trust=False),
            )
        assert result.ok

    def test_strict_trust_does_not_mutate_input(self) -> None:
        """verify_proposal() must not mutate the caller's proposal dict."""
        proposal = make_proposal(trust="trusted", impact="money")
        original = copy.deepcopy(proposal)
        verify_proposal(
            proposal,
            options=PipelineOptions(strict_trust=True),
        )
        assert proposal == original

    def test_default_pipeline_options_strict_trust_is_true(self) -> None:
        """The secure default: PipelineOptions() constructed without arguments
        yields strict_trust=True and emits no PICLegacyTrustModeWarning."""
        with warnings.catch_warnings():
            warnings.simplefilter("error", PICLegacyTrustModeWarning)
            options = PipelineOptions()
        assert options.strict_trust is True

    def test_explicit_false_emits_legacy_trust_mode_warning(self) -> None:
        """PipelineOptions(strict_trust=False) fires PICLegacyTrustModeWarning
        at construction time. The message identifies the legacy opt-in as a
        compatibility mode, not a removal announcement."""
        with pytest.warns(
            PICLegacyTrustModeWarning,
            match="strict_trust=False enables legacy trust behavior",
        ):
            options = PipelineOptions(strict_trust=False)
        assert options.strict_trust is False
