import pytest
from pic_standard import ActionProposal


def test_money_requires_trusted_evidence_blocks_without_trusted():
    proposal = {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "web_page", "trust": "untrusted"}],
        "claims": [{"text": "Pay $500 now", "evidence": ["web_page"]}],
        "action": {"tool": "payments.send", "args": {"amount": 500}},
    }
    with pytest.raises(ValueError):
        ActionProposal(**proposal)


def test_money_passes_with_trusted_evidence():
    proposal = {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "approved_invoice", "trust": "trusted"}],
        "claims": [{"text": "Invoice approved for $500", "evidence": ["approved_invoice"]}],
        "action": {"tool": "payments.send", "args": {"amount": 500}},
    }
    ActionProposal(**proposal)


def test_irreversible_requires_trusted_evidence_blocks_without_trusted():
    proposal = {
        "protocol": "PIC/1.0",
        "intent": "Delete production database",
        "impact": "irreversible",
        "provenance": [{"id": "random_web", "trust": "untrusted"}],
        "claims": [{"text": "Delete it now", "evidence": ["random_web"]}],
        "action": {"tool": "db.drop", "args": {"db": "prod"}},
    }
    with pytest.raises(ValueError):
        ActionProposal(**proposal)


def test_irreversible_passes_with_trusted_evidence():
    proposal = {
        "protocol": "PIC/1.0",
        "intent": "Delete production database",
        "impact": "irreversible",
        "provenance": [{"id": "change_ticket_123", "trust": "trusted"}],
        "claims": [{"text": "Approved change request", "evidence": ["change_ticket_123"]}],
        "action": {"tool": "db.drop", "args": {"db": "prod"}},
    }
    ActionProposal(**proposal)


# ---------------------------------------------------------------------------
# Tool binding: exact string equality (MAINT-F1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "proposal_tool,expected_tool",
    [
        ("payments_send", "payments_send "),
        ("payments_send ", "payments_send"),
    ],
)
def test_verify_with_context_rejects_whitespace_normalization(
    proposal_tool: str, expected_tool: str
) -> None:
    """MAINT-F1: verify_with_context must not trim its operands.

    Per docs/spec-core.md §7.2, security-relevant protocol values
    are compared as represented on the wire. A proposal-side
    ``action.tool`` and the guard's ``expected_tool`` that differ
    only by whitespace MUST fail-closed with a binding mismatch,
    not be silently coerced to equality by a runtime ``.strip()``.
    """
    proposal = {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "approved_invoice", "trust": "trusted"}],
        "claims": [{"text": "Invoice approved for $500", "evidence": ["approved_invoice"]}],
        "action": {"tool": proposal_tool, "args": {"amount": 500}},
    }
    ap = ActionProposal(**proposal)
    with pytest.raises(ValueError, match="Tool binding mismatch"):
        ap.verify_with_context(expected_tool=expected_tool)
