from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from pic_standard.integrations import PICToolNode
from pic_standard.pipeline import PICLegacyTrustModeWarning


@tool
def payments_send(amount: int) -> str:
    """Send a payment of the given amount (test tool)."""
    return f"sent ${amount}"


def make_money_proposal(trust: str) -> dict:
    prov_id = "invoice_123" if trust == "trusted" else "random_web"
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": prov_id, "trust": trust, "source": "unit-test"}],
        "claims": [{"text": "Pay $500", "evidence": [prov_id]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


def test_pic_toolnode_blocks_untrusted_money():
    node = PICToolNode([payments_send])
    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "payments_send",
                        "args": {"amount": 500, "__pic": make_money_proposal("untrusted")},
                        "id": "1",
                    }
                ],
            )
        ]
    }
    with pytest.raises(ValueError):
        node.invoke(state)


def test_pic_toolnode_allows_trusted_money():
    node = PICToolNode([payments_send], strict_trust=False)
    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "payments_send",
                        "args": {"amount": 500, "__pic": make_money_proposal("trusted")},
                        "id": "2",
                    }
                ],
            )
        ]
    }
    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = node.invoke(state)
    assert out["messages"][0].content == "sent $500"


def test_pic_toolnode_blocks_tool_binding_mismatch():
    """
    Integration must block when the actual tool call name doesn't match
    proposal.action.tool. This should be enforced via ActionProposal.verify_with_context(...).
    """
    node = PICToolNode([payments_send], strict_trust=False)

    proposal = make_money_proposal("trusted")
    proposal["action"]["tool"] = "some_other_tool"  # mismatch on purpose

    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "payments_send",  # actual tool being called
                        "args": {"amount": 500, "__pic": proposal},
                        "id": "3",
                    }
                ],
            )
        ]
    }

    with (
        pytest.warns(
            PICLegacyTrustModeWarning,
            match="strict_trust=False enables legacy trust behavior",
        ),
        pytest.raises(ValueError) as e,
    ):
        node.invoke(state)

    # Don't assert the exact string (too brittle), but require clear intent.
    msg = str(e.value).lower()
    assert "tool" in msg and ("binding" in msg or "mismatch" in msg)


# ---------------------------------------------------------------------------
# v0.8: PICToolNode config passthrough tests
# ---------------------------------------------------------------------------


def test_pic_toolnode_strict_trust_blocks_self_asserted_trust():
    """strict_trust=True via PICToolNode constructor → pipeline sanitizes trust → blocked."""
    node = PICToolNode(
        [payments_send],
        strict_trust=True,
        verify_evidence=False,
    )
    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "payments_send",
                        "args": {"amount": 500, "__pic": make_money_proposal("trusted")},
                        "id": "4",
                    }
                ],
            )
        ]
    }
    with pytest.raises(ValueError) as e:
        node.invoke(state)

    msg = str(e.value).lower()
    assert "pic blocked" in msg


def test_pic_toolnode_passes_config_to_pipeline(monkeypatch):
    """Prove all PICToolNode config fields are threaded into PipelineOptions."""
    captured = {}

    def fake_verify_proposal(proposal, *, options):
        captured["tool_name"] = options.tool_name
        captured["expected_tool"] = options.expected_tool
        captured["policy"] = options.policy
        captured["verify_evidence"] = options.verify_evidence
        captured["strict_trust"] = options.strict_trust
        captured["key_resolver"] = options.key_resolver
        captured["proposal_base_dir"] = options.proposal_base_dir
        captured["evidence_root_dir"] = options.evidence_root_dir

        class Result:
            ok = True
            action_proposal = None
            evidence_report = None
            impact = "money"
            eval_ms = 0
            error = None

        return Result()

    monkeypatch.setattr(
        "pic_standard.integrations.langgraph_pic_toolnode.verify_proposal",
        fake_verify_proposal,
    )

    resolver = object()
    policy = object()
    proposal_base_dir = Path("/tmp/proposals")
    evidence_root_dir = Path("/tmp/evidence")

    node = PICToolNode(
        [payments_send],
        policy=policy,
        verify_evidence=True,
        strict_trust=True,
        key_resolver=resolver,
        proposal_base_dir=proposal_base_dir,
        evidence_root_dir=evidence_root_dir,
    )

    state = {
        "messages": [
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "payments_send",
                        "args": {"amount": 500, "__pic": make_money_proposal("trusted")},
                        "id": "5",
                    }
                ],
            )
        ]
    }

    node.invoke(state)

    assert captured["tool_name"] == "payments_send"
    assert captured["expected_tool"] == "payments_send"
    assert captured["policy"] is policy
    assert captured["verify_evidence"] is True
    assert captured["strict_trust"] is True
    assert captured["key_resolver"] is resolver
    assert captured["proposal_base_dir"] == proposal_base_dir
    assert captured["evidence_root_dir"] == evidence_root_dir
