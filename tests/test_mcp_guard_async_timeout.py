from __future__ import annotations

import asyncio

import pytest
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool_async
from pic_standard.pipeline import PICLegacyTrustModeWarning
from pic_standard.policy import PICPolicy


def _proposal(trust: str) -> dict:
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "invoice_123", "trust": trust, "source": "unit-test"}],
        "claims": [{"text": "Pay $500", "evidence": ["invoice_123"]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


async def _slow_tool(amount: int) -> str:
    await asyncio.sleep(0.2)
    return f"sent ${amount}"


def test_async_guard_times_out_tool_execution():
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})

    wrapped = guard_mcp_tool_async(
        "payments_send",
        _slow_tool,
        policy=policy,
        verify_evidence=False,
        max_tool_ms=10,  # 10ms timeout
        strict_trust=False,
    )

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = asyncio.run(wrapped(amount=500, __pic=_proposal("trusted")))

    assert isinstance(out, dict)
    assert out.get("isError") is True
    err = out.get("error") or {}
    assert err.get("code", "").startswith("PIC_")
    # message is stable regardless of PIC_DEBUG
    assert err.get("message") == "Tool execution timed out"
