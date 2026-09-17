from __future__ import annotations

import time

import pytest
from pic_standard.integrations.mcp_pic_guard import PICEvaluateLimits, guard_mcp_tool
from pic_standard.pipeline import PICLegacyTrustModeWarning
from pic_standard.policy import PICPolicy


def _tool(amount: int) -> str:
    return f"sent ${amount}"


def _proposal(trust: str) -> dict:
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "invoice_123", "trust": trust, "source": "unit-test"}],
        "claims": [{"text": "Pay $500", "evidence": ["invoice_123"]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


def test_time_budget_exceeded_blocks(monkeypatch):
    # Simulate perf_counter moving forward so the budget is exceeded
    t = {"n": 0}

    def fake_perf_counter() -> float:
        # 0.0s, then 1.0s, then 2.0s...
        v = float(t["n"])
        t["n"] += 1
        return v

    monkeypatch.setattr(time, "perf_counter", fake_perf_counter)

    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    limits = PICEvaluateLimits(max_eval_ms=10)  # 10ms budget (will be exceeded by fake time jumps)
    wrapped = guard_mcp_tool(
        "payments_send",
        _tool,
        policy=policy,
        limits=limits,
        verify_evidence=False,
        strict_trust=False,
    )

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = wrapped(amount=500, __pic=_proposal("trusted"))

    assert isinstance(out, dict)
    assert out.get("isError") is True
    err = out.get("error") or {}
    assert (err.get("code") or "").startswith("PIC_")
    assert err.get("message") == "PIC evaluation exceeded time budget"
