from __future__ import annotations

import asyncio

import pytest
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool, guard_mcp_tool_async
from pic_standard.pipeline import PICLegacyTrustModeWarning
from pic_standard.policy import PICPolicy


def _tool(amount: int) -> str:
    return f"sent ${amount}"


async def _async_tool(amount: int) -> str:
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


def test_guard_blocks_missing_pic_for_money():
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool("payments_send", _tool, policy=policy, verify_evidence=False)

    out = wrapped(amount=500)
    assert isinstance(out, dict)
    assert out.get("isError") is True
    assert out["error"]["code"].startswith("PIC_")


def test_guard_blocks_untrusted_money():
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool("payments_send", _tool, policy=policy, verify_evidence=False)

    out = wrapped(amount=500, __pic=_proposal("untrusted"))
    assert isinstance(out, dict)
    assert out.get("isError") is True


def test_guard_allows_trusted_money():
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool(
        "payments_send",
        _tool,
        policy=policy,
        verify_evidence=False,
        strict_trust=False,
    )

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = wrapped(amount=500, __pic=_proposal("trusted"))

    # ✅ New deterministic success envelope contract (v0.3.2 hardening)
    assert out == {"isError": False, "result": "sent $500"}


def test_guard_blocks_tool_binding_mismatch():
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool(
        "payments_send",
        _tool,
        policy=policy,
        verify_evidence=False,
        strict_trust=False,
    )

    bad = _proposal("trusted")
    bad["action"]["tool"] = "some_other_tool"  # mismatch on purpose

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = wrapped(amount=500, __pic=bad)
    assert isinstance(out, dict)
    assert out.get("isError") is True

    err = out.get("error") or {}
    code = (err.get("code") or "").upper()
    msg = (err.get("message") or "").lower()

    # Strong but not brittle: must clearly be a tool-binding block.
    assert "TOOL" in code and ("BIND" in code or "MISMATCH" in code)
    assert "tool" in msg and ("bind" in msg or "mismatch" in msg)


def test_mcp_guard_does_not_leak_internal_exception_details_by_default(monkeypatch):
    monkeypatch.delenv("PIC_DEBUG", raising=False)

    def boom(amount: int) -> str:
        raise RuntimeError("secret path C:\\users\\bob\\prod.key")

    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool(
        "payments_send",
        boom,
        policy=policy,
        verify_evidence=False,
        strict_trust=False,
    )

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = wrapped(amount=1, __pic=_proposal("trusted"))
    assert isinstance(out, dict)
    assert out.get("isError") is True
    err = out.get("error") or {}
    # Must not leak raw exception text by default
    details = err.get("details") or {}
    assert "exception" not in details
    assert "exception_type" not in details


def test_mcp_guard_leaks_internal_exception_details_when_debug(monkeypatch):
    monkeypatch.setenv("PIC_DEBUG", "1")

    def boom(amount: int) -> str:
        raise RuntimeError("leak-me")

    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool(
        "payments_send",
        boom,
        policy=policy,
        verify_evidence=False,
        strict_trust=False,
    )

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        out = wrapped(amount=1, __pic=_proposal("trusted"))
    err = out.get("error") or {}
    details = err.get("details") or {}
    assert details.get("exception_type") == "RuntimeError"
    assert "leak-me" in (details.get("exception") or "")


# ---------------------------------------------------------------------------
# v0.8: strict_trust + key_resolver passthrough tests
# ---------------------------------------------------------------------------


def test_guard_sync_strict_trust_blocks_self_asserted_trust():
    """strict_trust=True via guard_mcp_tool → pipeline sanitizes trust → blocked."""
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool(
        "payments_send",
        _tool,
        policy=policy,
        verify_evidence=False,
        strict_trust=True,
    )

    out = wrapped(amount=500, __pic=_proposal("trusted"))
    assert isinstance(out, dict)
    assert out.get("isError") is True
    err = out.get("error") or {}
    assert err.get("code", "").startswith("PIC_")


def test_guard_async_strict_trust_blocks_self_asserted_trust():
    """strict_trust=True via guard_mcp_tool_async → pipeline sanitizes trust → blocked."""
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool_async(
        "payments_send",
        _async_tool,
        policy=policy,
        verify_evidence=False,
        strict_trust=True,
    )

    out = asyncio.run(wrapped(amount=500, __pic=_proposal("trusted")))
    assert isinstance(out, dict)
    assert out.get("isError") is True
    err = out.get("error") or {}
    assert err.get("code", "").startswith("PIC_")


def test_guard_sync_passes_key_resolver(monkeypatch):
    """Prove key_resolver is threaded from guard_mcp_tool through to PipelineOptions."""
    captured = {}

    def fake_verify_proposal(proposal, *, options):
        captured["key_resolver"] = options.key_resolver

        class Result:
            ok = True
            action_proposal = None
            evidence_report = None
            impact = "money"
            eval_ms = 0
            error = None

        return Result()

    monkeypatch.setattr(
        "pic_standard.integrations.mcp_pic_guard.verify_proposal",
        fake_verify_proposal,
    )

    resolver = object()
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool(
        "payments_send",
        _tool,
        policy=policy,
        key_resolver=resolver,
    )

    out = wrapped(amount=500, __pic=_proposal("trusted"))
    assert out["isError"] is False
    assert captured["key_resolver"] is resolver


def test_guard_async_passes_key_resolver(monkeypatch):
    """Prove key_resolver is threaded from guard_mcp_tool_async through to PipelineOptions."""
    captured = {}

    def fake_verify_proposal(proposal, *, options):
        captured["key_resolver"] = options.key_resolver

        class Result:
            ok = True
            action_proposal = None
            evidence_report = None
            impact = "money"
            eval_ms = 0
            error = None

        return Result()

    monkeypatch.setattr(
        "pic_standard.integrations.mcp_pic_guard.verify_proposal",
        fake_verify_proposal,
    )

    resolver = object()
    policy = PICPolicy(impact_by_tool={"payments_send": "money"})
    wrapped = guard_mcp_tool_async(
        "payments_send",
        _async_tool,
        policy=policy,
        key_resolver=resolver,
    )

    out = asyncio.run(wrapped(amount=500, __pic=_proposal("trusted")))
    assert out["isError"] is False
    assert captured["key_resolver"] is resolver
