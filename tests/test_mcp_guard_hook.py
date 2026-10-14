from __future__ import annotations

import asyncio
import gc
import json
import logging
import warnings
from types import SimpleNamespace

import pytest
from pic_standard.canonical import intent_digest_hex, sha256_hex
from pic_standard.errors import PICError, PICErrorCode
from pic_standard.integrations import MCPAllowDecision, MCPToolCall
from pic_standard.integrations.mcp_pic_guard import (
    evaluate_pic_for_tool_call,
    guard_mcp_tool,
    guard_mcp_tool_async,
)
from pic_standard.pipeline import PICLegacyTrustModeWarning
from pic_standard.policy import PICPolicy

MCP_LOGGER = "pic_standard.mcp"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _tool(**kwargs):
    return {"ran": True, "args": dict(kwargs)}


async def _async_tool(**kwargs):
    return {"ran": True, "args": dict(kwargs)}


def _proposal(trust: str = "trusted") -> dict:
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "invoice_123", "trust": trust, "source": "unit-test"}],
        "claims": [{"text": "Pay $500", "evidence": ["invoice_123"]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


def _money_policy() -> PICPolicy:
    return PICPolicy(impact_by_tool={"payments_send": "money"})


def _events(caplog, kind: str) -> list[dict]:
    out = []
    for r in caplog.records:
        if r.name != MCP_LOGGER:
            continue
        try:
            obj = json.loads(r.getMessage())
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict) and obj.get("event") == kind:
            out.append(obj)
    return out


class _Recorder:
    def __init__(self):
        self.calls: list[tuple] = []

    def __call__(self, decision, tool_call):
        self.calls.append((decision, tool_call))


def _declared_ap(amount: int = 500) -> SimpleNamespace:
    return SimpleNamespace(
        intent="Send payment", action={"tool": "payments_send", "args": {"amount": amount}}
    )


def _patch_verify_ok(
    monkeypatch, *, action_proposal, impact="money", eval_ms=5, verified=("e1",)
) -> None:
    result = SimpleNamespace(
        ok=True,
        error=None,
        impact=impact,
        eval_ms=eval_ms,
        action_proposal=action_proposal,
        evidence_report=SimpleNamespace(verified_ids=set(verified)),
    )
    monkeypatch.setattr(
        "pic_standard.integrations.mcp_pic_guard.verify_proposal",
        lambda proposal, *, options: result,
    )


def _patch_verify_fail(monkeypatch, code: PICErrorCode) -> None:
    result = SimpleNamespace(ok=False, error=PICError(code=code, message="verification failed"))
    monkeypatch.setattr(
        "pic_standard.integrations.mcp_pic_guard.verify_proposal",
        lambda proposal, *, options: result,
    )


# --------------------------------------------------------------------------- #
# Unit tests for the hook data types
# --------------------------------------------------------------------------- #
def test_allow_decision_audit_bytes_shape_and_order():
    d = MCPAllowDecision(
        tool="payments_send",
        impact="money",
        request_id="r1",
        proposal_present=True,
        proposal_id="p1",
        verified_evidence_count=1,
        eval_ms=3,
    )
    expected = {
        "event": "pic_mcp_decision",
        "decision": "allow",
        "tool": "payments_send",
        "impact": "money",
        "request_id": "r1",
        "proposal_id": "p1",
        "verified_evidence_count": 1,
        "eval_ms": 3,
    }
    assert d.to_audit_bytes() == json.dumps(expected, ensure_ascii=False).encode("utf-8")
    assert list(json.loads(d.to_audit_bytes())) == list(expected)


def test_allow_decision_audit_omits_hook_only_fields():
    d = MCPAllowDecision(
        tool="t", impact=None, proposal_present=True, intent_digest="a" * 64, args_digest="b" * 64
    )
    b = d.to_audit_bytes()
    assert b"intent_digest" not in b
    assert b"args_digest" not in b
    assert b"proposal_present" not in b
    assert json.loads(b)["impact"] is None


def test_allow_decision_is_fixed_and_keyword_only():
    with pytest.raises(TypeError):
        MCPAllowDecision(tool="t", impact="money", decision="block")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        MCPAllowDecision("t", "money")  # type: ignore[misc]
    assert not hasattr(MCPAllowDecision(tool="t", impact=None), "__dict__")


def test_tool_call_build_is_consistent_and_immutable():
    tc = MCPToolCall.build("payments_send", {"amount": 500})
    assert tc.to_dict() == {"name": "payments_send", "arguments": {"amount": 500}}
    assert tc.arguments_digest == sha256_hex({"amount": 500})
    assert tc.tool_call_digest == sha256_hex(
        {"name": "payments_send", "arguments": {"amount": 500}}
    )
    assert not hasattr(tc, "__dict__")
    mutated = tc.to_dict()
    mutated["arguments"]["amount"] = 999
    assert tc.to_dict() == {"name": "payments_send", "arguments": {"amount": 500}}


def test_tool_call_rejects_inconsistent_instance():
    with pytest.raises(ValueError):
        MCPToolCall(
            name="safe_tool",
            canonical_bytes=b'{"name":"other_tool","arguments":{}}',
            arguments_digest="x",
            tool_call_digest="y",
        )


# --------------------------------------------------------------------------- #
# No-hook: unchanged behavior + audit
# --------------------------------------------------------------------------- #
def test_no_hook_allow_runs_and_audits_once(caplog):
    wrapped = guard_mcp_tool("read_thing", _tool)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(x=1, __pic_request_id="r0")
    assert out == {"isError": False, "result": {"ran": True, "args": {"x": 1}}}
    allows = _events(caplog, "pic_mcp_decision")
    assert len(allows) == 1 and allows[0]["decision"] == "allow"


def test_public_evaluate_returns_two_tuple_and_one_allow(caplog):
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        res = evaluate_pic_for_tool_call(
            tool_name="read_thing", tool_args={"x": 2}, policy=PICPolicy()
        )
    assert isinstance(res, tuple) and len(res) == 2
    assert len([e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "allow"]) == 1


def test_no_hook_non_canonicalizable_args_still_run():
    # No hook => no MCPToolCall build => no canonicalization requirement on live args.
    wrapped = guard_mcp_tool("read_thing", _tool)
    out = wrapped(obj=object())
    assert out["isError"] is False


# --------------------------------------------------------------------------- #
# Hook fires: ordering, sanitized call, digests
# --------------------------------------------------------------------------- #
def test_hook_fires_once_before_tool_sync():
    order: list[str] = []
    rec = _Recorder()

    def tracking_tool(**kwargs):
        order.append("tool")
        return "done"

    def hook(decision, tool_call):
        order.append("hook")
        rec(decision, tool_call)

    wrapped = guard_mcp_tool("read_thing", tracking_tool, on_allow=hook)
    out = wrapped(a="b", __pic_request_id="r1")
    assert out["isError"] is False
    assert order == ["hook", "tool"]
    assert len(rec.calls) == 1
    decision, tool_call = rec.calls[0]
    assert decision.decision == "allow" and decision.proposal_present is False
    assert decision.intent_digest is None and decision.args_digest is None
    assert tool_call.to_dict() == {"name": "read_thing", "arguments": {"a": "b"}}
    assert "__pic_request_id" not in tool_call.to_dict()["arguments"]


def test_hook_proposal_backed_digests_and_meta_stripped_sync(monkeypatch):
    rec = _Recorder()
    _patch_verify_ok(monkeypatch, action_proposal=_declared_ap(500))
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy(), on_allow=rec)
    out = wrapped(amount=500, __pic={"id": "p1"}, __pic_request_id="rM")
    assert out["isError"] is False
    decision, tool_call = rec.calls[0]
    assert decision.proposal_present is True and decision.proposal_id == "p1"
    assert decision.request_id == "rM"
    assert decision.impact == "money" and decision.verified_evidence_count == 1
    assert decision.intent_digest == intent_digest_hex("Send payment")
    assert decision.args_digest == sha256_hex({"amount": 500})
    assert tool_call.arguments_digest == decision.args_digest
    # both PIC metadata keys stripped from the hook's view AND the tool's args
    assert tool_call.to_dict()["arguments"] == {"amount": 500}
    assert out["result"]["args"] == {"amount": 500}


def test_hook_real_pipeline_proposal_backed():
    # Exercises the real ActionProposal (intent / action["args"]) end-to-end.
    rec = _Recorder()
    wrapped = guard_mcp_tool(
        "payments_send", _tool, policy=_money_policy(), strict_trust=False, on_allow=rec
    )
    with pytest.warns(PICLegacyTrustModeWarning):
        out = wrapped(amount=500, __pic=_proposal("trusted"))
    assert out["isError"] is False
    decision, tool_call = rec.calls[0]
    assert decision.proposal_present is True
    assert decision.intent_digest == intent_digest_hex("Send payment")
    assert decision.args_digest == sha256_hex({"amount": 500})
    assert tool_call.arguments_digest == decision.args_digest


def test_live_arg_mismatch_blocks(monkeypatch, caplog):
    # The proposal declares {"amount": 500}, but the sanitized live call has
    # {"amount": 501}. Binding fails closed in the evaluator before the allow
    # decision: one block, no allow, no hook, no dispatch.
    rec = _Recorder()
    _patch_verify_ok(monkeypatch, action_proposal=_declared_ap(500))
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy(), on_allow=rec)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(amount=501, __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_ARG_BINDING_MISMATCH"
    assert rec.calls == []  # hook never invoked
    blocks = [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "block"]
    assert len(blocks) == 1 and blocks[0]["reason_code"] == "PIC_ARG_BINDING_MISMATCH"
    assert not [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "allow"]


def test_detached_copy_mutation_does_not_reach_tool():
    received: dict = {}

    def tool(**kwargs):
        received.update(kwargs)
        return "ok"

    def hook(decision, tool_call):
        d = tool_call.to_dict()
        d["arguments"]["a"] = "TAMPERED"  # mutate the returned copy at the boundary

    wrapped = guard_mcp_tool("read_thing", tool, on_allow=hook)
    out = wrapped(a="b")
    assert out["isError"] is False
    assert received == {"a": "b"}  # business tool receives the original sanitized args


def test_logged_allow_equals_decision_to_audit_bytes(caplog):
    rec = _Recorder()
    wrapped = guard_mcp_tool("read_thing", _tool, on_allow=rec)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        wrapped(a="b", __pic_request_id="r1")
    decision, _ = rec.calls[0]
    logged = [
        r.getMessage()
        for r in caplog.records
        if r.name == MCP_LOGGER and '"pic_mcp_decision"' in r.getMessage()
    ]
    assert len(logged) == 1
    assert logged[0] == decision.to_audit_bytes().decode("utf-8")


# --------------------------------------------------------------------------- #
# Hook failure: fail-closed, distinct error, correlated, no leak, no block
# --------------------------------------------------------------------------- #
def test_raising_hook_fails_closed_sync(caplog):
    ran = []

    def tool(**kwargs):
        ran.append(True)
        return "x"

    def hook(decision, tool_call):
        raise ValueError("boom with secret arg value")

    wrapped = guard_mcp_tool("read_thing", tool, on_allow=hook)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(a="b", __pic_request_id="rX")
    assert out == {
        "isError": True,
        "error": {
            "code": "PIC_INTERNAL_ERROR",
            "message": "PIC pre-execution hook failed",
        },
    }
    assert ran == []  # tool never dispatched
    assert len(_events(caplog, "pic_mcp_hook_error")) == 1
    assert not [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "block"]
    assert len([e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "allow"]) == 1


def test_hook_error_correlates_with_decision_and_no_leak(monkeypatch, caplog):
    monkeypatch.delenv("PIC_DEBUG", raising=False)

    def hook(decision, tool_call):
        raise ValueError("secret-value-1234")

    wrapped = guard_mcp_tool("read_thing", _tool, on_allow=hook)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(a="b", __pic_request_id="rX")
    assert out["isError"] is True
    he = _events(caplog, "pic_mcp_hook_error")[0]
    assert he["tool"] == "read_thing" and he["request_id"] == "rX"
    assert he["impact"] is None
    assert he["reason_code"] == "PIC_INTERNAL_ERROR"
    assert "secret-value-1234" not in json.dumps(he)
    assert "detail" not in he


def test_hook_error_impact_comes_from_decision_not_policy(monkeypatch, caplog):
    # Regression guard: the hook-error identity is derived from the resolved decision
    # (result.impact), NOT from policy.impact_by_tool. Here policy says "money" but the
    # pipeline resolves "data"; the audited impact must follow the decision.
    monkeypatch.delenv("PIC_DEBUG", raising=False)
    _patch_verify_ok(monkeypatch, action_proposal=_declared_ap(500), impact="data")

    def hook(decision, tool_call):
        raise ValueError("x")

    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy(), on_allow=hook)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(amount=500, __pic={"id": "p1"})
    assert out["isError"] is True
    he = _events(caplog, "pic_mcp_hook_error")[0]
    assert he["impact"] == "data"  # from the decision, not policy "money"


def test_hook_error_detail_only_in_debug(monkeypatch, caplog):
    def hook(decision, tool_call):
        raise ValueError("whatever")

    wrapped = guard_mcp_tool("read_thing", _tool, on_allow=hook)
    monkeypatch.setenv("PIC_DEBUG", "1")
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        wrapped(a="b")
    he = _events(caplog, "pic_mcp_hook_error")[0]
    assert he.get("detail") == "ValueError"  # exception type only, never the value


def test_async_def_hook_fails_closed_without_warning_sync(caplog):
    async def hook(decision, tool_call):  # wrong: async def
        return None

    wrapped = guard_mcp_tool("read_thing", _tool, on_allow=hook)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
            out = wrapped(a="b")
        gc.collect()
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"
    assert len(_events(caplog, "pic_mcp_hook_error")) == 1
    assert not any("never awaited" in str(x.message) for x in w)


def test_non_none_hook_fails_closed_sync(caplog):
    wrapped = guard_mcp_tool("read_thing", _tool, on_allow=lambda d, t: "not none")
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(a="b")
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"
    assert len(_events(caplog, "pic_mcp_hook_error")) == 1


def test_hook_context_canonicalization_failure_fails_closed(caplog):
    rec = _Recorder()
    wrapped = guard_mcp_tool("read_thing", _tool, on_allow=rec)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(obj=object())  # not JSON-canonicalizable
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"
    assert rec.calls == []  # hook never received a (false) context
    assert len(_events(caplog, "pic_mcp_hook_error")) == 1


def test_proposal_backed_missing_action_proposal_fails_closed(monkeypatch, caplog):
    # ok=True but no ActionProposal is an internal invariant failure, caught in
    # the evaluator before the allow decision: PIC_INTERNAL_ERROR block, hook
    # never invoked, and a decision block (not a pic_mcp_hook_error event).
    rec = _Recorder()
    _patch_verify_ok(monkeypatch, action_proposal=None)  # present, but no ActionProposal
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy(), on_allow=rec)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(amount=500, __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"
    assert rec.calls == []  # hook never invoked
    assert _events(caplog, "pic_mcp_hook_error") == []
    blocks = [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "block"]
    assert len(blocks) == 1 and blocks[0]["reason_code"] == "PIC_INTERNAL_ERROR"
    assert not [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "allow"]


# --------------------------------------------------------------------------- #
# Block path unchanged + hook never fires on block
# --------------------------------------------------------------------------- #
def test_block_path_unchanged_and_hook_never_fires(monkeypatch, caplog):
    rec = _Recorder()
    _patch_verify_fail(monkeypatch, PICErrorCode.EVIDENCE_FAILED)
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy(), on_allow=rec)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(amount=500, __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_EVIDENCE_FAILED"
    blocks = [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "block"]
    assert len(blocks) == 1
    assert not [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "allow"]
    assert rec.calls == []  # hook never fires on a block


# --------------------------------------------------------------------------- #
# Async parity
# --------------------------------------------------------------------------- #
def test_hook_fires_before_await_async():
    order: list[str] = []

    async def tool(**kwargs):
        order.append("tool")
        return "ok"

    def hook(decision, tool_call):
        order.append("hook")

    wrapped = guard_mcp_tool_async("read_thing", tool, on_allow=hook)
    out = asyncio.run(wrapped(a="b"))
    assert out["isError"] is False and order == ["hook", "tool"]


def test_hook_proposal_backed_async(monkeypatch):
    rec = _Recorder()
    _patch_verify_ok(monkeypatch, action_proposal=_declared_ap(500))
    wrapped = guard_mcp_tool_async(
        "payments_send", _async_tool, policy=_money_policy(), on_allow=rec
    )
    out = asyncio.run(wrapped(amount=500, __pic={"id": "p1"}, __pic_request_id="rA"))
    assert out["isError"] is False
    assert len(rec.calls) == 1
    decision, tool_call = rec.calls[0]
    assert decision.proposal_present is True and decision.proposal_id == "p1"
    assert decision.request_id == "rA"
    assert decision.impact == "money" and decision.verified_evidence_count == 1
    assert decision.intent_digest == intent_digest_hex("Send payment")
    assert decision.args_digest == sha256_hex({"amount": 500})
    assert tool_call.to_dict() == {"name": "payments_send", "arguments": {"amount": 500}}
    assert tool_call.arguments_digest == decision.args_digest
    assert out["result"]["args"] == {"amount": 500}


def test_async_def_hook_fails_closed_without_warning_async(caplog):
    async def hook(decision, tool_call):
        return None

    wrapped = guard_mcp_tool_async("read_thing", _async_tool, on_allow=hook)
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
            out = asyncio.run(wrapped(a="b"))
        gc.collect()
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"
    assert len(_events(caplog, "pic_mcp_hook_error")) == 1
    assert not any("never awaited" in str(x.message) for x in w)


def test_raising_hook_fails_closed_async(caplog):
    ran = []

    async def tool(**kwargs):
        ran.append(True)
        return "x"

    def hook(decision, tool_call):
        raise RuntimeError("nope")

    wrapped = guard_mcp_tool_async("read_thing", tool, on_allow=hook)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = asyncio.run(wrapped(a="b"))
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"
    assert ran == []  # async tool never dispatched
    assert len(_events(caplog, "pic_mcp_hook_error")) == 1
    assert not [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "block"]
