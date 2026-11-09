"""Issue #185: audit separation, public safety, correlation, and compatibility."""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from pic_standard.errors import PICError, PICErrorCode
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool, guard_mcp_tool_async
from pic_standard.policy import PICPolicy

MARKER = "SENSITIVE-SYNTHETIC-TOOL-SECRET-185"


def _events(caplog):
    return [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "pic_standard.mcp" and record.getMessage().startswith("{")
    ]


def _invoke(mode, tool, *, policy=None, max_tool_ms=None, on_allow=None, **kwargs):
    opts = {
        "policy": policy
        or PICPolicy(impact_by_tool={"sample": "privacy"}, require_pic_for_impacts=set())
    }
    if on_allow is not None:
        opts["on_allow"] = on_allow
    if mode == "async":
        if max_tool_ms is not None:
            opts["max_tool_ms"] = max_tool_ms
        return asyncio.run(guard_mcp_tool_async("sample", tool, **opts)(**kwargs))
    return guard_mcp_tool("sample", tool, **opts)(**kwargs)


def _tool_exception(kind):
    if kind == "pic":
        return PICError(
            PICErrorCode.INVALID_REQUEST,
            MARKER,
            details={"secret": MARKER},
        )
    if kind == "timeout":
        return TimeoutError(MARKER)
    return RuntimeError(MARKER)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("debug", [False, True])
def test_success_still_has_one_allow_and_original_envelope(mode, debug, monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1" if debug else "0")
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    entered = []

    if mode == "async":

        async def tool(amount):
            entered.append(amount)
            return "ok"
    else:

        def tool(amount):
            entered.append(amount)
            return "ok"

    result = _invoke(mode, tool, amount=7, __pic_request_id="req-success")
    assert result == {"isError": False, "result": "ok"}
    assert entered == [7]
    events = _events(caplog)
    assert [e["event"] for e in events] == ["pic_mcp_decision"]
    assert events[0]["decision"] == "allow"
    assert events[0]["request_id"] == "req-success"


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("debug", [False, True])
@pytest.mark.parametrize("kind", ["runtime", "pic", "timeout"])
def test_post_allow_exceptions_are_execution_errors(mode, debug, kind, monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1" if debug else "0")
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    entered = []

    if mode == "async":

        async def tool(amount):
            entered.append(amount)
            raise _tool_exception(kind)
    else:

        def tool(amount):
            entered.append(amount)
            raise _tool_exception(kind)

    result = _invoke(
        mode,
        tool,
        amount=7,
        __pic_request_id="req-execution",
        max_tool_ms=100 if mode == "async" else None,
    )
    assert entered == [7]
    assert result == {
        "isError": True,
        "error": {"code": "PIC_MCP_TOOL_ERROR", "message": "Tool execution failed"},
    }
    events = _events(caplog)
    assert [e["event"] for e in events] == [
        "pic_mcp_decision",
        "pic_mcp_tool_execution_error",
    ]
    assert events[0]["decision"] == "allow"
    assert events[0]["request_id"] == "req-execution"
    err = events[1]
    assert "decision" not in err
    assert err["tool"] == "sample"
    assert err["impact"] == "privacy"
    assert err["request_id"] == "req-execution"
    assert err["reason_code"] == "PIC_MCP_TOOL_ERROR"
    assert "proposal_id" not in err
    assert (
        (err.get("detail") == type(_tool_exception(kind)).__name__)
        if debug
        else ("detail" not in err)
    )
    assert MARKER not in str(events)
    assert MARKER not in str(result)


@pytest.mark.parametrize("debug", [False, True])
def test_async_guard_deadline_distinct_from_tool_raised_timeout(debug, monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1" if debug else "0")
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    entered, cancelled = [], []

    async def slow(amount):
        entered.append(amount)
        try:
            await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    result = _invoke("async", slow, amount=4, __pic_request_id="req-deadline", max_tool_ms=10)
    assert entered == [4]
    assert cancelled == [True]
    assert result["isError"] is True
    assert result["error"]["code"] == "PIC_MCP_TOOL_TIMEOUT"
    assert result["error"]["message"] == "Tool execution timed out"
    assert result["error"].get("details") == ({"max_tool_ms": 10} if debug else None)
    events = _events(caplog)
    assert [e["event"] for e in events] == [
        "pic_mcp_decision",
        "pic_mcp_tool_execution_error",
    ]
    assert events[0]["decision"] == "allow"
    assert events[1]["reason_code"] == "PIC_MCP_TOOL_TIMEOUT"
    assert events[1]["request_id"] == "req-deadline"
    assert "decision" not in events[1]


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("debug", [False, True])
def test_pre_dispatch_pic_block_preserved(mode, debug, monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1" if debug else "0")
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    entered = []

    if mode == "async":

        async def tool(**kwargs):
            entered.append(kwargs)
    else:

        def tool(**kwargs):
            entered.append(kwargs)

    policy = PICPolicy(impact_by_tool={"sample": "money"})
    result = _invoke(mode, tool, policy=policy, __pic_request_id="req-block")
    assert result["isError"] is True
    assert entered == []
    events = _events(caplog)
    assert [e["event"] for e in events] == ["pic_mcp_decision"]
    assert events[0]["decision"] == "block"


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("debug", [False, True])
def test_hook_abort_preserves_allow_no_dispatch(mode, debug, monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1" if debug else "0")
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    entered = []

    if mode == "async":

        async def tool(**kwargs):
            entered.append(kwargs)
    else:

        def tool(**kwargs):
            entered.append(kwargs)

    def hook(_decision, _tool_call):
        raise ValueError(MARKER)

    result = _invoke(mode, tool, on_allow=hook, __pic_request_id="req-hook")
    assert entered == []
    assert result["isError"] is True
    events = _events(caplog)
    assert [e["event"] for e in events] == [
        "pic_mcp_decision",
        "pic_mcp_hook_error",
    ]
    assert events[0]["decision"] == "allow"
    assert MARKER not in str(events)
    assert MARKER not in str(result)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("debug", [False, True])
def test_unexpected_pre_dispatch_exception_is_sanitized(mode, debug, monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1" if debug else "0")
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    entered = []

    def broken_evaluate(**kwargs):
        raise RuntimeError(MARKER)

    monkeypatch.setattr(
        "pic_standard.integrations.mcp_pic_guard._evaluate_pic_for_tool_call_with_decision",
        broken_evaluate,
    )
    if mode == "async":

        async def tool(**kwargs):
            entered.append(kwargs)
    else:

        def tool(**kwargs):
            entered.append(kwargs)

    result = _invoke(mode, tool)
    assert entered == []
    assert result == {
        "isError": True,
        "error": {"code": "PIC_INTERNAL_ERROR", "message": "Internal error while enforcing PIC"},
    }
    events = _events(caplog)
    assert [e["event"] for e in events] == ["pic_mcp_decision"]
    assert events[0]["decision"] == "block"
    assert MARKER not in str(events)
    assert MARKER not in str(result)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_proposal_metadata_and_live_argument_binding(mode, monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="pic_standard.mcp")
    monkeypatch.setenv("PIC_DEBUG", "0")
    entered = []

    def fake_verify(_proposal, *, options):
        return SimpleNamespace(
            ok=True,
            error=None,
            impact="money",
            eval_ms=2,
            action_proposal=SimpleNamespace(
                intent="synthetic", action={"tool": "sample", "args": {"amount": 7}}
            ),
            evidence_report=None,
        )

    monkeypatch.setattr("pic_standard.integrations.mcp_pic_guard.verify_proposal", fake_verify)

    if mode == "async":

        async def tool(amount):
            entered.append(amount)
            raise RuntimeError(MARKER)
    else:

        def tool(amount):
            entered.append(amount)
            raise RuntimeError(MARKER)

    proposal = {"id": "proposal-185"}
    result = _invoke(mode, tool, amount=7, __pic=proposal, __pic_request_id="req-proposal")
    assert entered == [7]
    assert result["error"]["code"] == "PIC_MCP_TOOL_ERROR"
    events = _events(caplog)
    assert [e["event"] for e in events] == [
        "pic_mcp_decision",
        "pic_mcp_tool_execution_error",
    ]
    assert events[0]["proposal_id"] == "proposal-185"
    assert events[1]["proposal_id"] == "proposal-185"
    assert events[1]["request_id"] == events[0]["request_id"] == "req-proposal"
    assert events[1]["impact"] == events[0]["impact"] == "money"

    caplog.clear()
    mismatch = _invoke(mode, tool, amount=8, __pic=proposal, __pic_request_id="req-mismatch")
    assert mismatch["isError"] is True
    assert mismatch["error"]["code"] == "PIC_ARG_BINDING_MISMATCH"
    assert entered == [7]
    events = _events(caplog)
    assert [e["event"] for e in events] == ["pic_mcp_decision"]
    assert events[0]["decision"] == "block"
