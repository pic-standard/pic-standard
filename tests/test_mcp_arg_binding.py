from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from pic_standard.canonical import sha256_hex
from pic_standard.errors import PICError, PICErrorCode
from pic_standard.integrations.mcp_pic_guard import (
    evaluate_pic_for_tool_call,
    guard_mcp_tool,
    guard_mcp_tool_async,
)
from pic_standard.policy import PICPolicy

MCP_LOGGER = "pic_standard.mcp"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _tool(**kwargs):
    return {"ran": True, "args": dict(kwargs)}


async def _async_tool(**kwargs):
    return {"ran": True, "args": dict(kwargs)}


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


def _audit_text(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records if r.name == MCP_LOGGER)


class _Recorder:
    def __init__(self):
        self.calls: list[tuple] = []

    def __call__(self, decision, tool_call):
        self.calls.append((decision, tool_call))


def _patch_ok(monkeypatch, declared_args, *, impact="money") -> None:
    """Force a successful verification whose action.args is `declared_args`."""
    ap = SimpleNamespace(
        intent="Send payment",
        action={"tool": "payments_send", "args": declared_args},
    )
    _patch_ok_ap(monkeypatch, ap, impact=impact)


def _patch_ok_ap(monkeypatch, action_proposal, *, impact="money") -> None:
    result = SimpleNamespace(
        ok=True,
        error=None,
        impact=impact,
        eval_ms=1,
        action_proposal=action_proposal,
        evidence_report=None,
    )
    monkeypatch.setattr(
        "pic_standard.integrations.mcp_pic_guard.verify_proposal",
        lambda proposal, *, options: result,
    )


def _run_guard(mode, declared, live, monkeypatch, *, on_allow=None):
    """Run the sync or async guard with declared action.args and live kwargs."""
    _patch_ok(monkeypatch, declared)
    if mode == "sync":
        wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy(), on_allow=on_allow)
        return wrapped(__pic={"id": "p1"}, **live)
    wrapped = guard_mcp_tool_async(
        "payments_send", _async_tool, policy=_money_policy(), on_allow=on_allow
    )
    return asyncio.run(wrapped(__pic={"id": "p1"}, **live))


# --------------------------------------------------------------------------- #
# Exact-match allows (sync + async)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_exact_match_allows(monkeypatch, mode):
    out = _run_guard(mode, {"amount": 500}, {"amount": 500}, monkeypatch)
    assert out["isError"] is False
    assert out["result"]["args"] == {"amount": 500}


# --------------------------------------------------------------------------- #
# Divergence classes block, through both guards
# --------------------------------------------------------------------------- #
_DIVERGENCE_CASES = [
    ("changed_value", {"amount": 500}, {"amount": 501}),
    ("extra_key", {"amount": 500}, {"amount": 500, "note": "x"}),
    ("missing_key", {"amount": 500, "to": "vendor"}, {"amount": 500}),
]


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("label,declared,live", _DIVERGENCE_CASES)
def test_divergence_blocks(monkeypatch, label, declared, live, mode):
    out = _run_guard(mode, declared, live, monkeypatch)
    assert out["isError"] is True and out["error"]["code"] == "PIC_ARG_BINDING_MISMATCH"


# --------------------------------------------------------------------------- #
# Canonical equality is order-independent (nested object reordered) -> allow
# --------------------------------------------------------------------------- #
def test_reordered_nested_object_canonically_equal_allows(monkeypatch):
    _patch_ok(monkeypatch, {"payload": {"a": 1, "b": 2}})
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    out = wrapped(payload={"b": 2, "a": 1}, __pic={"id": "p1"})
    assert out["isError"] is False
    assert out["result"]["args"] == {"payload": {"b": 2, "a": 1}}


# --------------------------------------------------------------------------- #
# Live arguments that cannot be canonicalized -> ARG_BINDING_MISMATCH, no leak
# (strongest config: PIC_DEBUG=1; neither representation nor declared digest leaks)
# --------------------------------------------------------------------------- #
def test_live_noncanonicalizable_blocks_without_leak(monkeypatch, caplog):
    monkeypatch.setenv("PIC_DEBUG", "1")
    _patch_ok(monkeypatch, {"x": 0})
    declared_digest = sha256_hex({"x": 0})
    sentinel = object()  # repr like "<object object at 0x...>"; not JSON-canonicalizable
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(x=sentinel, __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_ARG_BINDING_MISMATCH"
    assert out["error"]["message"] == "Live tool arguments could not be canonicalized for binding"
    serialized_out = json.dumps(out)
    audit_text = _audit_text(caplog)
    assert "object at" not in serialized_out
    assert "object at" not in audit_text
    assert declared_digest not in serialized_out
    assert declared_digest not in audit_text


# --------------------------------------------------------------------------- #
# Internal proposal invariants -> PIC_INTERNAL_ERROR (never ARG_BINDING_MISMATCH)
# --------------------------------------------------------------------------- #
def test_missing_declared_args_is_internal_error(monkeypatch):
    ap = SimpleNamespace(intent="Send payment", action={"tool": "payments_send"})  # no "args"
    _patch_ok_ap(monkeypatch, ap)
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    out = wrapped(amount=500, __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"


def test_noncanonicalizable_declared_args_is_internal_error(monkeypatch):
    # Verified action.args cannot be canonicalized -> internal invariant failure,
    # not a caller binding mismatch. Checked before the live digest.
    ap = SimpleNamespace(
        intent="Send payment",
        action={"tool": "payments_send", "args": {"x": object()}},
    )
    _patch_ok_ap(monkeypatch, ap)
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    out = wrapped(x=object(), __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_INTERNAL_ERROR"


# --------------------------------------------------------------------------- #
# Correlation keys: plain request_id participates; __pic_request_id never does
# --------------------------------------------------------------------------- #
def test_plain_request_id_absent_from_args_blocks(monkeypatch):
    _patch_ok(monkeypatch, {"amount": 500})
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    out = wrapped(amount=500, request_id="r1", __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_ARG_BINDING_MISMATCH"


def test_plain_request_id_present_in_args_allows(monkeypatch):
    _patch_ok(monkeypatch, {"amount": 500, "request_id": "r1"})
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    out = wrapped(amount=500, request_id="r1", __pic={"id": "p1"})
    assert out["isError"] is False
    assert out["result"]["args"] == {"amount": 500, "request_id": "r1"}


def test_pic_request_id_never_participates(monkeypatch):
    _patch_ok(monkeypatch, {"amount": 500})
    wrapped = guard_mcp_tool("payments_send", _tool, policy=_money_policy())
    out = wrapped(amount=500, __pic_request_id="r1", __pic={"id": "p1"})
    assert out["isError"] is False
    assert out["result"]["args"] == {"amount": 500}  # __pic_request_id stripped, not dispatched


# --------------------------------------------------------------------------- #
# Mismatch lifecycle: one block, no allow, hook never invoked, tool never ran,
# and no argument value or digest in the envelope or audit
# --------------------------------------------------------------------------- #
def test_mismatch_blocks_once_no_allow_no_hook_no_dispatch(monkeypatch, caplog):
    ran: list = []

    def tool(**kwargs):
        ran.append(True)
        return "x"

    rec = _Recorder()
    _patch_ok(monkeypatch, {"amount": 500})
    wrapped = guard_mcp_tool("payments_send", tool, policy=_money_policy(), on_allow=rec)
    with caplog.at_level(logging.INFO, logger=MCP_LOGGER):
        out = wrapped(amount=501, __pic={"id": "p1"})
    assert out["isError"] is True and out["error"]["code"] == "PIC_ARG_BINDING_MISMATCH"
    assert ran == []  # tool never dispatched
    assert rec.calls == []  # hook never invoked
    blocks = [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "block"]
    assert len(blocks) == 1 and blocks[0]["reason_code"] == "PIC_ARG_BINDING_MISMATCH"
    assert not [e for e in _events(caplog, "pic_mcp_decision") if e["decision"] == "allow"]

    declared_digest = sha256_hex({"amount": 500})
    live_digest = sha256_hex({"amount": 501})
    serialized_out = json.dumps(out)
    audit_text = _audit_text(caplog)
    for leak in ("501", declared_digest, live_digest):
        assert leak not in serialized_out
        assert leak not in audit_text


# --------------------------------------------------------------------------- #
# Low-level evaluate_pic_for_tool_call raises on mismatch (fixed message, no details)
# --------------------------------------------------------------------------- #
def test_direct_evaluate_raises_on_mismatch(monkeypatch):
    _patch_ok(monkeypatch, {"amount": 500})
    with pytest.raises(PICError) as exc:
        evaluate_pic_for_tool_call(
            tool_name="payments_send",
            tool_args={"amount": 501, "__pic": {"id": "p1"}},
            policy=_money_policy(),
        )
    assert exc.value.code == PICErrorCode.ARG_BINDING_MISMATCH
    assert exc.value.message == "Tool argument binding mismatch"
    assert not getattr(exc.value, "details", None)
