"""Smoke tests — MCP SDK importability + MCP guard integration path.

These tests use ``pytest.importorskip`` so they gracefully skip
when the MCP optional dependency is not installed, and run when CI
installs ``requirements-mcp.txt``.

The integration-path tests exercise ``evaluate_pic_for_tool_call`` with
MCP-shaped arguments to confirm end-to-end compatibility.  These are
pure Python and do NOT require the mcp package.
"""

from __future__ import annotations

import pytest
from conftest import make_proposal
from pic_standard.pipeline import PICLegacyTrustModeWarning

# ---------------------------------------------------------------------------
# Upstream MCP SDK importability (exact symbols used by demos)
# ---------------------------------------------------------------------------


def test_mcp_fastmcp_importable():
    """mcp_pic_server_demo.py imports FastMCP (line 41)."""
    pytest.importorskip("mcp")
    from mcp.server.fastmcp import FastMCP  # noqa: F401


def test_mcp_client_session_importable():
    """mcp_pic_client_demo.py imports ClientSession (line 20)."""
    pytest.importorskip("mcp")
    from mcp.client.session import ClientSession  # noqa: F401


def test_mcp_client_stdio_importable():
    """mcp_pic_client_demo.py imports stdio_client (line 21)."""
    pytest.importorskip("mcp")
    from mcp.client.stdio import stdio_client  # noqa: F401


# ---------------------------------------------------------------------------
# Real integration-path smoke tests (pure Python, no mcp dep needed)
# ---------------------------------------------------------------------------


def test_evaluate_pic_allows_low_impact_without_proposal():
    """evaluate_pic_for_tool_call(): read-impact tool with no __pic → allowed, no proposal."""
    from pic_standard.integrations.mcp_pic_guard import evaluate_pic_for_tool_call
    from pic_standard.policy import PICPolicy

    policy = PICPolicy(
        impact_by_tool={"docs_search": "read"},
        require_pic_for_impacts=["money", "irreversible"],
    )

    ap, returned_args = evaluate_pic_for_tool_call(
        tool_name="docs_search",
        tool_args={"query": "hello"},
        policy=policy,
    )

    assert ap is None
    assert returned_args == {"query": "hello"}


def test_evaluate_pic_allows_trusted_money_proposal():
    """evaluate_pic_for_tool_call(): valid trusted money proposal → allowed under legacy trust mode, __pic still in args."""
    from pic_standard.integrations.mcp_pic_guard import evaluate_pic_for_tool_call
    from pic_standard.policy import PICPolicy

    policy = PICPolicy(
        impact_by_tool={"payments_send": "money"},
        require_pic_for_impacts=["money"],
    )

    proposal = make_proposal(
        tool="payments_send",
        impact="money",
        trust="trusted",
        args={"to": "vendor", "amount": 50},
    )

    with pytest.warns(
        PICLegacyTrustModeWarning,
        match="strict_trust=False enables legacy trust behavior",
    ):
        ap, returned_args = evaluate_pic_for_tool_call(
            tool_name="payments_send",
            tool_args={"to": "vendor", "amount": 50, "__pic": proposal},
            policy=policy,
            strict_trust=False,
        )

    assert ap is not None
    assert "__pic" in returned_args  # stripping happens in guard_mcp_tool(), not here


def test_evaluate_pic_rejects_missing_required_proposal():
    """evaluate_pic_for_tool_call(): money tool with no __pic → PICError(INVALID_REQUEST)."""
    from pic_standard.errors import PICError, PICErrorCode
    from pic_standard.integrations.mcp_pic_guard import evaluate_pic_for_tool_call
    from pic_standard.policy import PICPolicy

    policy = PICPolicy(
        impact_by_tool={"payments_send": "money"},
        require_pic_for_impacts=["money"],
    )

    with pytest.raises(PICError) as exc:
        evaluate_pic_for_tool_call(
            tool_name="payments_send",
            tool_args={"to": "vendor", "amount": 50},
            policy=policy,
        )
    assert exc.value.code == PICErrorCode.INVALID_REQUEST
