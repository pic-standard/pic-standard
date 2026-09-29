from __future__ import annotations

import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# Demo-only bootstrap: allow examples to run without `pip install -e .`
REPO_ROOT = Path(__file__).resolve().parents[1]
try:
    import pic_standard  # noqa: F401
except ModuleNotFoundError:
    sdk_python = REPO_ROOT / "sdk-python"
    if sdk_python.exists() and str(sdk_python) not in sys.path:
        sys.path.insert(0, str(sdk_python))

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

# ---- MCP version compatibility: ServerParameters is not stable across releases ----
ServerParameters = None
try:
    from mcp.client.stdio import ServerParameters as _ServerParameters  # type: ignore

    ServerParameters = _ServerParameters
except Exception:
    pass

if ServerParameters is None:
    try:
        from mcp.client.stdio import StdioServerParameters as _ServerParameters  # type: ignore

        ServerParameters = _ServerParameters
    except Exception:
        pass

if ServerParameters is None:

    @dataclass
    class ServerParameters:  # type: ignore
        command: str
        args: list[str]
        cwd: Optional[str] = None
        env: Optional[Dict[str, str]] = None


def _proposal(trust: str) -> dict:
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "invoice_123", "trust": trust, "source": "evidence"}],
        "claims": [{"text": "Pay $500", "evidence": ["invoice_123"]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
        "evidence": [
            {
                "id": "invoice_123",
                "type": "hash",
                "ref": "file://examples/artifacts/invoice_123.txt",
                "sha256": "4d021a98393dd33246437f8439ece6156b86abda5fd7a0d43dc915eda166c3c9",
                "attestor": "demo",
            }
        ],
    }


def _extract_pic_envelope(resp: Any) -> Optional[dict]:
    # Try structuredContent first (older MCP versions and some setups
    # populate this), then fall back to parsing content[0].text as JSON
    # (newer MCP versions on some platforms serialize dict tool returns
    # into text content and leave structuredContent as None).
    candidates: list[dict] = []

    sc = getattr(resp, "structuredContent", None)
    if isinstance(sc, dict) and ("result" in sc or "isError" in sc):
        candidates.append(sc)

    content = getattr(resp, "content", None) or []
    for item in content:
        text = getattr(item, "text", None)
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, dict) and ("result" in parsed or "isError" in parsed):
            candidates.append(parsed)

    for wrapper in candidates:
        # A) direct envelope (future MCP behavior)
        if "isError" in wrapper:
            return wrapper

        r = wrapper.get("result")

        # B) wrapped envelope: {"result": envelope}
        if isinstance(r, dict) and "isError" in r:
            return r

        # C) doubly-wrapped envelope: {"result": {"result": envelope}}
        if isinstance(r, dict) and "result" in r:
            inner = r.get("result")
            if isinstance(inner, dict) and "isError" in inner:
                return inner

    return None


def _print_pic(resp: Any, *, expect_block: bool) -> bool:
    """Print PASS/FAIL for one case. Returns True on PASS, False on FAIL."""
    env = _extract_pic_envelope(resp)
    if env is None:
        print("FAIL: could not parse PIC envelope from MCP response")
        print(resp)
        return False

    is_err = bool(env.get("isError"))

    if is_err and expect_block:
        print("PASS: blocked as expected")
        result = True
    elif (not is_err) and (not expect_block):
        print("PASS: allowed as expected")
        result = True
    elif is_err and (not expect_block):
        print("FAIL: unexpected: should have been ALLOWED but was BLOCKED")
        result = False
    else:
        print("FAIL: unexpected: should have been BLOCKED but was ALLOWED")
        result = False

    print(json.dumps(env, indent=2, ensure_ascii=False))
    return result


async def run() -> bool:
    """Run the three demo cases. Returns True if all passed, else False."""
    server = ServerParameters(
        command=sys.executable,
        args=["-u", "examples/mcp_pic_server_demo.py"],
        cwd=str(REPO_ROOT),
        env=os.environ.copy(),
    )

    # Load the signature-backed positive-path proposal from disk so the
    # signature and key_id stay in sync with pic_keys.demo.json without
    # any inline regeneration inside this demo.
    signed_proposal_path = REPO_ROOT / "examples" / "financial_sig_ok.json"
    signed_proposal = json.loads(signed_proposal_path.read_text(encoding="utf-8"))

    all_pass = True
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        tools = await session.list_tools()
        print("Tools:", [t.name for t in tools.tools])

        print("\n1) untrusted money -> should be BLOCKED")
        r1 = await session.call_tool(
            "payments_send_tool",
            {"amount": 500, "pic": _proposal("untrusted"), "request_id": "demo-req-001"},
        )
        all_pass &= _print_pic(r1, expect_block=True)

        print("\n2) self-declared trusted money with hash evidence -> should be BLOCKED")
        r2 = await session.call_tool(
            "payments_send_tool",
            {"amount": 500, "pic": _proposal("trusted"), "request_id": "demo-req-002"},
        )
        all_pass &= _print_pic(r2, expect_block=True)

        print("\n3) signature-backed trusted money -> should be ALLOWED")
        r3 = await session.call_tool(
            "payments_send_tool",
            {"amount": 500, "pic": signed_proposal, "request_id": "demo-req-003"},
        )
        all_pass &= _print_pic(r3, expect_block=False)

    return all_pass


def main() -> None:
    ok = asyncio.run(run())
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
