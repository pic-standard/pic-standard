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
    sc = getattr(resp, "structuredContent", None)
    if not isinstance(sc, dict):
        return None
    if "result" not in sc:
        return None

    r = sc.get("result")

    # A) direct envelope
    if isinstance(r, dict) and "isError" in r:
        return r

    # B) wrapped envelope: {"result": envelope}
    if isinstance(r, dict) and "result" in r:
        inner = r.get("result")
        if isinstance(inner, dict) and "isError" in inner:
            return inner

    return None


def _print_pic(resp: Any, *, expect_block: bool) -> None:
    env = _extract_pic_envelope(resp)
    if env is None:
        print("FAIL: could not parse PIC envelope from MCP response")
        print(resp)
        return

    is_err = bool(env.get("isError"))

    if is_err and expect_block:
        print("PASS: blocked as expected")
    elif (not is_err) and (not expect_block):
        print("PASS: allowed as expected")
    elif is_err and (not expect_block):
        print("FAIL: unexpected: trusted money should have been allowed")
    else:
        print("FAIL: unexpected: untrusted money should have been blocked")

    print(json.dumps(env, indent=2, ensure_ascii=False))


async def run() -> None:
    server = ServerParameters(
        command=sys.executable,
        args=["-u", "examples/mcp_pic_server_demo.py"],
        cwd=str(REPO_ROOT),
        env=os.environ.copy(),
    )

    async with stdio_client(server) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools:", [t.name for t in tools.tools])

            print("\n1) untrusted money -> should be BLOCKED")
            r1 = await session.call_tool(
                "payments_send_tool",
                {"amount": 500, "pic": _proposal("untrusted"), "request_id": "demo-req-001"},
            )
            _print_pic(r1, expect_block=True)

            print("\n2) trusted money -> should be ALLOWED")
            r2 = await session.call_tool(
                "payments_send_tool",
                {"amount": 500, "pic": _proposal("trusted"), "request_id": "demo-req-002"},
            )
            _print_pic(r2, expect_block=False)


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
