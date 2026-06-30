"""
OpenClaw PIC Bridge Demo
========================

End-to-end demonstration of the PIC HTTP bridge used by the OpenClaw plugin.

Starts a PIC bridge server on a random port, then fires four HTTP requests
to show allow / block / fail-closed behaviour:

  1. Trusted money proposal     → ALLOWED
  2. Untrusted money proposal   → BLOCKED (provenance)
  3. Tool-binding mismatch      → BLOCKED (binding)
  4. Missing __pic on high-impact → BLOCKED (no proposal)

Run::

    python examples/openclaw_pic_bridge_demo.py
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[1]

# --- Logging ----------------------------------------------------------------

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.INFO)
stderr_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))


def _setup_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(name)
    lg.setLevel(logging.INFO)
    lg.propagate = False
    if not lg.handlers:
        lg.addHandler(stderr_handler)
    return lg


log = _setup_logger("pic_standard.bridge_demo")
_setup_logger("pic_standard.http_bridge")

# --- Bootstrap (run without pip install -e .) --------------------------------

try:
    import pic_standard  # noqa: F401
except ModuleNotFoundError:
    sdk_python = REPO_ROOT / "sdk-python"
    if sdk_python.exists() and str(sdk_python) not in sys.path:
        sys.path.insert(0, str(sdk_python))
        log.info("Demo bootstrap: added %s to sys.path", sdk_python)

from pic_standard.integrations.http_bridge import PICBridgeServer
from pic_standard.integrations.mcp_pic_guard import PICEvaluateLimits
from pic_standard.policy import PICPolicy

# --- Helpers -----------------------------------------------------------------

# Build a demo policy that classifies payments_send as high-impact (money).
# In production, this comes from pic_policy.json in the repo root.
POLICY = PICPolicy(impact_by_tool={"payments_send": "money"})
LIMITS = PICEvaluateLimits()


def _pic_proposal(
    *,
    tool: str,
    params: Dict[str, Any],
    trust: str = "trusted",
) -> Dict[str, Any]:
    """Build a minimal but valid __pic proposal matching proposal_schema.json."""
    return {
        "protocol": "PIC/1.0",
        "intent": "Demo: transfer funds",
        "impact": "money",
        "provenance": [{"id": "demo_user_input", "trust": trust, "source": "demo"}],
        "claims": [{"text": "User confirmed this transfer", "evidence": ["demo_user_input"]}],
        "action": {"tool": tool, "args": params},
    }


def _http_post(url: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Fire a POST request and return the parsed JSON response."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


# --- Demo scenarios ----------------------------------------------------------

def run_demo(base_url: str) -> None:
    print("\n" + "=" * 60)
    print("  PIC HTTP Bridge Demo")
    print("=" * 60)

    # 1 — Trusted money proposal → ALLOWED
    print("\n--- Scenario 1: Trusted money proposal ---")
    tool_params = {"amount": 100}
    pic = _pic_proposal(tool="payments_send", params=tool_params, trust="trusted")
    body = {"tool_name": "payments_send", "tool_args": {**tool_params, "__pic": pic}}
    result = _http_post(f"{base_url}/verify", body)
    print(f"  allowed={result['allowed']}  eval_ms={result['eval_ms']}")
    assert result["allowed"] is True, f"Expected allowed=True, got error={result.get('error')}"

    # 2 — Untrusted money proposal → BLOCKED
    print("\n--- Scenario 2: Untrusted money proposal ---")
    pic_untrusted = _pic_proposal(tool="payments_send", params=tool_params, trust="untrusted")
    body = {"tool_name": "payments_send", "tool_args": {**tool_params, "__pic": pic_untrusted}}
    result = _http_post(f"{base_url}/verify", body)
    print(f"  allowed={result['allowed']}  code={result['error']['code']}")
    assert result["allowed"] is False, f"Expected allowed=False, got {result}"

    # 3 — Tool-binding mismatch → BLOCKED
    print("\n--- Scenario 3: Tool-binding mismatch ---")
    pic_wrong_tool = _pic_proposal(tool="wrong_tool", params=tool_params, trust="trusted")
    body = {"tool_name": "payments_send", "tool_args": {**tool_params, "__pic": pic_wrong_tool}}
    result = _http_post(f"{base_url}/verify", body)
    print(f"  allowed={result['allowed']}  code={result['error']['code']}")
    assert result["allowed"] is False, f"Expected allowed=False, got {result}"

    # 4 — No __pic on high-impact tool → BLOCKED
    print("\n--- Scenario 4: Missing __pic on high-impact tool ---")
    body = {"tool_name": "payments_send", "tool_args": {"amount": 50}}
    result = _http_post(f"{base_url}/verify", body)
    print(f"  allowed={result['allowed']}  code={result['error']['code']}")
    assert result["allowed"] is False, f"Expected allowed=False, got {result}"

    print("\n" + "=" * 60)
    print("  All 4 scenarios passed (OK)")
    print("=" * 60 + "\n")


# --- Main --------------------------------------------------------------------

def main() -> None:
    log.info("Policy: payments_send -> money (high-impact)")

    server = PICBridgeServer(
        ("127.0.0.1", 0),  # port 0 = OS-assigned random port
        policy=POLICY,
        limits=LIMITS,
        verify_evidence=False,
        proposal_base_dir=REPO_ROOT,
    )
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    log.info("Bridge started on %s", base_url)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # Give the server a moment to bind
    time.sleep(0.1)

    try:
        run_demo(base_url)
    finally:
        server.shutdown()
        server.server_close()
        log.info("Bridge stopped")


if __name__ == "__main__":
    main()
