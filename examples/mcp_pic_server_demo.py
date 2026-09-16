from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]

# --- Shared handlers (file + stderr) ---
file_handler = logging.FileHandler(REPO_ROOT / "examples" / "_mcp_server.log", encoding="utf-8")
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.INFO)
stderr_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))


def _setup_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(name)
    lg.setLevel(logging.INFO)
    lg.propagate = False  # avoid duplicate lines if root logger also has handlers
    if not lg.handlers:
        lg.addHandler(file_handler)
        lg.addHandler(stderr_handler)
    return lg


# Demo logger + PIC guard logger
log = _setup_logger("pic_standard.mcp.demo")
_setup_logger("pic_standard.mcp")  # ✅ this is what guard_mcp_tool uses

# Demo-only bootstrap: allow examples to run without pip install -e .
try:
    import pic_standard  # noqa: F401
except ModuleNotFoundError:
    sdk_python = REPO_ROOT / "sdk-python"
    if sdk_python.exists() and str(sdk_python) not in sys.path:
        sys.path.insert(0, str(sdk_python))
        log.info("Demo bootstrap: added %s to sys.path", sdk_python)

from mcp.server.fastmcp import FastMCP
from pic_standard.config import dump_policy, load_policy
from pic_standard.integrations.mcp_pic_guard import guard_mcp_tool

mcp = FastMCP("pic-mcp-demo")


def _payments_send(amount: int) -> str:
    return f"sent ${amount}"


POLICY = load_policy(repo_root=REPO_ROOT)
log.info("Loaded policy: %s", dump_policy(POLICY))

payments_send = guard_mcp_tool(
    "payments_send",
    _payments_send,
    policy=POLICY,
    verify_evidence=True,
    proposal_base_dir=REPO_ROOT,
    evidence_root_dir=REPO_ROOT / "examples",
)


@mcp.tool()
def payments_send_tool(
    amount: int,
    pic: Dict[str, Any] | None = None,
    request_id: Optional[str] = None,
) -> Any:
    envelope = payments_send(amount=amount, __pic=pic, __pic_request_id=request_id)
    return {"result": envelope}


def main() -> None:
    log.info("Starting MCP stdio server. repo_root=%s python=%s", REPO_ROOT, sys.executable)
    mcp.run()


if __name__ == "__main__":
    main()
