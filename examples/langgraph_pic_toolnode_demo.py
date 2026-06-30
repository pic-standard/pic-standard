import sys
from pathlib import Path

# NOTE: This path tweak is only to make examples runnable without installation.
REPO_ROOT = Path(__file__).resolve().parents[1]
SDK_DIR = REPO_ROOT / "sdk-python"
if str(SDK_DIR) not in sys.path:
    sys.path.insert(0, str(SDK_DIR))

from langchain_core.messages import AIMessage
from langchain_core.tools import tool

from pic_standard.integrations import PICToolNode


@tool
def payments_send(amount: int) -> str:
    """Send a payment of the given amount (demo tool)."""
    return f"sent ${amount}"


def make_money_proposal(*, trust: str) -> dict:
    prov_id = "invoice_123" if trust == "trusted" else "random_web"
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": prov_id, "trust": trust}],
        "claims": [{"text": "Pay $500", "evidence": [prov_id]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


def pretty_error(e: Exception) -> str:
    """
    Pydantic wraps validator ValueErrors into a ValidationError and prints a big message
    with a pydantic.dev link. For demos, show only the actual contract violation message.
    """
    if hasattr(e, "errors"):
        try:
            errs = e.errors()
            # pydantic v2 usually stores the message at errs[0]["msg"]
            if errs and isinstance(errs, list) and "msg" in errs[0]:
                return errs[0]["msg"]
        except Exception:
            pass
    return str(e)


def main():
    print("=== PIC x LangGraph ToolNode demo ===")
    print("This demo runs two tool calls:")
    print("  1) money + untrusted evidence  -> should be BLOCKED")
    print("  2) money + trusted evidence    -> should be ALLOWED")
    print()

    node = PICToolNode([payments_send])

    # 1) FAIL: money + untrusted evidence
    try:
        state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "payments_send",
                            "args": {"amount": 500, "__pic": make_money_proposal(trust="untrusted")},
                            "id": "1",
                        }
                    ],
                )
            ]
        }
        node.invoke(state)
        print("FAIL: unexpected: untrusted money proposal should have been blocked")
    except Exception as e:
        print("PASS: blocked as expected (untrusted money)")
        print("   ", pretty_error(e))
        print()

    # 2) PASS: money + trusted evidence
    try:
        state = {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "payments_send",
                            "args": {"amount": 500, "__pic": make_money_proposal(trust="trusted")},
                            "id": "2",
                        }
                    ],
                )
            ]
        }
        out = node.invoke(state)
        msgs = out.get("messages", [])
        result = msgs[0].content if msgs else "<no output>"
        print("PASS: allowed as expected (trusted money)")
        print("   ", result)
    except Exception as e:
        print("FAIL: unexpected: trusted money proposal should have been allowed")
        print("   ", pretty_error(e))


if __name__ == "__main__":
    main()

