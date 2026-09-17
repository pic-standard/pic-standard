from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool

from pic_standard.pipeline import PipelineOptions, verify_proposal

PIC_ARG_KEY = "__pic"  # tool_calls[i]["args"]["__pic"] = {... PIC proposal ...}


@dataclass
class PICToolNode:
    """
    PIC-enforced tool execution node compatible with LangGraph-style "messages state".

    Requires each tool call to include:
        args["__pic"] = {...proposal...}

    Enforces:
      - schema validation
      - verifier rules
      - tool binding via ActionProposal.verify_with_context(expected_tool=...)

    Then executes the tool and returns ToolMessages.
    """

    tools: list[BaseTool]
    policy: Any = None
    verify_evidence: bool = False
    strict_trust: bool = True
    key_resolver: Any = None
    proposal_base_dir: Optional[Path] = None
    evidence_root_dir: Optional[Path] = None

    _tools_by_name: Dict[str, BaseTool] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._tools_by_name = {t.name: t for t in self.tools}

    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        messages = state.get("messages", [])
        if not messages:
            raise ValueError(
                "PICToolNode expects state['messages'] to contain at least one message."
            )

        last = messages[-1]
        if not isinstance(last, AIMessage):
            raise ValueError(
                "PICToolNode expects the last message to be an AIMessage with tool_calls."
            )

        tool_calls = getattr(last, "tool_calls", None) or []
        if not tool_calls:
            return {"messages": []}

        results: list[ToolMessage] = []

        for tc in tool_calls:
            name = tc.get("name")
            if not name:
                raise ValueError("Tool call missing 'name'.")

            tool = self._tools_by_name.get(name)
            if tool is None:
                raise ValueError(
                    f"Unknown tool '{name}'. Available: {list(self._tools_by_name.keys())}"
                )

            args = dict(tc.get("args") or {})

            if PIC_ARG_KEY not in args:
                raise ValueError(
                    f"PIC missing: tool call '{name}' must include "
                    f"args['{PIC_ARG_KEY}'] with the PIC proposal."
                )

            proposal = args.pop(PIC_ARG_KEY)

            if not isinstance(proposal, dict):
                raise ValueError(
                    f"PIC invalid: args['{PIC_ARG_KEY}'] must be a dict "
                    f"(parsed JSON), got {type(proposal)}."
                )

            # Enforce PIC BEFORE calling the tool (delegates to shared pipeline)
            result = verify_proposal(
                proposal,
                options=PipelineOptions(
                    tool_name=name,
                    expected_tool=name,
                    policy=self.policy,
                    verify_evidence=self.verify_evidence,
                    strict_trust=self.strict_trust,
                    key_resolver=self.key_resolver,
                    proposal_base_dir=self.proposal_base_dir,
                    evidence_root_dir=self.evidence_root_dir,
                ),
            )
            if not result.ok:
                msg = result.error.message if result.error else "PIC verification failed"
                code = result.error.code.value if result.error else "PIC_INTERNAL_ERROR"
                raise ValueError(f"PIC blocked ({code}): {msg}")

            # Execute tool
            observation = tool.invoke(args)

            tool_call_id = tc.get("id") or "tool_call"
            results.append(ToolMessage(content=str(observation), tool_call_id=tool_call_id))

        return {"messages": results}
