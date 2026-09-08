from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, model_validator


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class ImpactClass(str, Enum):
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"
    IRREVERSIBLE = "irreversible"
    MONEY = "money"
    COMPUTE = "compute"
    PRIVACY = "privacy"


class Provenance(BaseModel):
    id: str
    trust: TrustLevel


class Claim(BaseModel):
    text: str
    evidence: List[str]


class ActionProposal(BaseModel):
    protocol: str = "PIC/1.0"
    intent: str
    impact: ImpactClass
    provenance: List[Provenance]
    claims: List[Claim]
    action: Dict[str, Any]

    # Impacts which require at least one claim referencing TRUSTED provenance evidence.
    # This aligns with your stated gap: privacy should be enforced too.
    HIGH_IMPACT: Set[ImpactClass] = {
        ImpactClass.MONEY,
        ImpactClass.IRREVERSIBLE,
        ImpactClass.PRIVACY,
    }

    @model_validator(mode="after")
    def verify_causal_contract(self) -> "ActionProposal":
        # Minimal reference rule: high-impact actions require trusted evidence
        if self.impact in self.HIGH_IMPACT:
            trusted_ids = {p.id for p in self.provenance if p.trust == TrustLevel.TRUSTED}

            has_trusted_evidence = any(
                any(ev_id in trusted_ids for ev_id in claim.evidence) for claim in self.claims
            )

            if not has_trusted_evidence:
                raise ValueError(
                    f"Contract Violation: Action of type '{self.impact}' cannot proceed "
                    f"without evidence from a TRUSTED source."
                )

        return self

    def verify_with_context(self, *, expected_tool: Optional[str] = None) -> None:
        """
        Optional integration-time checks that require runtime context.

        expected_tool:
          - If provided, enforce tool binding: proposal.action.tool must match.
          - If not provided, no tool-binding enforcement is performed (offline-safe).
        """
        if expected_tool is None:
            return

        exp = expected_tool.strip()
        if not exp:
            return

        tool = self.action.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            raise ValueError("Contract Violation: proposal.action.tool must be a non-empty string")

        if tool.strip() != exp:
            raise ValueError(
                f"Contract Violation: Tool binding mismatch (proposal.action.tool='{tool.strip()}' "
                f"but actual tool='{exp}')."
            )
