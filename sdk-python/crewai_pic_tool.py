# This shows how to wrap any CrewAI tool with a PIC safety layer.

from crewai_tools import BaseTool


class PICProtectedTool(BaseTool):
    name: str = "Protected Financial Tool"
    description: str = "A tool that requires a PIC contract before executing."

    def _run(self, amount: int, recipient: str, pic_contract: dict) -> str:
        # 1. Intercept the call
        # 2. Run the Verifier
        if pic_contract.get("impact") == "money" and not self.has_trusted_evidence(pic_contract):
            return "Access Denied: PIC Contract Violation. No trusted provenance."

        # 3. Only execute if valid
        return f"Payment of ${amount} to {recipient} authorized via PIC."

    def has_trusted_evidence(self, contract):
        # Logic to check if any provenance source is 'trusted'
        return any(p.get("trust") == "trusted" for p in contract.get("provenance", []))
