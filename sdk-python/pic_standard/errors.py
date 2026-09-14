from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class PICErrorCode(str, Enum):
    """PIC protocol error codes.

    Authoritative documentation for each code (retryability, HTTP mapping,
    example wire shape) lives in ``docs/ERRORS.md``. The mapping between
    this enum and that document is enforced by
    ``tests/test_errors_md.py``.

    Mirrored in ``integrations/openclaw/lib/types.ts``; keep in sync.
    """

    #: Request was not well-formed enough to enter the pipeline
    #: (malformed body, non-JSON payload, missing / invalid headers,
    #: HTTP request body over the bridge size limit). HTTP 400 in the reference bridge.
    INVALID_REQUEST = "PIC_INVALID_REQUEST"

    #: Proposal exceeded a hard limit configured in ``PICEvaluateLimits``:
    #: byte size, provenance count, claim count, evidence count, or
    #: per-request evaluation time budget.
    LIMIT_EXCEEDED = "PIC_LIMIT_EXCEEDED"

    #: JSON Schema validation of the proposal failed (missing required
    #: field, wrong type, unknown enum value, etc.).
    SCHEMA_INVALID = "PIC_SCHEMA_INVALID"

    #: Semantic post-schema validation failed: ``ActionProposal`` pydantic
    #: rejection, ``verify_causal_contract`` violation, or a similar
    #: structural rule violation. See ``pipeline.py``.
    VERIFIER_FAILED = "PIC_VERIFIER_FAILED"

    #: Proposal ``action.tool`` did not match the guard's ``expected_tool``.
    TOOL_BINDING_MISMATCH = "PIC_TOOL_BINDING_MISMATCH"

    #: Policy required evidence for the resolved impact but the proposal
    #: carried no evidence entries.
    EVIDENCE_REQUIRED = "PIC_EVIDENCE_REQUIRED"

    #: At least one evidence entry failed verification (hash mismatch,
    #: unresolvable file, signature failure, keyring / key-lifecycle
    #: issue, canonical binding mismatch, etc.).
    EVIDENCE_FAILED = "PIC_EVIDENCE_FAILED"

    #: Policy-level (operator-defined) rule blocked the action, distinct
    #: from PIC's protocol-level verifier rules. Reserved for future
    #: policy surfaces; not raised in the shared pipeline today.
    POLICY_VIOLATION = "PIC_POLICY_VIOLATION"

    #: Transient guard-side condition (unexpected exception in the guard
    #: itself, not in the proposal or its evidence). Retryable.
    INTERNAL_ERROR = "PIC_INTERNAL_ERROR"


@dataclass
class PICError(Exception):
    """A structured error that can be safely returned to callers."""

    code: PICErrorCode
    message: str
    details: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        # Keep it clean for logs / CLI
        return f"{self.code}: {self.message}"

    def to_public_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.details:
            out["details"] = self.details
        return out


def _debug_enabled() -> bool:
    """Check if PIC_DEBUG is enabled (env var).

    Used by pipeline.py and integration wrappers to gate verbose error details.
    """
    v = (os.getenv("PIC_DEBUG") or "").strip().lower()
    return v in {"1", "true", "yes", "on"}
