"""
PIC HTTP Bridge - lightweight verification server for non-Python integrations.

Wraps ``evaluate_pic_for_tool_call()`` from the MCP guard module and exposes
it over HTTP so that TypeScript / Go / etc. consumers can verify PIC proposals
without shelling out to ``pic-cli``.

Endpoints
---------
POST /verify
    Body: {"tool_name": "<name>", "tool_args": {"__pic": {…}, …}}
    Headers: X-Request-ID (optional)
    200:  {"allowed": true,  "error": null,          "eval_ms": <int>, "request_id": "<UUID>"}
    200:  {"allowed": false, "error": {"code": "…", "message": "…"},
           "eval_ms": <int>, "request_id": "<UUID>"}

GET  /health
    200:  {"status": "ok", "request_id": "<UUID>"}

GET  /v1/version
    200:  {"pic_version": "1.0", "package_version": "0.9.0a1",
           "commit": "<hex-or-unknown>", "policy_version": "1.0",
           "impl_name": "pic-standard-py", "impl_version": "0.9.0a1",
           "pic_protocol_version": "PIC/1.0",
           "conformance_manifest_ref": {"path": "conformance/manifest.json",
                                        "sha256": "sha256:<hex>|unknown",
                                        "commit": "<hex-or-unknown>"},
           "supported_modes": ["canonicalization", "core", "evidence",
                               "trust_sanitization"],
           "request_id": "<UUID>"}

Design notes
------------
* stdlib only - no Flask / FastAPI dependency.
* Fail-closed - any internal error returns ``allowed: false``.
* Binds to 127.0.0.1 by default (localhost-only for security).
* Reuses the battle-tested ``evaluate_pic_for_tool_call`` pipeline
  (limits → schema → verifier → tool-binding → evidence → time-budget).
* X-Request-ID header: if provided in request, echoed back in response.
  If not provided, a UUID is generated and included in response.
* Audit logging: one JSON line per decision to the audit logger (pic_standard.audit)
  with request_id, tool, allowed, eval_ms, and optional code/error_message.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Optional

from pic_standard.config import load_policy
from pic_standard.errors import PICError, PICErrorCode, _debug_enabled
from pic_standard.integrations.mcp_pic_guard import (
    PICEvaluateLimits,
    evaluate_pic_for_tool_call,
)
from pic_standard.policy import PICPolicy

log = logging.getLogger("pic_standard.http_bridge")
audit_log = logging.getLogger("pic_standard.audit")

PIC_VERSION = "1.0"
# TODO: Replace static placeholder when PIC policy objects expose an explicit
# version field that can be surfaced by the bridge.
POLICY_VERSION = "1.0"

# §15.3 machine-readable version metadata.
IMPL_NAME = "pic-standard-py"
PIC_PROTOCOL_VERSION = "PIC/1.0"
SUPPORTED_MODES = (
    "canonicalization",
    "core",
    "evidence",
    "trust_sanitization",
)

# Maximum request body size (1MB) to prevent memory exhaustion attacks
MAX_REQUEST_BYTES = 1024 * 1024

# Socket read timeout (seconds) to prevent slow/malicious clients from hanging the server
READ_TIMEOUT_SECS = 5.0

MAX_REQUEST_ID_LEN = 128
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

# ------------------------------------------------------------------
# Request / response helpers
# ------------------------------------------------------------------


@lru_cache(maxsize=1)
def _get_git_commit() -> str:
    """Get the current git commit hash, or 'unknown' if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent.parent,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


@lru_cache(maxsize=1)
def _get_package_version() -> str:
    try:
        return metadata.version("pic-standard")
    except metadata.PackageNotFoundError:
        return "unknown"


@lru_cache(maxsize=1)
def _find_conformance_manifest() -> Optional[Path]:
    """Locate ``conformance/manifest.json`` from the current install layout.

    Walks parent directories of this module looking for a ``conformance``
    directory containing ``manifest.json``. Works in a repo checkout where
    the file lives at ``<repo>/conformance/manifest.json``. Returns
    ``None`` from a packaged/wheel install that does not bundle the
    conformance suite; ``/v1/version`` degrades to ``sha256: "unknown"``
    in that case rather than raising.
    """
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:6]:
        candidate = parent / "conformance" / "manifest.json"
        if candidate.is_file():
            return candidate
    return None


@lru_cache(maxsize=1)
def _get_conformance_manifest_sha256() -> str:
    """Return ``sha256:<hex>`` of the conformance manifest, or ``"unknown"``.

    Content-addresses the manifest so ``/v1/version`` consumers can pin
    conformance runs to an exact manifest byte sequence regardless of
    whether git is available on the host.
    """
    path = _find_conformance_manifest()
    if path is None:
        return "unknown"
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unknown"
    return f"sha256:{digest}"


def _sanitize_request_id(request_id: Optional[str]) -> Optional[str]:
    if request_id is None:
        return None

    normalized = request_id.replace("\r", "").replace("\n", "").strip()
    if not normalized:
        return None
    if len(normalized) > MAX_REQUEST_ID_LEN:
        return None
    if not REQUEST_ID_RE.fullmatch(normalized):
        return None
    return normalized


def _generate_request_id() -> str:
    """Generate a unique request ID."""
    return str(uuid.uuid4())


def _json_response(
    handler: BaseHTTPRequestHandler,
    status: int,
    body: Dict[str, Any],
    request_id: Optional[str] = None,
) -> None:
    """Write a JSON response with proper headers."""
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    if request_id:
        handler.send_header("X-Request-ID", request_id)
    handler.end_headers()
    handler.wfile.write(payload)


def _read_json_body(handler: BaseHTTPRequestHandler) -> Dict[str, Any]:
    """Read and parse JSON request body. Raises ValueError on bad input."""
    content_type = handler.headers.get("Content-Type", "")
    if content_type and "application/json" not in content_type:
        raise ValueError(f"Expected Content-Type application/json, got '{content_type}'")

    length_str = handler.headers.get("Content-Length")
    if not length_str:
        raise ValueError("Missing Content-Length header")

    try:
        length = int(length_str)
    except ValueError:
        log.warning("Malformed Content-Length header: %r", length_str)
        raise ValueError(f"Invalid Content-Length header: '{length_str}'") from None

    if length < 0:
        log.warning("Negative Content-Length received: %d", length)
        raise ValueError(f"Invalid Content-Length: negative value ({length})")
    if length == 0:
        raise ValueError("Empty request body")
    if length > MAX_REQUEST_BYTES:
        log.warning("Oversized request body: %d bytes (max %d)", length, MAX_REQUEST_BYTES)
        raise ValueError(f"Request body too large: {length} bytes (max {MAX_REQUEST_BYTES})")

    # Set socket timeout to prevent hanging on slow/malicious clients
    # that send fewer bytes than Content-Length claims
    original_timeout = handler.connection.gettimeout()
    try:
        handler.connection.settimeout(READ_TIMEOUT_SECS)
        raw = handler.rfile.read(length)
    finally:
        handler.connection.settimeout(original_timeout)

    if len(raw) < length:
        log.warning("Incomplete request body: expected %d bytes, got %d", length, len(raw))
        raise ValueError(f"Incomplete request body: expected {length} bytes, got {len(raw)}")

    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Request body must be a JSON object (dict), got {type(data).__name__}")
    return data


# ------------------------------------------------------------------
# Core verification (thin wrapper around evaluate_pic_for_tool_call)
# ------------------------------------------------------------------


def _log_audit(
    request_id: str,
    tool: str,
    allowed: bool,
    eval_ms: int,
    code: Optional[str] = None,
    error_message: Optional[str] = None,
    event: str = "verify_decision",
) -> None:
    """Log a structured JSON audit record (one line per decision)."""
    audit_record = {
        "event": event,
        "request_id": request_id,
        "tool": tool,
        "code": code or "PIC_OK",
        "allowed": allowed,
        "eval_ms": eval_ms,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if error_message:
        audit_record["error_message"] = error_message

    audit_log.info(json.dumps(audit_record, ensure_ascii=False))


def handle_verify(
    body: Dict[str, Any],
    *,
    policy: PICPolicy,
    limits: PICEvaluateLimits,
    verify_evidence: bool,
    proposal_base_dir: Path,
    evidence_root_dir: Optional[Path],
    request_id: Optional[str] = None,
    strict_trust: bool = True,
) -> Dict[str, Any]:
    """
    Run PIC verification and return a structured response dict.

    Always returns - never raises.

    ``strict_trust=True`` is the secure default: self-asserted
    provenance trust is sanitized to ``untrusted`` before the causal-
    contract check runs. ``strict_trust=False`` is legacy compatibility
    mode; the underlying ``PipelineOptions`` construction emits
    ``PICLegacyTrustModeWarning`` when legacy mode is opted into.
    """
    if request_id is None:
        request_id = _generate_request_id()

    t0 = time.perf_counter()

    tool_name = body.get("tool_name")
    tool_args = body.get("tool_args")

    if not isinstance(tool_name, str) or not tool_name.strip():
        error_message = "Missing or empty 'tool_name'"
        eval_ms = int((time.perf_counter() - t0) * 1000)
        _log_audit(
            request_id=request_id,
            tool=str(tool_name) if tool_name else "",
            allowed=False,
            eval_ms=eval_ms,
            code=PICErrorCode.INVALID_REQUEST.value,
            error_message=error_message,
            event="request_validation_failed",
        )
        return {
            "allowed": False,
            "error": {"code": PICErrorCode.INVALID_REQUEST.value, "message": error_message},
            "eval_ms": eval_ms,
            "request_id": request_id,
        }

    if not isinstance(tool_args, dict):
        error_message = "'tool_args' must be an object"
        eval_ms = int((time.perf_counter() - t0) * 1000)
        _log_audit(
            request_id=request_id,
            tool=tool_name.strip(),
            allowed=False,
            eval_ms=eval_ms,
            code=PICErrorCode.INVALID_REQUEST.value,
            error_message=error_message,
            event="request_validation_failed",
        )
        return {
            "allowed": False,
            "error": {"code": PICErrorCode.INVALID_REQUEST.value, "message": error_message},
            "eval_ms": eval_ms,
            "request_id": request_id,
        }

    try:
        evaluate_pic_for_tool_call(
            tool_name=tool_name.strip(),
            tool_args=tool_args,
            policy=policy,
            limits=limits,
            verify_evidence=verify_evidence,
            proposal_base_dir=proposal_base_dir,
            evidence_root_dir=evidence_root_dir,
            strict_trust=strict_trust,
        )
        eval_ms = int((time.perf_counter() - t0) * 1000)
        log.info("ALLOW tool=%s eval_ms=%d", tool_name.strip(), eval_ms)
        _log_audit(
            request_id=request_id,
            tool=tool_name.strip(),
            allowed=True,
            eval_ms=eval_ms,
            event="verification_allowed",
        )
        return {
            "allowed": True,
            "error": None,
            "eval_ms": eval_ms,
            "request_id": request_id,
        }

    except PICError as e:
        eval_ms = int((time.perf_counter() - t0) * 1000)
        log.info("BLOCK tool=%s code=%s eval_ms=%d", tool_name.strip(), e.code.value, eval_ms)
        _log_audit(
            request_id=request_id,
            tool=tool_name.strip(),
            allowed=False,
            eval_ms=eval_ms,
            code=e.code.value,
            error_message=e.message,
            event="verification_blocked",
        )
        result: Dict[str, Any] = {
            "allowed": False,
            "error": {"code": e.code.value, "message": e.message},
            "eval_ms": eval_ms,
            "request_id": request_id,
        }
        if _debug_enabled() and e.details:
            result["error"]["details"] = e.details
        return result

    except Exception as e:
        eval_ms = int((time.perf_counter() - t0) * 1000)
        log.exception("BLOCK tool=%s reason=internal_error eval_ms=%d", tool_name.strip(), eval_ms)
        _log_audit(
            request_id=request_id,
            tool=tool_name.strip(),
            allowed=False,
            eval_ms=eval_ms,
            code=PICErrorCode.INTERNAL_ERROR.value,
            error_message="Internal verification error",
            event="internal_error",
        )
        result = {
            "allowed": False,
            "error": {
                "code": PICErrorCode.INTERNAL_ERROR.value,
                "message": "Internal verification error",
            },
            "eval_ms": eval_ms,
            "request_id": request_id,
        }
        if _debug_enabled():
            result["error"]["details"] = {
                "exception_type": type(e).__name__,
                "exception": str(e),
            }
        return result


# ------------------------------------------------------------------
# HTTP handler
# ------------------------------------------------------------------


class PICBridgeHandler(BaseHTTPRequestHandler):
    """
    Minimal HTTP handler for PIC verification.

    Server-level config is stored on the *server* instance (see ``start_bridge``).
    """

    # Suppress default stderr logging per request (we use our own logger)
    def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
        log.debug(fmt, *args)

    def _resolve_request_id(self) -> tuple[str, bool]:
        """Resolve the effective request ID and detect invalid supplied headers.

        Returns ``(request_id, invalid_supplied)``:

        * No ``X-Request-ID`` header supplied → ``(fresh_uuid, False)``.
        * Valid ``X-Request-ID`` supplied → ``(sanitized_value, False)``.
        * Invalid ``X-Request-ID`` supplied → ``(fresh_uuid, True)``. The
          caller MUST reject the request with 400 / ``PIC_INVALID_REQUEST``
          via :meth:`_reject_invalid_request_id` rather than proceeding to
          endpoint-specific handling.

        Centralized so the invalid-header rule applies uniformly across
        every endpoint (``/verify``, ``/health``, ``/v1/version``) and
        every transport response (unknown path 404, disallowed method
        405). Aligns runtime behavior with the ``PIC_INVALID_REQUEST``
        contract in ``docs/ERRORS.md``.
        """
        raw = self.headers.get("X-Request-ID")
        if raw is None:
            return _generate_request_id(), False
        sanitized = _sanitize_request_id(raw)
        if sanitized is None:
            return _generate_request_id(), True
        return sanitized, False

    def _reject_invalid_request_id(self, request_id: str) -> None:
        """Emit the 400 / ``PIC_INVALID_REQUEST`` envelope for a bad header.

        ``request_id`` is a freshly generated UUID (never the invalid
        supplied value) so downstream log correlation stays clean.
        """
        message = "Invalid X-Request-ID header"
        _json_response(
            self,
            400,
            {
                "allowed": False,
                "error": {
                    "code": PICErrorCode.INVALID_REQUEST.value,
                    "message": message,
                },
                "eval_ms": 0,
                "request_id": request_id,
            },
            request_id=request_id,
        )
        _log_audit(
            request_id=request_id,
            tool="",
            allowed=False,
            eval_ms=0,
            code=PICErrorCode.INVALID_REQUEST.value,
            error_message=message,
            event="request_validation_failed",
        )

    def do_GET(self) -> None:
        request_id, invalid = self._resolve_request_id()
        if invalid:
            self._reject_invalid_request_id(request_id)
            return

        if self.path.rstrip("/") == "/health":
            _json_response(
                self, 200, {"status": "ok", "request_id": request_id}, request_id=request_id
            )
            return
        if self.path.rstrip("/") == "/v1/version":
            commit = _get_git_commit()
            package_version = _get_package_version()
            _json_response(
                self,
                200,
                {
                    "pic_version": PIC_VERSION,
                    "package_version": package_version,
                    "commit": commit,
                    "policy_version": POLICY_VERSION,
                    "impl_name": IMPL_NAME,
                    "impl_version": package_version,
                    "pic_protocol_version": PIC_PROTOCOL_VERSION,
                    "conformance_manifest_ref": {
                        "path": "conformance/manifest.json",
                        "sha256": _get_conformance_manifest_sha256(),
                        "commit": commit,
                    },
                    "supported_modes": list(SUPPORTED_MODES),
                    "request_id": request_id,
                },
                request_id=request_id,
            )
            return
        _json_response(
            self, 404, {"error": "Not found", "request_id": request_id}, request_id=request_id
        )

    def do_POST(self) -> None:
        request_id, invalid = self._resolve_request_id()
        if invalid:
            self._reject_invalid_request_id(request_id)
            return

        if self.path.rstrip("/") != "/verify":
            _json_response(
                self, 404, {"error": "Not found", "request_id": request_id}, request_id=request_id
            )
            return

        try:
            body = _read_json_body(self)
        except ValueError as e:
            # Specific validation errors (missing header, too large, etc.)
            _json_response(
                self,
                400,
                {
                    "allowed": False,
                    "error": {"code": PICErrorCode.INVALID_REQUEST.value, "message": str(e)},
                    "eval_ms": 0,
                    "request_id": request_id,
                },
                request_id=request_id,
            )
            _log_audit(
                request_id=request_id,
                tool="",
                allowed=False,
                eval_ms=0,
                code=PICErrorCode.INVALID_REQUEST.value,
                error_message=str(e),
                event="request_validation_failed",
            )
            return
        except Exception:
            # JSON parse errors or unexpected issues
            _json_response(
                self,
                400,
                {
                    "allowed": False,
                    "error": {
                        "code": PICErrorCode.INVALID_REQUEST.value,
                        "message": "Malformed or non-JSON body",
                    },
                    "eval_ms": 0,
                    "request_id": request_id,
                },
                request_id=request_id,
            )
            _log_audit(
                request_id=request_id,
                tool="",
                allowed=False,
                eval_ms=0,
                code=PICErrorCode.INVALID_REQUEST.value,
                error_message="Malformed or non-JSON body",
                event="request_validation_failed",
            )
            return

        srv: PICBridgeServer = self.server  # type: ignore[assignment]
        result = handle_verify(
            body,
            policy=srv.policy,
            limits=srv.limits,
            verify_evidence=srv.verify_evidence,
            proposal_base_dir=srv.proposal_base_dir,
            evidence_root_dir=srv.evidence_root_dir,
            request_id=request_id,
        )
        _json_response(self, 200, result, request_id=request_id)

    def do_PUT(self) -> None:
        request_id, invalid = self._resolve_request_id()
        if invalid:
            self._reject_invalid_request_id(request_id)
            return
        _json_response(
            self,
            405,
            {"error": "Method not allowed", "request_id": request_id},
            request_id=request_id,
        )

    def do_DELETE(self) -> None:
        request_id, invalid = self._resolve_request_id()
        if invalid:
            self._reject_invalid_request_id(request_id)
            return
        _json_response(
            self,
            405,
            {"error": "Method not allowed", "request_id": request_id},
            request_id=request_id,
        )

    def do_PATCH(self) -> None:
        request_id, invalid = self._resolve_request_id()
        if invalid:
            self._reject_invalid_request_id(request_id)
            return
        _json_response(
            self,
            405,
            {"error": "Method not allowed", "request_id": request_id},
            request_id=request_id,
        )


# ------------------------------------------------------------------
# Server with config
# ------------------------------------------------------------------


class PICBridgeServer(HTTPServer):
    """HTTPServer subclass that holds PIC configuration."""

    def __init__(
        self,
        server_address: tuple,
        *,
        policy: PICPolicy,
        limits: Optional[PICEvaluateLimits] = None,
        verify_evidence: bool = False,
        proposal_base_dir: Optional[Path] = None,
        evidence_root_dir: Optional[Path] = None,
    ) -> None:
        super().__init__(server_address, PICBridgeHandler)
        self.policy = policy
        self.limits = limits or PICEvaluateLimits()
        self.verify_evidence = verify_evidence
        self.proposal_base_dir = proposal_base_dir or Path(".").resolve()
        self.evidence_root_dir = evidence_root_dir


# ------------------------------------------------------------------
# Public entry point
# ------------------------------------------------------------------


def start_bridge(
    *,
    host: str = "127.0.0.1",
    port: int = 7580,
    policy: Optional[PICPolicy] = None,
    limits: Optional[PICEvaluateLimits] = None,
    verify_evidence: bool = False,
    proposal_base_dir: Optional[Path] = None,
    evidence_root_dir: Optional[Path] = None,
) -> None:
    """
    Start the PIC HTTP bridge server (blocking).

    Parameters
    ----------
    host : str
        Bind address.  Defaults to ``127.0.0.1`` (localhost-only).
    port : int
        Listen port.  Defaults to ``7580``.
    policy : PICPolicy | None
        Tool-impact policy.  When ``None``, loaded via ``load_policy()``.

    Notes
    -----
    This server is single-threaded and processes one request at a time.
    For production deployments with concurrent load, run multiple bridge
    instances behind a load balancer or use a process manager.

    A 5-second socket read timeout (READ_TIMEOUT_SECS) prevents slow clients
    from blocking the server indefinitely during request body reading.
    """
    policy = policy or load_policy()

    server = PICBridgeServer(
        (host, port),
        policy=policy,
        limits=limits,
        verify_evidence=verify_evidence,
        proposal_base_dir=proposal_base_dir,
        evidence_root_dir=evidence_root_dir,
    )

    log.info("PIC HTTP bridge listening on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("PIC HTTP bridge shutting down")
    finally:
        server.server_close()
