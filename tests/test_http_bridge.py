"""Tests for the PIC HTTP Bridge (sdk-python/pic_standard/integrations/http_bridge.py)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml
from pic_standard.integrations.http_bridge import (
    PICBridgeServer,
    PICEvaluateLimits,
    handle_verify,
)
from pic_standard.policy import PICPolicy

# ------------------------------------------------------------------
# Helpers (same pattern as test_mcp_guard_unit.py)
# ------------------------------------------------------------------

POLICY = PICPolicy(impact_by_tool={"payments_send": "money"})


def _proposal(trust: str) -> dict:
    return {
        "protocol": "PIC/1.0",
        "intent": "Send payment",
        "impact": "money",
        "provenance": [{"id": "invoice_123", "trust": trust, "source": "unit-test"}],
        "claims": [{"text": "Pay $500", "evidence": ["invoice_123"]}],
        "action": {"tool": "payments_send", "args": {"amount": 500}},
    }


def _verify(tool_name: str, tool_args: dict, policy: PICPolicy = POLICY) -> dict:
    """Shortcut: call handle_verify with sensible defaults."""
    return handle_verify(
        {"tool_name": tool_name, "tool_args": tool_args},
        policy=policy,
        limits=PICEvaluateLimits(),
        verify_evidence=False,
        proposal_base_dir=Path(".").resolve(),
        evidence_root_dir=None,
    )


# ------------------------------------------------------------------
# Unit tests (call handle_verify directly - no HTTP)
# ------------------------------------------------------------------


def test_bridge_blocks_missing_pic_for_money():
    result = _verify("payments_send", {"amount": 500})
    assert result["allowed"] is False
    assert result["error"]["code"].startswith("PIC_")


def test_bridge_blocks_untrusted_money():
    result = _verify("payments_send", {"amount": 500, "__pic": _proposal("untrusted")})
    assert result["allowed"] is False
    assert result["error"]["code"].startswith("PIC_")


def test_bridge_allows_trusted_money():
    result = _verify("payments_send", {"amount": 500, "__pic": _proposal("trusted")})
    assert result["allowed"] is True
    assert result["error"] is None
    assert isinstance(result["eval_ms"], int)


def test_bridge_blocks_tool_binding_mismatch():
    bad = _proposal("trusted")
    bad["action"]["tool"] = "some_other_tool"

    result = _verify("payments_send", {"amount": 500, "__pic": bad})
    assert result["allowed"] is False

    code = result["error"]["code"].upper()
    msg = result["error"]["message"].lower()
    assert "TOOL" in code and ("BIND" in code or "MISMATCH" in code)
    assert "tool" in msg and ("bind" in msg or "mismatch" in msg)


def test_bridge_missing_tool_name():
    result = handle_verify(
        {"tool_name": "", "tool_args": {}},
        policy=POLICY,
        limits=PICEvaluateLimits(),
        verify_evidence=False,
        proposal_base_dir=Path(".").resolve(),
        evidence_root_dir=None,
    )
    assert result["allowed"] is False
    assert "tool_name" in result["error"]["message"]


def test_bridge_missing_tool_args():
    result = handle_verify(
        {"tool_name": "payments_send", "tool_args": "not-a-dict"},
        policy=POLICY,
        limits=PICEvaluateLimits(),
        verify_evidence=False,
        proposal_base_dir=Path(".").resolve(),
        evidence_root_dir=None,
    )
    assert result["allowed"] is False
    assert "tool_args" in result["error"]["message"]


def test_bridge_no_detail_leakage_by_default(monkeypatch):
    monkeypatch.delenv("PIC_DEBUG", raising=False)

    result = _verify("payments_send", {"amount": 500, "__pic": _proposal("untrusted")})
    assert result["allowed"] is False
    assert "details" not in result.get("error", {})


def test_bridge_leaks_details_when_debug(monkeypatch):
    monkeypatch.setenv("PIC_DEBUG", "1")

    result = _verify("payments_send", {"amount": 500, "__pic": _proposal("untrusted")})
    assert result["allowed"] is False
    # Debug mode: response must still be well-formed regardless of detail presence.
    assert "code" in result["error"]
    assert "message" in result["error"]


def test_bridge_audit_shape_allow(caplog):
    caplog.set_level("INFO", logger="pic_standard.audit")

    result = handle_verify(
        {"tool_name": "payments_send", "tool_args": {"amount": 500, "__pic": _proposal("trusted")}},
        policy=POLICY,
        limits=PICEvaluateLimits(),
        verify_evidence=False,
        proposal_base_dir=Path(".").resolve(),
        evidence_root_dir=None,
        request_id="req-audit-allow",
    )
    assert result["allowed"] is True

    record = next(
        r
        for r in caplog.records
        if r.name == "pic_standard.audit" and "req-audit-allow" in r.message
    )
    payload = json.loads(record.message)
    assert payload["event"] == "verification_allowed"
    assert payload["request_id"] == "req-audit-allow"
    assert payload["tool"] == "payments_send"
    assert payload["allowed"] is True
    assert payload["code"] == "PIC_OK"
    assert isinstance(payload["eval_ms"], int)
    assert isinstance(payload["timestamp"], str)


def test_bridge_audit_shape_block(caplog):
    caplog.set_level("INFO", logger="pic_standard.audit")

    result = handle_verify(
        {
            "tool_name": "payments_send",
            "tool_args": {"amount": 500, "__pic": _proposal("untrusted")},
        },
        policy=POLICY,
        limits=PICEvaluateLimits(),
        verify_evidence=False,
        proposal_base_dir=Path(".").resolve(),
        evidence_root_dir=None,
        request_id="req-audit-block",
    )
    assert result["allowed"] is False

    record = next(
        r
        for r in caplog.records
        if r.name == "pic_standard.audit" and "req-audit-block" in r.message
    )
    payload = json.loads(record.message)
    assert payload["event"] == "verification_blocked"
    assert payload["request_id"] == "req-audit-block"
    assert payload["tool"] == "payments_send"
    assert payload["allowed"] is False
    assert isinstance(payload["code"], str)
    assert payload["code"].startswith("PIC_")
    assert isinstance(payload["eval_ms"], int)
    assert isinstance(payload["timestamp"], str)


_INVALID_X_REQUEST_ID = "bad id with spaces!"


# Each entry: (method, path, body-or-None).
# The centralized invalid-X-Request-ID rule must apply BEFORE any per-endpoint
# routing, so we cover representative endpoints across all shapes: the two GET
# endpoints, the POST endpoint (with a body that would otherwise ALLOW), an
# unknown path (would otherwise 404), and a disallowed method (would otherwise
# 405). Each MUST return 400 + PIC_INVALID_REQUEST + a fresh generated UUID.
_INVALID_XRID_CASES = [
    pytest.param("GET", "/health", None, id="get_health"),
    pytest.param("GET", "/v1/version", None, id="get_version"),
    pytest.param(
        "POST",
        "/verify",
        {"tool_name": "docs_search", "tool_args": {}},
        id="post_verify",
    ),
    pytest.param("GET", "/not-found", None, id="get_not_found"),
    pytest.param("PUT", "/verify", None, id="put_verify"),
]


@pytest.mark.parametrize("method,path,body", _INVALID_XRID_CASES)
def test_bridge_invalid_x_request_id_rejected_uniformly(bridge_url, method, path, body):
    """Invalid X-Request-ID MUST be rejected before any endpoint work.

    Per docs/ERRORS.md, an invalid supplied X-Request-ID is a pre-pipeline
    validation error surfacing as HTTP 400 with PIC_INVALID_REQUEST. The
    rule is centralized in the handler so it applies uniformly to /verify,
    /health, /v1/version, unknown paths (would otherwise 404) and
    disallowed methods (would otherwise 405). The response request_id MUST
    be a freshly generated UUID, never echoing the invalid supplied value.
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"X-Request-ID": _INVALID_X_REQUEST_ID}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{bridge_url}{path}", data=data, headers=headers, method=method)
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(req)
    err = excinfo.value
    assert err.code == 400

    result = json.loads(err.read())
    assert result["allowed"] is False
    assert result["error"]["code"] == "PIC_INVALID_REQUEST"
    assert isinstance(result["error"]["message"], str) and result["error"]["message"]
    assert result["eval_ms"] == 0

    # request_id must be a fresh UUID, never the invalid supplied value.
    returned = result["request_id"]
    assert isinstance(returned, str) and returned
    assert returned != _INVALID_X_REQUEST_ID

    # Response X-Request-ID header MUST match the body request_id.
    assert err.headers.get("X-Request-ID") == returned


# ------------------------------------------------------------------
# HTTP integration tests (start real server on random port)
# ------------------------------------------------------------------


@pytest.fixture()
def bridge_url():
    """Start a PICBridgeServer on a random port and yield its base URL."""
    server = PICBridgeServer(
        ("127.0.0.1", 0),  # port 0 = OS picks a free port
        policy=POLICY,
        verify_evidence=False,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _http_post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _http_get(url: str) -> dict:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


# ------------------------------------------------------------------
# OpenAPI contract helpers (A4)
# ------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_OPENAPI_SPEC_PATH = _REPO_ROOT / "openapi" / "pic-bridge.v1.yaml"


def _load_openapi_spec() -> dict:
    """Load the bridge OpenAPI spec once; used by every contract test.

    The spec file is the source of truth for expected shape (required
    fields, error-code enum, request examples). If PyYAML is missing
    the test suite must FAIL loudly rather than skip, because the
    contract test not running defeats its purpose.
    """
    with _OPENAPI_SPEC_PATH.open("rb") as f:
        return yaml.safe_load(f)


def _assert_response_shape(response: dict, schema: dict, *, label: str) -> None:
    """Assert a live response has exactly the keys the yaml schema declares.

    Required properties must all be present. Because every stable
    response envelope in the yaml uses ``additionalProperties: false``,
    unexpected top-level keys are also a contract violation. Both
    failure messages are sorted for deterministic diffs.
    """
    required = set(schema["required"])
    properties = set(schema["properties"])
    keys = set(response.keys())
    missing = required - keys
    assert not missing, f"{label} missing required keys: {sorted(missing)}"
    unexpected = keys - properties
    assert not unexpected, f"{label} has unexpected keys: {sorted(unexpected)}"


def test_bridge_health_endpoint(bridge_url):
    result = _http_get(f"{bridge_url}/health")
    assert result["status"] == "ok"
    # Phase 2.2: request_id should be present
    assert "request_id" in result


def test_bridge_version_endpoint(bridge_url):
    result = _http_get(f"{bridge_url}/v1/version")
    assert result["pic_version"] == "1.0"
    assert isinstance(result["package_version"], str)
    assert result["package_version"]
    # Phase 2.2: commit and policy_version required
    assert "commit" in result
    assert isinstance(result["commit"], str)
    assert "policy_version" in result
    assert result["policy_version"] == "1.0"
    # Phase 2.2: request_id should be present
    assert "request_id" in result

    # v0.9.0a1 (§15.3): machine-readable version metadata for cross-impl parity.
    # These fields are additive on top of the legacy fields above; the legacy
    # names remain for backward compat; the §15.3 names are intended for
    # Repo B's TS runner and the differential CI harness.
    assert result["impl_name"] == "pic-standard-py"
    assert isinstance(result["impl_version"], str) and result["impl_version"]
    # impl_version and package_version must agree: splitting them would let
    # the wheel's version and the reported impl version drift apart.
    assert result["impl_version"] == result["package_version"]
    assert result["pic_protocol_version"] == "PIC/1.0"

    manifest_ref = result["conformance_manifest_ref"]
    assert isinstance(manifest_ref, dict)
    assert manifest_ref["path"] == "conformance/manifest.json"
    # sha256 is either "sha256:<64 lowercase hex>" or exactly "unknown" when
    # the manifest file cannot be located (packaged/wheel layout).
    sha = manifest_ref["sha256"]
    assert isinstance(sha, str)
    if sha != "unknown":
        assert sha.startswith("sha256:")
        hex_part = sha[len("sha256:") :]
        assert len(hex_part) == 64
        assert all(c in "0123456789abcdef" for c in hex_part)
    # commit degrades to "unknown" when git is not available; never empty.
    assert isinstance(manifest_ref["commit"], str)
    assert manifest_ref["commit"]
    # Top-level `commit` and manifest_ref.commit refer to the same checkout
    # state and must agree so consumers can cross-reference safely.
    assert manifest_ref["commit"] == result["commit"]

    # supported_modes is the machine-checkable list of conformance modes this
    # implementation runs. Python supports all four; TS in v0.9.0 will report
    # only the three modes it implements (evidence deferred to v0.9.x).
    modes = result["supported_modes"]
    assert isinstance(modes, list)
    assert modes == ["canonicalization", "core", "evidence", "trust_sanitization"]


def test_bridge_http_allows_trusted(bridge_url):
    result = _http_post(
        f"{bridge_url}/verify",
        {"tool_name": "payments_send", "tool_args": {"amount": 500, "__pic": _proposal("trusted")}},
    )
    assert result["allowed"] is True
    assert result["error"] is None
    assert isinstance(result["eval_ms"], int)
    # Phase 2.2: request_id should be present
    assert "request_id" in result
    assert isinstance(result["request_id"], str)


# ------------------------------------------------------------------
# Phase 2.2: X-Request-ID header and request_id in responses
# ------------------------------------------------------------------


def test_bridge_request_id_generated_if_not_provided(bridge_url):
    """If X-Request-ID header not provided, server generates one."""
    result = _http_get(f"{bridge_url}/health")
    assert "request_id" in result
    request_id = result["request_id"]
    assert isinstance(request_id, str)
    assert len(request_id) > 0


def test_bridge_request_id_echoed_if_provided(bridge_url):
    """If X-Request-ID header provided, server echoes it back."""
    import urllib.request

    custom_request_id = "my-custom-request-12345"
    req = urllib.request.Request(
        f"{bridge_url}/health",
        method="GET",
        headers={"X-Request-ID": custom_request_id},
    )
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
        assert result["request_id"] == custom_request_id
        # Also check it's in response headers
        assert resp.headers.get("X-Request-ID") == custom_request_id


def test_bridge_request_id_in_verify_response(bridge_url):
    """Verify endpoint includes request_id in response."""
    result = _http_post(
        f"{bridge_url}/verify",
        {"tool_name": "payments_send", "tool_args": {"amount": 500, "__pic": _proposal("trusted")}},
    )
    assert "request_id" in result
    assert isinstance(result["request_id"], str)


def test_bridge_request_id_in_error_response(bridge_url):
    """Error responses also include request_id."""
    result = _http_post(
        f"{bridge_url}/verify",
        {
            "tool_name": "payments_send",
            "tool_args": {"amount": 500, "__pic": _proposal("untrusted")},
        },
    )
    assert result["allowed"] is False
    assert "request_id" in result
    assert isinstance(result["request_id"], str)


def test_bridge_http_blocks_untrusted(bridge_url):
    result = _http_post(
        f"{bridge_url}/verify",
        {
            "tool_name": "payments_send",
            "tool_args": {"amount": 500, "__pic": _proposal("untrusted")},
        },
    )
    assert result["allowed"] is False
    assert result["error"]["code"].startswith("PIC_")


def test_bridge_http_malformed_json(bridge_url):
    req = urllib.request.Request(
        f"{bridge_url}/verify",
        data=b"this is not json",
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        pytest.fail("Expected HTTPError for malformed JSON")
    except urllib.error.HTTPError as e:
        assert e.code == 400
        result = json.loads(e.read())
        assert result["allowed"] is False
        assert result["error"]["code"] == "PIC_INVALID_REQUEST"


def test_bridge_http_not_found(bridge_url):
    req = urllib.request.Request(
        f"{bridge_url}/nonexistent",
        data=json.dumps({}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        pytest.fail("Expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_bridge_http_method_not_allowed(bridge_url):
    req = urllib.request.Request(
        f"{bridge_url}/verify",
        method="DELETE",
    )
    try:
        urllib.request.urlopen(req)
        pytest.fail("Expected 405")
    except urllib.error.HTTPError as e:
        assert e.code == 405


# ------------------------------------------------------------------
# Content-Length and Body Size Validation
# ------------------------------------------------------------------


def _send_raw_http(bridge_url: str, headers: bytes, body: bytes = b"") -> str:
    """Send a raw HTTP request and return the response as a string.

    Useful for testing edge cases that urllib won't allow (missing headers,
    invalid Content-Length, etc.).
    """
    import socket

    # Parse host and port from bridge_url
    host_port = bridge_url.replace("http://", "")
    host, port_str = host_port.split(":")
    port = int(port_str)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.settimeout(5.0)
        s.sendall(headers + body)
        # Read response in chunks until connection closes
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode()


def test_bridge_http_missing_content_length(bridge_url):
    """Missing Content-Length header returns 400 with specific error message."""
    response = _send_raw_http(
        bridge_url,
        b"POST /verify HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\r\n",
    )
    assert "400" in response
    assert "Missing Content-Length" in response


def test_bridge_http_empty_body(bridge_url):
    """Empty request body (Content-Length: 0) returns 400."""
    req = urllib.request.Request(
        f"{bridge_url}/verify",
        data=b"",
        headers={"Content-Type": "application/json", "Content-Length": "0"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        pytest.fail("Expected HTTPError for empty body")
    except urllib.error.HTTPError as e:
        assert e.code == 400
        result = json.loads(e.read())
        assert result["allowed"] is False
        assert result["error"]["code"] == "PIC_INVALID_REQUEST"
        assert "Empty request body" in result["error"]["message"]


def test_bridge_http_oversized_body(bridge_url):
    """Request body larger than MAX_REQUEST_BYTES returns 400."""
    from pic_standard.integrations.http_bridge import MAX_REQUEST_BYTES

    oversized_length = MAX_REQUEST_BYTES + 1
    response = _send_raw_http(
        bridge_url,
        b"POST /verify HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(oversized_length).encode() + b"\r\n"
        b"\r\n",
    )
    assert "400" in response
    assert "too large" in response
    assert str(MAX_REQUEST_BYTES) in response


def test_bridge_http_negative_content_length(bridge_url):
    """Negative Content-Length header returns 400."""
    response = _send_raw_http(
        bridge_url,
        b"POST /verify HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: -1\r\n"
        b"\r\n",
    )
    assert "400" in response
    assert "negative" in response.lower()


def test_bridge_http_malformed_content_length(bridge_url):
    """Non-numeric Content-Length header returns 400."""
    response = _send_raw_http(
        bridge_url,
        b"POST /verify HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: abc\r\n"
        b"\r\n",
    )
    assert "400" in response
    assert "Invalid Content-Length" in response


def test_bridge_http_non_dict_json_body(bridge_url):
    """JSON body that is not an object (array, string, number) returns 400."""
    test_cases = [
        (b"[1, 2, 3]", "list"),
        (b'"hello"', "str"),
        (b"123", "int"),
        (b"true", "bool"),
        (b"null", "NoneType"),
    ]
    for body, expected_type in test_cases:
        req = urllib.request.Request(
            f"{bridge_url}/verify",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
            pytest.fail(f"Expected HTTPError for non-dict JSON body: {body}")
        except urllib.error.HTTPError as e:
            assert e.code == 400, f"Expected 400 for {body}, got {e.code}"
            result = json.loads(e.read())
            assert result["allowed"] is False
            assert result["error"]["code"] == "PIC_INVALID_REQUEST"
            assert "dict" in result["error"]["message"]
            assert expected_type in result["error"]["message"]


def test_openapi_contract_verify_examples_match_bridge(bridge_url):
    """POST /verify examples from the yaml exercise the live bridge.

    Loads both documented examples (allow_low_impact and
    block_untrusted_high_impact), POSTs each without local patching,
    and asserts the response matches the yaml's VerifyResponse shape:
      * required top-level keys present (derived from the yaml)
      * no unexpected top-level keys (yaml uses additionalProperties: false)
      * allowed is boolean
      * eval_ms is a non-negative integer
      * request_id is a non-empty string
      * allow: error is None
      * block: error.code is a documented PICErrorCode enum value
    """
    spec = _load_openapi_spec()
    examples = spec["paths"]["/verify"]["post"]["requestBody"]["content"]["application/json"][
        "examples"
    ]
    verify_response_schema = spec["components"]["schemas"]["VerifyResponse"]
    codes = set(spec["components"]["schemas"]["PICErrorCode"]["enum"])
    assert "allow_low_impact" in examples
    assert "block_untrusted_high_impact" in examples

    # allow_low_impact must land as a genuine allow.
    r = _http_post(f"{bridge_url}/verify", examples["allow_low_impact"]["value"])
    _assert_response_shape(r, verify_response_schema, label="allow response")
    assert isinstance(r["allowed"], bool) and r["allowed"] is True
    assert r["error"] is None
    assert isinstance(r["eval_ms"], int) and r["eval_ms"] >= 0
    assert isinstance(r["request_id"], str) and r["request_id"]

    # block_untrusted_high_impact must land as a block with a documented code.
    r = _http_post(f"{bridge_url}/verify", examples["block_untrusted_high_impact"]["value"])
    _assert_response_shape(r, verify_response_schema, label="block response")
    assert isinstance(r["allowed"], bool) and r["allowed"] is False
    assert isinstance(r["error"], dict)
    assert r["error"]["code"] in codes, (
        f"error code {r['error']['code']} not in yaml enum {sorted(codes)}"
    )
    assert isinstance(r["error"]["message"], str) and r["error"]["message"]
    assert isinstance(r["eval_ms"], int) and r["eval_ms"] >= 0
    assert isinstance(r["request_id"], str) and r["request_id"]


def test_openapi_contract_version_response_has_all_required_fields(bridge_url):
    """/v1/version response carries every field the yaml marks as required.

    Also asserts no unexpected top-level fields, since the yaml's
    VersionResponse uses additionalProperties: false. Same shape check
    is applied to conformance_manifest_ref, which is also
    additionalProperties: false.
    """
    spec = _load_openapi_spec()
    version_schema = spec["components"]["schemas"]["VersionResponse"]
    manifest_schema = spec["components"]["schemas"]["ConformanceManifestRef"]

    result = _http_get(f"{bridge_url}/v1/version")
    _assert_response_shape(result, version_schema, label="/v1/version")

    manifest = result["conformance_manifest_ref"]
    assert isinstance(manifest, dict)
    _assert_response_shape(manifest, manifest_schema, label="conformance_manifest_ref")
