from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Union
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from pic_standard.canonical import canonicalize
from pic_standard.keyring import KeyResolver, StaticKeyRingResolver, TrustedKeyRing

# ----------------------------
# Models (match schema intent)
# ----------------------------


class HashEvidenceRef(BaseModel):
    """v0.3: deterministic sha256 over file bytes."""

    id: str
    type: Literal["hash"] = "hash"
    ref: str = Field(..., description="file://... (sandboxed)")
    sha256: str = Field(..., description="Expected SHA-256 hex digest (64 chars)")
    attestor: Optional[str] = None


class SigEvidenceRef(BaseModel):
    """v0.4: Ed25519 signature over payload bytes."""

    id: str
    type: Literal["sig"] = "sig"

    # ref is informational for now (e.g. "inline:approval_payload")
    ref: str = Field(..., description="Evidence reference label (e.g. inline:...)")

    payload: str = Field(..., description="Exact bytes-to-verify as UTF-8 string")
    alg: Literal["ed25519"] = "ed25519"
    signature: str = Field(..., description="Base64 Ed25519 signature over payload bytes")
    key_id: str = Field(..., description="Key id resolved in trusted keyring")
    signer: Optional[str] = Field(None, description="Human/service identity (informational)")
    attestor: Optional[str] = None


EvidenceRef = Union[HashEvidenceRef, SigEvidenceRef]


# ----------------------------
# Report types
# ----------------------------


@dataclass
class EvidenceResult:
    id: str
    ok: bool
    message: str


@dataclass
class EvidenceReport:
    ok: bool
    results: List[EvidenceResult]
    verified_ids: Set[str]


# ----------------------------
# Helpers
# ----------------------------


def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    """Python 3.10 compatible Path.is_relative_to()."""
    try:
        path.relative_to(root)
        return True
    except Exception:
        return False


def _resolve_file_uri_path(ref: str, *, base_dir: Path) -> Path:
    """Parse file:// URI into a Path (not yet sandbox-validated).

    Supports:
      - file://artifacts/invoice.txt      (relative)
      - file://invoice.txt               (relative)
      - file:///C:/path/on/windows       (absolute)
      - file:///absolute/path            (POSIX absolute)
      - file://C:/path/on/windows        (sometimes seen; absolute)
    """
    if not ref.startswith("file://"):
        raise ValueError(f"Unsupported ref scheme for hash evidence: {ref}")

    parsed = urlparse(ref)

    # file://A/B -> netloc="A", path="/B"
    netloc = parsed.netloc or ""
    path_part = parsed.path or ""

    if netloc and path_part:
        combined = f"{netloc}/{path_part.lstrip('/')}"
    elif netloc and not path_part:
        combined = netloc
    else:
        combined = path_part

    if not combined:
        raise ValueError("Empty file URI path")

    # Windows: "/C:/..." -> "C:/..."
    if combined.startswith("/") and len(combined) >= 3 and combined[2] == ":":
        combined = combined.lstrip("/")

    p = Path(combined)

    p = (base_dir / p).resolve() if not p.is_absolute() else p.resolve()

    return p


def _read_sandboxed_file(
    ref: str,
    *,
    base_dir: Path,
    evidence_root_dir: Path,
    max_file_bytes: int,
) -> bytes:
    """Resolve file:// URI and enforce sandbox."""
    p = _resolve_file_uri_path(ref, base_dir=base_dir)

    root = evidence_root_dir.resolve()
    if not _is_relative_to(p, root):
        raise ValueError(f"Evidence file escapes evidence_root_dir: {p} not under {root}")

    if not p.exists():
        raise FileNotFoundError(f"Evidence file not found: {p}")

    size = p.stat().st_size
    if size > max_file_bytes:
        raise ValueError(f"Evidence file too large: {size} bytes (max {max_file_bytes})")

    return p.read_bytes()


def _b64decode(s: str, *, what: str, strict: bool = False) -> bytes:
    """Accept standard or urlsafe base64, with/without padding.

    When ``strict=True`` (Phase 1 canonicalization), require standard
    RFC 4648 base64 alphabet with correct padding — no lenient fixups.
    """
    try:
        if strict:
            raw = s.strip()
            if raw != s:
                raise ValueError(
                    f"Invalid base64 for {what}: leading/trailing whitespace not allowed"
                )
            if "-" in raw or "_" in raw:
                raise ValueError(f"Invalid base64 for {what}: URL-safe base64 alphabet not allowed")
            if len(raw) % 4 != 0:
                raise ValueError(f"Invalid base64 for {what}: missing/invalid padding")
            return base64.b64decode(raw, validate=True)
        raw = s.strip().replace("-", "+").replace("_", "/")
        pad = "=" * ((4 - len(raw) % 4) % 4)
        return base64.b64decode(raw + pad, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64 for {what}") from e


def _verify_ed25519_signature(*, public_key_raw: bytes, signature_b64: str, message: bytes) -> bool:
    """Verify Ed25519 signature using cryptography."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except Exception as e:  # pragma: no cover
        raise ValueError(
            "cryptography is required for signature evidence. "
            "Install it via: pip install 'pic-standard[crypto]'"
        ) from e

    sig_raw = _b64decode(signature_b64, what="signature")
    if len(sig_raw) != 64:
        raise ValueError("Invalid Ed25519 signature length (expected 64 raw bytes)")

    pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key_raw)
    try:
        pk.verify(sig_raw, message)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Canonical attestation-object signing (v0.8.2 PR V8.2-5)
# ---------------------------------------------------------------------------
#
# Per docs/spec-evidence.md §6.2-§6.4, signature evidence carries one of two
# signing modes detected at verify time from the parsed payload:
#
#   - Legacy mode: payload is not a JSON object, OR is a JSON object without
#     an `attestation_version` key. Bytes-to-verify are the raw UTF-8 bytes
#     of the payload string. Preserves the v0.4 signing contract.
#
#   - Canonical mode: payload parses as a JSON object containing a
#     string-valued `attestation_version` from the supported allowlist.
#     Bytes-to-verify are computed as `canonicalize(parsed_attestation_object)`
#     per docs/canonicalization.md §8.4. After signature verification, the
#     attestation's tool / impact / args_digest / claims_digest /
#     intent_digest (when present) / provenance_ids / expires_at (when
#     present) MUST bind to the corresponding fields of the Action Proposal
#     per spec-evidence.md §6.4.
#
#   - Canonical-looking but malformed/unknown: payload parses as a JSON
#     object containing `attestation_version` but is non-conformant (value
#     non-string OR string outside allowlist OR object carries duplicate
#     keys at any nesting level). MUST fail closed with PIC_EVIDENCE_FAILED;
#     no silent fallback to legacy bytes.
#
# Extending the allowlist is a versioned change; per spec-evidence.md §18,
# removing values is backward-incompatible.

_SUPPORTED_ATTESTATION_VERSIONS: frozenset[str] = frozenset({"PIC-ATT/1.0"})

# Lowercase 64-char hex per spec-evidence.md §6.4 digest field-shape rule.
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

# RFC 3339 with required timezone designator (Z or +HH:MM / -HH:MM).
# Rejects naive timestamps, space-separated date/time, and other
# ISO-ish variants that fromisoformat would otherwise accept.
_RFC3339_AWARE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _parse_payload_for_mode_detection(payload: str) -> Tuple[Optional[Any], bool]:
    """Parse a sig-evidence payload for signing-mode detection.

    Returns ``(parsed_value, had_duplicate_keys)``.

    ``parsed_value`` is the result of ``json.loads(payload)`` when parsing
    succeeds, including ``None`` for JSON ``null``. It is also ``None``
    when the payload is not valid JSON. The caller treats ``None`` and any
    other non-dict parsed value as legacy mode, so both JSON ``null`` and
    invalid JSON follow the legacy raw-byte path.

    ``had_duplicate_keys`` reflects any duplicate object member names in
    the parsed structure at any nesting level (the ``object_pairs_hook``
    fires recursively via ``json.loads``). The canonical-mode path
    consults this signal.

    JSON syntax errors (``json.JSONDecodeError``) are treated as legacy
    mode per spec-evidence.md §6.2. Other ``Exception`` subclasses from
    the parser path (``RecursionError``, ``MemoryError``, unexpected
    runtime errors) fail closed rather than silently downgrading to
    legacy — a downgrade on parser-level failure would re-open the
    security gap canonical mode is designed to close.

    Note: ``BaseException`` subclasses that are not ``Exception``
    subclasses — ``KeyboardInterrupt``, ``SystemExit``, ``GeneratorExit``
    — propagate naturally past the ``except Exception`` clause.
    """
    duplicate_seen = [False]

    def _hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        seen: Dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                duplicate_seen[0] = True
            seen[key] = value
        return seen

    try:
        parsed = json.loads(payload, object_pairs_hook=_hook)
    except json.JSONDecodeError:
        return None, False
    except Exception as e:
        raise ValueError(
            f"could not parse payload JSON for mode detection: {type(e).__name__}: {e}"
        ) from e
    return parsed, duplicate_seen[0]


def _parse_rfc3339_aware_utc(s: object) -> datetime:
    """Parse RFC 3339 timestamp; reject naive, whitespace-padded, and non-conformant forms.

    Accepts ``Z`` and ``+HH:MM`` / ``-HH:MM`` offsets. Leading/trailing
    whitespace, naive timestamps, space-separated date/time, and other
    ISO-ish variants fail closed. Aware values are normalized to UTC.
    """
    if not isinstance(s, str):
        raise ValueError(f"timestamp must be a string, got {type(s).__name__}")
    # No .strip(): whitespace padding is non-conformant input.
    if s != s.strip():
        raise ValueError(f"invalid RFC 3339 timestamp: {s!r}")
    if not _RFC3339_AWARE_RE.match(s):
        raise ValueError(f"invalid RFC 3339 timestamp: {s!r}")
    # Python 3.10 fromisoformat doesn't accept 'Z' suffix; normalize first.
    s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(s2)
    except ValueError as e:
        # Regex passes calendar-invalid strings (e.g. month 99); convert
        # fromisoformat's raw ValueError to the locked failure shape.
        raise ValueError(f"invalid RFC 3339 timestamp: {s!r}") from e
    if dt.tzinfo is None:
        # Should be unreachable given regex; defensive.
        raise ValueError(f"timestamp must be timezone-aware: {s!r}")
    return dt.astimezone(timezone.utc)


def _validate_digest_hex(value: object, field_name: str) -> str:
    """Validate that ``value`` is a lowercase 64-char hex digest string.

    Returns the validated string. Raises ``ValueError`` fail-closed on any
    shape violation: not a string, wrong length, non-hex chars, or
    uppercase hex. Per spec-evidence.md §6.4.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string, got {type(value).__name__}")
    if not _DIGEST_HEX_RE.match(value):
        raise ValueError(f"{field_name} must be lowercase 64-char hex, got {value!r}")
    return value


def _canonical_attestation_bytes(
    parsed_payload: Dict[str, Any],
    *,
    had_duplicate_keys: bool,
    max_payload_bytes: int,
) -> bytes:
    """Compute canonical bytes for canonical-mode sig verification.

    Pre-condition: ``parsed_payload`` is a dict containing
    ``attestation_version`` (mode detection has already confirmed
    canonical-looking). Validates per spec-evidence.md §6.2:

      - duplicate keys at any nesting level (fails closed;
        canonical-looking duplicates are a security footgun);
      - ``attestation_version`` is a string in the supported allowlist;
      - canonicalization (PIC-CJSON/1.0) succeeds;
      - canonical bytes do not exceed ``max_payload_bytes`` (post-canonical
        size cap, since RFC 8785 number normalization may grow the
        serialization, e.g. ``1e10`` -> ``10000000000``).

    Raises ``ValueError`` with locked failure messages on any violation.
    Returns the canonical bytes ready for ed25519 signature verification.
    """
    if had_duplicate_keys:
        raise ValueError("canonical payload contains duplicate object keys")
    av = parsed_payload["attestation_version"]
    if not isinstance(av, str):
        raise ValueError(f"attestation_version must be a string, got {type(av).__name__}")
    if av not in _SUPPORTED_ATTESTATION_VERSIONS:
        raise ValueError(f"unsupported attestation_version: {av!r}")
    try:
        payload_bytes = canonicalize(parsed_payload)
    except Exception as e:
        raise ValueError(
            f"canonicalization failed for attestation object: {type(e).__name__}: {e}"
        ) from e
    if len(payload_bytes) > max_payload_bytes:
        raise ValueError(
            f"Canonical payload too large: {len(payload_bytes)} bytes (max {max_payload_bytes})"
        )
    return payload_bytes


# ---------------------------------------------------------------------------
# Canonical-mode binding checks.
# ---------------------------------------------------------------------------
# Keep these together with docs/spec-evidence.md §6.4. Adding or removing
# a binding rule REQUIRES a coordinated update across:
#
#   1. docs/spec-evidence.md §6.4 (normative wording)
#   2. The helper below (implementation)
#   3. The conformance vectors under conformance/evidence/ that pin the
#      rule (one block vector per binding rule, exactly one failing
#      condition per vector)
#   4. The persistent test suite in tests/test_evidence_canonical_signing.py
#
# Spec/code/vector drift is the main future risk for this surface.
# ---------------------------------------------------------------------------


def _verify_canonical_attestation_binding(
    parsed_payload: Dict[str, Any],
    proposal: Dict[str, Any],
    *,
    key_id: str,
) -> None:
    """Verify canonical-mode digest + field binding per spec-evidence.md §6.4.

    Pre-conditions: signature has already verified over canonical bytes;
    ``parsed_payload`` is a dict containing ``attestation_version`` (mode
    detection has already confirmed canonical-looking).

    Validates (all fail closed via ValueError):

      - Attestation field shapes: ``tool`` (str), ``impact`` (str),
        ``provenance_ids`` (list of str);
      - Proposal shape: ``action`` (dict with str ``tool`` + ``args``),
        ``impact`` (str), ``claims`` (list), ``provenance`` (list of
        dicts with str ``id``);
      - Field equality: tool, impact, provenance_ids;
      - Digest binding (constant-time): args_digest, claims_digest,
        intent_digest (when present);
      - Freshness: expires_at not in past (when present).

    Returns ``None`` on success.
    """
    # Attestation field-shape validation (MUST fields).
    attest_tool = parsed_payload.get("tool")
    if not isinstance(attest_tool, str):
        raise ValueError(f"attestation tool must be a string, got {type(attest_tool).__name__}")
    attest_impact = parsed_payload.get("impact")
    if not isinstance(attest_impact, str):
        raise ValueError(f"attestation impact must be a string, got {type(attest_impact).__name__}")
    attest_prov_ids = parsed_payload.get("provenance_ids")
    if not isinstance(attest_prov_ids, list) or not all(
        isinstance(x, str) for x in attest_prov_ids
    ):
        raise ValueError("attestation provenance_ids must be a list of strings")

    # Proposal-shape guards: verify_all() may be called outside the
    # schema-validating pipeline, so the proposal might carry arbitrary
    # shape. Fail closed on malformed proposal context rather than crash
    # mid-digest.
    proposal_action = proposal.get("action")
    if not isinstance(proposal_action, dict):
        raise ValueError("proposal action must be an object")
    proposal_tool = proposal_action.get("tool")
    if not isinstance(proposal_tool, str):
        raise ValueError(
            f"proposal action.tool must be a string, got {type(proposal_tool).__name__}"
        )
    if "args" not in proposal_action:
        raise ValueError("proposal action.args is required for args_digest binding")
    proposal_impact = proposal.get("impact")
    if not isinstance(proposal_impact, str):
        raise ValueError(f"proposal impact must be a string, got {type(proposal_impact).__name__}")
    proposal_claims = proposal.get("claims")
    if not isinstance(proposal_claims, list):
        raise ValueError(f"proposal claims must be a list, got {type(proposal_claims).__name__}")
    proposal_provenance = proposal.get("provenance")
    if not isinstance(proposal_provenance, list):
        raise ValueError(
            f"proposal provenance must be a list, got {type(proposal_provenance).__name__}"
        )
    proposal_prov_ids: List[str] = []
    for p in proposal_provenance:
        if not isinstance(p, dict) or not isinstance(p.get("id"), str):
            raise ValueError("proposal provenance entries must be objects with string id")
        proposal_prov_ids.append(p["id"])

    # Field equality.
    if attest_tool != proposal_tool:
        raise ValueError(f"attestation tool mismatch: {attest_tool!r} vs {proposal_tool!r}")
    if attest_impact != proposal_impact:
        raise ValueError(f"attestation impact mismatch: {attest_impact!r} vs {proposal_impact!r}")
    if attest_prov_ids != proposal_prov_ids:
        raise ValueError("attestation provenance_ids mismatch")

    # args_digest binding (constant-time).
    attest_args_digest = _validate_digest_hex(parsed_payload.get("args_digest"), "args_digest")
    try:
        args_canon = canonicalize(proposal_action["args"])
    except Exception as e:
        raise ValueError(
            f"canonicalization failed for proposal action args: {type(e).__name__}: {e}"
        ) from e
    actual_args_digest = hashlib.sha256(args_canon).hexdigest()
    if not hmac.compare_digest(attest_args_digest, actual_args_digest):
        raise ValueError(f"args_digest mismatch (key_id='{key_id}')")

    # claims_digest binding (constant-time).
    attest_claims_digest = _validate_digest_hex(
        parsed_payload.get("claims_digest"), "claims_digest"
    )
    try:
        claims_canon = canonicalize(proposal_claims)
    except Exception as e:
        raise ValueError(
            f"canonicalization failed for proposal claims: {type(e).__name__}: {e}"
        ) from e
    actual_claims_digest = hashlib.sha256(claims_canon).hexdigest()
    if not hmac.compare_digest(attest_claims_digest, actual_claims_digest):
        raise ValueError(f"claims_digest mismatch (key_id='{key_id}')")

    # intent_digest binding (when present, constant-time).
    if "intent_digest" in parsed_payload:
        attest_intent_digest = _validate_digest_hex(
            parsed_payload.get("intent_digest"), "intent_digest"
        )
        proposal_intent = proposal.get("intent")
        if not isinstance(proposal_intent, str):
            raise ValueError(
                f"proposal intent must be a string for intent_digest binding, "
                f"got {type(proposal_intent).__name__}"
            )
        actual_intent_digest = hashlib.sha256(proposal_intent.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(attest_intent_digest, actual_intent_digest):
            raise ValueError(f"intent_digest mismatch (key_id='{key_id}')")

    # expires_at freshness (when present).
    if "expires_at" in parsed_payload:
        expires_at = _parse_rfc3339_aware_utc(parsed_payload["expires_at"])
        now = datetime.now(timezone.utc)
        if expires_at < now:
            raise ValueError(f"attestation expired at {expires_at.isoformat()}")


# ----------------------------
# EvidenceSystem
# ----------------------------


class EvidenceSystem:
    """Evidence verification engine.

    Supported evidence:
      - v0.3: type="hash" (sha256 over sandboxed file bytes)
      - v0.4: type="sig"  (ed25519 signature over payload bytes)
              v0.8.2: opt-in canonical attestation-object signing
              (PIC-ATT/1.0) — see _canonical_attestation_bytes and
              _verify_canonical_attestation_binding.

    Hardening:
      - sandbox file:// under evidence_root_dir
      - max_file_bytes
      - max_payload_bytes (enforced pre-parse AND post-canonicalization)
    """

    def __init__(
        self,
        *,
        key_resolver: Optional[KeyResolver] = None,
        max_file_bytes: int = 5 * 1024 * 1024,  # 5MB
        max_payload_bytes: int = 16 * 1024,  # 16KB payload cap (DoS guard)
        allow_file_evidence: bool = True,
        allow_sig_evidence: bool = True,
    ) -> None:
        self._key_resolver = key_resolver  # None = lazy default on first sig
        self.max_file_bytes = int(max_file_bytes)
        self.max_payload_bytes = int(max_payload_bytes)
        self.allow_file_evidence = bool(allow_file_evidence)
        self.allow_sig_evidence = bool(allow_sig_evidence)

    def _get_key_resolver(self) -> KeyResolver:
        """Lazy-load default resolver on first use. Preserves hash-only semantics."""
        if self._key_resolver is None:
            self._key_resolver = StaticKeyRingResolver(TrustedKeyRing.load_default())
        return self._key_resolver

    def _resolve_public_key(self, key_id: str) -> bytes:
        """Resolve raw public key bytes via the injected (or default) KeyResolver."""
        kid = (key_id or "").strip()
        if not kid:
            raise ValueError("Missing key_id for signature evidence")

        resolver = self._get_key_resolver()
        status = resolver.key_status(kid)

        if status == "revoked":
            raise ValueError(f"Key '{kid}' is revoked")
        if status == "expired":
            raise ValueError(f"Key '{kid}' is expired")
        if status == "missing":
            raise ValueError(f"Unknown key_id '{kid}' (not present in trusted keyring)")

        pub = resolver.get_key(kid)
        if pub is None:
            raise ValueError(f"Unknown or inactive key_id '{kid}'")

        if not isinstance(pub, (bytes, bytearray)):
            raise ValueError(f"Invalid key type for '{kid}' (expected bytes)")
        if len(pub) != 32:
            raise ValueError(f"Invalid Ed25519 public key length for '{kid}' (expected 32 bytes)")

        return bytes(pub)

    def verify_all(
        self,
        proposal: Dict[str, Any],
        *,
        base_dir: Path,
        evidence_root_dir: Optional[Path] = None,
    ) -> EvidenceReport:
        evidence_list = proposal.get("evidence") or []
        if not evidence_list:
            return EvidenceReport(ok=False, results=[], verified_ids=set())

        root_dir = (evidence_root_dir or base_dir).resolve()

        results: List[EvidenceResult] = []
        verified: Set[str] = set()

        for raw in evidence_list:
            ev_id = raw.get("id", "<missing id>")
            try:
                # Parse by declared type (fail-closed)
                ev_type = raw.get("type")
                if ev_type == "hash":
                    ev: EvidenceRef = HashEvidenceRef(**raw)
                elif ev_type == "sig":
                    ev = SigEvidenceRef(**raw)
                else:
                    raise ValueError(f"Unsupported evidence type: {ev_type!r}")

                if isinstance(ev, HashEvidenceRef):
                    if not self.allow_file_evidence:
                        raise ValueError("file evidence is disabled by policy")

                    expected = (ev.sha256 or "").strip().lower()
                    if len(expected) != 64:
                        raise ValueError("Invalid sha256 (expected 64 hex chars)")

                    data = _read_sandboxed_file(
                        ev.ref,
                        base_dir=base_dir,
                        evidence_root_dir=root_dir,
                        max_file_bytes=self.max_file_bytes,
                    )
                    actual = _compute_sha256(data).lower()

                    if actual != expected:
                        results.append(
                            EvidenceResult(
                                id=ev.id,
                                ok=False,
                                message=f"sha256 mismatch (expected {expected}, got {actual})",
                            )
                        )
                        continue

                    verified.add(ev.id)
                    results.append(EvidenceResult(id=ev.id, ok=True, message="sha256 verified"))
                    continue

                # SigEvidenceRef
                if not self.allow_sig_evidence:
                    raise ValueError("signature evidence is disabled by policy")

                # Pre-parse size guard: JSON parsing + canonicalization
                # are not DoS surfaces on oversize payloads.
                raw_payload_bytes = ev.payload.encode("utf-8")
                if len(raw_payload_bytes) > self.max_payload_bytes:
                    raise ValueError(
                        f"Payload too large: {len(raw_payload_bytes)} bytes "
                        f"(max {self.max_payload_bytes})"
                    )

                # Mode detection per spec-evidence.md §6.2.
                parsed_payload, had_duplicate_keys = _parse_payload_for_mode_detection(ev.payload)
                canonical_mode = (
                    isinstance(parsed_payload, dict) and "attestation_version" in parsed_payload
                )

                if canonical_mode:
                    payload_bytes = _canonical_attestation_bytes(
                        parsed_payload,
                        had_duplicate_keys=had_duplicate_keys,
                        max_payload_bytes=self.max_payload_bytes,
                    )
                else:
                    # Legacy mode: raw UTF-8 bytes of the payload string.
                    payload_bytes = raw_payload_bytes

                pub_raw = self._resolve_public_key(ev.key_id)
                ok = _verify_ed25519_signature(
                    public_key_raw=pub_raw,
                    signature_b64=ev.signature,
                    message=payload_bytes,
                )
                if not ok:
                    results.append(
                        EvidenceResult(
                            id=ev.id,
                            ok=False,
                            message=f"signature invalid (key_id='{ev.key_id}')",
                        )
                    )
                    continue

                # Canonical-mode binding (post-signature). See
                # _verify_canonical_attestation_binding for spec/code/vector
                # co-evolution discipline.
                if canonical_mode:
                    _verify_canonical_attestation_binding(
                        parsed_payload, proposal, key_id=ev.key_id
                    )

                verified.add(ev.id)
                results.append(
                    EvidenceResult(
                        id=ev.id,
                        ok=True,
                        message=f"signature verified (key_id='{ev.key_id}')",
                    )
                )

            except Exception as e:
                results.append(EvidenceResult(id=str(ev_id), ok=False, message=str(e)))

        ok = all(r.ok for r in results) and len(results) > 0
        return EvidenceReport(ok=ok, results=results, verified_ids=verified)


def apply_verified_ids_to_provenance(
    proposal: Dict[str, Any], verified_ids: Set[str]
) -> Dict[str, Any]:
    """Upgrade provenance trust levels in-memory based on verified evidence IDs.

    v0.3/v0.4 behavior:
      - If a provenance entry's id is verified, upgrade trust to 'trusted'.
      - Ensure 'source' exists (defensive).
    """
    out = dict(proposal)
    prov_in = proposal.get("provenance") or []
    prov: List[Dict[str, Any]] = [dict(p) for p in prov_in if isinstance(p, dict)]

    for p in prov:
        if p.get("id") in verified_ids:
            p["trust"] = "trusted"
            if not p.get("source"):
                p["source"] = "evidence"

    out["provenance"] = prov
    return out
