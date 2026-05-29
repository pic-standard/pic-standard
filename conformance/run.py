"""PIC Conformance Runner v0.1.

Executes the conformance vectors declared in ``conformance/manifest.json``
against the Python reference implementation and reports pass/fail.

First pass: canonicalization and core modes. Evidence mode added in v0.8.2
(see ``conformance/evidence/README.md``). Trust-sanitization mode and
cross-implementation runners follow in subsequent v0.8.2 PRs per the v0.8.2
release plan; see ``ROADMAP.md`` §1.2.

Usage
-----
From the repo root::

    python -m conformance.run
    python -m conformance.run --manifest conformance/manifest.json
    python -m conformance.run --verbose

Exit codes
----------
- 0  — all vectors passed.
- 1  — at least one vector failed (manifest itself was valid).
- 2  — manifest was malformed (unknown field, invalid mode/expected
       combination, duplicate id, missing required field, etc.).

Schema validation
-----------------
The runner rejects any manifest entry with fields outside the strict
whitelist for its ``(mode, expected)`` tuple, and any ``mode`` /
``expected`` combination not declared in the schema. ``expected_error_code``
(present on block entries for modes whose schema declares it) must be a
non-empty string starting with ``PIC_``. This strictness is deliberate: a
typo in the manifest should surface as a ``ManifestError`` at runner
startup, not as a silently-passing vector.

Manifest-vector consistency
---------------------------
Per-vector execution additionally checks that the vector file's internal
fields agree with the manifest entry (``id``, ``mode`` when declared or
required by the vector mode, ``expected``, and ``expected_error_code`` for
block vectors in modes that declare it). Drift between the manifest and
the file is reported as a vector-level failure with a ``manifest/vector
drift`` reason, not silently preferring one over the other.

Warning handling
----------------
The runner suppresses exactly one known-transitional warning class —
``pic_standard.pipeline.PICTrustFutureWarning`` — around the
``verify_proposal()`` call for core-mode and evidence-mode vectors. Per
``conformance/core/README.md``, warnings are language-specific and out of
scope for shared portable vectors; leaving this particular warning
unsuppressed would produce noise in CI logs during passing runs of
``core-allow-002-trusted-money`` and similar legacy-trust/evidence vectors.
All other warning classes are left unfiltered so that a future regression
surfacing as a ``DeprecationWarning``, ``ResourceWarning``, or
``RuntimeWarning`` is still visible to reviewers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure sdk-python is importable without install — mirrors tests/conftest.py.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SDK_PATH = str(_REPO_ROOT / "sdk-python")
if _SDK_PATH not in sys.path:
    sys.path.insert(0, _SDK_PATH)

from pic_standard.canonical import canonicalize  # noqa: E402 (sys.path setup above)
from pic_standard.keyring import StaticKeyRingResolver, TrustedKeyRing  # noqa: E402
from pic_standard.pipeline import (  # noqa: E402
    PICTrustFutureWarning,
    PipelineOptions,
    verify_proposal,
)

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

VALID_MODES = {"canonicalization", "core", "evidence"}

EXPECTED_BY_MODE: Dict[str, set] = {
    "canonicalization": {"canonical_match"},
    "core": {"allow", "block"},
    "evidence": {"allow", "block"},
}

MANIFEST_TOP_FIELDS = {"version", "vectors"}

# Exact fields allowed on a manifest vector entry, keyed by (mode, expected).
# Anything outside the declared set triggers ManifestError.
# Note: evidence-mode vector-internal fields (`options`, `proposal`,
# `embedded_keyring`) live in the vector file, NOT the manifest entry.
ENTRY_FIELDS: Dict[tuple, set] = {
    ("canonicalization", "canonical_match"): {"id", "file", "mode", "expected"},
    ("core", "allow"): {"id", "file", "mode", "expected"},
    ("core", "block"): {"id", "file", "mode", "expected", "expected_error_code"},
    ("evidence", "allow"): {"id", "file", "mode", "expected"},
    ("evidence", "block"): {"id", "file", "mode", "expected", "expected_error_code"},
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class VectorResult:
    """Outcome of running a single manifest vector."""

    id: str
    mode: str
    passed: bool
    reason: str = ""


@dataclass
class RunnerReport:
    """Aggregate outcome of running a manifest."""

    manifest_version: str
    results: List[VectorResult] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def all_passed(self) -> bool:
        return self.total_count > 0 and self.passed_count == self.total_count

    def format_summary(self, verbose: bool = False) -> str:
        lines = [
            "PIC Conformance Runner v0.1",
            f"Manifest version: {self.manifest_version}",
            f"Vectors:          {self.total_count}",
            "",
        ]
        for r in self.results:
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"  {status}  {r.id}")
            if (not r.passed or verbose) and r.reason:
                for line in r.reason.splitlines():
                    lines.append(f"        {line}")
        lines.append("")
        if self.all_passed:
            lines.append(f"Summary: {self.passed_count}/{self.total_count} passed")
        else:
            failed = self.total_count - self.passed_count
            lines.append(
                f"Summary: {self.passed_count}/{self.total_count} passed ({failed} failed)"
            )
        return "\n".join(lines)


class ManifestError(Exception):
    """Raised when the manifest itself is malformed or contains invalid entries."""


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------


def _validate_manifest(manifest: Any) -> None:
    """Validate manifest structure at load time.

    Rejects unknown fields and mode/expected combinations that aren't in the
    schema. Raises ManifestError on the first problem with a precise message
    including the vector index.
    """
    if not isinstance(manifest, dict):
        raise ManifestError("manifest root must be a JSON object")

    extra = set(manifest.keys()) - MANIFEST_TOP_FIELDS
    if extra:
        raise ManifestError(f"manifest has unexpected top-level fields: {sorted(extra)}")

    missing = MANIFEST_TOP_FIELDS - set(manifest.keys())
    if missing:
        raise ManifestError(f"manifest missing required top-level fields: {sorted(missing)}")

    if not isinstance(manifest["version"], str) or not manifest["version"]:
        raise ManifestError("manifest.version must be a non-empty string")

    if not isinstance(manifest["vectors"], list):
        raise ManifestError("manifest.vectors must be a JSON array")

    seen_ids: set = set()
    for i, entry in enumerate(manifest["vectors"]):
        try:
            _validate_entry(entry)
        except ManifestError as e:
            raise ManifestError(f"manifest.vectors[{i}]: {e}") from e
        eid = entry["id"]
        if eid in seen_ids:
            raise ManifestError(f"manifest.vectors[{i}]: duplicate id {eid!r}")
        seen_ids.add(eid)


def _validate_entry(entry: Any) -> None:
    """Validate a single manifest entry against the (mode, expected) schema."""
    if not isinstance(entry, dict):
        raise ManifestError(f"entry must be an object, got {type(entry).__name__}")

    for required_basic in ("id", "file", "mode", "expected"):
        if required_basic not in entry:
            raise ManifestError(f"missing required field {required_basic!r}")

    mode = entry["mode"]
    if mode not in VALID_MODES:
        raise ManifestError(f"mode {mode!r} is not one of {sorted(VALID_MODES)}")

    expected = entry["expected"]
    allowed_expected = EXPECTED_BY_MODE[mode]
    if expected not in allowed_expected:
        raise ManifestError(
            f"expected {expected!r} is not allowed for mode {mode!r} "
            f"(allowed: {sorted(allowed_expected)})"
        )

    allowed_fields = ENTRY_FIELDS[(mode, expected)]
    extra = set(entry.keys()) - allowed_fields
    if extra:
        raise ManifestError(
            f"unexpected fields {sorted(extra)} for (mode={mode!r}, expected={expected!r}); "
            f"allowed: {sorted(allowed_fields)}"
        )

    missing = allowed_fields - set(entry.keys())
    if missing:
        raise ManifestError(
            f"missing fields {sorted(missing)} for (mode={mode!r}, expected={expected!r})"
        )

    # `expected_error_code` validation generalizes over any (mode, expected)
    # whose ENTRY_FIELDS schema includes the field. Extends cleanly to evidence
    # and future modes without re-touching this branch.
    if "expected_error_code" in allowed_fields:
        ec = entry["expected_error_code"]
        if not isinstance(ec, str) or not ec.startswith("PIC_"):
            raise ManifestError(
                f"expected_error_code must be a non-empty string starting with 'PIC_', got {ec!r}"
            )


# ---------------------------------------------------------------------------
# Manifest-vector consistency check
# ---------------------------------------------------------------------------


def _check_vector_file_agrees_with_entry(
    vec: Dict[str, Any],
    entry: Dict[str, Any],
) -> Optional[str]:
    """Check that the vector file's internal fields agree with the manifest entry.

    Returns a reason string describing the drift if there is any, or None
    if the file and manifest agree. Callers should turn a non-None return
    into a per-vector failure rather than silently proceeding.

    Applies to core-mode and evidence-mode vectors (both carry `expected` and
    optionally `expected_error_code` inside the vector file). Canonicalization
    vector files do not carry duplicate `expected` / `expected_error_code`
    fields, so there is nothing to cross-check at that layer beyond the id.

    Mode drift (v0.8.2+):
      - If a vector file declares `mode` and it disagrees with the manifest
        entry's `mode`, that is drift regardless of which mode is declared.
        This generic check runs for ALL modes — a canonicalization vector
        with a wrong `mode` declaration would still drift.
      - Evidence-mode vector files MUST declare `mode: "evidence"` per
        ``conformance/evidence/README.md``. Existing core-mode vector files
        do NOT declare `mode` and are not required to; backward compat
        preserved.
    """
    mode = entry["mode"]

    # Generic declared-mode mismatch check — runs for ALL modes, before the
    # canonicalization early-return below. Catches canonicalization vectors
    # that declare a stale or wrong `mode` value internally.
    if "mode" in vec and vec["mode"] != entry["mode"]:
        return f"'mode' mismatch: manifest={entry['mode']!r} file={vec['mode']!r}"

    if mode not in ("core", "evidence"):
        return None

    # Evidence-mode vector files MUST declare `mode: "evidence"` explicitly.
    # (Core-mode vector files MAY omit `mode`; the generic check above lets
    # them through as long as no wrong `mode` is declared.)
    if mode == "evidence" and vec.get("mode") != "evidence":
        return "evidence vector file must declare mode='evidence'"

    vec_expected = vec.get("expected")
    if vec_expected != entry["expected"]:
        return f"'expected' mismatch: manifest={entry['expected']!r} file={vec_expected!r}"

    if entry["expected"] == "block":
        vec_code = vec.get("expected_error_code")
        if vec_code != entry["expected_error_code"]:
            return (
                f"'expected_error_code' mismatch: "
                f"manifest={entry['expected_error_code']!r} file={vec_code!r}"
            )
    else:
        # allow: vector file must NOT carry expected_error_code
        if "expected_error_code" in vec:
            return (
                "vector file contains 'expected_error_code' but the manifest "
                "entry declares expected='allow'"
            )

    return None


# ---------------------------------------------------------------------------
# Per-mode vector execution
# ---------------------------------------------------------------------------


def _run_canonicalization_vector(vec: Dict[str, Any]) -> VectorResult:
    """Verify byte-exact canonicalization output and SHA-256 against the vector file."""
    vid = vec["id"]
    try:
        input_value = vec["input"]
        expected_hex = vec["expected_canonical_bytes_hex"]
        expected_sha = vec["expected_sha256_hex"]
    except KeyError as e:
        return VectorResult(
            id=vid,
            mode="canonicalization",
            passed=False,
            reason=f"vector file missing required field: {e}",
        )

    try:
        actual_bytes = canonicalize(input_value)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="canonicalization",
            passed=False,
            reason=f"canonicalize() raised {type(e).__name__}: {e}",
        )

    actual_hex = actual_bytes.hex()
    if actual_hex != expected_hex:
        return VectorResult(
            id=vid,
            mode="canonicalization",
            passed=False,
            reason=(
                f"canonical bytes mismatch\n  expected: {expected_hex}\n  actual:   {actual_hex}"
            ),
        )

    actual_sha = hashlib.sha256(actual_bytes).hexdigest()
    if actual_sha != expected_sha:
        return VectorResult(
            id=vid,
            mode="canonicalization",
            passed=False,
            reason=(f"SHA-256 mismatch\n  expected: {expected_sha}\n  actual:   {actual_sha}"),
        )

    return VectorResult(id=vid, mode="canonicalization", passed=True)


def _run_core_vector(vec: Dict[str, Any], entry: Dict[str, Any]) -> VectorResult:
    """Run proposal through verify_proposal() and check allow/block + error code.

    Suppresses exactly the ``PICTrustFutureWarning`` class around the
    ``verify_proposal()`` call — that warning is known-transitional and
    out of scope for shared portable vectors per conformance/core/README.md.
    All other warning classes pass through unfiltered so that any future
    unexpected warning (regression signal) remains visible in CI logs.
    """
    vid = vec["id"]
    if "proposal" not in vec:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason="vector file missing required field: 'proposal'",
        )

    proposal = vec["proposal"]
    options_dict = vec.get("options", {})
    try:
        options = PipelineOptions(**options_dict)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason=f"could not construct PipelineOptions: {type(e).__name__}: {e}",
        )

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=PICTrustFutureWarning)
            result = verify_proposal(proposal, options=options)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason=f"verify_proposal() raised {type(e).__name__}: {e}",
        )

    if entry["expected"] == "allow":
        if result.ok:
            return VectorResult(id=vid, mode="core", passed=True)
        code = result.error.code.value if (result.error and result.error.code) else "<none>"
        return VectorResult(
            id=vid, mode="core", passed=False, reason=f"expected allow but got block ({code})"
        )

    # expected == "block"
    if result.ok:
        return VectorResult(
            id=vid, mode="core", passed=False, reason="expected block but proposal was allowed"
        )
    if result.error is None or result.error.code is None:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason="expected block with error code, got block with no error code",
        )
    actual_code = result.error.code.value
    expected_code = entry["expected_error_code"]
    if actual_code != expected_code:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason=f"expected {expected_code} but got {actual_code}",
        )
    return VectorResult(id=vid, mode="core", passed=True)


# ---------------------------------------------------------------------------
# Evidence-mode helpers + dispatch (v0.8.2)
# ---------------------------------------------------------------------------


def _build_key_resolver_from_embedded_keyring(vec: Dict[str, Any]) -> Optional[Any]:
    """Construct an in-memory KeyResolver from the vector's `embedded_keyring`.

    Returns None if the vector has no `embedded_keyring` field (hash-only
    vectors don't need a resolver). Returns a StaticKeyRingResolver wrapping
    a TrustedKeyRing parsed via `TrustedKeyRing.from_dict()` otherwise.

    The keyring is hermetic per `conformance/evidence/README.md` — no env
    vars consulted, no disk I/O.
    """
    ek = vec.get("embedded_keyring")
    if ek is None:
        return None
    keyring = TrustedKeyRing.from_dict(ek)
    return StaticKeyRingResolver(keyring)


def _resolve_evidence_root_against_repo_root(
    options_dict: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a copy of `options_dict` with `evidence_root_dir` resolved.

    Per `conformance/evidence/README.md` (LOCKED rule), `evidence_root_dir`
    in vectors is resolved relative to the **repository root** — NOT the
    manifest directory, NOT the process working directory. The repo root is
    `_REPO_ROOT` defined at module load time (two levels up from this file).

    Behavior:

      - Key absent: returns `options_dict` unchanged. Legitimate for sig-only
        vectors that don't need a filesystem root.
      - Key present but null / non-string / empty: REJECTED with
        ``"evidence_root_dir must be a non-empty repository-root-relative
        string"``. Treating "explicit null" the same as "absent" would leave a
        malformed portable path knob accepted by the runner.
      - Key present and a non-empty string: enforces three additional
        invariants below, all fail-closed.

    Resolution invariants enforced (all fail-closed):

      1. Absolute paths are REJECTED — they would encode local filesystem
         layout into a portable vector.
      2. Paths that escape `_REPO_ROOT` via `..` traversal are REJECTED — a
         vector that resolves outside the repository root would re-introduce
         local-filesystem coupling through the back door.
      3. Paths outside `conformance/artifacts/` are REJECTED — the public
         contract is that SHA-pinned artifacts live under that subtree. A
         vector that points elsewhere (e.g., `"."` or `"sdk-python"`) could
         hash arbitrary repo files and weaken the artifact contract.

    Hermeticity for file-backed hash vectors is enforced separately in
    `_run_evidence_vector` via a non-empty-string check before this function
    is called; that catches "key absent" for hash vectors that need it.
    """
    out = dict(options_dict)
    if "evidence_root_dir" not in out:
        return out

    erd = out["evidence_root_dir"]
    if not isinstance(erd, str) or not erd:
        raise ValueError("evidence_root_dir must be a non-empty repository-root-relative string")

    p = Path(erd)
    if p.is_absolute():
        raise ValueError("evidence_root_dir must be repository-root-relative")
    p = (_REPO_ROOT / p).resolve()
    try:
        p.relative_to(_REPO_ROOT)
    except ValueError as e:
        raise ValueError("evidence_root_dir must stay within repository root") from e
    artifacts_root = (_REPO_ROOT / "conformance" / "artifacts").resolve()
    try:
        p.relative_to(artifacts_root)
    except ValueError as e:
        raise ValueError("evidence_root_dir must stay within conformance/artifacts") from e
    out["evidence_root_dir"] = p
    return out


def _proposal_evidence_entries(proposal: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Return dict-shaped evidence entries from a proposal."""
    evidence = proposal.get("evidence", [])
    if not isinstance(evidence, list):
        return []
    return [ev for ev in evidence if isinstance(ev, dict)]


def _proposal_contains_sig_evidence(proposal: Dict[str, Any]) -> bool:
    """True when the proposal contains signature evidence."""
    return any(ev.get("type") == "sig" for ev in _proposal_evidence_entries(proposal))


def _proposal_contains_file_hash_evidence(proposal: Dict[str, Any]) -> bool:
    """True when the proposal contains hash evidence backed by file:// refs."""
    return any(
        ev.get("type") == "hash"
        and isinstance(ev.get("ref"), str)
        and ev["ref"].startswith("file://")
        for ev in _proposal_evidence_entries(proposal)
    )


def _run_evidence_vector(vec: Dict[str, Any], entry: Dict[str, Any]) -> VectorResult:
    """Run an evidence-mode vector through verify_proposal() with the vector's
    declared options + a runner-constructed key_resolver.

    Mirrors `_run_core_vector` but:
      - Enforces that `options` is present and `verify_evidence=True` (a vector
        that doesn't actually exercise evidence verification is a vector bug)
      - Rejects `key_resolver` declared inside vector options (the only path to
        a resolver is via `embedded_keyring`; smuggling a resolver-shaped value
        through JSON is a vector bug)
      - Rejects `proposal_base_dir` declared inside vector options (the runner
        derives it from `evidence_root_dir`; a vector-declared value would be
        a non-portable filesystem knob)
      - Rejects non-dict `proposal` values fail-closed before any helper
        attempts dict access
      - Enforces hermeticity: sig-evidence vectors MUST declare a non-null
        object `embedded_keyring`; file-backed hash-evidence vectors MUST
        declare a non-empty string `options.evidence_root_dir`. Presence-only
        checks (e.g., `"key" in vec`) are NOT sufficient — explicit nulls
        would otherwise allow env-var / CWD fallbacks
      - Constructs a key_resolver from `embedded_keyring` (if present)
      - Resolves `evidence_root_dir` against the repository root and rejects
        absolute paths, paths that escape the repo root via `..` traversal,
        and paths outside `conformance/artifacts/`. Also rejects an explicit
        null/non-string/empty value (closes a sig-only vector bypass)
      - Derives `proposal_base_dir` from the resolved `evidence_root_dir` so
        that `file://<name>` refs inside evidence entries resolve under the
        configured artifact root (matches the README path-resolution contract)
      - Suppresses PICTrustFutureWarning around the verify call (same as core)
    """
    vid = vec["id"]
    if "proposal" not in vec:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="vector file missing required field: 'proposal'",
        )

    # Enforce that evidence vectors declare options AND set verify_evidence=true.
    # Evidence mode must prove evidence actually ran; an empty/missing options
    # block or verify_evidence!=true would make the vector a no-op and silently
    # pass on cases that should be exercising the evidence path.
    if "options" not in vec or not isinstance(vec["options"], dict):
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="evidence vector missing required object field: 'options'",
        )

    options_dict = vec["options"]

    # Prevent a vector JSON from smuggling a runner-constructed object field
    # into PipelineOptions. The only path to a key_resolver is via
    # embedded_keyring -> _build_key_resolver_from_embedded_keyring().
    if "key_resolver" in options_dict:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="evidence vector options must not declare key_resolver; use embedded_keyring",
        )

    # Prevent a vector JSON from declaring proposal_base_dir directly. The
    # runner derives it from the resolved evidence_root_dir below — a
    # vector-supplied value would be a non-portable filesystem knob that
    # breaks the README path-resolution contract.
    if "proposal_base_dir" in options_dict:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=(
                "evidence vector options must not declare proposal_base_dir; "
                "the runner derives it from evidence_root_dir"
            ),
        )

    if options_dict.get("verify_evidence") is not True:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="evidence vector must set options.verify_evidence=true",
        )

    proposal = vec["proposal"]

    # Defensive type guard. Helpers below call `proposal.get(...)`, which
    # crashes if `proposal` is a list, string, number, etc. Fail-closed with
    # a clear reason instead of leaking an AttributeError.
    if not isinstance(proposal, dict):
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="vector file field 'proposal' must be an object",
        )

    # Hermeticity guards: prevent fallback to env-var keyring or CWD-based
    # evidence root. Per conformance/evidence/README.md, sig vectors carry
    # their own keyring and file-backed hash vectors declare their root.
    # `null` is treated as missing — a vector with `"embedded_keyring": null`
    # would otherwise let the evidence system fall back to PIC_KEYS_PATH.
    if _proposal_contains_sig_evidence(proposal) and not isinstance(
        vec.get("embedded_keyring"), dict
    ):
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="signature evidence vector must declare object field embedded_keyring",
        )

    if _proposal_contains_file_hash_evidence(proposal):
        erd = options_dict.get("evidence_root_dir")
        if not isinstance(erd, str) or not erd:
            return VectorResult(
                id=vid,
                mode="evidence",
                passed=False,
                reason=(
                    "file-backed hash evidence vector must set non-empty "
                    "string options.evidence_root_dir"
                ),
            )

    # Build key_resolver from embedded_keyring (if any)
    try:
        key_resolver = _build_key_resolver_from_embedded_keyring(vec)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"could not build key_resolver from embedded_keyring: {type(e).__name__}: {e}",
        )

    # Resolve evidence_root_dir against repo root (rejects absolute paths,
    # paths that escape the repo via `..` traversal, paths outside
    # conformance/artifacts/, and explicit null/non-string/empty values)
    try:
        options_dict = _resolve_evidence_root_against_repo_root(options_dict)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"could not resolve evidence_root_dir: {type(e).__name__}: {e}",
        )

    # Derive proposal_base_dir from the resolved evidence_root_dir so that
    # file://<name> refs inside evidence entries resolve under the configured
    # artifact root. Without this, the pipeline defaults base_dir to CWD,
    # which breaks the README path-resolution contract (rule 2). Vectors
    # cannot declare proposal_base_dir themselves — see guard above.
    if "evidence_root_dir" in options_dict:
        options_dict = {
            **options_dict,
            "proposal_base_dir": options_dict["evidence_root_dir"],
        }

    # Inject key_resolver into options (if built)
    if key_resolver is not None:
        options_dict = {**options_dict, "key_resolver": key_resolver}

    try:
        options = PipelineOptions(**options_dict)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"could not construct PipelineOptions: {type(e).__name__}: {e}",
        )

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=PICTrustFutureWarning)
            result = verify_proposal(proposal, options=options)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"verify_proposal() raised {type(e).__name__}: {e}",
        )

    if entry["expected"] == "allow":
        if result.ok:
            return VectorResult(id=vid, mode="evidence", passed=True)
        code = result.error.code.value if (result.error and result.error.code) else "<none>"
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"expected allow but got block ({code})",
        )

    # expected == "block"
    if result.ok:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="expected block but proposal was allowed",
        )
    if result.error is None or result.error.code is None:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="expected block with error code, got block with no error code",
        )
    actual_code = result.error.code.value
    expected_code = entry["expected_error_code"]
    if actual_code != expected_code:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"expected {expected_code} but got {actual_code}",
        )
    return VectorResult(id=vid, mode="evidence", passed=True)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_manifest(manifest_path: Path) -> RunnerReport:
    """Load and validate a manifest, execute every vector, return aggregate report.

    Raises:
        ManifestError: if the manifest itself is malformed. Per-vector
            execution failures (including manifest/vector drift) are
            captured in the returned report rather than raised, so all
            failures are visible in one pass.
    """
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        raise ManifestError(f"manifest not found: {manifest_path}")

    with manifest_path.open("r", encoding="utf-8") as f:
        try:
            manifest = json.load(f)
        except json.JSONDecodeError as e:
            raise ManifestError(f"manifest is not valid JSON: {e}") from e

    _validate_manifest(manifest)

    conformance_root = manifest_path.resolve().parent
    report = RunnerReport(manifest_version=manifest["version"])

    for entry in manifest["vectors"]:
        vec_path = conformance_root / entry["file"]
        if not vec_path.exists():
            report.results.append(
                VectorResult(
                    id=entry["id"],
                    mode=entry["mode"],
                    passed=False,
                    reason=f"vector file not found: {entry['file']}",
                )
            )
            continue
        try:
            with vec_path.open("r", encoding="utf-8") as f:
                vec = json.load(f)
        except json.JSONDecodeError as e:
            report.results.append(
                VectorResult(
                    id=entry["id"],
                    mode=entry["mode"],
                    passed=False,
                    reason=f"vector file is not valid JSON: {e}",
                )
            )
            continue

        if vec.get("id") != entry["id"]:
            report.results.append(
                VectorResult(
                    id=entry["id"],
                    mode=entry["mode"],
                    passed=False,
                    reason=f"id mismatch: manifest={entry['id']!r} file={vec.get('id')!r}",
                )
            )
            continue

        drift = _check_vector_file_agrees_with_entry(vec, entry)
        if drift is not None:
            report.results.append(
                VectorResult(
                    id=entry["id"],
                    mode=entry["mode"],
                    passed=False,
                    reason=f"manifest/vector drift: {drift}",
                )
            )
            continue

        if entry["mode"] == "canonicalization":
            report.results.append(_run_canonicalization_vector(vec))
        elif entry["mode"] == "evidence":
            report.results.append(_run_evidence_vector(vec, entry))
        else:
            # core (default — preserved for backward compat with existing
            # manifest entries that don't declare evidence/trust_sanitization)
            report.results.append(_run_core_vector(vec, entry))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m conformance.run",
        description=(
            "PIC Conformance Runner v0.1 — executes canonicalization, core, and evidence vectors."
        ),
    )
    parser.add_argument(
        "--manifest",
        default=str(_REPO_ROOT / "conformance" / "manifest.json"),
        help=(
            "Path to the conformance manifest JSON "
            "(default: conformance/manifest.json at repo root)."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show per-vector detail even for passing vectors.",
    )
    args = parser.parse_args(argv)

    try:
        report = run_manifest(Path(args.manifest))
    except ManifestError as e:
        print(f"ManifestError: {e}", file=sys.stderr)
        return 2

    print(report.format_summary(verbose=args.verbose))
    return 0 if report.all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
